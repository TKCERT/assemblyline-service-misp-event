import json
from enum import IntEnum
from urllib.parse import urlsplit
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import BODY_FORMAT, Result, ResultSection

from pymisp import ExpandedPyMISP, MISPEvent, MISPObject

# Unified mapping configuration for AL -> MISP processing.
# A list is used intentionally to avoid redundant top-level keys.
#
# Naming conventions in mapping entries:
# - al_tag_patterns: Assemblyline tag keys to read values from.
# - misp_attributes: Per-relation options keyed by MISP object relation.
#   The primary relation is the one without a value entry.
#   Supported options: value, type, ids, correlate, tag.
#   type is required for each relation used by the mapping.
#   Defaults: ids=False, correlate=False, tag=False.
# - misp_source_file_relationship: Optional reference relationship from object to source file.
#   Defaults to derived-from for non-file object mappings; omitted for file mappings unless needed.
TAG_PROCESSING_MAPPINGS: List[Dict[str, Any]] = [
    {
        "al_tag_patterns": ["network.dynamic.uri", "network.static.uri"],
        "misp_object_name": "url",
        "misp_attributes": {
            "url": {"type": "url", "ids": True, "correlate": True, "tag": True},
            "scheme": {"value": lambda x: urlsplit(x).scheme, "type": "text"},
            "host": {"value": lambda x: urlsplit(x).netloc, "type": "text"},
            "resource_path": {"value": lambda x: urlsplit(x).path, "type": "text"},
            "query_string": {"value": lambda x: urlsplit(x).query, "type": "text"},
            "fragment": {"value": lambda x: urlsplit(x).fragment, "type": "text"},
        },
    },
    {
        "al_tag_patterns": ["network.dynamic.domain", "network.static.domain"],
        "misp_object_name": "domain-ip",
        "misp_attributes": {
            "domain": {"type": "domain", "ids": True, "correlate": True, "tag": True},
        },
    },
    {
        "al_tag_patterns": ["network.dynamic.ip", "network.static.ip"],
        "misp_object_name": "domain-ip",
        "misp_attributes": {
            "ip": {"type": "ip-dst", "ids": True, "correlate": True, "tag": True},
        },
    },
    {
        "al_tag_patterns": ["network.email.address"],
        "misp_object_name": "person",
        "misp_attributes": {
            "e-mail": {"type": "email-src", "ids": True, "correlate": True, "tag": True},
        },
    },
    {
        "al_tag_patterns": ["network.email.subject"],
        "misp_object_name": "email",
        "misp_attributes": {
            "subject": {"type": "email-subject", "correlate": True, "tag": True},
        },
    },
    {
        "al_tag_patterns": ["dynamic.registry_key"],
        "misp_object_name": "registry-key",
        "misp_attributes": {
            "key": {"type": "regkey", "ids": True, "correlate": True, "tag": True},
        },
    },
    {
        "al_tag_patterns": ["static.signature.name", "static.signature.category", "file.rule.yara", "av.virus_name"],
        "misp_object_name": "av-signature",
        "misp_attributes": {
            "signature": {"type": "text", "correlate": True},
            "software": {"value": "Assemblyline", "type": "text"},
        },
    },
    {
        "al_tag_patterns": ["dynamic.signature.name", "dynamic.signature.category", "file.behavior"],
        "misp_object_name": "sb-signature",
        "misp_attributes": {
            "signature": {"type": "text", "correlate": True},
            "software": {"value": "Assemblyline", "type": "text"},
        },
    },
    {
        "al_tag_patterns": ["dynamic.signature.family"],
        "misp_object_name": "malware",
        "misp_attributes": {
            "name": {"type": "text", "correlate": True},
            "is_family": {"value": True, "type": "boolean"},
        },
    },
    {
        "al_tag_patterns": ["file.sha256"],
        "misp_object_name": "file",
        "misp_attributes": {
            "sha256": {"type": "sha256", "ids": True, "correlate": True, "tag": True},
        },
    },
    {
        "al_tag_patterns": ["file.name"],
        "misp_object_name": "file",
        "misp_attributes": {
            "filename": {"type": "filename", "correlate": True, "tag": True},
        },
    },
    {
        "al_tag_patterns": ["file.name.extracted"],
        "misp_object_name": "file",
        "misp_attributes": {
            "filename": {"type": "filename", "correlate": True, "tag": True},
        },
        "misp_source_file_relationship": "extracted-from",
    },
]


class MalwareAnalysisResult(IntEnum):
    UNKNOWN = 0
    BENIGN = 1
    SUSPICIOUS = 2
    MALICIOUS = 3


IFX_VETTING_TAG_PREFIX = "ifx-vetting:vetted"
WORKFLOW_REVIEW_TAG = 'workflow:todo="review-before-publication"'

class MISPService(ServiceBase):
    MISP_SERVICE_URL_CONFIG_KEY: str = "misp_service_url"
    MISP_SERVICE_API_KEY_CONFIG_KEY: str = "misp_service_api_key"
    SUBMISSION_EVENT_INFO_PREFIX: str = "Assemblyline Submission"
    MALWARE_ANALYSIS_PRODUCT: str = "Assemblyline"
    SUBMISSION_CONFIGURATION_VERSION_PREFIX: str = "submission-id:"
    DEFAULT_ANCESTRY_RELATIONSHIP_TYPE: str = "derived-from"
    PARENT_RELATION_TO_MISP_RELATIONSHIP: Dict[str, str] = {
        "DECRYPTED": "derived-from",
        "DEOBFUSCATED": "derived-from",
        "DOWNLOADED": "downloaded-from",
        "DROPPED": "dropped-by",
        "DYNAMIC": "dropped-by",
        "EXTRACTED": "extracted-from",
        "INCLUDED": "included-in",
        "ROOT": "derived-from",
    }

    def __init__(self, config: Optional[Dict] = None) -> None:
        super(MISPService, self).__init__(config)

        self.misp_service_url = self.config.get(self.MISP_SERVICE_URL_CONFIG_KEY)
        self.misp_service_api_key = self.config.get(self.MISP_SERVICE_API_KEY_CONFIG_KEY)
        self.verify = self.config.get("verify_certificate", True)

        if not self.misp_service_url:
            raise RuntimeError("MISP service URL not set in the config. Check the config section in the manifest?")

        if not self.misp_service_api_key:
            raise RuntimeError("MISP service API key not set in the config. Check the config section in the manifest?")

    def start(self):
        self.log.info(f"start() from {self.service_attributes.name} service called")

        self.pymisp = ExpandedPyMISP(self.misp_service_url, self.misp_service_api_key, self.verify, tool="Assemblyline")

    def _json_dump(self, data: Any) -> str:
        return json.dumps(data, indent=2, default=str)

    def _submission_event_info(self, sid: str) -> str:
        return f"{self.SUBMISSION_EVENT_INFO_PREFIX} {sid}"

    def _submission_configuration_version_marker(self, sid: str) -> str:
        return f"{self.SUBMISSION_CONFIGURATION_VERSION_PREFIX}{sid}"

    def _relationship_type_for_parent_relation(self, parent_relation: Optional[str]) -> str:
        if not parent_relation:
            return self.DEFAULT_ANCESTRY_RELATIONSHIP_TYPE
        return self.PARENT_RELATION_TO_MISP_RELATIONSHIP.get(
            str(parent_relation).upper(),
            self.DEFAULT_ANCESTRY_RELATIONSHIP_TYPE,
        )

    def _normalize_events(self, raw_events: Any) -> Iterable[MISPEvent]:
        if isinstance(raw_events, MISPEvent):
            return [raw_events]

        if isinstance(raw_events, list):
            iterable = raw_events
        elif isinstance(raw_events, dict) and isinstance(raw_events.get("response"), list):
            iterable = raw_events["response"]
        elif isinstance(raw_events, dict):
            iterable = [raw_events]
        else:
            iterable = []

        normalized_events = []
        for item in iterable:
            if isinstance(item, MISPEvent):
                normalized_events.append(item)
                continue

            if not isinstance(item, dict):
                continue

            try:
                event = MISPEvent()
                event.load(item)
                normalized_events.append(event)
            except Exception:
                continue

        return normalized_events

    def _extract_event_id_from_attribute(self, attribute: Any) -> Optional[str]:
        event_id = getattr(attribute, "event_id", None)
        if event_id:
            return str(event_id)

        if isinstance(attribute, dict):
            if attribute.get("event_id"):
                return str(attribute["event_id"])
            event_data = attribute.get("Event")
            if isinstance(event_data, dict) and event_data.get("id"):
                return str(event_data["id"])

        return None

    def _event_has_submission_marker(self, event: MISPEvent, sid: str) -> bool:
        marker = self._submission_configuration_version_marker(sid)
        expected_product = self.MALWARE_ANALYSIS_PRODUCT.lower()
        expected_marker = marker.lower()

        for obj in event.objects:
            if obj.name != "malware-analysis":
                continue

            products = {
                str(attr.value).strip().lower()
                for attr in obj.get_attributes_by_relation("product")
                if hasattr(attr, "value") and str(attr.value).strip()
            }
            configuration_versions = {
                str(attr.value).strip().lower()
                for attr in obj.get_attributes_by_relation("configuration_version")
                if hasattr(attr, "value") and str(attr.value).strip()
            }

            if expected_product in products and expected_marker in configuration_versions:
                return True

        return False

    def _find_existing_event(self, sid: str) -> Optional[MISPEvent]:
        event_info = self._submission_event_info(sid)
        search_result = self.pymisp.search(
            controller="events",
            return_format="json",
            eventinfo=event_info,
            pythonify=True,
        )
        events = list(self._normalize_events(search_result))
        if events:
            return events[0]

        marker = self._submission_configuration_version_marker(sid)
        attribute_search = self.pymisp.search(
            controller="attributes",
            return_format="json",
            value=marker,
            include_context=True,
            pythonify=True,
        )
        if isinstance(attribute_search, list):
            attributes_iterable = attribute_search
        elif isinstance(attribute_search, dict) and isinstance(attribute_search.get("response"), list):
            attributes_iterable = attribute_search["response"]
        elif isinstance(attribute_search, dict):
            attributes_iterable = [attribute_search]
        else:
            attributes_iterable = []

        seen_event_ids: Set[str] = set()
        for attribute in attributes_iterable:
            event_id = self._extract_event_id_from_attribute(attribute)
            if not event_id or event_id in seen_event_ids:
                continue
            seen_event_ids.add(event_id)

            try:
                event = self.pymisp.get_event(event_id, pythonify=True)
            except Exception:
                continue

            if isinstance(event, MISPEvent) and self._event_has_submission_marker(event, sid):
                return event

        return None

    def _object_has_relation_value(self, obj: MISPObject, object_relation: str, value: Any) -> bool:
        relation_values = {str(a.value) for a in obj.get_attributes_by_relation(object_relation) if hasattr(a, "value")}
        return str(value) in relation_values

    def _set_object_attribute_value(
        self,
        obj: MISPObject,
        object_relation: str,
        value: Any,
        attr_type: Optional[str] = None,
    ) -> None:
        if value is None:
            return
        if isinstance(value, str) and not value.strip():
            return

        relation_attributes = obj.get_attributes_by_relation(object_relation)
        if relation_attributes:
            first_attribute = relation_attributes[0]
            if str(first_attribute.value) == str(value) and len(relation_attributes) == 1:
                return

            duplicates = relation_attributes[1:]
            if duplicates:
                obj.Attribute = [attribute for attribute in obj.Attribute if attribute not in duplicates]
                del relation_attributes[1:]

            first_attribute.value = value
            if attr_type:
                first_attribute.type = attr_type
            obj.edited = True
            return

        self._add_object_attribute_if_missing(obj, object_relation, value, attr_type)

    def _ifx_vetting_rank(self, tag_value: str) -> int:
        normalized = tag_value.strip().lower()
        if normalized == "malicious":
            return 2
        if normalized in {"malicious-uncertain", "suspicious"}:
            return 1
        return 0

    def _highest_ifx_vetting_tag_name(self, event: MISPEvent) -> Optional[str]:
        highest_value: Optional[str] = None
        highest_rank = 0
        prefix = f'{IFX_VETTING_TAG_PREFIX}="'

        for obj in event.objects:
            for attribute in getattr(obj, "attributes", []) or []:
                for tag in getattr(attribute, "tags", []) or []:
                    raw_name = str(getattr(tag, "name", "")).strip()
                    if not raw_name.lower().startswith(prefix.lower()) or not raw_name.endswith('"'):
                        continue
                    tag_value = raw_name[len(prefix):-1]
                    rank = self._ifx_vetting_rank(tag_value)
                    if rank > highest_rank:
                        highest_rank = rank
                        highest_value = tag_value

        if highest_rank == 0 or not highest_value:
            return None
        return f'{IFX_VETTING_TAG_PREFIX}="{highest_value}"'

    def _apply_event_tags_from_ifx_vetting(self, event: MISPEvent) -> None:
        highest_ifx_tag = self._highest_ifx_vetting_tag_name(event)
        if highest_ifx_tag:
            event.add_tag(highest_ifx_tag)
            event.add_tag(WORKFLOW_REVIEW_TAG)

    def _ifx_vetting_tag_value(self, score: Optional[int]) -> Optional[str]:
        result = self._malware_analysis_result_for_score(score)
        if result == MalwareAnalysisResult.MALICIOUS:
            return "malicious"
        if result == MalwareAnalysisResult.SUSPICIOUS:
            return "malicious-uncertain"
        return None

    def _tag_attribute_if_needed(
        self,
        attribute: Any,
        score: Optional[int],
        force_to_ids_false: bool = False,
    ) -> None:
        if attribute is None:
            return
        tag_value = self._ifx_vetting_tag_value(score)
        if force_to_ids_false:
            attribute.to_ids = False
        else:
            attribute.to_ids = tag_value is not None
        if tag_value is None:
            return
        tag_name = f'{IFX_VETTING_TAG_PREFIX}="{tag_value}"'
        attribute.add_tag(tag_name)

    def _add_object_attribute_if_missing(
        self,
        obj: MISPObject,
        object_relation: str,
        value: Any,
        attr_type: Optional[str] = None,
        disable_correlation: Optional[bool] = None,
    ) -> Optional[Any]:
        if value is None:
            return None
        if isinstance(value, str) and not value.strip():
            return None
        if self._object_has_relation_value(obj, object_relation, value):
            relation_attributes = obj.get_attributes_by_relation(object_relation)
            return relation_attributes[0] if relation_attributes else None

        if disable_correlation is None:
            disable_correlation = False
        try:
            if attr_type:
                return obj.add_attribute(object_relation, value, type=attr_type, disable_correlation=disable_correlation)
            else:
                return obj.add_attribute(object_relation, value, disable_correlation=disable_correlation)
        except Exception as error:
            # If object templates are unavailable, PyMISP requires explicit attribute types.
            if "type of the attribute is required" not in str(error):
                raise
            if not attr_type:
                raise RuntimeError(
                    f"Attribute type is required for {obj.name}:{object_relation} when MISP templates are unavailable."
                )
            return obj.add_attribute(object_relation, value, type=attr_type, disable_correlation=disable_correlation)

    def _value_norm_key(self, value: str) -> str:
        return value.strip().lower()

    def _object_attribute_index_key(self, object_name: str, object_relation: str) -> str:
        return f"{object_name}:{object_relation}"

    def _stats_key_for_object_name(self, object_name: str) -> str:
        normalized_object_name = object_name.strip().replace("-", "_")
        return f"new_{normalized_object_name}_objects"

    def _index_existing_object_values(self, event: MISPEvent) -> Dict[str, Dict[str, MISPObject]]:
        index: Dict[str, Dict[str, MISPObject]] = {}

        for obj in event.objects:
            if obj.name == "domain-ip":
                for object_relation in ("domain", "ip"):
                    bucket_key = self._object_attribute_index_key("domain-ip", object_relation)
                    index.setdefault(bucket_key, {})
                    for attr in obj.get_attributes_by_relation(object_relation):
                        index[bucket_key][self._value_norm_key(str(attr.value))] = obj
            elif obj.name == "url":
                bucket_key = self._object_attribute_index_key("url", "url")
                index.setdefault(bucket_key, {})
                for attr in obj.get_attributes_by_relation("url"):
                    index[bucket_key][self._value_norm_key(str(attr.value))] = obj
            elif obj.name == "registry-key":
                bucket_key = self._object_attribute_index_key("registry-key", "key")
                index.setdefault(bucket_key, {})
                for attr in obj.get_attributes_by_relation("key"):
                    index[bucket_key][self._value_norm_key(str(attr.value))] = obj
            elif obj.name == "malware":
                bucket_key = self._object_attribute_index_key("malware", "name")
                index.setdefault(bucket_key, {})
                # Keep alias as a compatibility source for matching historical malware objects.
                for object_relation in ("name", "alias"):
                    for attr in obj.get_attributes_by_relation(object_relation):
                        index[bucket_key][self._value_norm_key(str(attr.value))] = obj
            elif obj.name in {"av-signature", "sb-signature"}:
                bucket_key = self._object_attribute_index_key(obj.name, "signature")
                index.setdefault(bucket_key, {})
                for attr in obj.get_attributes_by_relation("signature"):
                    index[bucket_key][self._value_norm_key(str(attr.value))] = obj
            elif obj.name == "file":
                sha_bucket_key = self._object_attribute_index_key("file", "sha256")
                filename_bucket_key = self._object_attribute_index_key("file", "filename")
                index.setdefault(sha_bucket_key, {})
                index.setdefault(filename_bucket_key, {})
                for attr in obj.get_attributes_by_relation("sha256"):
                    index[sha_bucket_key][self._value_norm_key(str(attr.value))] = obj
                for attr in obj.get_attributes_by_relation("filename"):
                    index[filename_bucket_key][self._value_norm_key(str(attr.value))] = obj

        return index

    def _count_file_objects(self, event: MISPEvent) -> int:
        return sum(1 for obj in event.objects if obj.name == "file")

    def _add_reference_if_missing(self, source_obj: MISPObject, target_obj: MISPObject, relationship_type: str) -> None:
        for reference in source_obj.references:
            if (
                reference.referenced_uuid == target_obj.uuid
                and reference.relationship_type == relationship_type
            ):
                return

        source_obj.add_reference(target_obj, relationship_type=relationship_type)

    def _extract_tag_values(self, tags: Dict[str, Any], key: str) -> Iterable[str]:
        for value_with_score in tags.get(key, []) or []:
            if isinstance(value_with_score, (list, tuple)) and value_with_score:
                tag_value = value_with_score[0]
            else:
                tag_value = value_with_score

            if tag_value is None:
                continue

            tag_value = str(tag_value).strip()
            if tag_value:
                yield tag_value

    def _extract_tag_values_with_scores(self, tags: Dict[str, Any], key: str) -> Iterable[Tuple[str, Optional[int]]]:
        for value_with_score in tags.get(key, []) or []:
            if isinstance(value_with_score, (list, tuple)) and value_with_score:
                tag_value = value_with_score[0]
                tag_score = value_with_score[1] if len(value_with_score) > 1 and isinstance(value_with_score[1], int) else None
            else:
                tag_value = value_with_score
                tag_score = None

            if tag_value is None:
                continue

            tag_value = str(tag_value).strip()
            if tag_value:
                yield tag_value, tag_score

    def _link_object_to_source_file(
        self,
        obj: MISPObject,
        source_file_obj: Optional[MISPObject],
        relationship_type: Optional[str] = None,
    ) -> bool:
        if source_file_obj is None or obj.uuid == source_file_obj.uuid:
            return False

        relation = relationship_type or self.DEFAULT_ANCESTRY_RELATIONSHIP_TYPE
        reference_count_before = len(obj.references)
        self._add_reference_if_missing(obj, source_file_obj, relation)
        return len(obj.references) > reference_count_before

    def _mapping_misp_attributes(self, mapping: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        raw_misp_attributes = mapping.get("misp_attributes", {}) or {}
        return {
            str(relation): dict(options or {})
            for relation, options in raw_misp_attributes.items()
        }

    def _primary_mapping_relation(self, misp_attributes: Dict[str, Dict[str, Any]]) -> str:
        primary_relations = [
            relation for relation, options in misp_attributes.items()
            if "value" not in options
        ]
        if len(primary_relations) != 1:
            raise RuntimeError(
                "Each mapping must define exactly one primary misp_attributes entry without 'value'."
            )
        return primary_relations[0]

    def _required_mapping_attribute_type(
        self,
        object_name: str,
        relation: str,
        options: Dict[str, Any],
    ) -> str:
        attr_type = options.get("type")
        if isinstance(attr_type, str) and attr_type.strip():
            return attr_type
        raise RuntimeError(
            f"Mapping for object '{object_name}' relation '{relation}' must define a non-empty 'type'."
        )

    def _upsert_object_from_mapping(
        self,
        event: MISPEvent,
        mapping: Dict[str, Any],
        value: str,
        object_value_index: Dict[str, Dict[str, MISPObject]],
        source_file_obj: Optional[MISPObject],
        score: Optional[int] = None,
    ) -> Tuple[bool, bool]:
        normalized = self._value_norm_key(value)
        object_name = str(mapping["misp_object_name"])
        misp_attributes = self._mapping_misp_attributes(mapping)
        object_relation = self._primary_mapping_relation(misp_attributes)
        index_key = self._object_attribute_index_key(object_name, object_relation)

        primary_relation_options = misp_attributes.get(object_relation, {})

        def _ids_enabled(relation: str) -> bool:
            return bool(misp_attributes.get(relation, {}).get("ids", False))

        def _disable_correlation(relation: str) -> bool:
            return not bool(misp_attributes.get(relation, {}).get("correlate", False))

        def _tag_enabled(relation: str) -> bool:
            return bool(misp_attributes.get(relation, {}).get("tag", False))

        def _apply_relation_flags(attribute: Any, relation: str) -> None:
            if attribute is None:
                return
            if hasattr(attribute, "disable_correlation"):
                attribute.disable_correlation = _disable_correlation(relation)

            if _tag_enabled(relation):
                self._tag_attribute_if_needed(
                    attribute,
                    score,
                    force_to_ids_false=not _ids_enabled(relation),
                )
            elif not _ids_enabled(relation):
                attribute.to_ids = False

        def _sync_object_index_for_relation(
            obj: MISPObject,
            relation: str,
            relation_value: Any,
        ) -> None:
            if obj.name != "file":
                return
            if relation not in {"sha256", "filename"}:
                return
            if relation_value is None:
                return
            relation_value_norm = str(relation_value).strip().lower()
            if not relation_value_norm:
                return
            relation_bucket_key = self._object_attribute_index_key("file", relation)
            object_value_index.setdefault(relation_bucket_key, {})[relation_value_norm] = obj

        default_source_file_relationship: Optional[str]
        if object_name == "file":
            default_source_file_relationship = None
        else:
            default_source_file_relationship = self.DEFAULT_ANCESTRY_RELATIONSHIP_TYPE
        source_file_relationship = mapping.get("misp_source_file_relationship", default_source_file_relationship)

        existing_object = object_value_index.setdefault(index_key, {}).get(normalized)
        if existing_object:
            existing_primary_attribute = self._add_object_attribute_if_missing(
                existing_object,
                object_relation,
                value,
                self._required_mapping_attribute_type(object_name, object_relation, primary_relation_options),
                disable_correlation=_disable_correlation(object_relation),
            )
            _apply_relation_flags(existing_primary_attribute, object_relation)

            for relation, options in misp_attributes.items():
                if relation == object_relation or "value" not in options:
                    continue
                attr_type = self._required_mapping_attribute_type(object_name, relation, options)
                raw_value = options.get("value")
                if callable(raw_value):
                    raw_value = raw_value(value)
                existing_attribute = self._add_object_attribute_if_missing(
                    existing_object,
                    relation,
                    raw_value,
                    attr_type,
                    disable_correlation=_disable_correlation(relation),
                )
                _apply_relation_flags(existing_attribute, relation)
                _sync_object_index_for_relation(existing_object, relation, raw_value)

            _sync_object_index_for_relation(existing_object, object_relation, value)

            if source_file_relationship:
                link_created = self._link_object_to_source_file(
                    existing_object,
                    source_file_obj,
                    str(source_file_relationship),
                )
            else:
                link_created = False
            return False, link_created

        obj = MISPObject(name=object_name)
        primary_attribute = self._add_object_attribute_if_missing(
            obj,
            object_relation,
            value,
            self._required_mapping_attribute_type(object_name, object_relation, primary_relation_options),
            disable_correlation=_disable_correlation(object_relation),
        )

        created_attributes: Dict[str, Any] = {object_relation: primary_attribute}
        created_relation_values: Dict[str, Any] = {object_relation: value}
        for relation, options in misp_attributes.items():
            if relation == object_relation or "value" not in options:
                continue
            attr_type = self._required_mapping_attribute_type(object_name, relation, options)
            raw_value = options.get("value")
            if callable(raw_value):
                raw_value = raw_value(value)
            created_attributes[relation] = self._add_object_attribute_if_missing(
                obj,
                relation,
                raw_value,
                attr_type,
                disable_correlation=_disable_correlation(relation),
            )
            created_relation_values[relation] = raw_value

        event.add_object(obj)
        object_value_index[index_key][normalized] = obj
        for relation, attribute in created_attributes.items():
            _apply_relation_flags(attribute, relation)
            relation_value = created_relation_values.get(relation)
            _sync_object_index_for_relation(obj, relation, relation_value)

        if source_file_relationship:
            link_created = self._link_object_to_source_file(
                obj,
                source_file_obj,
                str(source_file_relationship),
            )
        else:
            link_created = False
        return True, link_created

    def _process_tag_mapping(
        self,
        event: MISPEvent,
        mapping: Dict[str, Any],
        tags: Dict[str, Any],
        object_value_index: Dict[str, Dict[str, MISPObject]],
        source_file_obj: Optional[MISPObject],
        stats: Dict[str, int],
    ) -> None:
        object_name = str(mapping.get("misp_object_name", "")).strip()

        for tag_key in mapping.get("al_tag_patterns", []):
            for tag_value, score in self._extract_tag_values_with_scores(tags, str(tag_key)):
                object_created, link_created = self._upsert_object_from_mapping(
                    event,
                    mapping,
                    tag_value,
                    object_value_index,
                    source_file_obj,
                    score,
                )
                if object_name:
                    self._update_stats_for_object_upsert(stats, object_created, link_created, object_name)

    def _malware_analysis_result_for_score(self, score: Any) -> MalwareAnalysisResult:
        try:
            score_value = int(score)
        except (TypeError, ValueError):
            return MalwareAnalysisResult.UNKNOWN
        if score_value >= 1000:
            return MalwareAnalysisResult.MALICIOUS
        if score_value >= 300:
            return MalwareAnalysisResult.SUSPICIOUS
        return MalwareAnalysisResult.BENIGN

    def _malware_analysis_result_from_value(self, result: Optional[Any]) -> MalwareAnalysisResult:
        if isinstance(result, MalwareAnalysisResult):
            return result
        if result is None:
            return MalwareAnalysisResult.UNKNOWN
        try:
            return MalwareAnalysisResult[str(result).strip().upper()]
        except KeyError:
            return MalwareAnalysisResult.UNKNOWN

    def _malware_analysis_result_label(self, result: MalwareAnalysisResult) -> str:
        return result.name.lower()

    def _highest_malware_analysis_result(
        self,
        current_result: Optional[Any],
        new_result: MalwareAnalysisResult,
    ) -> MalwareAnalysisResult:
        existing_result = self._malware_analysis_result_from_value(current_result)
        return max(existing_result, new_result)

    def _max_tag_score(self, tags: Dict[str, Any]) -> Optional[int]:
        max_score: Optional[int] = None

        for values in tags.values():
            for value_with_score in values or []:
                if not isinstance(value_with_score, (list, tuple)) or len(value_with_score) < 2:
                    continue

                score = value_with_score[1]
                if not isinstance(score, int):
                    continue

                if max_score is None or score > max_score:
                    max_score = score

        return max_score

    def _source_file_relation_policy(self, analysis_result: MalwareAnalysisResult) -> Dict[str, bool]:
        if analysis_result in (MalwareAnalysisResult.SUSPICIOUS, MalwareAnalysisResult.MALICIOUS):
            return {"ids": True, "tag": True}
        return {"ids": False, "tag": False}

    def _ensure_submission_analysis_object(
        self,
        event: MISPEvent,
        sid: str,
        source_file_obj: Optional[MISPObject],
        analysis_result: MalwareAnalysisResult,
    ) -> bool:
        analysis_result_label = self._malware_analysis_result_label(analysis_result)
        marker = self._submission_configuration_version_marker(sid)

        for obj in event.objects:
            if obj.name != "malware-analysis":
                continue
            if not self._object_has_relation_value(obj, "configuration_version", marker):
                continue

            existing_result = None
            existing_results = obj.get_attributes_by_relation("result")
            if existing_results:
                existing_result = str(existing_results[0].value)

            analysis_result = self._highest_malware_analysis_result(existing_result, analysis_result)
            analysis_result_label = self._malware_analysis_result_label(analysis_result)

            self._add_object_attribute_if_missing(obj, "product", self.MALWARE_ANALYSIS_PRODUCT, "text", True)
            self._set_object_attribute_value(obj, "result", analysis_result_label, "text")
            if source_file_obj is not None and obj.uuid != source_file_obj.uuid:
                self._add_reference_if_missing(source_file_obj, obj, "analysed-with")
            return False

        obj = MISPObject(name="malware-analysis")
        self._add_object_attribute_if_missing(obj, "product", self.MALWARE_ANALYSIS_PRODUCT, "text", True)
        self._add_object_attribute_if_missing(obj, "configuration_version", marker, "text", False)
        self._add_object_attribute_if_missing(obj, "result", analysis_result_label, "text", False)
        event.add_object(obj)
        if source_file_obj is not None and obj.uuid != source_file_obj.uuid:
            self._add_reference_if_missing(source_file_obj, obj, "analysed-with")
        return True

    def _update_stats_for_object_upsert(
        self,
        stats: Dict[str, int],
        object_created: bool,
        link_created: bool,
        object_name: str,
    ) -> None:
        stats_key = self._stats_key_for_object_name(object_name)
        if object_created:
            stats[stats_key] = stats.get(stats_key, 0) + 1
        if link_created:
            stats["new_non_file_links"] += 1



    def _merge_misp_data(
        self,
        event: MISPEvent,
        request: ServiceRequest,
        tags: Dict[str, Any],
        metadata: Dict[str, Any],
        temp_submission_data: Dict[str, Any],
    ) -> Dict[str, int]:
        stats = {
            "new_file_objects": 0,
            "new_malware_analysis_objects": 0,
            "new_ancestry_links": 0,
            "new_non_file_links": 0,
        }

        object_value_index = self._index_existing_object_values(event)
        existing_file_count = self._count_file_objects(event)

        source_file_score = self._max_tag_score(tags)
        analysis_result = self._malware_analysis_result_for_score(source_file_score)

        source_file_mapping: Dict[str, Any] = {
            "misp_object_name": "file",
            "misp_attributes": {
                "sha256": {"type": "sha256", "ids": True, "correlate": True, "tag": True},
                "filename": {"type": "filename", "value": request.file_name, "correlate": True, "tag": True},
                "mime-type": {"type": "mime-type", "value": request.file_type},
                "size-in-bytes": {"type": "size-in-bytes", "value": request.file_size},
            },
        }

        self._upsert_object_from_mapping(
            event,
            source_file_mapping,
            request.sha256,
            object_value_index,
            None,
            source_file_score,
        )
        source_file_obj: Optional[MISPObject] = None
        if request.sha256:
            source_file_obj = object_value_index.setdefault(
                self._object_attribute_index_key("file", "sha256"), {},
            ).get(self._value_norm_key(request.sha256))

        if self._ensure_submission_analysis_object(event, request.sid, source_file_obj, analysis_result):
            stats["new_malware_analysis_objects"] += 1

        ancestry = temp_submission_data.get("ancestry", []) or []
        for ancestry_chain in ancestry:
            previous_obj = None
            if not isinstance(ancestry_chain, list):
                continue

            for node in ancestry_chain:
                if not isinstance(node, dict):
                    continue

                raw_node_sha256 = node.get("sha256")
                node_sha256 = str(raw_node_sha256).strip() if raw_node_sha256 else ""
                node_type = node.get("type")
                node_parent_relation = node.get("parent_relation")
                ancestry_node_mapping: Dict[str, Any] = {
                    "misp_object_name": "file",
                    "misp_attributes": {
                        "sha256": {"type": "sha256", "ids": True, "correlate": True},
                        "mime-type": {"type": "mime-type", "value": node_type},
                    },
                }
                self._upsert_object_from_mapping(event, ancestry_node_mapping, node_sha256, object_value_index, None)
                file_obj = object_value_index.setdefault(
                    self._object_attribute_index_key("file", "sha256"), {},
                ).get(self._value_norm_key(node_sha256)) if node_sha256 else None
                if file_obj is None:
                    continue

                if previous_obj is not None and previous_obj.uuid != file_obj.uuid:
                    before_refs = len(file_obj.references)
                    relationship_type = self._relationship_type_for_parent_relation(node_parent_relation)
                    self._add_reference_if_missing(file_obj, previous_obj, relationship_type)
                    if len(file_obj.references) > before_refs:
                        stats["new_ancestry_links"] += 1

                previous_obj = file_obj

        for mapping in TAG_PROCESSING_MAPPINGS:
            self._process_tag_mapping(event, mapping, tags, object_value_index, source_file_obj, stats)

        self._apply_event_tags_from_ifx_vetting(event)

        stats["new_file_objects"] = self._count_file_objects(event) - existing_file_count
        return stats

    def _ensure_submission_event(self, sid: str) -> Tuple[MISPEvent, str]:
        existing_event = self._find_existing_event(sid)
        if existing_event:
            event = self.pymisp.get_event(existing_event, pythonify=True)
            if not isinstance(event, MISPEvent):
                raise RuntimeError(f"Unable to load existing MISP event for submission {sid}: {event}")
            return event, "update"

        event = MISPEvent()
        event.info = self._submission_event_info(sid)
        event.distribution = 0
        event.analysis = 2
        event.threat_level_id = 4
        return event, "create"

    def _save_event(self, event: MISPEvent, operation: str) -> MISPEvent:
        if operation == "update":
            result = self.pymisp.update_event(event, pythonify=True)
        else:
            result = self.pymisp.add_event(event, pythonify=True)

        if isinstance(result, MISPEvent):
            return result

        if isinstance(result, dict):
            if result.get("errors"):
                raise RuntimeError(self._json_dump(result))
            loaded = MISPEvent()
            loaded.load(result)
            return loaded

        raise RuntimeError(f"Unexpected MISP response: {result}")

    def execute(self, request: ServiceRequest) -> None:
        self.log.info(f"execute() from {self.service_attributes.name} service called for '{request.file_name}'")

        result = Result()

        # ==================================================================
        # ServiceResult data including request task metadata
        #
        data = request.task.get_service_result()
        result_section = ResultSection('ServiceResult data', body_format=BODY_FORMAT.MEMORY_DUMP,
                        body=self._json_dump(data), auto_collapse=True)
        result.add_section(result_section)

        # ==================================================================
        # Tags generated from other services
        #
        # NOTE: To be able to use this, the service must set "uses_tags: true"
        #       in its manifest.
        tags = request.task.tags or {}
        tag_section = ResultSection('Tags generated from other services', body_format=BODY_FORMAT.MEMORY_DUMP,
                        body=self._json_dump(tags), auto_collapse=True)
        result.add_section(tag_section)

        # ==================================================================
        # Metadata provided during submission
        #
        # NOTE: To be able to use this, the service must set "uses_metadata: true"
        #       in its manifest.
        metadata = request.task.metadata or {}
        meta_section = ResultSection('Metadata provided during submission', body_format=BODY_FORMAT.MEMORY_DUMP,
                         body=self._json_dump(metadata), auto_collapse=True)
        result.add_section(meta_section)

        # ==================================================================
        # Temporary submission data provided:
        #   - During submission
        #   - By other services
        #
        # NOTE: To be able to use this, the service must set "uses_temp_submission_data: true"
        #       in its manifest.
        temp_submission_data = request.temp_submission_data or {}
        temp_section = ResultSection('Temporary submission data', body_format=BODY_FORMAT.MEMORY_DUMP,
                                     body=self._json_dump(temp_submission_data), auto_collapse=True)
        result.add_section(temp_section)


        sync_summary: Dict[str, Any] = {
            "operation": None,
            "submission_id": request.sid,
            "event_id": None,
            "event_uuid": None,
            "stats": {},
            "status": "error",
        }

        try:
            event, operation = self._ensure_submission_event(request.sid)
            stats = self._merge_misp_data(event, request, tags, metadata, temp_submission_data)
            saved_event = self._save_event(event, operation)

            sync_summary.update(
                {
                    "operation": operation,
                    "event_id": getattr(saved_event, "id", None),
                    "event_uuid": getattr(saved_event, "uuid", None),
                    "stats": stats,
                    "status": "ok",
                }
            )
        except Exception as err:
            self.log.exception("MISP event synchronization failed")
            sync_summary["error"] = str(err)

        misp_sync_section = ResultSection(
            "MISP event synchronization",
            body_format=BODY_FORMAT.MEMORY_DUMP,
            body=self._json_dump(sync_summary),
        )
        result.add_section(misp_sync_section)

        request.result = result
