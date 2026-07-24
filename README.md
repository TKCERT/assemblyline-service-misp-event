[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline_service_misp_event-blue?logo=github)](https://github.com/TKCERT/assemblyline-service-misp-event)
[![GitHub Issues](https://img.shields.io/github/issues/TKCERT/assemblyline-service-misp-event)](https://github.com/TKCERT/assemblyline-service-misp-event/issues)

# MISPEvent Service

This Assemblyline service runs in the `REVIEW` stage and synchronizes submission context into a MISP event.

## Service Details

### Execution

The service inspects review-stage tags, metadata, and temporary submission data and then creates or updates one MISP event per Assemblyline submission ID.

Main behavior:

- Resolve the event by deterministic UUID derived from submission ID (base62), then fall back to event info and marker searches.
- Upsert source file context (`file` object, hashes, filename, mime type, size).
- Add or update `malware-analysis` object for this submission marker (`submission-id:<sid>`).
- Merge ancestry file chains from temporary submission data and create typed object references.
- Convert selected Assemblyline tags into typed MISP objects and attributes.
- Apply attribute-level vetting tags from score thresholds, then derive event-level outcome tags.

The service is designed for contextual event enrichment and does not require file content.

### Runtime Behavior

- Runs in `REVIEW` stage.
- Uses tags from `request.task.tags` (`uses_tags: true`).
- Reads tag scores when present (`uses_tag_scores: true`).
- Uses submission metadata (`uses_metadata: true`).
- Uses temporary submission data (`uses_temp_submission_data: true`).
- Does not require file content (`file_required: false`).
- Disables result caching because behavior depends on submission context (`disable_cache: true`).

### Tag to MISP Mapping (Overview)

The service currently maps the following Assemblyline tag families into MISP objects:

- URLs -> `url`
- Domains and IPs -> `domain-ip`
- Email address -> `person`
- Email subject -> `email`
- Registry key -> `registry-key`
- Static signatures / AV labels -> `av-signature`
- Dynamic behavior signatures -> `sb-signature`
- Malware family -> `malware`
- File hashes and names -> `file`

### Score to Analysis Mapping

The highest observed tag score on the source context is mapped to malware analysis result:

- `< 300` -> `benign`
- `300..999` -> `suspicious`
- `>= 1000` -> `malicious`

By default, suspicious and malicious values are translated into attribute and event tags through configurable mappings.

## Configuration

Configuration is defined in [service_manifest.yml](service_manifest.yml).

### Service Configuration

| Name | Description |
| :--- | :---------- |
| `misp_service_url` | Base URL used for result links to the MISP web UI. |
| `misp_service_api_url` | API URL used by PyMISP. If empty, falls back to `misp_service_url`. |
| `misp_service_api_key` | API key used to authenticate to MISP. |
| `attribute_tag_name` | Attribute tag namespace used for vetting tags (for example `ifx-vetting:vetted`). |
| `attribute_tag_value_from_result` | Mapping from analysis result (`suspicious`, `malicious`) to attribute tag value. |
| `event_tag_name` | Event tag namespace used for final event-level result tagging. |
| `event_tag_value_from_attribute` | Mapping from attribute tag value to event tag value. |
| `workflow_review_tag` | Additional workflow tag added to synchronized events. |
| `verify_certificate` | Enable or disable TLS certificate verification for MISP API calls. |

## Image variants and tags

Assemblyline services are built from the [Assemblyline service base image](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
which is based on Debian 11 with Python 3.11.

Assemblyline services use the following tag definitions:

| **Tag Type** | **Description** | **Example Tag** |
| :----------: | :-------------- | :-------------: |
| latest | The most recent build (can be unstable). | `latest` |
| build_type | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. | `stable` or `dev` |
| series | Complete build details, including version and build type: `version.buildType`. | `4.5.stable`, `4.5.1.dev3` |

## Running this service

This is an Assemblyline service. It is designed to run as part of the Assemblyline framework.

If you would like to test this service locally, you can run the Docker image directly from a shell:

	docker run \
		--name MISPEvent \
		--env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
		--network=host \
		ghcr.io/tkcert/assemblyline-service-misp-event

To add this service to your Assemblyline deployment, follow this
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

General Assemblyline documentation can be found at: https://cybercentrecanada.github.io/assemblyline4_docs/
