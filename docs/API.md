# API reference

Base URL: `http://127.0.0.1:8000/api/v1`

OpenAPI UI: `http://127.0.0.1:8000/docs`

Except for health checks and login, endpoints require `X-API-Key: <NMAP_AI_API_TOKEN>`. `POST /auth/login` checks `NMAP_AI_USERNAME` and `NMAP_AI_PASSWORD` and returns the configured API token. Do not use placeholder credentials on a network-accessible deployment.

## Health and authentication

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | API process health |
| GET | `/ready` | Database availability and Nmap installation status; does not return the database URL |
| POST | `/auth/login` | Exchange configured username/password for the API token |

## Dashboard and network inventory

| Method | Path | Purpose |
|---|---|---|
| GET | `/dashboard/summary` | Counts and recent scan/alert summary from non-demo stored records |
| GET | `/hosts` | Hosts from completed scans and XML imports |
| GET | `/hosts/{host_id}` | Host services, Nmap evidence, and related findings |
| GET | `/topology` | Observed hosts and configured scanner relationships |
| GET | `/scans/compare?left={scan_id}&right={scan_id}` | Compare observed ports between two scan records |

## Scans

| Method | Path | Purpose |
|---|---|---|
| GET | `/scans/profiles` | Supported profiles and Nmap installation status |
| POST | `/scans/preview` | Validate target syntax and preview arguments without scanning |
| POST | `/scans` | Start an explicitly authorized scan |
| GET | `/scans` | List scan records |
| GET | `/scans/{scan_id}` | Get scan status and results |
| POST | `/scans/{scan_id}/cancel` | Cancel a queued/running scan process |
| GET | `/scans/{scan_id}/xml` | Download original scan XML |
| GET | `/scans/{scan_id}/json` | Download normalized scan output |
| POST | `/scans/import` | Import Nmap XML; uploads are limited to 20 MiB |

Scan requests require a profile, an IP/CIDR target, a matching confirmation string, and `confirm_authorization: true`. The target must be contained in the configured authorized CIDR allowlist. Preview does not execute Nmap. The `vuln_safe` profile uses Nmap's `safe` script category.

## Findings, alerts, and telemetry

| Method | Path | Purpose |
|---|---|---|
| GET | `/findings` | List findings; accepts `severity`, `validation_status`, `q`, and `cve` filters |
| GET | `/findings/{finding_id}` | Get a finding and its evidence |
| PATCH | `/findings/{finding_id}` | Update analyst workflow status |
| GET | `/alerts` | List telemetry detection alerts; accepts `status` and `method` filters |
| PATCH | `/alerts/{alert_id}` | Update alert status or append an investigation note |
| GET | `/traffic/status` | Read the current ingestion health record |
| GET | `/traffic/events` | List recent observed telemetry events |
| POST | `/traffic/ingest` | Submit a telemetry event to the flow/signature pipeline |

The standalone HTTP ingestion endpoint is intended for a configured data source. It should not be used to create synthetic operational records. Model predictions and signature matches are indicators, not proof of compromise.

## Reports, settings, and model operations

| Method | Path | Purpose |
|---|---|---|
| GET | `/reports` | List generated report records |
| POST | `/reports` | Generate JSON and PDF reports from stored records |
| GET | `/reports/{report_id}/json` | Download report JSON |
| GET | `/reports/{report_id}/pdf` | Download report PDF |
| GET | `/settings` | Read scanner configuration, allowlist, and optional dependency status |
| PATCH | `/settings` | Update supported non-secret settings |
| POST | `/settings/targets` | Add an explicitly authorized CIDR |
| DELETE | `/settings/targets/{target_id}` | Remove an authorized CIDR |
| GET | `/ml/model` | Read active classifier metadata and offline evaluation |
| POST | `/ml/infer` | Classify a vector that matches the stored feature schema |
| GET | `/ml/training` | List model training runs |
| POST | `/ml/training` | Start training on the configured local benchmark dataset |
| WS | `/ws/events?token={token}` | Subscribe to authenticated scan events |

The model training/inference API is optional; the live telemetry pipeline skips classification when no usable model or sufficient flow features are available. Reports exclude legacy records tagged as demo and do not include credentials.
