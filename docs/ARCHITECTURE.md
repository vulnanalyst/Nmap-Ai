# Architecture

## Components

- **Frontend:** React, TypeScript, Vite, and Tailwind. Its navigation is limited to dashboard, network discovery, scan management, findings, live traffic, reports, and settings.
- **API:** FastAPI endpoints under `/api/v1`, authenticated with the configured API token. Health checks and the login endpoint are public.
- **Persistence:** SQLAlchemy models with SQLite by default. SQLite records and scan/report artifacts are local under `data/`.
- **Scanning:** The scan service validates targets against configured CIDRs and explicit operator confirmation, launches Nmap with an argument list and timeout, stores original XML, then parses the result into host, service, and finding records.
- **Analysis:** A local CVE/service catalog correlates observed banners; a risk score ranks findings. Neither a catalog match nor an ML prediction proves exploitation.
- **Telemetry:** HTTP ingestion or the optional length-prefixed TCP listener records received events. A stateful flow extractor may call the optional trained classifier; signature rules create alerts.
- **Reporting:** JSON and PDF reports are generated from persisted non-demo records.

## Evidence flow

```text
Authorized target + explicit operator confirmation
    -> CIDR allowlist validation
    -> Nmap argv subprocess (no shell)
    -> raw XML + normalized scan records
    -> service catalog correlation + finding triage
    -> dashboard / reports

Configured telemetry source
    -> bounded frame decoder or HTTP endpoint
    -> persisted event + flow features
    -> optional model prediction + signature alerts
    -> live traffic view / reports
```

The application does not choose targets, schedule scans, fabricate traffic, or seed simulated findings. Existing records tagged `data_source='demo'` remain excluded from operational queries and reports.

## Scanning and parsing boundaries

- A target must be a valid IPv4/IPv6 address or CIDR and fall within a configured authorized network.
- A scan request requires an exact target confirmation and an explicit authorization flag.
- Scan commands are built as argument arrays and have a configurable timeout.
- Scan output is retained as XML and normalized JSON; host and port data is populated from parsed Nmap output only.
- XML imports are limited to 20 MiB. Parser errors are returned to the client rather than reported as successful imports.
- Scan cancellation terminates the associated Nmap process.

## Vulnerability interpretation

The local catalog performs product/version correlation. Results retain the match evidence and a validation state; banners alone are not proof of exploitability. Risk values are prioritization aids only. Their components and limitations are implemented in `backend/app/services/risk.py`.

## Telemetry and ML

The optional TCP listener accepts a four-byte big-endian length followed by an Ethernet frame, with a 65,535-byte frame limit. It is a receiver, not an interface sniffer; a separate authorized source must supply frames. Scapy is optional for frame parsing. The HTTP endpoint accepts already-extracted packet fields.

ML training uses the local CIC-IDS2017-derived dataset and a frozen ten-feature schema. Predictions are attempted only for sufficient flow features and an available compatible model. Benchmark metrics do not guarantee live-network accuracy.

## Security boundaries

| Boundary | Control |
|---|---|
| Browser/API | Configured API token required for protected routes; credentials are read from environment configuration |
| Network scope | Explicit target confirmation and configured CIDR allowlist |
| Process execution | Nmap argument array, no shell interpolation, process timeout and cancellation |
| XML import | Nmap root validation and upload size limit |
| Telemetry | Loopback listener default and bounded frame size |
| Data disclosure | Health endpoint reports availability, not database URLs; reports omit credentials |

The backend and telemetry listener default to loopback. Changing the bind address requires separate network controls and unique credentials.
