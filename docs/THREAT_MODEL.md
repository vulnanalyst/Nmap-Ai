# Threat model

## Assets and trust boundaries

The application processes authenticated scan requests, target allowlists, local scan evidence, telemetry, findings, and reports. Its boundaries are the browser/API, the API/Nmap subprocess, the host/authorized network, and optional external telemetry sources.

## Risks and controls

### Unauthorized or overly broad scanning

Scan targets must parse as IP addresses/CIDRs, fall within an operator-configured allowlist, match an explicit confirmation string, and include explicit authorization. Scans run only after an operator starts them; no target selection or scheduled scanning occurs automatically. Nmap runs as an argument array with a timeout and supports cancellation.

Allowlist configuration represents the operator's authorization decision. Administrators must keep it limited to networks they own or are explicitly permitted to assess. The application does not independently verify legal authorization.

### Command injection

The scanner uses `subprocess` argument arrays rather than shell interpolation. Target parsing rejects malformed input, and scan profiles are selected from a fixed allowlist.

### Malformed or oversized XML

XML imports require an Nmap XML root and are limited to 20 MiB. Parse failures are returned as errors. Imported content can still contain untrusted banner or script text; PDF report text is escaped before rendering.

### Telemetry resource exhaustion

The optional TCP listener uses four-byte length-prefixed frames with a maximum frame size of 65,535 bytes and defaults to loopback. It is a receiver, not an interface sniffer. If exposed to another host, use firewall restrictions and only trusted, configured capture sources.

### Misleading security conclusions

Open ports, catalog correlations, risk ranks, signatures, and ML results are not evidence of exploitation. Findings preserve their evidence and validation state. Flow inference is skipped if features are incomplete or no compatible model exists. No sample telemetry is created by the UI.

### Credential or infrastructure disclosure

Protected endpoints require the configured API token. Login credentials and tokens belong in the ignored local `.env`; use unique values and do not expose the default loopback development server with placeholder credentials. Public readiness checks do not return the database URL, and generated reports omit credentials.

## Deployment limits

This project is designed for a local authorized lab. Loopback is the default bind address. A network-accessible deployment needs strong credentials, TLS, firewalling, protected storage, and operational monitoring beyond the controls in this repository.
