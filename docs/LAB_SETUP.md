# Authorized lab setup

Use a private, isolated virtual network for active scans. Do not use an address or subnet from an example as a target; configure only the addresses and ranges you personally own or are explicitly authorized to assess.

## Configure the application

Follow the installation steps in the root README. Before starting the API:

1. Copy `.env.example` to `.env`.
2. Set unique `NMAP_AI_API_TOKEN` and `NMAP_AI_PASSWORD` values.
3. Keep `NMAP_AI_HOST` and `NMAP_AI_INGEST_HOST` bound to loopback unless network access is required and separately controlled.
4. Install Nmap on the backend host if active scanning is needed. Set `NMAP_AI_NMAP_PATH` to its executable path if it is not on `PATH`.

Sign in to the UI with `NMAP_AI_USERNAME` and `NMAP_AI_PASSWORD`. In **Settings**, add only the lab CIDR(s) authorized for scanning. The application does not infer a target or scan automatically.

## Scan or import evidence

Select a profile in **Scan Management**, inspect the argument preview, enter the target and re-enter it for confirmation, and explicitly confirm authorization before starting. The target must be inside a configured allowlist network. Import an existing Nmap XML file instead when active scanning is not appropriate; imported XML is limited to 20 MiB.

Available scan profiles:

- Host discovery (`-sn`)
- TCP connect (`-sT`)
- Service/version detection (`-sT -sV`)
- OS guess (`-sT -O`)
- Nmap scripts in the `safe` category (`-sT -sV --script safe`)

Nmap behavior can still affect a target, including the `safe` script profile. Confirm scope and permission with the target owner before use.

## Optional telemetry

The API accepts normalized packet events at `/api/v1/traffic/ingest`. The optional `capture/live_monitor.py` process is a TCP receiver for length-prefixed Ethernet frames; it does not capture an interface itself. A separate, authorized capture source must connect and supply frames. Scapy is needed to decode Ethernet/IP/TCP/UDP frames. Keep the listener on loopback unless remote input is explicitly required and restricted.

Telemetry classification is optional. The flow must contain enough packets to calculate the model's required feature schema, and a compatible model artifact must be present. Otherwise the event retains a skipped status rather than a synthetic prediction.
