# REST API Specification — Nmap-AI Security Intelligence Platform

Base URL: `http://127.0.0.1:8000/api/v1`

Interactive Swagger UI: `http://127.0.0.1:8000/docs`  
ReDoc UI: `http://127.0.0.1:8000/redoc`

---

## Authentication

All protected endpoints require the `X-API-Key` HTTP header.

```http
X-API-Key: <token>
```

Default lab token is defined in `.env` (`NMAP_AI_API_TOKEN`). Default testing fallback token is `test-token`.

---

## 1. System & Health

### `GET /health`
Returns system status.
```json
{ "status": "ok" }
```

### `POST /auth/login`
Validates credentials and returns API token.
```json
// Request
{ "username": "lab", "password": "labpass" }

// Response (200 OK)
{ "token": "test-token" }
```

---

## 2. Dashboard Summary

### `GET /dashboard/summary`
Query parameters:
- `include_demo` (boolean, optional, default: false)

Returns aggregate counts derived from database records.
```json
{
  "hosts_total": 3,
  "hosts_up": 3,
  "ports_open": 6,
  "ports_closed": 120,
  "ports_filtered": 4,
  "services_observed": 6,
  "findings_by_severity": {
    "high": 1,
    "medium": 1,
    "low": 1
  },
  "findings_by_validation": {
    "confirmed_by_check": 1,
    "suspected": 1,
    "potential_issue": 1
  },
  "latest_scan": {
    "id": "scan-1234",
    "status": "completed",
    "profile": "service_version",
    "created_at": "2026-10-24T18:00:00Z",
    "duration_seconds": 45.2,
    "error": null,
    "data_source": "live"
  },
  "model": {
    "version": "rf-20261024T183348Z",
    "trained_at": "2026-10-24T18:33:48Z",
    "disclaimer": "Offline CIC-IDS2017 metrics do not guarantee live-lab accuracy."
  },
  "traffic_ml_labels": { "ATTACK": 12, "BENIGN": 140 },
  "recent_alerts": [],
  "scan_trend": [],
  "data_source_filter": "live+import"
}
```

---

## 3. Host Discovery & Topology

### `GET /hosts`
Query parameters: `include_demo` (bool)
Returns observed host inventory with discovered services and OS guesses.

### `GET /hosts/{host_id}`
Returns granular service banners, Nmap script output, and associated findings for a host.

### `GET /topology`
Query parameters: `include_demo` (bool)
Returns nodes (scanner, observed hosts) and edges (provenance-verified scan connections).

### `GET /scans/compare?left={scan_id}&right={scan_id}`
Calculates deltas (newly opened/closed ports) between two scans.

---

## 4. Scan Management

### `GET /scans/profiles`
Returns supported safe profiles (`host_discovery`, `tcp_connect`, `service_version`, `os_fingerprint`, `vuln_safe`) and Nmap installation status.

### `POST /scans/preview`
Generates safe command argument array without execution.
```json
// Request
{
  "profile": "tcp_connect",
  "target": "192.168.1.10",
  "confirm_target": "192.168.1.10",
  "confirm_authorization": true
}

// Response
{
  "argv": ["nmap", "-sT", "--stats-every", "5s", "-oX", "data/scans/id/scan.xml", "192.168.1.10"],
  "profile": "tcp_connect",
  "target": "192.168.1.10"
}
```

### `POST /scans`
Launches background scan. Target must match `authorized_targets` CIDR.

### `POST /scans/import`
Uploads raw Nmap XML file (`multipart/form-data`) to parse and populate database records.

### `GET /scans/{scan_id}/xml`
Downloads raw XML artifact.

---

## 5. Vulnerability Intelligence

### `GET /findings`
Query parameters:
- `severity` (`critical`, `high`, `medium`, `low`, `info`)
- `validation_status` (`validated_vulnerability`, `confirmed_by_check`, `suspected`, `potential_issue`, `no_verified_cve_match`)
- `q` (free-text search)
- `cve` (CVE identifier)
- `include_demo` (bool)

### `PATCH /findings/{finding_id}`
Updates analyst triage status.
```json
// Request
{ "workflow_status": "confirmed" }
```

---

## 6. Threat Alerts

### `GET /alerts`
Query parameters: `status`, `method`, `include_demo`.

### `PATCH /alerts/{alert_id}`
Updates alert status (`acknowledged`, `resolved`) and appends investigation notes.
```json
// Request
{ "status": "acknowledged", "note": "Verified normal administrative SSH session." }
```

---

## 7. Traffic & Ingestion

### `GET /traffic/status`
Returns ingestion adapter health, packet throughput, and parse error counts.

### `POST /traffic/ingest`
Submits raw packet telemetry to flow accumulator and inference pipeline.
```json
// Request
{
  "src_addr": "192.168.1.100",
  "dst_addr": "192.168.1.50",
  "src_port": 49152,
  "dst_port": 445,
  "protocol": "TCP",
  "packet_length": 64
}
```

---

## 8. AI / ML Lab

### `GET /ml/model`
Returns active model metadata, feature importances, and historical runs.

### `POST /ml/infer`
Evaluates a 10-feature vector against the loaded Random Forest model.
```json
// Request
{
  "features": {
    "Destination Port": 445,
    "Flow Duration": 120500,
    "Total Fwd Packets": 15,
    "Total Backward Packets": 12,
    "Total Length of Fwd Packets": 960,
    "Fwd Packet Length Max": 128,
    "Bwd Packet Length Max": 128,
    "Flow Bytes/s": 24500,
    "Flow Packets/s": 420.5,
    "Average Packet Size": 74.2
  }
}

// Response
{
  "prediction": 1,
  "label": "ATTACK",
  "probability": 0.984,
  "model_version": "rf-20261024T183348Z",
  "class_probabilities": { "0": 0.016, "1": 0.984 }
}
```

### `POST /ml/training`
Triggers background model retraining on `dataset/final_dataset.csv`.

---

## 9. Reports

### `POST /reports`
Compiles current stored scan records, findings, and alerts into an executive report.

### `GET /reports/{report_id}/json`
Returns normalized JSON export.

### `GET /reports/{report_id}/pdf`
Downloads formatted PDF report.

---

## 10. Settings & Allowlist

### `GET /settings`
Returns scanner/target identities, allowlist subnets, capture interfaces, and demo mode flag.

### `PATCH /settings`
Updates configurable settings keys.

### `POST /settings/targets`
Adds CIDR subnet to authorized target allowlist.
```json
{ "cidr": "192.168.56.0/24", "label": "Host-Only Target Subnet" }
```

### `DELETE /settings/targets/{target_id}`
Removes subnet from allowlist.

### `POST /settings/demo/seed`
Populates isolated demo fixtures (`data_source='demo'`).

### `DELETE /settings/demo/seed`
Removes all demo fixtures.
