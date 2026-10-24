# Implementation Plan — Nmap-AI Security Intelligence Platform

## Audit findings (existing repository)

The original repository is a small Python prototype, not a platform:

| Path | Role | Issues |
|------|------|--------|
| `main.py` | Demo harness | Hard-coded demo packet + 10-feature vector; no API/UI |
| `ids/ml_ids.py` | Random Forest inference | Relative `model/ids_model.pkl`; `predict_proba(...)[0][1]` assumes class index 1 |
| `ids/signature_ids.py` | Rules | Treats any access to SSH/RDP/SMB as an alert |
| `capture/live_monitor.py` | TCP listener | Hard-coded `N:\MAIN\Projects\Nmap Ai`; binds `0.0.0.0:9999`; treats TCP chunks as Ethernet frames; fabricates flow features (`1000.0`, `1.0`); bare `except` |
| `dataset/prepare.py` | CIC-IDS2017 subset | Assumes 1000 BENIGN and 1000 attack rows exist |
| `model/train_model.py` | RF trainer | CWD-relative paths; no schema/metrics artifact |
| `alerts/alert_engine.py` | File logger | Append-only `alerts/alerts.log`; not queryable |
| `dataset/*.csv` | CIC-IDS2017 PortScan day | Keep; do not delete |
| `model/ids_model.pkl` | Existing RF pickle | Preserve; new training writes to `ml/artifacts/` |
| `capture.pcapng` | Small capture | Preserve |

Dataset schema (verified): 79 CICFlowMeter columns; labels `PortScan` (158930) and `BENIGN` (127537). Prepared `final_dataset.csv` has 2000 balanced rows and features:

`Destination Port, Flow Duration, Total Fwd Packets, Total Backward Packets, Total Length of Fwd Packets, Fwd Packet Length Max, Bwd Packet Length Max, Flow Bytes/s, Flow Packets/s, Average Packet Size, Label`

No dashboard, no Nmap integration, no database, no auth, no reports.

## Target architecture

- FastAPI + SQLAlchemy + SQLite (localhost bind)
- React + TypeScript + Vite + Tailwind dashboard
- Evidence-first persistence: raw Nmap XML + normalized rows
- ML pipeline with frozen feature schema and real evaluation metrics
- Configurable lab targets (no invented IPs)
- Demo fixtures isolated behind an explicit demo-mode flag

## Phase map

1. Config, database, auth, API shell, frontend shell
2. Nmap XML parser, scan jobs, inventory, overview
3. Findings, CVE catalog matching, alerts, workflow
4. Dataset prep, training, inference, evaluation UI
5. Capture adapters, signatures, live status
6. Reports, settings, docs, tests, hardening

Existing modules are migrated into `backend/` and `ml/`. Original files remain as compatibility wrappers.
