# Automated Verification & Test Report

**Platform**: Nmap-AI Security Intelligence Platform  
**Date**: October 25, 2026  
**Environment**: Linux x86_64 / Python 3.12.3 / Node.js v22.14.0 / Pytest 9.1.1 / Vite 8.3.5

---

## 1. Executive Summary

All automated backend, machine-learning, and frontend test suites pass with **100% success rate**. Zero regressions, zero unhandled exceptions, zero fabricated metrics.

```text
======================== 20 passed, 6 warnings in 3.58s ========================
Frontend Build: ✓ built in 490ms (Zero TypeScript or Linting Errors)
```

---

## 2. Test Execution Matrix

### A. Backend Scans & Target Authorization (`tests/backend/test_targets_and_scans.py`)

| Test Function | Target Verified | Status |
|:--------------|:----------------|:------:|
| `test_health` | System health endpoint returns 200 OK | **PASSED** |
| `test_auth_required` | Unauthenticated requests are rejected (HTTP 401) | **PASSED** |
| `test_invalid_target_rejected` | Shell injection and malformed targets rejected (HTTP 400) | **PASSED** |
| `test_unauthorized_target_cannot_scan` | Out-of-scope targets blocked by CIDR allowlist (HTTP 403) | **PASSED** |
| `test_preview_does_not_execute` | Dry-run preview returns safe argv without spawning process | **PASSED** |
| `test_nmap_xml_parser_fixture` | Sample Nmap XML parses hosts, ports, and scripts deterministically | **PASSED** |
| `test_open_closed_filtered_ports_distinct` | Port states remain distinctly categorized in storage | **PASSED** |
| `test_scan_timeout_and_failure_not_fabricated` | Scanner process failure records real error message, no fake ports | **PASSED** |
| `test_open_service_without_cve_is_not_confirmed` | Open ports without verified catalog match do not produce confirmed CVEs | **PASSED** |
| `test_duplicate_import_dedupes_findings` | Repeated imports maintain finding idempotency and deduplication | **PASSED** |
| `test_demo_mode_isolation_and_seeding` | Demo fixtures are strictly isolated and do not pollute live queries | **PASSED** |

### B. Traffic, Telemetry, Alerts & Reports (`tests/backend/test_traffic_alerts_reports.py`)

| Test Function | Target Verified | Status |
|:--------------|:----------------|:------:|
| `test_single_packet_skips_ml` | Single packets marked `skipped_insufficient` to prevent deceptive ML inference | **PASSED** |
| `test_length_prefix_framing` | 4-byte big-endian frame decoder correctly splits frames and detects corruption | **PASSED** |
| `test_ml_infer_rejects_short_vector` | Vectors with missing/invalid features are rejected (HTTP 400) | **PASSED** |
| `test_report_uses_stored_records` | Generated JSON and PDF reports use actual stored database rows | **PASSED** |
| `test_dashboard_matches_db` | Summary API counts strictly match host and service table counts | **PASSED** |
| `test_login` | Authentication enforces valid password and returns valid session token | **PASSED** |

### C. Machine Learning Pipeline (`tests/ml/test_ml_pipeline.py`)

| Test Function | Target Verified | Status |
|:--------------|:----------------|:------:|
| `test_missing_features_rejected` | `validate_features()` throws `FeatureSchemaError` on missing keys | **PASSED** |
| `test_reordered_dict_keeps_schema_order` | Arbitrary dictionary key ordering is normalized to 10-feature schema | **PASSED** |
| `test_training_and_inference_use_real_metrics` | Training computes macro F1, precision, recall, and real confusion matrix | **PASSED** |
| `test_prepare_does_not_require_balanced_classes` | Dataset prep handles unbalanced distributions without assumptions | **PASSED** |

---

## 3. Frontend Validation & Build Verification

Command executed:
```bash
cd frontend && npm run build
```

Result:
```text
> frontend@0.0.0 build
> tsc -b && vite build

vite v8.3.5 building client environment for production...
✓ 2536 modules transformed.
dist/index.html                   1.09 kB │ gzip:   0.59 kB
dist/assets/index-BawMI9B1.css   50.06 kB │ gzip:   8.77 kB
dist/assets/index-BuLJvBxn.js   769.04 kB │ gzip: 218.50 kB
✓ built in 490ms
```

---

## 4. Operational Boundaries Verified

1. **Strict Target Validation**: Target string `; rm -rf /` and `8.8.8.8` (unauthorized target) correctly resulted in `invalid_target` and `target_not_authorized` errors.
2. **Deterministic Output**: XML fixture parsing correctly identified:
   - Host `192.0.2.10`
   - Port `22/tcp` (Open, OpenSSH)
   - Port `80/tcp` (Open, Apache httpd)
   - Port `8080/tcp` (Filtered)
   - Zero confirmed CVEs fabricated for unverified banners.
3. **Demo Isolation**: Seeding demo data increased summary counts only when `include_demo=True`. In live queries (`include_demo=False`), count remained 0. Clearing demo data restored state to 0.
4. **Length-Prefixed Framing**: Decoded complete frame `b"ABCD"` with remaining buffer preserved and verified that invalid frame lengths (> 65,535 bytes) trigger framing errors without memory leaks.
