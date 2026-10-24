from pathlib import Path

from backend.app.db.session import get_session_factory
from backend.app.services.scan_service import import_xml, start_scan
from backend.app.services.settings_service import add_target
from backend.app.services.nmap_parser import parse_nmap_xml


FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "sample_nmap.xml"


def test_health(client):
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"


def test_auth_required(client):
    res = client.get("/api/v1/dashboard/summary")
    assert res.status_code == 401


def test_saved_scanner_identity_appears_in_topology(client, auth_headers):
    invalid = client.patch(
        "/api/v1/settings",
        headers=auth_headers,
        json={"values": {"scanner_name": "Should roll back", "scanner_ip": "not-an-ip"}},
    )
    assert invalid.status_code == 400
    response = client.patch(
        "/api/v1/settings",
        headers=auth_headers,
        json={"values": {"scanner_name": "Lab scanner", "scanner_ip": "192.0.2.5"}},
    )
    assert response.status_code == 200
    topology = client.get("/api/v1/topology", headers=auth_headers)
    assert topology.status_code == 200
    assert topology.json()["nodes"][0]["label"] == "Lab scanner"
    assert topology.json()["nodes"][0]["ip"] == "192.0.2.5"


def test_legacy_demo_records_are_hidden_from_operational_apis(client, auth_headers):
    from backend.app.models import Alert, Finding, Host, ReportRecord, ScanJob

    db = get_session_factory()()
    scan = ScanJob(
        id="legacy-demo-scan",
        profile="tcp_connect",
        targets="192.0.2.10",
        status="completed",
        data_source="demo",
    )
    db.add(scan)
    db.flush()
    host = Host(scan_id=scan.id, ip="192.0.2.10", state="up", data_source="demo")
    db.add(host)
    finding = Finding(
        id="legacy-demo-finding",
        scan_id=scan.id,
        host_ip="192.0.2.10",
        title="Legacy demo finding",
        fingerprint="legacy-demo-finding",
        data_source="demo",
    )
    alert = Alert(
        detection_method="demo",
        title="Legacy demo alert",
        fingerprint="legacy-demo-alert",
        data_source="demo",
    )
    report = ReportRecord(
        id="legacy-demo-report",
        json_path="/nonexistent/legacy-demo.json",
        data_source="demo",
    )
    db.add_all([finding, alert, report])
    db.commit()
    host_id = host.id
    alert_id = alert.id
    db.close()

    assert client.get("/api/v1/scans", headers=auth_headers).json()["items"] == []
    assert client.get("/api/v1/scans/legacy-demo-scan", headers=auth_headers).status_code == 404
    assert client.get("/api/v1/hosts", headers=auth_headers).json()["items"] == []
    assert client.get(f"/api/v1/hosts/{host_id}", headers=auth_headers).status_code == 404
    assert client.get("/api/v1/findings", headers=auth_headers).json()["items"] == []
    assert client.get("/api/v1/findings/legacy-demo-finding", headers=auth_headers).status_code == 404
    assert client.get("/api/v1/alerts", headers=auth_headers).json()["items"] == []
    assert client.patch(
        f"/api/v1/alerts/{alert_id}",
        headers=auth_headers,
        json={"status": "resolved"},
    ).status_code == 404
    assert client.get("/api/v1/reports", headers=auth_headers).json()["items"] == []
    assert client.get(
        "/api/v1/reports/legacy-demo-report/json",
        headers=auth_headers,
    ).status_code == 404


def test_invalid_target_rejected(client, auth_headers):
    res = client.post(
        "/api/v1/scans",
        headers=auth_headers,
        json={
            "profile": "tcp_connect",
            "target": "not-an-ip; rm -rf /",
            "confirm_target": "not-an-ip; rm -rf /",
            "confirm_authorization": True,
        },
    )
    assert res.status_code == 400
    assert res.json()["error"]["code"] == "invalid_target"


def test_unauthorized_target_cannot_scan(client, auth_headers):
    client.post("/api/v1/settings/targets", headers=auth_headers, json={"cidr": "192.0.2.0/24", "label": "TEST-NET"})
    res = client.post(
        "/api/v1/scans",
        headers=auth_headers,
        json={
            "profile": "tcp_connect",
            "target": "8.8.8.8",
            "confirm_target": "8.8.8.8",
            "confirm_authorization": True,
            "dry_run": True,
        },
    )
    assert res.status_code == 403
    assert res.json()["error"]["code"] == "unauthorized_target"


def test_empty_allowlist_blocks_scan(client, auth_headers):
    res = client.post(
        "/api/v1/scans",
        headers=auth_headers,
        json={
            "profile": "tcp_connect",
            "target": "192.0.2.10",
            "confirm_target": "192.0.2.10",
            "confirm_authorization": True,
            "dry_run": True,
        },
    )
    assert res.status_code == 403
    assert res.json()["error"]["code"] == "allowlist_empty"


def test_xml_parse_and_port_states(client, auth_headers):
    parsed = parse_nmap_xml(FIXTURE)
    assert parsed["hosts"][0]["ip"] == "192.0.2.10"
    states = {p["port"]: p["state"] for p in parsed["hosts"][0]["ports"]}
    assert states[22] == "open"
    assert states[80] == "closed"
    assert states[139] == "filtered"
    assert parsed["port_counts"]["open"] == 2
    assert parsed["port_counts"]["closed"] == 1
    assert parsed["port_counts"]["filtered"] == 1

    with FIXTURE.open("rb") as handle:
        res = client.post("/api/v1/scans/import", headers=auth_headers, files={"file": ("sample.xml", handle, "application/xml")})
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "completed"
    assert body["ports_open"] == 2
    assert body["ports_closed"] == 1
    assert body["ports_filtered"] == 1

    hosts = client.get("/api/v1/hosts", headers=auth_headers).json()["items"]
    assert hosts[0]["ip"] == "192.0.2.10"
    assert hosts[0]["os_label"] == "guess"


def test_scan_timeout_and_failure_not_fabricated(client, auth_headers):
    client.post("/api/v1/settings/targets", headers=auth_headers, json={"cidr": "192.0.2.0/24", "label": "lab"})
    db = get_session_factory()()

    def failing_runner(argv, xml_path, timeout):
        raise RuntimeError("simulated scanner failure")

    job = start_scan(
        db,
        profile="tcp_connect",
        target="192.0.2.10",
        confirm_target="192.0.2.10",
        confirm_authorization=True,
        runner=failing_runner,
    )
    import time

    from backend.app.models import ScanJob

    for _ in range(50):
        db.expire_all()
        row = db.query(ScanJob).filter_by(id=job.id).one()
        if row.status in {"error", "timeout", "completed"}:
            break
        time.sleep(0.05)
    db.expire_all()
    row = db.query(ScanJob).filter_by(id=job.id).one()
    assert row.status == "error"
    assert "simulated scanner failure" in (row.error or "")
    assert row.ports_open == 0
    db.close()


def test_open_service_without_cve_is_not_confirmed(client, auth_headers):
    with FIXTURE.open("rb") as handle:
        client.post("/api/v1/scans/import", headers=auth_headers, files={"file": ("sample.xml", handle, "application/xml")})
    findings = client.get("/api/v1/findings", headers=auth_headers).json()["items"]
    confirmed_cves = [f for f in findings if f["validation_status"] == "validated_vulnerability"]
    assert confirmed_cves == []
    assert any(f["validation_status"] in {"no_verified_cve_match", "potential_issue", "suspected"} for f in findings)


def test_duplicate_import_dedupes_findings(client, auth_headers):
    for _ in range(2):
        with FIXTURE.open("rb") as handle:
            client.post("/api/v1/scans/import", headers=auth_headers, files={"file": ("sample.xml", handle, "application/xml")})
    findings = client.get("/api/v1/findings", headers=auth_headers).json()["items"]
    fingerprints = [f["id"] for f in findings]
    assert len(fingerprints) == len(set(fingerprints))


def test_demo_seeding_endpoints_are_not_available(client, auth_headers):
    response = client.post("/api/v1/settings/demo/seed", headers=auth_headers)
    assert response.status_code == 404


def test_oversized_xml_import_is_rejected(client, auth_headers, monkeypatch):
    from backend.app.api.routes import scans

    monkeypatch.setattr(scans, "MAX_XML_UPLOAD_BYTES", 16)
    response = client.post(
        "/api/v1/scans/import",
        headers=auth_headers,
        files={"file": ("large.xml", b"x" * 17, "application/xml")},
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "upload_too_large"


def test_cancel_scan_terminates_its_process(client):
    from backend.app.models import ScanJob
    from backend.app.services.scan_service import (
        _CANCELLED_SCANS,
        _PROCESS_LOCK,
        _RUNNING_PROCESSES,
        cancel_scan,
    )

    class RunningProcess:
        terminated = False

        def poll(self):
            return None

        def terminate(self):
            self.terminated = True

    process = RunningProcess()
    db = get_session_factory()()
    job = ScanJob(id="cancel-test", profile="tcp_connect", targets="192.0.2.10", status="running", argv=[])
    db.add(job)
    db.commit()
    with _PROCESS_LOCK:
        _RUNNING_PROCESSES[job.id] = process
    try:
        cancelled = cancel_scan(db, job.id)
        assert cancelled.status == "cancelled"
        assert process.terminated
        assert job.id in _CANCELLED_SCANS
    finally:
        with _PROCESS_LOCK:
            _RUNNING_PROCESSES.pop(job.id, None)
            _CANCELLED_SCANS.discard(job.id)
        db.close()


def test_cancelled_scan_does_not_spawn_nmap(tmp_path, monkeypatch):
    from backend.app.services.scan_service import (
        _CANCELLED_SCANS,
        _PROCESS_LOCK,
        _run_nmap_process,
    )

    def unexpected_spawn(*args, **kwargs):
        raise AssertionError("cancelled scan must not spawn Nmap")

    monkeypatch.setattr("backend.app.services.scan_service.subprocess.Popen", unexpected_spawn)
    scan_id = "cancel-before-spawn"
    with _PROCESS_LOCK:
        _CANCELLED_SCANS.add(scan_id)
    try:
        assert _run_nmap_process(scan_id, [], tmp_path / "scan.xml", 1) == (-1, "", "")
    finally:
        with _PROCESS_LOCK:
            _CANCELLED_SCANS.discard(scan_id)
