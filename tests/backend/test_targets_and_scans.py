from pathlib import Path

from backend.app.db.session import get_session_factory
from backend.app.services.nmap_parser import parse_nmap_xml
from backend.app.services.scan_service import start_scan


FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "sample_nmap.xml"


def allow_target(client, auth_headers, cidr="192.0.2.10/32"):
    return client.post(
        "/api/v1/settings/targets",
        headers=auth_headers,
        json={"cidr": cidr, "label": "test lab"},
    )


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

    allow_target(client, auth_headers)
    with FIXTURE.open("rb") as handle:
        res = client.post("/api/v1/scans/import", headers=auth_headers, files={"file": ("sample.xml", handle, "application/xml")})
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "completed"
    assert body["ports_open"] == 2
    assert body["ports_closed"] == 1
    assert body["ports_filtered"] == 1
    assert body["targets"] == "192.0.2.10"
    assert body["profile"] == "manual_import"
    assert body["scan_source"] == "manual/imported"
    assert body["started_at"] is not None
    assert body["finished_at"] is not None

    hosts = client.get("/api/v1/hosts", headers=auth_headers).json()["items"]
    assert hosts[0]["ip"] == "192.0.2.10"
    assert hosts[0]["os_label"] == "guess"
    details = client.get(f"/api/v1/scans/{body['id']}", headers=auth_headers).json()
    assert details["hosts"][0]["services"][0]["protocol"] == "tcp"
    assert details["hosts"][0]["services"][0]["name"] == "ssh"
    assert details["hosts"][0]["services"][0]["product"] == "OpenSSH"
    assert details["source_name"] == "sample.xml"
    summary = client.get("/api/v1/dashboard/summary", headers=auth_headers).json()
    assert summary["latest_scan"]["id"] == body["id"]
    assert summary["ports_open"] == 2


def test_manual_xml_import_requires_authorized_target(client, auth_headers):
    with FIXTURE.open("rb") as handle:
        response = client.post(
            "/api/v1/scans/import",
            headers=auth_headers,
            files={"file": ("scan.xml", handle, "application/xml")},
        )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "allowlist_empty"

    allow_target(client, auth_headers, "192.0.2.11/32")
    with FIXTURE.open("rb") as handle:
        response = client.post(
            "/api/v1/scans/import",
            headers=auth_headers,
            files={"file": ("scan.xml", handle, "application/xml")},
        )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "unauthorized_target"


def test_manual_xml_import_validates_target_expression_in_nmap_arguments(client, auth_headers):
    allow_target(client, auth_headers, "192.0.2.10/32")
    content = FIXTURE.read_bytes().replace(
        b"192.0.2.10\"",
        b"192.0.2.0/24\"",
        1,
    )
    response = client.post(
        "/api/v1/scans/import",
        headers=auth_headers,
        files={"file": ("scan.xml", content, "application/xml")},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "unauthorized_target"


def test_manual_xml_import_is_idempotent_and_appears_in_history(client, auth_headers):
    allow_target(client, auth_headers)
    responses = []
    for _ in range(2):
        with FIXTURE.open("rb") as handle:
            responses.append(
                client.post(
                    "/api/v1/scans/import",
                    headers=auth_headers,
                    files={"file": ("scan.xml", handle, "application/xml")},
                )
            )
    assert all(response.status_code == 200 for response in responses)
    first, duplicate = (response.json() for response in responses)
    assert first["id"] == duplicate["id"]
    assert duplicate["duplicate"] is True
    history = client.get("/api/v1/scans", headers=auth_headers).json()["items"]
    assert len(history) == 1
    assert history[0]["scan_source"] == "manual/imported"


def test_target_dataset_import_validates_and_lists_authorized_targets(client, auth_headers):
    allow_target(client, auth_headers, "192.0.2.101/32")
    response = client.post(
        "/api/v1/scans/targets/import",
        headers=auth_headers,
        files={
            "file": (
                "targets.csv",
                b"ip,target_name\n192.0.2.101,lab-host\n192.0.2.101,updated-name\n",
                "text/csv",
            )
        },
    )
    assert response.status_code == 200
    assert response.json()["count"] == 1
    assert response.json()["items"][0]["name"] == "updated-name"
    assert client.get("/api/v1/scans/targets", headers=auth_headers).json()["items"][0]["ip"] == "192.0.2.101"


def test_target_dataset_import_rejects_invalid_and_unauthorized_ips(client, auth_headers):
    invalid = client.post(
        "/api/v1/scans/targets/import",
        headers=auth_headers,
        files={"file": ("targets.csv", b"ip,name\nnot-an-ip,test\n", "text/csv")},
    )
    assert invalid.status_code == 400
    assert invalid.json()["error"]["code"] == "invalid_dataset"

    allow_target(client, auth_headers, "192.0.2.101/32")
    unauthorized = client.post(
        "/api/v1/scans/targets/import",
        headers=auth_headers,
        files={"file": ("targets.csv", b"ip,name\n192.0.2.102,not-allowed\n", "text/csv")},
    )
    assert unauthorized.status_code == 403


def test_dataset_selected_target_uses_existing_allowlisted_scan_workflow(client, auth_headers):
    allow_target(client, auth_headers, "192.168.56.101/32")
    dataset = client.post(
        "/api/v1/scans/targets/import",
        headers=auth_headers,
        files={"file": ("targets.csv", b"ip,name\n192.168.56.101,Metasploitable\n", "text/csv")},
    ).json()
    selected_target = dataset["items"][0]["ip"]
    scan = client.post(
        "/api/v1/scans",
        headers=auth_headers,
        json={
            "profile": "service_version",
            "target": selected_target,
            "confirm_target": selected_target,
            "confirm_authorization": True,
            "dry_run": True,
            "dataset_target_id": dataset["items"][0]["id"],
        },
    )
    assert scan.status_code == 200
    assert scan.json()["targets"] == "192.168.56.101"
    assert scan.json()["status"] == "dry_run"
    assert scan.json()["ports_open"] == 0
    assert scan.json()["dataset_targets"][0]["ip"] == "192.168.56.101"

    allow_target(client, auth_headers, "192.168.56.102/32")
    mismatch = client.post(
        "/api/v1/scans",
        headers=auth_headers,
        json={
            "profile": "service_version",
            "target": "192.168.56.102",
            "confirm_target": "192.168.56.102",
            "confirm_authorization": True,
            "dry_run": True,
            "dataset_target_id": dataset["items"][0]["id"],
        },
    )
    assert mismatch.status_code == 400
    assert mismatch.json()["error"]["code"] == "dataset_target_mismatch"


def test_nmap_xml_rejects_entity_declarations(client, auth_headers):
    malicious = b'<!DOCTYPE nmaprun [<!ENTITY test "x">]><nmaprun scanner="nmap"></nmaprun>'
    response = client.post(
        "/api/v1/scans/import",
        headers=auth_headers,
        files={"file": ("scan.xml", malicious, "application/xml")},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "xml_parse_error"


def test_target_ip_identity_does_not_replace_allowlist(client, auth_headers, monkeypatch):
    monkeypatch.setenv("NMAP_AI_TARGET_IP", "192.0.2.10")
    from backend.app.core.config import get_settings

    get_settings.cache_clear()
    try:
        with FIXTURE.open("rb") as handle:
            response = client.post(
                "/api/v1/scans/import",
                headers=auth_headers,
                files={"file": ("scan.xml", handle, "application/xml")},
            )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "allowlist_empty"
    finally:
        get_settings.cache_clear()


def test_import_from_authorized_metasploitable_target_is_persisted(client, auth_headers):
    target_xml = FIXTURE.read_bytes().replace(b"192.0.2.10", b"192.168.56.101")
    allow_target(client, auth_headers, "192.168.56.101/32")
    client.post(
        "/api/v1/scans/targets/import",
        headers=auth_headers,
        files={"file": ("targets.csv", b"ip,name\n192.168.56.101,Metasploitable\n", "text/csv")},
    )
    response = client.post(
        "/api/v1/scans/import",
        headers=auth_headers,
        files={"file": ("manual-scan.xml", target_xml, "application/xml")},
    )
    assert response.status_code == 200
    scan = response.json()
    assert scan["targets"] == "192.168.56.101"
    assert scan["data_source"] == "manual_import"
    assert scan["ports_open"] == 2
    assert scan["dataset_targets"][0]["name"] == "Metasploitable"
    assert client.get("/api/v1/dashboard/summary", headers=auth_headers).json()["latest_scan"]["id"] == scan["id"]


def test_imported_unreachable_scan_surfaces_nmap_status(client, auth_headers):
    allow_target(client, auth_headers, "192.168.56.101/32")
    xml = FIXTURE.read_bytes()
    xml = xml.replace(b'192.0.2.10', b'192.168.56.101')
    xml = xml.replace(b'state="up"', b'state="down"')
    xml = xml.replace(b'up="1" down="0"', b'up="0" down="1"')
    response = client.post(
        "/api/v1/scans/import",
        headers=auth_headers,
        files={"file": ("unreachable.xml", xml, "application/xml")},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "completed"
    assert "no scanned hosts up" in response.json()["error"]


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
    allow_target(client, auth_headers)
    with FIXTURE.open("rb") as handle:
        client.post("/api/v1/scans/import", headers=auth_headers, files={"file": ("sample.xml", handle, "application/xml")})
    findings = client.get("/api/v1/findings", headers=auth_headers).json()["items"]
    confirmed_cves = [f for f in findings if f["validation_status"] == "validated_vulnerability"]
    assert confirmed_cves == []
    assert any(f["validation_status"] in {"no_verified_cve_match", "potential_issue", "suspected"} for f in findings)


def test_duplicate_import_dedupes_findings(client, auth_headers):
    allow_target(client, auth_headers)
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


def test_kali_agent_heartbeat_and_status(client, auth_headers):
    # Heartbeat registration
    hb = client.post(
        "/api/v1/scans/agent/heartbeat",
        headers=auth_headers,
        json={
            "scanner_name": "Kali-Lab",
            "scanner_ip": "192.168.56.102",
            "nmap_version": "Nmap 7.94SVN",
            "nmap_path": "/usr/bin/nmap",
        },
    )
    assert hb.status_code == 200
    assert hb.json()["status"] == "online"

    # Profiles endpoint now reflects Kali agent
    res = client.get("/api/v1/scans/profiles", headers=auth_headers)
    assert res.status_code == 200
    nmap = res.json()["nmap"]
    assert nmap["installed"] is True
    assert nmap["mode"] == "kali_agent"
    assert nmap["scanner_ip"] == "192.168.56.102"
    assert "Nmap 7.94SVN" in nmap["version"]


def test_kali_agent_job_dispatch_and_completion(client, auth_headers):
    allow_target(client, auth_headers, "192.168.56.101/32")

    # Send heartbeat so agent mode is active
    client.post(
        "/api/v1/scans/agent/heartbeat",
        headers=auth_headers,
        json={
            "scanner_name": "Kali",
            "scanner_ip": "192.168.56.102",
            "nmap_version": "Nmap 7.94SVN",
            "nmap_path": "/usr/bin/nmap",
        },
    )

    # Launch scan
    scan = client.post(
        "/api/v1/scans",
        headers=auth_headers,
        json={
            "profile": "service_version",
            "target": "192.168.56.101",
            "confirm_target": "192.168.56.101",
            "confirm_authorization": True,
            "dry_run": False,
        },
    )
    assert scan.status_code == 200
    job_id = scan.json()["id"]
    assert scan.json()["status"] == "queued"

    # Agent polls for job
    poll = client.post("/api/v1/scans/agent/poll", headers=auth_headers)
    assert poll.status_code == 200
    polled_job = poll.json()["job"]
    assert polled_job is not None
    assert polled_job["job_id"] == job_id
    assert polled_job["target"] == "192.168.56.101"

    # Agent completes the job with XML output
    xml_content = FIXTURE.read_text().replace("192.0.2.10", "192.168.56.101")
    comp = client.post(
        "/api/v1/scans/agent/complete",
        headers=auth_headers,
        json={
            "job_id": job_id,
            "return_code": 0,
            "stdout": "Nmap done",
            "stderr": "",
            "xml_content": xml_content,
        },
    )
    assert comp.status_code == 200
    body = comp.json()
    assert body["status"] == "completed"
    assert body["ports_open"] == 2
    assert body["hosts_up"] == 1

    # Verify persisted in scan list and dashboard
    scans_list = client.get("/api/v1/scans", headers=auth_headers).json()["items"]
    assert any(s["id"] == job_id for s in scans_list)
    summary = client.get("/api/v1/dashboard/summary", headers=auth_headers).json()
    assert summary["latest_scan"]["id"] == job_id
    assert summary["ports_open"] == 2


def test_dataset_targets_listing_and_authorization_status(client, auth_headers):
    allow_target(client, auth_headers, "192.168.56.101/32")
    client.post(
        "/api/v1/scans/targets/import",
        headers=auth_headers,
        files={
            "file": (
                "targets.csv",
                b"ip,name\n192.168.56.101,Metasploitable Lab\n",
                "text/csv",
            )
        },
    )
    # Default: only authorized
    targets_auth = client.get("/api/v1/scans/targets", headers=auth_headers).json()["items"]
    assert len(targets_auth) == 1
    assert targets_auth[0]["ip"] == "192.168.56.101"
    assert targets_auth[0]["authorized"] is True

    # With all=true
    targets_all = client.get("/api/v1/scans/targets?all=true", headers=auth_headers).json()["items"]
    assert len(targets_all) == 1
    assert targets_all[0]["authorized"] is True

