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


def test_demo_mode_isolation_and_seeding(client, auth_headers):
    # 1. Seed demo data
    seed_res = client.post("/api/v1/settings/demo/seed", headers=auth_headers)
    assert seed_res.status_code == 200

    # 2. Query summary without demo mode -> demo data not included
    live_summary = client.get("/api/v1/dashboard/summary?include_demo=false", headers=auth_headers).json()
    assert live_summary["hosts_total"] == 0

    # 3. Query summary with demo mode -> demo data included
    demo_summary = client.get("/api/v1/dashboard/summary?include_demo=true", headers=auth_headers).json()
    assert demo_summary["hosts_total"] >= 3
    assert demo_summary["ports_open"] >= 4

    # 4. Clear demo data
    clear_res = client.delete("/api/v1/settings/demo/seed", headers=auth_headers)
    assert clear_res.status_code == 200

    # 5. Verify demo data removed
    cleared_summary = client.get("/api/v1/dashboard/summary?include_demo=true", headers=auth_headers).json()
    assert cleared_summary["hosts_total"] == 0

