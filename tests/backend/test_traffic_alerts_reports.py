from pathlib import Path

from backend.app.services.traffic_ingestion import decode_length_prefixed


FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "sample_nmap.xml"


def test_single_packet_skips_ml(client, auth_headers):
    res = client.post(
        "/api/v1/traffic/ingest",
        headers=auth_headers,
        json={
            "src_addr": "192.0.2.1",
            "dst_addr": "192.0.2.10",
            "src_port": 4000,
            "dst_port": 22,
            "protocol": "TCP",
            "packet_length": 60,
        },
    )
    assert res.status_code == 200
    assert res.json()["feature_complete"] is False
    assert res.json()["ml_status"] == "skipped_insufficient"
    events = client.get("/api/v1/traffic/events", headers=auth_headers).json()["items"]
    assert events
    assert events[0]["data_source"] == "live"
    alerts = client.get("/api/v1/alerts", headers=auth_headers).json()["items"]
    sensitive = [a for a in alerts if "sensitive" in a["title"].lower()]
    assert sensitive
    assert sensitive[0]["severity"] == "info"


def test_length_prefix_framing():
    import struct

    payload = b"\x00\x00\x00\x04ABCD" + struct.pack("!I", 16) + b"leftover"
    frames, rest, errors = decode_length_prefixed(payload)
    assert frames == [b"ABCD"]
    assert rest == struct.pack("!I", 16) + b"leftover"
    assert errors == 0
    frames, _, errors = decode_length_prefixed(b"\xff\xff\xff\xff")
    assert errors == 1


def test_ml_infer_rejects_short_vector(client, auth_headers):
    res = client.post("/api/v1/ml/infer", headers=auth_headers, json={"features": [1, 2, 3]})
    assert res.status_code in {400, 409}


def test_report_uses_stored_records(client, auth_headers):
    with FIXTURE.open("rb") as handle:
        client.post("/api/v1/scans/import", headers=auth_headers, files={"file": ("sample.xml", handle, "application/xml")})
    created = client.post("/api/v1/reports", headers=auth_headers).json()
    data = client.get(f"/api/v1/reports/{created['id']}/json", headers=auth_headers).json()
    assert data["hosts"][0]["ip"] == "192.0.2.10"
    assert "Exploitation is not claimed" in " ".join(data["limitations"])
    pdf = client.get(f"/api/v1/reports/{created['id']}/pdf", headers=auth_headers)
    assert pdf.status_code == 200
    assert pdf.headers["content-type"].startswith("application/pdf")


def test_dashboard_matches_db(client, auth_headers):
    empty = client.get("/api/v1/dashboard/summary", headers=auth_headers).json()
    assert empty["hosts_total"] == 0
    with FIXTURE.open("rb") as handle:
        client.post("/api/v1/scans/import", headers=auth_headers, files={"file": ("sample.xml", handle, "application/xml")})
    summary = client.get("/api/v1/dashboard/summary", headers=auth_headers).json()
    hosts = client.get("/api/v1/hosts", headers=auth_headers).json()
    assert summary["hosts_total"] == hosts["count"]
    assert summary["ports_open"] == 2


def test_login(client):
    bad = client.post("/api/v1/auth/login", json={"username": "lab", "password": "wrong"})
    assert bad.status_code == 401
    ok = client.post("/api/v1/auth/login", json={"username": "lab", "password": "labpass"})
    assert ok.status_code == 200
    assert ok.json()["token"] == "test-token"
