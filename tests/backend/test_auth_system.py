import pytest

from backend.app.core.config import get_settings
from backend.app.core.rate_limit import login_rate_limiter
from backend.app.core.security import hash_password, session_manager


@pytest.fixture(autouse=True)
def clean_security_state():
    """Ensure clean rate-limiting and session state before and after each test."""
    login_rate_limiter.clear()
    session_manager.clear()
    yield
    login_rate_limiter.clear()
    session_manager.clear()


def test_login_success_with_provisioned_account(client):
    res = client.post("/api/v1/auth/login", json={"username": "lab", "password": "labpass"})
    assert res.status_code == 200
    data = res.json()
    assert "token" in data
    assert data["token_type"] == "bearer"
    assert data["username"] == "lab"

    # Verify session can access protected endpoints
    summary = client.get("/api/v1/dashboard/summary", headers={"X-API-Key": data["token"]})
    assert summary.status_code == 200


def test_login_rejected_with_incorrect_password(client):
    res = client.post("/api/v1/auth/login", json={"username": "lab", "password": "wrongpassword"})
    assert res.status_code == 401
    body = res.json()
    assert body["error"]["code"] == "unauthorized"


def test_login_rejected_with_unknown_username(client):
    res = client.post("/api/v1/auth/login", json={"username": "nonexistent_admin", "password": "labpass"})
    assert res.status_code == 401
    assert res.json()["error"]["code"] == "unauthorized"


def test_login_validation_empty_and_malformed_inputs(client):
    # Empty username
    r1 = client.post("/api/v1/auth/login", json={"username": "", "password": "labpass"})
    assert r1.status_code == 422

    # Whitespace only username
    r2 = client.post("/api/v1/auth/login", json={"username": "   ", "password": "labpass"})
    assert r2.status_code == 422

    # Empty password
    r3 = client.post("/api/v1/auth/login", json={"username": "lab", "password": ""})
    assert r3.status_code == 422

    # Missing fields
    r4 = client.post("/api/v1/auth/login", json={"username": "lab"})
    assert r4.status_code == 422

    # Malformed non-JSON body
    r5 = client.post("/api/v1/auth/login", content="not json", headers={"Content-Type": "application/json"})
    assert r5.status_code == 422


def test_password_hashing_verification(client, monkeypatch):
    hashed = hash_password("SuperSecretHash123!")
    monkeypatch.setenv("NMAP_AI_PASSWORD_HASH", hashed)
    monkeypatch.setenv("NMAP_AI_PASSWORD", "should_not_match")
    get_settings.cache_clear()

    # Wrong password fails
    bad = client.post("/api/v1/auth/login", json={"username": "lab", "password": "wrongpassword"})
    assert bad.status_code == 401

    # Right password succeeds using scrypt hash verification
    ok = client.post("/api/v1/auth/login", json={"username": "lab", "password": "SuperSecretHash123!"})
    assert ok.status_code == 200
    assert "token" in ok.json()


def test_rate_limiting_brute_force_protection(client):
    # Perform 5 consecutive failed login attempts
    for _ in range(5):
        res = client.post("/api/v1/auth/login", json={"username": "lab", "password": "wrong"})
        assert res.status_code == 401

    # 6th attempt should be blocked with HTTP 429 Too Many Requests
    blocked = client.post("/api/v1/auth/login", json={"username": "lab", "password": "wrong"})
    assert blocked.status_code == 429
    body = blocked.json()
    assert body["error"]["code"] == "rate_limited"
    assert "Too many failed login attempts" in body["error"]["message"]

    # Even a valid password attempt while blocked is denied
    even_valid = client.post("/api/v1/auth/login", json={"username": "lab", "password": "labpass"})
    assert even_valid.status_code == 429


def test_rate_limiter_resets_on_successful_login(client):
    # 2 failed attempts
    for _ in range(2):
        res = client.post("/api/v1/auth/login", json={"username": "lab", "password": "wrong"})
        assert res.status_code == 401

    # Successful login resets the counter
    ok = client.post("/api/v1/auth/login", json={"username": "lab", "password": "labpass"})
    assert ok.status_code == 200

    # Can fail 4 more times without being blocked at the 3rd total
    for _ in range(4):
        res = client.post("/api/v1/auth/login", json={"username": "lab", "password": "wrong"})
        assert res.status_code == 401


def test_logout_invalidates_session_token(client):
    # 1. Login to receive session token
    login_res = client.post("/api/v1/auth/login", json={"username": "lab", "password": "labpass"})
    assert login_res.status_code == 200
    token = login_res.json()["token"]

    # 2. Access protected endpoint before logout
    headers = {"Authorization": f"Bearer {token}"}
    access_before = client.get("/api/v1/dashboard/summary", headers=headers)
    assert access_before.status_code == 200

    # 3. Call logout endpoint
    logout_res = client.post("/api/v1/auth/logout", headers=headers)
    assert logout_res.status_code == 200
    assert logout_res.json()["message"] == "Logged out successfully"

    # 4. Accessing protected endpoint after logout must be rejected with 401
    access_after = client.get("/api/v1/dashboard/summary", headers=headers)
    assert access_after.status_code == 401

    # 5. Calling logout again with the revoked token must fail
    logout_again = client.post("/api/v1/auth/logout", headers=headers)
    assert logout_again.status_code == 401


def test_direct_access_to_protected_apis_without_auth(client):
    endpoints = [
        ("GET", "/api/v1/dashboard/summary"),
        ("GET", "/api/v1/scans"),
        ("GET", "/api/v1/scans/targets"),
        ("POST", "/api/v1/scans"),
        ("GET", "/api/v1/settings"),
        ("POST", "/api/v1/settings/targets"),
        ("GET", "/api/v1/hosts"),
        ("GET", "/api/v1/topology"),
        ("GET", "/api/v1/findings"),
        ("GET", "/api/v1/alerts"),
        ("GET", "/api/v1/reports"),
        ("GET", "/api/v1/ml/model"),
        ("GET", "/api/v1/traffic/events"),
        ("POST", "/api/v1/traffic/ingest"),
    ]

    for method, path in endpoints:
        if method == "GET":
            res = client.get(path)
        else:
            res = client.post(path, json={})
        assert res.status_code == 401, f"Expected 401 for {method} {path}, got {res.status_code}"
        assert res.json()["error"]["code"] == "unauthorized"


def test_public_registration_is_unavailable(client):
    # Verify that registration and signup routes do not exist
    r1 = client.post("/api/v1/auth/register", json={"username": "new", "password": "new"})
    assert r1.status_code in (404, 405)

    r2 = client.post("/api/v1/auth/signup", json={"username": "new", "password": "new"})
    assert r2.status_code in (404, 405)

    r3 = client.post("/api/v1/register", json={"username": "new", "password": "new"})
    assert r3.status_code in (404, 405)


def test_existing_workflow_and_dataset_with_session_token(client):
    # 1. Login with valid provisioned account
    login_res = client.post("/api/v1/auth/login", json={"username": "lab", "password": "labpass"})
    token = login_res.json()["token"]
    headers = {"X-API-Key": token}

    # 2. Add authorized target with session token
    t_res = client.post(
        "/api/v1/settings/targets",
        headers=headers,
        json={"cidr": "192.168.56.101/32", "label": "Metasploitable Target"},
    )
    assert t_res.status_code == 200

    # 3. Read dataset targets with session token
    d_res = client.get("/api/v1/scans/targets", headers=headers)
    assert d_res.status_code == 200

    # 4. Create dry-run scan job with session token
    s_res = client.post(
        "/api/v1/scans",
        headers=headers,
        json={
            "profile": "tcp_connect",
            "target": "192.168.56.101",
            "confirm_target": "192.168.56.101",
            "confirm_authorization": True,
            "dry_run": True,
        },
    )
    assert s_res.status_code == 200
    scan_id = s_res.json()["id"]

    # 5. Fetch scan details with session token
    scan_detail = client.get(f"/api/v1/scans/{scan_id}", headers=headers)
    assert scan_detail.status_code == 200
    assert scan_detail.json()["id"] == scan_id

    # 6. Fetch dashboard summary with session token
    dash = client.get("/api/v1/dashboard/summary", headers=headers)
    assert dash.status_code == 200
    assert "hosts_total" in dash.json()
