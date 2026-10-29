import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app.core.config import get_settings
from backend.app.db.session import init_db, reset_engine


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr("backend.app.core.config.repo_root", lambda: tmp_path)
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("NMAP_AI_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("NMAP_AI_API_TOKEN", "test-token")
    monkeypatch.setenv("NMAP_AI_USERNAME", "lab")
    monkeypatch.setenv("NMAP_AI_PASSWORD", "labpass")
    monkeypatch.setenv("NMAP_AI_TARGET_IP", "")
    monkeypatch.setenv("NMAP_AI_AUTHORIZED_TARGETS", "")
    get_settings.cache_clear()
    reset_engine()
    init_db()
    from backend.app.main import create_app

    app = create_app()
    with TestClient(app) as test_client:
        yield test_client
    get_settings.cache_clear()
    reset_engine()


@pytest.fixture
def auth_headers():
    return {"X-API-Key": "test-token"}
