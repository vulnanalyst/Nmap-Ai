from __future__ import annotations

import shutil
from pathlib import Path

from sqlalchemy.orm import Session

from backend.app.core.config import get_settings
from backend.app.models import AuthorizedTarget, Setting
from backend.app.services.scan_service import nmap_status
from backend.app.services.targets import parse_target
from ml.inference.predict import latest_artifact


EDITABLE = {
    "scanner_name",
    "scanner_ip",
    "target_name",
    "target_ip",
    "capture_interface",
    "nmap_path",
    "timezone",
    "log_level",
    "demo_mode",
}


def get_all(db: Session) -> dict:
    settings = get_settings()
    targets = [{"id": t.id, "cidr": t.cidr, "label": t.label} for t in db.query(AuthorizedTarget).all()]
    allow = [t["cidr"] for t in targets]
    nmap = nmap_status()
    model = latest_artifact()
    nvd = bool(settings.nvd_api_key)
    stored = {row.key: row.value for row in db.query(Setting).all()}
    return {
        "scanner_name": stored.get("scanner_name", settings.scanner_name) or None,
        "scanner_ip": stored.get("scanner_ip", settings.scanner_ip) or None,
        "target_name": stored.get("target_name", settings.target_name) or None,
        "target_ip": stored.get("target_ip", settings.target_ip) or None,
        "authorized_targets": targets,
        "authorized_cidrs": allow,
        "capture_interface": stored.get("capture_interface", settings.capture_interface) or None,
        "ingest_host": settings.ingest_host,
        "ingest_port": settings.ingest_port,
        "nmap": nmap,
        "nvd_api_key_configured": nvd,
        "database_url": _redact_db(settings.sqlite_url),
        "demo_mode": stored.get("demo_mode", str(settings.demo_mode).lower()) == "true",
        "timezone": stored.get("timezone", settings.timezone),
        "log_level": stored.get("log_level", settings.log_level),
        "model": {
            "version": model.get("version") if model else None,
            "trained_at": model.get("trained_at") if model else None,
            "path": model.get("model_path") if model else None,
        },
        "placeholders": {
            "scanner": "Configure Kali scanner identity when known.",
            "target": "Configure the Windows 10 lab target IP when known. Do not guess.",
        },
    }


def upsert(db: Session, key: str, value: str) -> None:
    if key not in EDITABLE:
        raise ValueError(f"Setting {key} is not editable")
    row = db.query(Setting).filter_by(key=key).one_or_none()
    if row:
        row.value = value
    else:
        db.add(Setting(key=key, value=value))


def add_target(db: Session, cidr: str, label: str = "") -> AuthorizedTarget:
    parse_target(cidr)
    existing = db.query(AuthorizedTarget).filter_by(cidr=cidr).one_or_none()
    if existing:
        return existing
    row = AuthorizedTarget(cidr=cidr, label=label)
    db.add(row)
    db.flush()
    return row


def _redact_db(url: str) -> str:
    if "://" in url and "@" in url:
        return url.split("@", 1)[0].split("://")[0] + "://***@" + url.split("@", 1)[1]
    return url
