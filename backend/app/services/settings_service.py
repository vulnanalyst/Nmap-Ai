from __future__ import annotations

import ipaddress

from sqlalchemy.orm import Session

from backend.app.core.config import get_settings
from backend.app.models import AuthorizedTarget, Setting
from backend.app.services.scan_service import nmap_status
from backend.app.services.targets import parse_target
from ml.inference.predict import latest_artifact


EDITABLE = {"scanner_name", "scanner_ip", "target_name", "target_ip"}


def get_all(db: Session) -> dict:
    settings = get_settings()
    stored = {row.key: row.value for row in db.query(Setting).all()}
    targets = [{"id": t.id, "cidr": t.cidr, "label": t.label} for t in db.query(AuthorizedTarget).all()]
    allow = [t["cidr"] for t in targets]
    nmap = nmap_status()
    model = latest_artifact()
    return {
        "scanner_name": stored.get("scanner_name", settings.scanner_name) or None,
        "scanner_ip": stored.get("scanner_ip", settings.scanner_ip) or None,
        "target_name": stored.get("target_name", settings.target_name) or None,
        "target_ip": stored.get("target_ip", settings.target_ip) or None,
        "authorized_targets": targets,
        "authorized_cidrs": allow,
        "ingest_host": settings.ingest_host,
        "ingest_port": settings.ingest_port,
        "nmap": nmap,
        "model": {
            "version": model.get("version") if model else None,
            "trained_at": model.get("trained_at") if model else None,
            "path": model.get("model_path") if model else None,
        },
        "placeholders": {
            "scanner": "Optional identity displayed in the observed network topology.",
            "target": "Optional identity included in generated reports; scan permission is controlled by the CIDR allowlist.",
        },
    }


def upsert(db: Session, key: str, value: str) -> None:
    if key not in EDITABLE:
        raise ValueError(f"Setting {key} is not editable")
    if key in {"scanner_ip", "target_ip"} and value:
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(f"{key} must be a valid IP address") from exc
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
