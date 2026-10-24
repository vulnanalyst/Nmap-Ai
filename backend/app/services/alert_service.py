from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from backend.app.models import Alert, AlertNote


SENSITIVE_PORTS = {22: "ssh", 23: "telnet", 3389: "rdp", 445: "smb", 135: "rpc", 21: "ftp", 3306: "mysql"}


def fingerprint(parts: list[str]) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:24]


def create_or_bump(db: Session, payload: dict[str, Any], window_seconds: int = 60) -> Alert:
    fp = payload["fingerprint"]
    existing = (
        db.query(Alert)
        .filter(Alert.fingerprint == fp, Alert.status == "open")
        .order_by(Alert.timestamp.desc())
        .first()
    )
    now = datetime.now(timezone.utc)
    if existing and existing.timestamp.replace(tzinfo=timezone.utc) and (now - existing.timestamp.replace(tzinfo=timezone.utc)).total_seconds() < window_seconds:
        extra = dict(existing.extra or {})
        extra["repeat_count"] = int(extra.get("repeat_count") or 1) + 1
        extra["last_seen"] = now.isoformat()
        existing.extra = extra
        existing.timestamp = now
        db.flush()
        return existing
    alert = Alert(**payload)
    db.add(alert)
    db.flush()
    return alert


def signature_alerts(event: dict[str, Any], recent_dst_ports: list[int]) -> list[dict[str, Any]]:
    """Pattern-based alerts. A single sensitive-port connection is informational, not an attack."""
    alerts = []
    dport = event.get("dst_port")
    src = event.get("src_addr")
    dst = event.get("dst_addr")
    proto = event.get("protocol")
    unique_ports = set(recent_dst_ports)
    if len(unique_ports) >= 20:
        alerts.append(
            {
                "title": "Port-scan-like destination port spread",
                "message": f"Observed {len(unique_ports)} distinct destination ports from {src} in the current window.",
                "severity": "medium",
                "detection_method": "signature",
                "rule_or_model": "port-spread-v1",
                "dst_port": dport,
                "src_addr": src,
                "dst_addr": dst,
                "protocol": proto,
                "confidence": None,
                "fingerprint": fingerprint(["spread", str(src), str(dst)]),
            }
        )
    pps = event.get("packets_per_sec")
    if pps is not None and pps > 100:
        alerts.append(
            {
                "title": "Unusual connection rate",
                "message": f"Estimated packets/s {pps} exceeded the configured lab threshold of 100.",
                "severity": "medium",
                "detection_method": "signature",
                "rule_or_model": "rate-v1",
                "dst_port": dport,
                "src_addr": src,
                "dst_addr": dst,
                "protocol": proto,
                "fingerprint": fingerprint(["rate", str(src), str(dst)]),
            }
        )
    if dport in SENSITIVE_PORTS:
        alerts.append(
            {
                "title": f"Connection to sensitive service ({SENSITIVE_PORTS[dport]})",
                "message": "Observed access to a sensitive lab service. This is not classified as an attack by itself.",
                "severity": "info",
                "detection_method": "signature",
                "rule_or_model": "sensitive-port-observe-v1",
                "dst_port": dport,
                "src_addr": src,
                "dst_addr": dst,
                "protocol": proto,
                "fingerprint": fingerprint(["sensitive", str(src), str(dst), str(dport)]),
            }
        )
    return alerts


def add_note(db: Session, alert_id: int, body: str, author: str = "analyst") -> AlertNote:
    note = AlertNote(alert_id=alert_id, body=body, author=author)
    db.add(note)
    db.flush()
    return note
