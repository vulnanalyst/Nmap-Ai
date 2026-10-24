from __future__ import annotations

import json
import shutil
import subprocess
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from sqlalchemy.orm import Session

from backend.app.core.config import get_settings
from backend.app.core.errors import AppError
from backend.app.core.events import event_bus
from backend.app.models import ScanJob
from backend.app.services.host_service import persist_parsed_scan
from backend.app.services.nmap_parser import parse_nmap_xml
from backend.app.services.targets import assert_authorized, parse_target

PROFILES: dict[str, list[str]] = {
    "host_discovery": ["-sn"],
    "tcp_connect": ["-sT"],
    "service_version": ["-sT", "-sV"],
    "os_fingerprint": ["-sT", "-O"],
    "vuln_safe": ["-sT", "-sV", "--script", "safe"],
}

Runner = Callable[[list[str], Path, int], tuple[int, str, str]]


def nmap_status() -> dict:
    settings = get_settings()
    path = shutil.which(settings.nmap_path) or (
        settings.nmap_path if Path(settings.nmap_path).exists() else None
    )
    if not path:
        return {
            "installed": False,
            "path": settings.nmap_path,
            "guidance": "Install Nmap (Kali: already present, or `sudo apt install nmap`) and set NMAP_AI_NMAP_PATH if it is not on PATH.",
        }
    try:
        proc = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10, check=False)
        version = (proc.stdout or proc.stderr).splitlines()[0] if (proc.stdout or proc.stderr) else "unknown"
        return {"installed": True, "path": path, "version": version}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"installed": False, "path": path, "guidance": str(exc)}


def preview_scan(profile: str, target: str) -> dict:
    parse_target(target)
    if profile not in PROFILES:
        raise AppError("Unknown scan profile", code="invalid_profile")
    settings = get_settings()
    argv = [settings.nmap_path, *PROFILES[profile], "-oX", "<scan-xml>", target]
    return {
        "profile": profile,
        "target": target,
        "argv": argv,
        "notes": [
            "The process is executed as an argument array; the target is not interpolated into a shell.",
            "vuln_safe uses Nmap's non-destructive 'safe' script category only.",
            "OS fingerprinting and some scripts may require root and can still fail in the lab.",
        ],
    }


def start_scan(
    db: Session,
    *,
    profile: str,
    target: str,
    confirm_target: str,
    confirm_authorization: bool,
    dry_run: bool = False,
    runner: Runner | None = None,
) -> ScanJob:
    if not confirm_authorization:
        raise AppError("Explicit authorization is required", status_code=403, code="authorization_required")
    if confirm_target.strip() != target.strip():
        raise AppError("Target confirmation does not match", status_code=400, code="target_mismatch")
    parse_target(target)
    assert_authorized(db, target)
    if profile not in PROFILES:
        raise AppError("Unknown scan profile", code="invalid_profile")

    settings = get_settings()
    scan_id = str(uuid.uuid4())
    out_dir = settings.data_dir / "scans" / scan_id
    out_dir.mkdir(parents=True, exist_ok=True)
    xml_path = out_dir / "scan.xml"
    json_path = out_dir / "scan.json"
    argv = [settings.nmap_path, *PROFILES[profile], "--stats-every", "5s", "-oX", str(xml_path), target]
    job = ScanJob(
        id=scan_id,
        profile=profile,
        targets=target,
        status="preview" if dry_run else "queued",
        argv=argv,
        dry_run=dry_run,
        data_source="live",
        xml_path=str(xml_path),
        json_path=str(json_path),
        authorized_by="lab-operator",
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    if dry_run:
        job.status = "dry_run"
        db.commit()
        return job

    if runner is None:
        status = nmap_status()
        if not status.get("installed"):
            job.status = "error"
            job.error = status.get("guidance") or "Nmap is not installed"
            job.finished_at = datetime.now(timezone.utc)
            db.commit()
            return job

    thread = threading.Thread(target=_run_job, args=(job.id, runner), daemon=True)
    thread.start()
    return job


def _run_job(scan_id: str, runner: Runner | None) -> None:
    from backend.app.db.session import get_session_factory

    db = get_session_factory()()
    try:
        job = db.query(ScanJob).filter_by(id=scan_id).one()
        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        db.commit()
        settings = get_settings()
        xml_path = Path(job.xml_path)
        try:
            code, stdout, stderr = (runner or _default_runner)(job.argv, xml_path, settings.scan_timeout_seconds)
        except subprocess.TimeoutExpired:
            job.status = "timeout"
            job.error = f"Scan exceeded {settings.scan_timeout_seconds}s"
            job.finished_at = datetime.now(timezone.utc)
            db.commit()
            return
        except Exception as exc:  # noqa: BLE001 — persist actual runner failure
            job.status = "error"
            job.error = str(exc)
            job.finished_at = datetime.now(timezone.utc)
            db.commit()
            return

        job.finished_at = datetime.now(timezone.utc)
        if job.started_at:
            job.duration_seconds = (job.finished_at - job.started_at).total_seconds()
        if code != 0 and not xml_path.exists():
            job.status = "error"
            job.error = stderr or stdout or f"nmap exited {code}"
            db.commit()
            return
        if not xml_path.exists():
            job.status = "error"
            job.error = "Nmap did not produce XML output"
            db.commit()
            return
        parsed = parse_nmap_xml(xml_path)
        Path(job.json_path).write_text(json.dumps(parsed, indent=2), encoding="utf-8")
        persist_parsed_scan(db, job, parsed, "live")
        job.status = "completed"
        job.progress_pct = 100
        db.commit()
        try:
            import asyncio

            asyncio.run(event_bus.publish({"type": "scan.completed", "scan_id": job.id}))
        except Exception:
            pass
    finally:
        db.close()


def _default_runner(argv: list[str], xml_path: Path, timeout: int) -> tuple[int, str, str]:
    proc = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        cwd=str(xml_path.parent),
    )
    return proc.returncode, proc.stdout, proc.stderr


def cancel_scan(db: Session, scan_id: str) -> ScanJob:
    job = db.query(ScanJob).filter_by(id=scan_id).one_or_none()
    if not job:
        raise AppError("Scan not found", status_code=404, code="not_found")
    if job.status in {"completed", "error", "timeout", "cancelled", "dry_run"}:
        return job
    job.status = "cancelled"
    job.error = "Cancelled by operator"
    job.finished_at = datetime.now(timezone.utc)
    db.commit()
    return job


def import_xml(db: Session, content: bytes, filename: str, data_source: str = "import") -> ScanJob:
    scan_id = str(uuid.uuid4())
    settings = get_settings()
    out_dir = settings.data_dir / "scans" / scan_id
    out_dir.mkdir(parents=True, exist_ok=True)
    xml_path = out_dir / "scan.xml"
    json_path = out_dir / "scan.json"
    xml_path.write_bytes(content)
    parsed = parse_nmap_xml(xml_path)
    json_path.write_text(json.dumps(parsed, indent=2), encoding="utf-8")
    job = ScanJob(
        id=scan_id,
        profile="import",
        targets=filename,
        status="completed",
        argv=[],
        dry_run=False,
        data_source=data_source,
        xml_path=str(xml_path),
        json_path=str(json_path),
        progress_pct=100,
        finished_at=datetime.now(timezone.utc),
        nmap_version=parsed.get("version"),
        duration_seconds=parsed.get("elapsed"),
    )
    db.add(job)
    persist_parsed_scan(db, job, parsed, data_source)
    db.commit()
    db.refresh(job)
    return job
