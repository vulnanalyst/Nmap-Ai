from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import logging
import platform
import shlex
import shutil
import subprocess
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.core.config import get_settings
from backend.app.core.errors import AppError
from backend.app.core.events import event_bus
from backend.app.models import DatasetTarget, ScanDatasetLink, ScanImport, ScanJob
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
_RUNNING_PROCESSES: dict[str, subprocess.Popen] = {}
_CANCELLED_SCANS: set[str] = set()
_PROCESS_LOCK = threading.Lock()
logger = logging.getLogger(__name__)
_AGENT_STATE: dict = {
    "last_heartbeat": None,
    "scanner_name": "Kali",
    "scanner_ip": "192.168.56.102",
    "nmap_version": None,
    "nmap_path": "/usr/bin/nmap",
}


def record_agent_heartbeat(
    *, scanner_name: str, scanner_ip: str, nmap_version: str | None, nmap_path: str
) -> dict:
    _AGENT_STATE.update(
        last_heartbeat=datetime.now(timezone.utc),
        scanner_name=scanner_name,
        scanner_ip=scanner_ip,
        nmap_version=nmap_version,
        nmap_path=nmap_path,
    )
    return {
        "status": "online",
        "scanner_name": scanner_name,
        "scanner_ip": scanner_ip,
        "recorded_at": _AGENT_STATE["last_heartbeat"].isoformat(),
    }


def nmap_status() -> dict:
    settings = get_settings()
    is_windows = platform.system().lower() == "windows"

    # Check if remote Kali agent is active
    agent_active = False
    if _AGENT_STATE.get("last_heartbeat"):
        elapsed = (datetime.now(timezone.utc) - _AGENT_STATE["last_heartbeat"]).total_seconds()
        if elapsed < 45:
            agent_active = True

    if agent_active:
        return {
            "installed": True,
            "mode": "kali_agent",
            "scanner_name": _AGENT_STATE.get("scanner_name") or "Kali Agent",
            "scanner_ip": _AGENT_STATE.get("scanner_ip") or "192.168.56.102",
            "version": _AGENT_STATE.get("nmap_version") or "Nmap (Kali Agent)",
            "path": _AGENT_STATE.get("nmap_path") or "/usr/bin/nmap",
            "last_heartbeat": _AGENT_STATE["last_heartbeat"].isoformat(),
        }

    path = shutil.which(settings.nmap_path) or (
        settings.nmap_path if Path(settings.nmap_path).exists() else None
    )
    if not path:
        guidance = (
            "Scanner engine not detected on Windows host. "
            "Start the Kali agent on Kali (`python agent/kali_agent.py worker --server http://192.168.56.1:8000 --token <token>`) "
            "or import manual Nmap XML files."
            if is_windows
            else "Install Nmap (Kali: already present, or `sudo apt install nmap`) and set NMAP_AI_NMAP_PATH if it is not on PATH."
        )
        return {
            "installed": False,
            "mode": "disconnected",
            "path": settings.nmap_path,
            "guidance": guidance,
        }
    try:
        proc = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10, check=False)
        version = (proc.stdout or proc.stderr).splitlines()[0] if (proc.stdout or proc.stderr) else "unknown"
        return {"installed": True, "mode": "local", "path": path, "version": version}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"installed": False, "mode": "disconnected", "path": path, "guidance": str(exc)}


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
    dataset_target_id: int | None = None,
) -> ScanJob:
    if not confirm_authorization:
        raise AppError("Explicit authorization is required", status_code=403, code="authorization_required")
    if confirm_target.strip() != target.strip():
        raise AppError("Target confirmation does not match", status_code=400, code="target_mismatch")
    parse_target(target)
    assert_authorized(db, target)
    dataset_target = None
    if dataset_target_id is not None:
        dataset_target = db.query(DatasetTarget).filter_by(id=dataset_target_id).one_or_none()
        if not dataset_target:
            raise AppError("Dataset target not found", status_code=404, code="not_found")
        if str(parse_target(target)) != dataset_target.ip:
            raise AppError(
                "Selected dataset target does not match the scan target",
                code="dataset_target_mismatch",
            )
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
    if dataset_target:
        db.add(ScanDatasetLink(scan_id=job.id, target_id=dataset_target.id))
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

    if runner is not None:
        thread = threading.Thread(target=_run_job, args=(job.id, runner), daemon=True)
        thread.start()
        return job

    status = nmap_status()
    if status.get("mode") == "kali_agent":
        logger.info("Scan job %s queued for remote Kali agent execution", job.id)
        return job

    thread = threading.Thread(target=_run_job, args=(job.id, None), daemon=True)
    thread.start()
    return job


def _run_job(scan_id: str, runner: Runner | None) -> None:
    from backend.app.db.session import get_session_factory

    db = get_session_factory()()
    try:
        job = db.query(ScanJob).filter_by(id=scan_id).one()
        if job.status == "cancelled":
            return
        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        db.commit()
        settings = get_settings()
        xml_path = Path(job.xml_path)
        try:
            if runner is None:
                code, stdout, stderr = _run_nmap_process(
                    scan_id, job.argv, xml_path, settings.scan_timeout_seconds
                )
            else:
                code, stdout, stderr = runner(job.argv, xml_path, settings.scan_timeout_seconds)
        except subprocess.TimeoutExpired:
            db.refresh(job)
            if job.status == "cancelled":
                return
            job.status = "timeout"
            job.error = f"Scan exceeded {settings.scan_timeout_seconds}s"
            job.finished_at = datetime.now(timezone.utc)
            db.commit()
            return
        except Exception as exc:  # noqa: BLE001 — persist actual runner failure
            db.refresh(job)
            if job.status == "cancelled":
                return
            job.status = "error"
            job.error = str(exc)
            job.finished_at = datetime.now(timezone.utc)
            db.commit()
            return

        db.refresh(job)
        if job.status == "cancelled":
            return
        job.finished_at = datetime.now(timezone.utc)
        if job.started_at:
            started = job.started_at if job.started_at.tzinfo else job.started_at.replace(tzinfo=timezone.utc)
            finished = job.finished_at if job.finished_at.tzinfo else job.finished_at.replace(tzinfo=timezone.utc)
            job.duration_seconds = max(0.0, (finished - started).total_seconds())
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
        job.error = _scan_result_error(parsed)
        job.status = "error" if parsed.get("exit") not in {None, "success"} else "completed"
        job.progress_pct = 100
        db.commit()
        try:
            import asyncio

            asyncio.run(event_bus.publish({"type": "scan.completed", "scan_id": job.id}))
        except Exception:
            logger.exception("Scan completed but completion event publication failed")
    finally:
        with _PROCESS_LOCK:
            _RUNNING_PROCESSES.pop(scan_id, None)
            _CANCELLED_SCANS.discard(scan_id)
        db.close()


def _run_nmap_process(
    scan_id: str, argv: list[str], xml_path: Path, timeout: int
) -> tuple[int, str, str]:
    with _PROCESS_LOCK:
        if scan_id in _CANCELLED_SCANS:
            return -1, "", ""
        process = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(xml_path.parent),
        )
        _RUNNING_PROCESSES[scan_id] = process
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise
    finally:
        with _PROCESS_LOCK:
            _RUNNING_PROCESSES.pop(scan_id, None)
    return process.returncode, stdout, stderr


def cancel_scan(db: Session, scan_id: str) -> ScanJob:
    job = db.query(ScanJob).filter(ScanJob.id == scan_id, ScanJob.data_source != "demo").one_or_none()
    if not job:
        raise AppError("Scan not found", status_code=404, code="not_found")
    if job.status in {"completed", "error", "timeout", "cancelled", "dry_run"}:
        return job
    job.status = "cancelled"
    job.error = "Cancelled by operator"
    job.finished_at = datetime.now(timezone.utc)
    db.commit()
    with _PROCESS_LOCK:
        _CANCELLED_SCANS.add(scan_id)
        process = _RUNNING_PROCESSES.get(scan_id)
    if process is not None and process.poll() is None:
        try:
            process.terminate()
        except ProcessLookupError:
            pass
    return job


def import_xml(
    db: Session, content: bytes, filename: str, data_source: str = "manual_import"
) -> tuple[ScanJob, bool]:
    parsed = parse_nmap_xml(content)
    target_ips = {host["ip"] for host in parsed["hosts"] if host.get("ip")}
    target_ips.update(_target_ips_from_args(parsed.get("args")))
    if not target_ips:
        raise AppError(
            "Nmap XML contains no target IPs to validate",
            status_code=400,
            code="missing_scan_targets",
        )
    for target_ip in sorted(target_ips):
        assert_authorized(db, target_ip)

    digest = hashlib.sha256(content).hexdigest()
    existing_import = db.query(ScanImport).filter_by(digest=digest).one_or_none()
    if existing_import:
        existing_job = db.query(ScanJob).filter_by(id=existing_import.scan_id).one_or_none()
        if existing_job:
            _link_dataset_targets(db, existing_job, target_ips)
            db.commit()
            return existing_job, True

    scan_id = str(uuid.uuid4())
    settings = get_settings()
    out_dir = settings.data_dir / "scans" / scan_id
    out_dir.mkdir(parents=True, exist_ok=True)
    xml_path = out_dir / "scan.xml"
    json_path = out_dir / "scan.json"
    now = datetime.now(timezone.utc)
    started_at = _xml_timestamp(parsed.get("start")) or now
    finished_at = _xml_timestamp(parsed.get("finished_time")) or now
    if finished_at < started_at:
        started_at = now
        finished_at = now
    job = ScanJob(
        id=scan_id,
        profile="manual_import",
        targets=", ".join(sorted(target_ips)),
        status="error" if parsed.get("exit") not in {None, "success"} else "completed",
        argv=[],
        dry_run=False,
        data_source=data_source,
        xml_path=str(xml_path),
        json_path=str(json_path),
        progress_pct=100,
        started_at=started_at,
        finished_at=finished_at,
        nmap_version=parsed.get("version"),
        duration_seconds=parsed.get("elapsed"),
        error=_scan_result_error(parsed),
    )
    scanner_args = parsed.get("args")
    try:
        xml_path.write_bytes(content)
        json_path.write_text(json.dumps(parsed, indent=2), encoding="utf-8")
        db.add(job)
        db.flush()
        _link_dataset_targets(db, job, {host["ip"] for host in parsed["hosts"] if host.get("ip")})
        db.add(
            ScanImport(
                digest=digest,
                scan_id=job.id,
                scanner_args=scanner_args[:2048] if scanner_args else None,
                source_name=Path(filename).name[:256],
            )
        )
        persist_parsed_scan(db, job, parsed, data_source)
        db.commit()
        db.refresh(job)
        return job, False
    except IntegrityError:
        db.rollback()
        for artifact in (xml_path, json_path):
            artifact.unlink(missing_ok=True)
        out_dir.rmdir()
        duplicate = db.query(ScanImport).filter_by(digest=digest).one_or_none()
        if duplicate:
            existing_job = db.query(ScanJob).filter_by(id=duplicate.scan_id).one_or_none()
            if existing_job:
                return existing_job, True
        raise
    except Exception:
        db.rollback()
        for artifact in (xml_path, json_path):
            artifact.unlink(missing_ok=True)
        out_dir.rmdir()
        raise


def _xml_timestamp(value: str | float | None) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _target_ips_from_args(args: str | None) -> set[str]:
    if not args:
        return set()
    try:
        tokens = shlex.split(args)
    except ValueError as exc:
        raise AppError("Nmap XML contains malformed command metadata", code="invalid_scan_metadata") from exc
    if any(token in {"-iL", "--input-file", "-iR"} for token in tokens):
        raise AppError(
            "Nmap XML using an external or random target list cannot be allowlist-validated",
            code="unverifiable_scan_targets",
        )

    takes_value = {
        "-D",
        "-e",
        "-g",
        "-iL",
        "-oA",
        "-oG",
        "-oN",
        "-oX",
        "-p",
        "-S",
        "--data",
        "--data-string",
        "--decoy",
        "--exclude",
        "--excludefile",
        "--interface",
        "--ports",
        "--source-ip",
        "--source-port",
        "--stylesheet",
    }
    targets: set[str] = set()
    skip_value = False
    for token in tokens:
        if skip_value:
            skip_value = False
            continue
        if token in takes_value:
            skip_value = True
            continue
        if token.startswith("-") or not token:
            continue
        for candidate in token.split(","):
            try:
                parsed_target = ipaddress.ip_network(candidate, strict=False)
            except ValueError:
                continue
            targets.add(str(parsed_target.network_address) if parsed_target.prefixlen == parsed_target.max_prefixlen else str(parsed_target))
    return targets


def _scan_result_error(parsed: dict) -> str | None:
    if parsed.get("exit") not in {None, "success"}:
        return f"Nmap reported exit={parsed['exit']}"
    if (parsed.get("hosts_up") or 0) == 0 and (parsed.get("hosts_down") or 0) > 0:
        return "Nmap completed but reported no scanned hosts up; the target may be unreachable or filtered"
    return None


def _link_dataset_targets(db: Session, scan: ScanJob, target_ips: set[str]) -> None:
    if not target_ips:
        return
    existing_ids = {link.target_id for link in scan.dataset_links}
    targets = db.query(DatasetTarget).filter(DatasetTarget.ip.in_(target_ips)).all()
    for target in targets:
        if target.id not in existing_ids:
            db.add(ScanDatasetLink(scan_id=scan.id, target_id=target.id))


def poll_agent_job(db: Session) -> dict | None:
    job = (
        db.query(ScanJob)
        .filter(ScanJob.status == "queued", ScanJob.dry_run == False)  # noqa: E712
        .order_by(ScanJob.created_at.asc())
        .first()
    )
    if not job:
        return None
    job.status = "running"
    job.started_at = datetime.now(timezone.utc)
    db.commit()
    settings = get_settings()
    return {
        "job_id": job.id,
        "profile": job.profile,
        "target": job.targets,
        "timeout": settings.scan_timeout_seconds,
        "argv": job.argv,
    }


def complete_agent_job(
    db: Session,
    *,
    job_id: str,
    return_code: int,
    stdout: str,
    stderr: str,
    xml_content: str,
) -> ScanJob:
    job = db.query(ScanJob).filter_by(id=job_id).one_or_none()
    if not job:
        raise AppError("Scan job not found", status_code=404, code="not_found")
    if job.status == "cancelled":
        return job

    now = datetime.now(timezone.utc)
    job.finished_at = now
    if job.started_at:
        started = job.started_at if job.started_at.tzinfo else job.started_at.replace(tzinfo=timezone.utc)
        finished = job.finished_at if job.finished_at.tzinfo else job.finished_at.replace(tzinfo=timezone.utc)
        job.duration_seconds = max(0.0, (finished - started).total_seconds())

    xml_path = Path(job.xml_path)
    json_path = Path(job.json_path)

    if not xml_content and return_code != 0:
        job.status = "error"
        job.error = stderr or stdout or f"nmap exited {return_code}"
        db.commit()
        return job

    if not xml_content:
        job.status = "error"
        job.error = "Kali agent did not produce XML output"
        db.commit()
        return job

    try:
        xml_bytes = xml_content.encode("utf-8")
        parsed = parse_nmap_xml(xml_bytes)
    except Exception as exc:
        job.status = "error"
        job.error = f"Failed to parse Nmap XML from Kali agent: {exc}"
        db.commit()
        return job

    target_ips = {host["ip"] for host in parsed.get("hosts", []) if host.get("ip")}
    for tip in target_ips:
        assert_authorized(db, tip)

    xml_path.write_text(xml_content, encoding="utf-8")
    json_path.write_text(json.dumps(parsed, indent=2), encoding="utf-8")
    persist_parsed_scan(db, job, parsed, "live")
    job.error = _scan_result_error(parsed)
    job.status = "error" if parsed.get("exit") not in {None, "success"} else "completed"
    job.progress_pct = 100
    _link_dataset_targets(db, job, target_ips)
    db.commit()
    db.refresh(job)

    try:
        import asyncio

        asyncio.run(event_bus.publish({"type": "scan.completed", "scan_id": job.id}))
    except Exception:
        logger.exception("Event publication failed for agent scan completion")

    return job


def _ensure_dataset_seeded(db: Session) -> None:
    try:
        if db.query(DatasetTarget).first() is not None:
            return
        settings = get_settings()
        csv_file = settings.root / "dataset" / "targets.csv"
        if not csv_file.exists():
            return
        import_target_dataset(db, csv_file.read_bytes(), "dataset/targets.csv")
    except Exception as exc:
        logger.debug("Dataset auto-seeding skipped: %s", exc)


def import_target_dataset(db: Session, content: bytes, filename: str) -> list[DatasetTarget]:
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise AppError("Target CSV must be UTF-8 encoded", code="invalid_dataset") from exc
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise AppError("Target CSV must include an ip or ip_address column", code="invalid_dataset")
    columns = {column.strip().lower(): column for column in reader.fieldnames if column}
    ip_column = (
        columns.get("ip")
        or columns.get("ip_address")
        or columns.get("host")
        or columns.get("target")
    )
    name_column = (
        columns.get("target_name")
        or columns.get("name")
        or columns.get("label")
        or columns.get("hostname")
        or columns.get("description")
    )
    if not ip_column:
        raise AppError("Target CSV must include an ip or ip_address column", code="invalid_dataset")

    records: dict[str, str | None] = {}
    for line_number, row in enumerate(reader, start=2):
        raw_ip = (row.get(ip_column) or "").strip()
        if not raw_ip:
            continue
        try:
            ip = str(ipaddress.ip_address(raw_ip))
        except ValueError as exc:
            raise AppError(
                f"Invalid IP address on CSV line {line_number}",
                code="invalid_dataset",
            ) from exc
        assert_authorized(db, ip)
        name = (row.get(name_column) or "").strip() if name_column else ""
        records[ip] = name[:256] or None
        if len(records) > 10000:
            raise AppError("Target CSV cannot contain more than 10000 unique IPs", code="invalid_dataset")
    if not records:
        raise AppError("Target CSV contains no IP addresses", code="invalid_dataset")

    for ip, name in records.items():
        target = db.query(DatasetTarget).filter_by(ip=ip).one_or_none()
        if target:
            target.name = name
            target.source_name = Path(filename).name[:256]
        else:
            db.add(DatasetTarget(ip=ip, name=name, source_name=Path(filename).name[:256]))
    db.commit()
    return db.query(DatasetTarget).order_by(DatasetTarget.ip).all()


def authorized_dataset_targets(db: Session) -> list[DatasetTarget]:
    _ensure_dataset_seeded(db)
    rows = db.query(DatasetTarget).order_by(DatasetTarget.ip).all()
    authorized = []
    for row in rows:
        try:
            assert_authorized(db, row.ip)
        except AppError as exc:
            if exc.code != "unauthorized_target":
                raise
        else:
            authorized.append(row)
    return authorized
