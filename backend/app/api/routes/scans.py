from pathlib import Path

from fastapi import APIRouter, File, UploadFile
from fastapi.responses import FileResponse

from backend.app.api.deps import AuthDep, DbDep
from backend.app.core.errors import AppError
from backend.app.models import ScanJob
from backend.app.schemas.api import ScanRequest
from backend.app.services.nmap_parser import NmapParseError
from backend.app.services.scan_service import cancel_scan, import_xml, nmap_status, preview_scan, start_scan

router = APIRouter(prefix="/scans", tags=["scans"])


def _job(job: ScanJob) -> dict:
    return {
        "id": job.id,
        "profile": job.profile,
        "targets": job.targets,
        "status": job.status,
        "argv": job.argv,
        "dry_run": job.dry_run,
        "progress_pct": job.progress_pct,
        "error": job.error,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
        "duration_seconds": job.duration_seconds,
        "xml_path": job.xml_path,
        "json_path": job.json_path,
        "data_source": job.data_source,
        "ports_open": job.ports_open,
        "ports_closed": job.ports_closed,
        "ports_filtered": job.ports_filtered,
        "hosts_up": job.hosts_up,
        "hosts_down": job.hosts_down,
        "nmap_version": job.nmap_version,
    }


@router.get("/profiles")
def profiles(_: AuthDep):
    return {
        "profiles": [
            {"id": "host_discovery", "label": "Host discovery", "flags": ["-sn"]},
            {"id": "tcp_connect", "label": "TCP connect", "flags": ["-sT"]},
            {"id": "service_version", "label": "Service/version detection", "flags": ["-sT", "-sV"]},
            {"id": "os_fingerprint", "label": "OS fingerprinting (guess)", "flags": ["-sT", "-O"]},
            {"id": "vuln_safe", "label": "Cautious safe-script checks", "flags": ["-sT", "-sV", "--script", "safe"]},
        ],
        "nmap": nmap_status(),
    }


@router.post("/preview")
def preview(_: AuthDep, body: ScanRequest):
    return preview_scan(body.profile, body.target)


@router.post("")
def create_scan(_: AuthDep, db: DbDep, body: ScanRequest):
    job = start_scan(
        db,
        profile=body.profile,
        target=body.target,
        confirm_target=body.confirm_target,
        confirm_authorization=body.confirm_authorization,
        dry_run=body.dry_run,
    )
    return _job(job)


@router.get("")
def list_scans(_: AuthDep, db: DbDep):
    rows = db.query(ScanJob).order_by(ScanJob.created_at.desc()).all()
    return {"items": [_job(j) for j in rows]}


@router.get("/{scan_id}")
def get_scan(_: AuthDep, db: DbDep, scan_id: str):
    job = db.query(ScanJob).filter_by(id=scan_id).one_or_none()
    if not job:
        raise AppError("Scan not found", status_code=404, code="not_found")
    return _job(job)


@router.post("/{scan_id}/cancel")
def cancel(_: AuthDep, db: DbDep, scan_id: str):
    return _job(cancel_scan(db, scan_id))


@router.get("/{scan_id}/xml")
def xml(_: AuthDep, db: DbDep, scan_id: str):
    job = db.query(ScanJob).filter_by(id=scan_id).one_or_none()
    if not job or not job.xml_path or not Path(job.xml_path).exists():
        raise AppError("XML artifact not found", status_code=404, code="not_found")
    return FileResponse(job.xml_path, media_type="application/xml", filename="scan.xml")


@router.get("/{scan_id}/json")
def json_art(_: AuthDep, db: DbDep, scan_id: str):
    job = db.query(ScanJob).filter_by(id=scan_id).one_or_none()
    if not job or not job.json_path or not Path(job.json_path).exists():
        raise AppError("JSON artifact not found", status_code=404, code="not_found")
    return FileResponse(job.json_path, media_type="application/json", filename="scan.json")


@router.post("/import")
async def import_scan(_: AuthDep, db: DbDep, file: UploadFile = File(...)):
    content = await file.read()
    try:
        job = import_xml(db, content, file.filename or "upload.xml", data_source="import")
    except NmapParseError as exc:
        raise AppError(str(exc), status_code=400, code="xml_parse_error") from exc
    return _job(job)
