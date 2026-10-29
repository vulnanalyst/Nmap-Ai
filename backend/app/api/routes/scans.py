from pathlib import Path

from fastapi import APIRouter, File, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy.orm import joinedload

from backend.app.api.deps import AuthDep, DbDep
from backend.app.core.events import event_bus
from backend.app.core.errors import AppError
from backend.app.models import DatasetTarget, Finding, Host, ScanDatasetLink, ScanJob
from backend.app.schemas.api import AgentHeartbeat, AgentScanCompleteRequest, ScanRequest
from backend.app.services.nmap_parser import NmapParseError
from backend.app.services.scan_service import (
    authorized_dataset_targets,
    cancel_scan,
    complete_agent_job,
    import_target_dataset,
    import_xml,
    nmap_status,
    poll_agent_job,
    preview_scan,
    record_agent_heartbeat,
    start_scan,
    _ensure_dataset_seeded,
)
from backend.app.services.targets import is_authorized, load_allowlist

router = APIRouter(prefix="/scans", tags=["scans"])
MAX_XML_UPLOAD_BYTES = 20 * 1024 * 1024
MAX_TARGET_DATASET_BYTES = 2 * 1024 * 1024


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
        "scanner_args": job.import_record.scanner_args if job.import_record else None,
        "source_name": job.import_record.source_name if job.import_record else None,
        "dataset_targets": [
            {
                "id": link.target.id,
                "ip": link.target.ip,
                "name": link.target.name,
                "source_name": link.target.source_name,
            }
            for link in job.dataset_links
        ],
        "scan_source": (
            "manual/imported"
            if job.data_source in {"manual_import", "import"} or job.profile == "import"
            else "Nmap-AI"
        ),
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
        dataset_target_id=body.dataset_target_id,
    )
    return _job(job)


@router.get("")
def list_scans(_: AuthDep, db: DbDep):
    rows = (
        db.query(ScanJob)
        .options(
            joinedload(ScanJob.import_record),
            joinedload(ScanJob.dataset_links).joinedload(ScanDatasetLink.target),
        )
        .filter(ScanJob.data_source != "demo")
        .order_by(ScanJob.created_at.desc())
        .all()
    )
    return {"items": [_job(j) for j in rows]}


@router.get("/targets")
def list_dataset_targets(_: AuthDep, db: DbDep, all: bool = False):
    _ensure_dataset_seeded(db)
    allowlist = load_allowlist(db)
    all_targets = db.query(DatasetTarget).order_by(DatasetTarget.ip).all()
    items = []
    for row in all_targets:
        auth = is_authorized(row.ip, allowlist)
        if not all and not auth:
            continue
        items.append({
            "id": row.id,
            "ip": row.ip,
            "name": row.name,
            "source_name": row.source_name,
            "authorized": auth,
        })
    return {"items": items}


@router.post("/targets/import")
async def import_targets(_: AuthDep, db: DbDep, file: UploadFile = File(...)):
    content = await file.read(MAX_TARGET_DATASET_BYTES + 1)
    if len(content) > MAX_TARGET_DATASET_BYTES:
        raise AppError(
            f"Target CSV exceeds the {MAX_TARGET_DATASET_BYTES // (1024 * 1024)} MB limit",
            status_code=413,
            code="upload_too_large",
        )
    rows = import_target_dataset(db, content, file.filename or "targets.csv")
    return {
        "items": [
            {"id": row.id, "ip": row.ip, "name": row.name, "source_name": row.source_name}
            for row in rows
        ],
        "count": len(rows),
    }


@router.post("/agent/heartbeat")
def agent_heartbeat(_: AuthDep, body: AgentHeartbeat):
    return record_agent_heartbeat(
        scanner_name=body.scanner_name,
        scanner_ip=body.scanner_ip,
        nmap_version=body.nmap_version,
        nmap_path=body.nmap_path,
    )


@router.post("/agent/poll")
def agent_poll(_: AuthDep, db: DbDep):
    job_data = poll_agent_job(db)
    return {"job": job_data}


@router.post("/agent/complete")
async def agent_complete(_: AuthDep, db: DbDep, body: AgentScanCompleteRequest):
    job = complete_agent_job(
        db,
        job_id=body.job_id,
        return_code=body.return_code,
        stdout=body.stdout,
        stderr=body.stderr,
        xml_content=body.xml_content,
    )
    return _job(job)


@router.get("/{scan_id}")
def get_scan(_: AuthDep, db: DbDep, scan_id: str):
    job = (
        db.query(ScanJob)
        .options(
            joinedload(ScanJob.import_record),
            joinedload(ScanJob.dataset_links).joinedload(ScanDatasetLink.target),
        )
        .filter(ScanJob.id == scan_id, ScanJob.data_source != "demo")
        .one_or_none()
    )
    if not job:
        raise AppError("Scan not found", status_code=404, code="not_found")
    result = _job(job)
    hosts = (
        db.query(Host)
        .options(joinedload(Host.services))
        .filter(Host.scan_id == scan_id, Host.data_source != "demo")
        .order_by(Host.ip)
        .all()
    )
    result["hosts"] = [
        {
            "ip": host.ip,
            "state": host.state,
            "hostname": host.hostname,
            "services": [
                {
                    "protocol": service.protocol,
                    "port": service.port,
                    "state": service.state,
                    "name": service.name,
                    "product": service.product,
                    "version": service.version,
                }
                for service in host.services
                if service.data_source != "demo"
            ],
        }
        for host in hosts
    ]
    return result


@router.post("/{scan_id}/cancel")
def cancel(_: AuthDep, db: DbDep, scan_id: str):
    return _job(cancel_scan(db, scan_id))


@router.get("/{scan_id}/xml")
def xml(_: AuthDep, db: DbDep, scan_id: str):
    job = db.query(ScanJob).filter(ScanJob.id == scan_id, ScanJob.data_source != "demo").one_or_none()
    if not job or not job.xml_path or not Path(job.xml_path).exists():
        raise AppError("XML artifact not found", status_code=404, code="not_found")
    return FileResponse(job.xml_path, media_type="application/xml", filename="scan.xml")


@router.get("/{scan_id}/json")
def json_art(_: AuthDep, db: DbDep, scan_id: str):
    job = db.query(ScanJob).filter(ScanJob.id == scan_id, ScanJob.data_source != "demo").one_or_none()
    if not job or not job.json_path or not Path(job.json_path).exists():
        raise AppError("JSON artifact not found", status_code=404, code="not_found")
    return FileResponse(job.json_path, media_type="application/json", filename="scan.json")


@router.post("/import")
async def import_scan(_: AuthDep, db: DbDep, file: UploadFile = File(...)):
    content = await file.read(MAX_XML_UPLOAD_BYTES + 1)
    if len(content) > MAX_XML_UPLOAD_BYTES:
        raise AppError(
            f"Nmap XML upload exceeds the {MAX_XML_UPLOAD_BYTES // (1024 * 1024)} MB limit",
            status_code=413,
            code="upload_too_large",
        )
    try:
        job, duplicate = import_xml(db, content, file.filename or "upload.xml")
    except NmapParseError as exc:
        raise AppError(str(exc), status_code=400, code="xml_parse_error") from exc
    if not duplicate:
        await event_bus.publish({"type": "scan.completed", "scan_id": job.id})
    response = _job(job)
    response.update(
        scan_id=job.id,
        duplicate=duplicate,
        findings_created=db.query(Finding).filter(Finding.scan_id == job.id).count(),
    )
    return response
