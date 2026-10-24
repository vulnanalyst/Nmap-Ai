from fastapi import APIRouter, Query

from backend.app.api.deps import AuthDep, DbDep
from backend.app.core.errors import AppError
from backend.app.models import Finding
from backend.app.schemas.api import FindingPatch

router = APIRouter(prefix="/findings", tags=["findings"])


def _row(f: Finding) -> dict:
    return {
        "id": f.id,
        "host_ip": f.host_ip,
        "port": f.port,
        "protocol": f.protocol,
        "service_name": f.service_name,
        "product": f.product,
        "version": f.version,
        "title": f.title,
        "cve": f.cve,
        "cvss": f.cvss,
        "severity": f.severity,
        "evidence": f.evidence,
        "detection_source": f.detection_source,
        "confidence": f.confidence,
        "validation_status": f.validation_status,
        "impact": f.impact,
        "remediation": f.remediation,
        "reference_url": f.reference_url,
        "first_observed": f.first_observed.isoformat() if f.first_observed else None,
        "last_observed": f.last_observed.isoformat() if f.last_observed else None,
        "workflow_status": f.workflow_status,
        "risk_score": f.risk_score,
        "risk_breakdown": f.risk_breakdown,
        "data_source": f.data_source,
    }


@router.get("")
def list_findings(
    _: AuthDep,
    db: DbDep,
    severity: str | None = None,
    validation_status: str | None = None,
    q: str | None = Query(None),
    cve: str | None = None,
    include_demo: bool = False,
):
    query = db.query(Finding)
    if not include_demo:
        query = query.filter(Finding.data_source != "demo")
    if severity:
        query = query.filter(Finding.severity == severity)
    if validation_status:
        query = query.filter(Finding.validation_status == validation_status)
    if cve:
        query = query.filter(Finding.cve == cve.upper())
    if q:
        like = f"%{q}%"
        query = query.filter(Finding.title.ilike(like) | Finding.host_ip.ilike(like))
    rows = query.order_by(Finding.last_observed.desc()).all()
    return {"items": [_row(f) for f in rows], "count": len(rows)}


@router.get("/{finding_id}")
def get_finding(_: AuthDep, db: DbDep, finding_id: str):
    row = db.query(Finding).filter_by(id=finding_id).one_or_none()
    if not row:
        raise AppError("Finding not found", status_code=404, code="not_found")
    return _row(row)


@router.patch("/{finding_id}")
def patch_finding(_: AuthDep, db: DbDep, finding_id: str, body: FindingPatch):
    row = db.query(Finding).filter_by(id=finding_id).one_or_none()
    if not row:
        raise AppError("Finding not found", status_code=404, code="not_found")
    row.workflow_status = body.workflow_status
    db.commit()
    db.refresh(row)
    return _row(row)
