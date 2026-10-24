from fastapi import APIRouter

from backend.app.api.deps import AuthDep, DbDep
from backend.app.core.errors import AppError
from backend.app.models import Alert
from backend.app.schemas.api import AlertPatch
from backend.app.services.alert_service import add_note

router = APIRouter(prefix="/alerts", tags=["alerts"])


def _row(a: Alert) -> dict:
    return {
        "id": a.id,
        "timestamp": a.timestamp.isoformat() if a.timestamp else None,
        "src_addr": a.src_addr,
        "dst_addr": a.dst_addr,
        "src_port": a.src_port,
        "dst_port": a.dst_port,
        "protocol": a.protocol,
        "detection_method": a.detection_method,
        "rule_or_model": a.rule_or_model,
        "evidence_ref": a.evidence_ref,
        "severity": a.severity,
        "confidence": a.confidence,
        "title": a.title,
        "message": a.message,
        "status": a.status,
        "data_source": a.data_source,
        "extra": a.extra,
        "notes": [
            {"id": n.id, "author": n.author, "body": n.body, "created_at": n.created_at.isoformat() if n.created_at else None}
            for n in a.notes
        ],
    }


@router.get("")
def list_alerts(_: AuthDep, db: DbDep, status: str | None = None, method: str | None = None, include_demo: bool = False):
    q = db.query(Alert)
    if not include_demo:
        q = q.filter(Alert.data_source != "demo")
    if status:
        q = q.filter(Alert.status == status)
    if method:
        q = q.filter(Alert.detection_method == method)
    rows = q.order_by(Alert.timestamp.desc()).limit(500).all()
    return {"items": [_row(a) for a in rows], "count": len(rows)}


@router.patch("/{alert_id}")
def patch_alert(_: AuthDep, db: DbDep, alert_id: int, body: AlertPatch):
    row = db.query(Alert).filter_by(id=alert_id).one_or_none()
    if not row:
        raise AppError("Alert not found", status_code=404, code="not_found")
    if body.status:
        row.status = body.status
    if body.note:
        add_note(db, alert_id, body.note)
    db.commit()
    db.refresh(row)
    return _row(row)
