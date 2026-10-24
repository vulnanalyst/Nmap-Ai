from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse

from backend.app.api.deps import AuthDep, DbDep
from backend.app.core.errors import AppError
from backend.app.models import ReportRecord
from backend.app.services.reporting_service import build_report

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("")
def create_report(_: AuthDep, db: DbDep):
    rec = build_report(db)
    return {"id": rec.id, "json_path": rec.json_path, "pdf_path": rec.pdf_path, "created_at": rec.created_at.isoformat()}


@router.get("")
def list_reports(_: AuthDep, db: DbDep):
    rows = (
        db.query(ReportRecord)
        .filter(ReportRecord.data_source != "demo")
        .order_by(ReportRecord.created_at.desc())
        .all()
    )
    return {
        "items": [
            {"id": r.id, "title": r.title, "created_at": r.created_at.isoformat(), "scope": r.scope}
            for r in rows
        ]
    }


@router.get("/{report_id}/json")
def json_report(_: AuthDep, db: DbDep, report_id: str):
    rec = db.query(ReportRecord).filter(ReportRecord.id == report_id, ReportRecord.data_source != "demo").one_or_none()
    if not rec or not Path(rec.json_path).exists():
        raise AppError("Report not found", status_code=404, code="not_found")
    return FileResponse(rec.json_path, media_type="application/json")


@router.get("/{report_id}/pdf")
def pdf_report(_: AuthDep, db: DbDep, report_id: str):
    rec = db.query(ReportRecord).filter(ReportRecord.id == report_id, ReportRecord.data_source != "demo").one_or_none()
    if not rec or not rec.pdf_path or not Path(rec.pdf_path).exists():
        raise AppError("PDF not found", status_code=404, code="not_found")
    return FileResponse(rec.pdf_path, media_type="application/pdf")
