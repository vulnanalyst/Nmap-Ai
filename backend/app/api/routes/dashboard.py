from fastapi import APIRouter

from backend.app.api.deps import AuthDep, DbDep
from backend.app.services.summary_service import dashboard_summary

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary")
def summary(_: AuthDep, db: DbDep):
    return dashboard_summary(db)
