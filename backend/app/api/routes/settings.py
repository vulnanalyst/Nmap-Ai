from fastapi import APIRouter

from backend.app.api.deps import AuthDep, DbDep
from backend.app.core.errors import AppError
from backend.app.schemas.api import SettingsPatch, TargetCreate
from backend.app.services.settings_service import add_target, get_all, upsert
from backend.app.models import AuthorizedTarget

router = APIRouter(prefix="/settings", tags=["settings"])


@router.get("")
def read_settings(_: AuthDep, db: DbDep):
    return get_all(db)


@router.patch("")
def patch_settings(_: AuthDep, db: DbDep, body: SettingsPatch):
    try:
        for key, value in body.values.items():
            upsert(db, key, value)
    except ValueError as exc:
        raise AppError(str(exc), status_code=400, code="invalid_setting") from exc
    db.commit()
    return get_all(db)


@router.post("/targets")
def create_target(_: AuthDep, db: DbDep, body: TargetCreate):
    row = add_target(db, body.cidr, body.label)
    db.commit()
    return {"id": row.id, "cidr": row.cidr, "label": row.label}


@router.delete("/targets/{target_id}")
def delete_target(_: AuthDep, db: DbDep, target_id: int):
    row = db.query(AuthorizedTarget).filter_by(id=target_id).one_or_none()
    if not row:
        raise AppError("Target not found", status_code=404, code="not_found")
    db.delete(row)
    db.commit()
    return {"ok": True}


@router.post("/demo/seed")
def seed_demo(_: AuthDep, db: DbDep):
    from backend.app.demo.fixtures import seed_demo_data

    return seed_demo_data(db)


@router.delete("/demo/seed")
def clear_demo(_: AuthDep, db: DbDep):
    from backend.app.demo.fixtures import clear_demo_data

    return clear_demo_data(db)

