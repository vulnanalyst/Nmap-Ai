from fastapi import APIRouter

from backend.app import __version__
from backend.app.core.config import get_settings
from backend.app.db.session import get_engine
from backend.app.services.scan_service import nmap_status

router = APIRouter(tags=["health"])


@router.get("/health")
def health():
    return {"status": "ok", "version": __version__}


@router.get("/ready")
def ready():
    settings = get_settings()
    db_ok = True
    try:
        get_engine().connect().close()
    except Exception as exc:  # noqa: BLE001
        db_ok = False
        return {"status": "degraded", "database": str(exc), "nmap": nmap_status()}
    return {
        "status": "ready" if db_ok else "degraded",
        "database": settings.sqlite_url,
        "bind": f"{settings.host}:{settings.port}",
        "nmap": nmap_status(),
    }
