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
    try:
        get_engine().connect().close()
    except Exception:  # noqa: BLE001
        return {"status": "degraded", "database": "unavailable", "nmap": nmap_status()}
    return {
        "status": "ready",
        "database": "available",
        "bind": f"{settings.host}:{settings.port}",
        "nmap": nmap_status(),
    }
