import hmac

from fastapi import APIRouter

from backend.app.core.config import get_settings
from backend.app.core.errors import AppError
from backend.app.schemas.api import LoginRequest

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login")
def login(body: LoginRequest):
    settings = get_settings()
    user_ok = hmac.compare_digest(body.username, settings.username)
    pass_ok = hmac.compare_digest(body.password, settings.password)
    if not (user_ok and pass_ok):
        raise AppError("Invalid credentials", status_code=401, code="unauthorized")
    return {"token": settings.api_token, "token_type": "bearer"}
