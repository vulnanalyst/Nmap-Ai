import hmac
from typing import Annotated

from fastapi import Depends, Header

from backend.app.core.config import get_settings
from backend.app.core.errors import AppError


def require_token(
    x_api_key: Annotated[str | None, Header()] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> str:
    settings = get_settings()
    presented = x_api_key
    if not presented and authorization and authorization.lower().startswith("bearer "):
        presented = authorization.split(" ", 1)[1].strip()
    if not presented or not hmac.compare_digest(presented, settings.api_token):
        raise AppError("Authentication required", status_code=401, code="unauthorized")
    return presented
