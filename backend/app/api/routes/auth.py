import hmac

from fastapi import APIRouter, Request

from backend.app.api.deps import AuthDep
from backend.app.core.config import get_settings
from backend.app.core.errors import AppError
from backend.app.core.rate_limit import login_rate_limiter
from backend.app.core.security import session_manager, verify_password
from backend.app.schemas.api import LoginRequest

router = APIRouter(prefix="/auth", tags=["auth"])


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


@router.post("/login")
def login(body: LoginRequest, request: Request):
    ip = _client_ip(request)
    user_key = f"user:{body.username.lower()}"
    ip_key = f"ip:{ip}"

    # Rate limiting checks for brute-force protection
    ip_ok, ip_retry = login_rate_limiter.check(ip_key)
    if not ip_ok:
        raise AppError(
            f"Too many failed login attempts. Please try again in {ip_retry} seconds.",
            status_code=429,
            code="rate_limited",
            details={"retry_after": ip_retry},
        )

    user_ok_rate, user_retry = login_rate_limiter.check(user_key)
    if not user_ok_rate:
        raise AppError(
            f"Too many failed login attempts. Please try again in {user_retry} seconds.",
            status_code=429,
            code="rate_limited",
            details={"retry_after": user_retry},
        )

    settings = get_settings()
    user_ok = hmac.compare_digest(body.username, settings.username)
    target_pw = settings.password_hash or settings.password
    pass_ok = verify_password(body.password, target_pw)

    if not (user_ok and pass_ok):
        login_rate_limiter.record_failure(ip_key)
        login_rate_limiter.record_failure(user_key)
        raise AppError("Invalid credentials", status_code=401, code="unauthorized")

    # Clear rate limiter on successful authentication
    login_rate_limiter.reset(ip_key)
    login_rate_limiter.reset(user_key)

    # Issue dynamic session token
    session_token = session_manager.create_session(body.username)
    return {
        "token": session_token,
        "token_type": "bearer",
        "username": body.username,
    }


@router.post("/logout")
def logout(token: AuthDep):
    session_manager.revoke_session(token)
    return {"message": "Logged out successfully"}


@router.get("/me")
def me(token: AuthDep):
    session = session_manager.validate_session(token)
    username = session["username"] if session else get_settings().username
    return {"username": username, "authenticated": True}
