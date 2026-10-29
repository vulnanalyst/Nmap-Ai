import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Annotated

from fastapi import Header

from backend.app.core.config import get_settings
from backend.app.core.errors import AppError


def hash_password(password: str) -> str:
    """Hash a password using scrypt with a cryptographically secure random 16-byte salt."""
    salt = secrets.token_bytes(16)
    key = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1)
    return f"scrypt$16384$8$1${salt.hex()}${key.hex()}"


def verify_password(plain_password: str, stored_hash_or_plain: str) -> bool:
    """Verify password against scrypt hash, PBKDF2-HMAC-SHA256, or constant-time plaintext fallback."""
    if not plain_password or not stored_hash_or_plain:
        return False

    if stored_hash_or_plain.startswith("scrypt$"):
        try:
            parts = stored_hash_or_plain.split("$")
            if len(parts) != 6:
                return False
            _, n_str, r_str, p_str, salt_hex, key_hex = parts
            n, r, p = int(n_str), int(r_str), int(p_str)
            salt = bytes.fromhex(salt_hex)
            expected_key = bytes.fromhex(key_hex)
            computed = hashlib.scrypt(plain_password.encode("utf-8"), salt=salt, n=n, r=r, p=p)
            return hmac.compare_digest(computed, expected_key)
        except Exception:
            return False

    if stored_hash_or_plain.startswith("pbkdf2:sha256:"):
        try:
            parts = stored_hash_or_plain.split("$")
            if len(parts) != 3:
                return False
            prefix, salt_str, hash_hex = parts
            iterations = int(prefix.split(":")[-1])
            salt = salt_str.encode("utf-8")
            expected_hash = bytes.fromhex(hash_hex)
            computed = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, iterations)
            return hmac.compare_digest(computed, expected_hash)
        except Exception:
            return False

    # Constant-time comparison for legacy plaintext configuration
    return hmac.compare_digest(plain_password, stored_hash_or_plain)


class SessionManager:
    """Thread-safe in-memory session manager with TTL and token revocation."""

    def __init__(self, session_ttl_hours: int = 24):
        self.session_ttl = timedelta(hours=session_ttl_hours)
        self._sessions: dict[str, dict] = {}
        self._revoked_tokens: set[str] = set()
        self._lock = Lock()

    def create_session(self, username: str) -> str:
        token = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        with self._lock:
            self._sessions[token] = {
                "username": username,
                "created_at": now,
                "last_active": now,
                "revoked": False,
            }
        return token

    def validate_session(self, token: str) -> dict | None:
        now = datetime.now(timezone.utc)
        with self._lock:
            if token in self._revoked_tokens:
                return None
            session = self._sessions.get(token)
            if not session:
                return None
            if session.get("revoked", False):
                return None
            if now - session["last_active"] > self.session_ttl:
                del self._sessions[token]
                return None
            session["last_active"] = now
            return session

    def is_revoked(self, token: str) -> bool:
        with self._lock:
            return token in self._revoked_tokens

    def revoke_session(self, token: str) -> bool:
        with self._lock:
            self._revoked_tokens.add(token)
            if token in self._sessions:
                self._sessions[token]["revoked"] = True
                del self._sessions[token]
            return True

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()
            self._revoked_tokens.clear()


session_manager = SessionManager(session_ttl_hours=24)


def require_token(
    x_api_key: Annotated[str | None, Header()] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> str:
    settings = get_settings()
    presented = x_api_key
    if not presented and authorization and authorization.lower().startswith("bearer "):
        presented = authorization.split(" ", 1)[1].strip()

    if not presented:
        raise AppError("Authentication required", status_code=401, code="unauthorized")

    # If the token has been explicitly revoked via logout, reject it
    if session_manager.is_revoked(presented):
        raise AppError("Token has been revoked", status_code=401, code="unauthorized")

    # 1. Check against dynamic active sessions (for interactive users)
    session = session_manager.validate_session(presented)
    if session:
        return presented

    # 2. Check against static system API token (for automation/scanner agents)
    if hmac.compare_digest(presented, settings.api_token):
        return presented

    raise AppError("Authentication required", status_code=401, code="unauthorized")
