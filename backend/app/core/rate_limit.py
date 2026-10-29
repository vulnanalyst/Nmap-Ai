import time
from collections import defaultdict
from threading import Lock


class LoginRateLimiter:
    """Thread-safe rate limiter for authentication endpoints to prevent brute-force attacks."""

    def __init__(self, max_attempts: int = 5, window_seconds: int = 60, block_duration_seconds: int = 60):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.block_duration = block_duration_seconds
        self._failures: dict[str, list[float]] = defaultdict(list)
        self._blocked_until: dict[str, float] = {}
        self._lock = Lock()

    def _clean(self, now: float) -> None:
        expired_blocks = [k for k, v in self._blocked_until.items() if v <= now]
        for k in expired_blocks:
            del self._blocked_until[k]

        for k in list(self._failures.keys()):
            self._failures[k] = [t for t in self._failures[k] if now - t < self.window_seconds]
            if not self._failures[k] and k not in self._blocked_until:
                del self._failures[k]

    def check(self, key: str) -> tuple[bool, int]:
        """Returns (is_allowed, retry_after_seconds)."""
        now = time.time()
        with self._lock:
            self._clean(now)
            blocked_until = self._blocked_until.get(key, 0)
            if blocked_until > now:
                return False, max(1, int(blocked_until - now))
            return True, 0

    def record_failure(self, key: str) -> tuple[bool, int]:
        """Records a failed attempt. If threshold reached, blocks the key for block_duration."""
        now = time.time()
        with self._lock:
            self._clean(now)
            self._failures[key].append(now)
            if len(self._failures[key]) >= self.max_attempts:
                self._blocked_until[key] = now + self.block_duration
                self._failures[key].clear()
                return True, self.block_duration
            return False, 0

    def reset(self, key: str) -> None:
        """Resets failed attempts and blocks for a key upon successful authentication."""
        with self._lock:
            self._failures.pop(key, None)
            self._blocked_until.pop(key, None)

    def clear(self) -> None:
        """Clears all rate limit state."""
        with self._lock:
            self._failures.clear()
            self._blocked_until.clear()


login_rate_limiter = LoginRateLimiter(max_attempts=5, window_seconds=60, block_duration_seconds=60)
