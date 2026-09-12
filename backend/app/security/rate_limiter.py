"""
CIPHER AI - Authentication Rate Limiter & Abuse Protection
In-memory sliding-window failure tracker protecting against brute-force credential stuffing,
registration flooding, and refresh token abuse.
"""

from collections import defaultdict
import time
from typing import Dict, List, Optional
from fastapi import HTTPException, status

from app.config import get_settings

settings = get_settings()


class LoginRateLimiter:
    """Tracks failed login attempts in a sliding time window per client identifier."""

    def __init__(self):
        self._failures: Dict[str, List[float]] = defaultdict(list)

    def _prune(self, key: str, now: float) -> None:
        """Removes timestamps outside the current sliding window."""
        window_start = now - settings.AUTH_RATE_LIMIT_WINDOW_SECONDS
        self._failures[key] = [ts for ts in self._failures[key] if ts > window_start]
        if not self._failures[key]:
            self._failures.pop(key, None)

    def check_rate_limit(self, key: str) -> None:
        """
        Checks if the client has exceeded allowed failed attempts.
        Raises HTTP 429 Too Many Requests if rate limit exceeded.
        """
        now = time.time()
        self._prune(key, now)
        if len(self._failures[key]) >= settings.AUTH_RATE_LIMIT_MAX_ATTEMPTS:
            retry_after = int(settings.AUTH_RATE_LIMIT_WINDOW_SECONDS - (now - self._failures[key][0]))
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed authentication attempts. Account access temporarily throttled. Please try again later.",
                headers={"Retry-After": str(max(retry_after, 1))},
            )

    def record_failure(self, key: str) -> None:
        """Records a failed authentication attempt."""
        now = time.time()
        self._prune(key, now)
        self._failures[key].append(now)

    def record_success(self, key: str) -> None:
        """Clears failure count upon successful authentication."""
        self._failures.pop(key, None)

    def reset_all(self) -> None:
        """Resets all tracked failures (used in tests)."""
        self._failures.clear()


class SlidingWindowRateLimiter:
    """Generic sliding-window rate limiter per client IP or key."""

    def __init__(self, default_limit: int = 20, default_window: int = 60, action: str = "request"):
        self._history: Dict[str, List[float]] = defaultdict(list)
        self.default_limit = default_limit
        self.default_window = default_window
        self.action = action

    def _prune(self, key: str, now: float, window: int) -> None:
        window_start = now - window
        self._history[key] = [ts for ts in self._history[key] if ts > window_start]
        if not self._history[key]:
            self._history.pop(key, None)

    def check_and_record(
        self,
        key: str,
        limit: Optional[int] = None,
        window: Optional[int] = None,
        action: Optional[str] = None,
    ) -> None:
        """
        Checks if the key has exceeded max requests in the sliding window.
        If allowed, records this request timestamp.
        Raises HTTP 429 if limit exceeded.
        """
        now = time.time()
        max_limit = limit or self.default_limit
        win = window or self.default_window
        act = action or self.action

        self._prune(key, now, win)
        if len(self._history[key]) >= max_limit:
            retry_after = int(win - (now - self._history[key][0]))
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many {act} attempts. Rate limit exceeded. Please try again in {max(retry_after, 1)} seconds.",
                headers={"Retry-After": str(max(retry_after, 1))},
            )
        self._history[key].append(now)

    def reset_all(self) -> None:
        """Resets all tracked history (used in tests)."""
        self._history.clear()


login_rate_limiter = LoginRateLimiter()
registration_rate_limiter = SlidingWindowRateLimiter(default_limit=10, default_window=300, action="registration")
refresh_rate_limiter = SlidingWindowRateLimiter(default_limit=30, default_window=300, action="session refresh")
