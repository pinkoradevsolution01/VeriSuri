"""Privacy-preserving request monitoring and bounded in-process abuse controls.

This is intentionally a first line of defence. Deployments must also enforce
rate limits at the CDN/WAF because serverless instances do not share memory.
No message, URL, account number, authorization token, or raw IP is logged.
"""

from __future__ import annotations

import hashlib
import logging
import time
from collections import defaultdict, deque


security_log = logging.getLogger("verisuri.security")


class RequestRateLimiter:
    def __init__(self, limit: int, window_seconds: int = 60) -> None:
        self.limit = max(1, limit)
        self.window_seconds = window_seconds
        self._requests: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, client_fingerprint: str, path: str) -> tuple[bool, int]:
        now = time.monotonic()
        key = f"{client_fingerprint}:{path}"
        attempts = self._requests[key]
        while attempts and attempts[0] <= now - self.window_seconds:
            attempts.popleft()
        if len(attempts) >= self.limit:
            retry_after = max(1, int(self.window_seconds - (now - attempts[0])) + 1)
            return False, retry_after
        attempts.append(now)
        return True, 0


def fingerprint_client(value: str, salt: str) -> str:
    """Return a short non-reversible value for aggregate abuse monitoring."""
    return hashlib.sha256(f"{salt}:{value}".encode()).hexdigest()[:16]
