"""
middleware/rate_limiter.py
In-process sliding window rate limiter.

Design goals:
  - No external dependency (Redis, Memcached) — swappable later
  - Thread-safe for uvicorn workers (uses threading.Lock)
  - Per-user-ID limit (user_id from verified JWT — never from request body)
  - Separate configurable limits per route group
  - Automatic cleanup of stale windows to prevent unbounded memory growth

Usage:
    from middleware.rate_limiter import RateLimiter

    analyze_limiter = RateLimiter(max_requests=30, window_seconds=60)

    # In endpoint:
    allowed, retry_after = analyze_limiter.check(user_id)
    if not allowed:
        raise HTTPException(status_code=429, detail=..., headers={"Retry-After": str(retry_after)})

Swap to Redis:
    Replace _bucket in RateLimiter with a Redis sliding window script
    without changing any call-site code.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict


class RateLimiter:
    """
    Sliding window rate limiter.

    Tracks per-key request timestamps in a dict of lists.
    Old timestamps (outside the window) are pruned on each check.

    Not suitable for multi-process deployments without a shared store (use Redis then).
    For single-process uvicorn or gunicorn with --workers 1, this is sufficient.
    """

    def __init__(
        self,
        max_requests: int,
        window_seconds: int,
        cleanup_interval: int = 300,
    ):
        """
        Parameters
        ----------
        max_requests     : Maximum requests allowed per key per window.
        window_seconds   : Sliding window duration in seconds.
        cleanup_interval : How often to sweep and purge all stale keys (seconds).
                           Prevents unbounded memory growth for large user bases.
        """
        self.max_requests    = max_requests
        self.window_seconds  = window_seconds
        self.cleanup_interval = cleanup_interval

        self._buckets: dict[str, list[float]] = defaultdict(list)
        self._lock            = threading.Lock()
        self._last_cleanup    = time.monotonic()

    def check(self, key: str) -> tuple[bool, int]:
        """
        Check whether a request from `key` is allowed.

        Parameters
        ----------
        key : Typically the authenticated user_id (UUID string from JWT).

        Returns
        -------
        (allowed, retry_after_seconds)
        - allowed=True, retry_after=0     → request is within limit
        - allowed=False, retry_after=N    → rate limited; client should wait N seconds
        """
        now = time.monotonic()
        window_start = now - self.window_seconds

        with self._lock:
            # Prune old timestamps for this key
            bucket = self._buckets[key]
            # In-place filter: keep only timestamps within the window
            new_bucket = [t for t in bucket if t > window_start]
            self._buckets[key] = new_bucket

            if len(new_bucket) >= self.max_requests:
                # Oldest request in window → client must wait until it falls out
                oldest = min(new_bucket)
                retry_after = int(self.window_seconds - (now - oldest)) + 1
                return False, max(retry_after, 1)

            # Allow: record this request
            self._buckets[key].append(now)

            # Periodic stale-key cleanup (amortized)
            if now - self._last_cleanup > self.cleanup_interval:
                self._cleanup(window_start)
                self._last_cleanup = now

            return True, 0

    def remaining(self, key: str) -> int:
        """Return how many requests this key has left in the current window."""
        now = time.monotonic()
        window_start = now - self.window_seconds
        with self._lock:
            bucket = [t for t in self._buckets.get(key, []) if t > window_start]
            return max(0, self.max_requests - len(bucket))

    def reset(self, key: str) -> None:
        """Clear all recorded requests for a key (for testing)."""
        with self._lock:
            self._buckets.pop(key, None)

    def _cleanup(self, window_start: float) -> None:
        """Remove keys whose entire bucket has expired. Called under lock."""
        expired_keys = [
            k for k, v in self._buckets.items()
            if not any(t > window_start for t in v)
        ]
        for k in expired_keys:
            del self._buckets[k]


# ── Pre-configured limiters ───────────────────────────────────────────────────
# Instantiated once at module import — shared across all requests.

# URL analysis: 30 analyses per minute per user
analyze_limiter = RateLimiter(max_requests=30, window_seconds=60)

# Export: 10 exports per 5 minutes per user
export_limiter  = RateLimiter(max_requests=10, window_seconds=300)

# Upload: 20 uploads per 10 minutes per user
upload_limiter  = RateLimiter(max_requests=20, window_seconds=600)
