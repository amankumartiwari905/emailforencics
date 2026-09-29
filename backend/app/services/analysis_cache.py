"""
In-memory TTL + LRU cache for email analysis results, keyed by the SHA-256
of the raw email bytes.

Properties:
  * Bounded: max entries, with LRU eviction and periodic expiry sweeps.
  * Thread-safe (sync handlers in a threadpool) and single-flight for async
    callers, so concurrent requests for the same file run the pipeline once.
  * Callers get copies, so mutating a result never corrupts the cache.
  * Degraded results (missing enrichment) are cached only briefly.
  * Keys include a pipeline version, so deploys don't serve stale logic.

Single-process only. For multiple workers, swap the store for Redis
(same interface).
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import os
import threading
import time
from collections import OrderedDict
from typing import Any, Awaitable, Callable, Optional

# ==========================================
# CONFIG
# ==========================================

PIPELINE_VERSION = os.getenv("ANALYSIS_PIPELINE_VERSION", "2.0")  # bump on scoring changes
TTL_SECONDS = int(os.getenv("ANALYSIS_CACHE_TTL_S", str(30 * 60)))
DEGRADED_TTL_SECONDS = int(os.getenv("ANALYSIS_CACHE_DEGRADED_TTL_S", "60"))
MAX_ENTRIES = int(os.getenv("ANALYSIS_CACHE_MAX_ENTRIES", "1000"))
SWEEP_INTERVAL_S = 60


# ==========================================
# HASHING
# ==========================================

def compute_email_hash(email_bytes: bytes) -> str:
    return hashlib.sha256(email_bytes).hexdigest()


def _key(email_hash: str, tenant: Optional[str] = None) -> str:
    # Add a tenant/user id if results must not be shared across users.
    return f"{PIPELINE_VERSION}:{tenant or '-'}:{email_hash}"


def is_degraded(result: dict) -> bool:
    """True if enrichment was incomplete, so the result shouldn't live long.
    Adjust the paths to match where your pipeline puts these fields."""
    if not isinstance(result, dict):
        return False
    if result.get("missing_inputs"):
        return True
    nlp = result.get("nlp_analysis")
    return isinstance(nlp, dict) and nlp.get("llm_status") == "error"


# ==========================================
# STORE
# ==========================================

class _TTLCache:
    def __init__(self, max_entries: int) -> None:
        self._data: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()
        self._max = max_entries
        self._lock = threading.Lock()
        self._last_sweep = time.monotonic()
        self.hits = 0
        self.misses = 0

    def _sweep(self, now: float) -> None:
        if now - self._last_sweep < SWEEP_INTERVAL_S:
            return
        self._last_sweep = now
        for k in [k for k, (exp, _) in self._data.items() if exp <= now]:
            del self._data[k]

    def get(self, key: str) -> Optional[dict]:
        now = time.monotonic()
        with self._lock:
            self._sweep(now)
            entry = self._data.get(key)
            if entry is None:
                self.misses += 1
                return None
            expires, value = entry
            if expires <= now:
                del self._data[key]
                self.misses += 1
                return None
            self._data.move_to_end(key)  # LRU touch
            self.hits += 1
            return copy.deepcopy(value)

    def set(self, key: str, value: dict, ttl: float) -> None:
        now = time.monotonic()
        stored = copy.deepcopy(value)
        with self._lock:
            self._sweep(now)
            self._data[key] = (now + ttl, stored)
            self._data.move_to_end(key)
            while len(self._data) > self._max:
                self._data.popitem(last=False)  # evict least recently used

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def stats(self) -> dict:
        with self._lock:
            return {"entries": len(self._data), "hits": self.hits, "misses": self.misses}


_cache = _TTLCache(MAX_ENTRIES)


# ==========================================
# PUBLIC API (backward compatible)
# ==========================================

def get_cached_analysis(email_hash: str, tenant: Optional[str] = None) -> Optional[dict]:
    return _cache.get(_key(email_hash, tenant))


def set_cached_analysis(
    email_hash: str,
    result: dict,
    tenant: Optional[str] = None,
    ttl: Optional[float] = None,
) -> None:
    if ttl is None:
        ttl = DEGRADED_TTL_SECONDS if is_degraded(result) else TTL_SECONDS
    _cache.set(_key(email_hash, tenant), result, ttl)


def clear_cache() -> None:
    _cache.clear()


def cache_stats() -> dict:
    return _cache.stats()


# ==========================================
# SINGLE-FLIGHT (async)
# ==========================================

_inflight: dict[str, "asyncio.Task[dict]"] = {}


async def get_or_compute(
    email_hash: str,
    compute: Callable[[], Awaitable[dict]],
    tenant: Optional[str] = None,
) -> dict:
    """Return a cached result, or run `compute` exactly once even if many
    requests for the same email arrive concurrently.

    Must be called from a single event loop (the normal FastAPI setup).
    """
    key = _key(email_hash, tenant)

    hit = _cache.get(key)
    if hit is not None:
        return hit

    task = _inflight.get(key)
    if task is None:
        async def _run() -> dict:
            result = await compute()
            set_cached_analysis(email_hash, result, tenant)
            return result

        task = asyncio.ensure_future(_run())
        _inflight[key] = task
        task.add_done_callback(lambda _t, k=key: _inflight.pop(k, None))

    # shield: one caller disconnecting must not cancel the shared computation
    result = await asyncio.shield(task)
    return copy.deepcopy(result)