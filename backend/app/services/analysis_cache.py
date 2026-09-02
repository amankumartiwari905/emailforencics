"""
Simple in-memory TTL cache for analysis results, keyed by the SHA-256
hash of the raw email bytes. This lets /analyze/report reuse a result
that was already computed by /analyze for the same file, instead of
re-running the entire pipeline (DNS, geolocation, ProxyCheck, etc.)
a second time.

In-memory is fine for a hackathon demo (single process). For production
this would move to Redis so it survives restarts and works across
multiple worker processes.
"""

import hashlib
import time

_CACHE: dict[str, tuple[float, dict]] = {}
_TTL_SECONDS = 60 * 30  # 30 minutes


def compute_email_hash(email_bytes: bytes) -> str:
    return hashlib.sha256(email_bytes).hexdigest()


def get_cached_analysis(email_hash: str) -> dict | None:
    entry = _CACHE.get(email_hash)
    if not entry:
        return None

    timestamp, result = entry
    if time.time() - timestamp > _TTL_SECONDS:
        _CACHE.pop(email_hash, None)
        return None

    return result


def set_cached_analysis(email_hash: str, result: dict) -> None:
    _CACHE[email_hash] = (time.time(), result)