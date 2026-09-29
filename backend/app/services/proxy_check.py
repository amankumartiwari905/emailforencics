"""VPN / proxy / TOR / hosting detection via ProxyCheck.io v3.

Requires Python 3.10+ and `requests`.

Backward compatible with the old module: `check_proxy(ip)` is still a
synchronous function returning a dict with the same keys. New code should use
`ProxyChecker` directly, or `acheck_proxy()` from async code (it runs the
blocking HTTP call in a worker thread so it won't stall the event loop).
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import math
import os
import random
import threading
import time
from collections import OrderedDict
from concurrent.futures import Future
from dataclasses import asdict, dataclass, replace
from enum import Enum
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

_MAX_IP_LENGTH = 45          # longest valid textual IP (IPv6 + embedded IPv4)
_MAX_FIELD_LENGTH = 256      # cap on strings accepted from the upstream API
_MAX_RETRY_AFTER_S = 10.0    # never sleep longer than this on a Retry-After


class CheckStatus(str, Enum):
    PUBLIC_IP = "public_ip"
    PRIVATE_IP = "private_ip"      # any non-globally-routable address
    INVALID_IP = "invalid_ip"
    LOOKUP_ERROR = "lookup_error"


@dataclass(frozen=True, slots=True)
class ProxyCheckResult:
    ip: str
    status: CheckStatus
    error: Optional[str] = None          # stable error code; None on success

    # Network
    asn: Optional[str] = None
    organization: Optional[str] = None
    provider: Optional[str] = None
    hostname: Optional[str] = None
    connection_type: Optional[str] = None

    # Location
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    postal_code: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None

    # Detections (None = the API did not say, which is not the same as False)
    vpn: Optional[bool] = None
    proxy: Optional[bool] = None
    tor: Optional[bool] = None
    hosting: Optional[bool] = None
    anonymous: Optional[bool] = None
    compromised: Optional[bool] = None
    scraper: Optional[bool] = None

    # Scores, 0-100
    risk_score: Optional[int] = None
    confidence: Optional[int] = None

    cached: bool = False

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


# --------------------------------------------------------------------------
# Pure helpers
# --------------------------------------------------------------------------

def _safe_repr(value: object) -> str:
    return repr(value)[:64]


def _parse_ip(value: object):
    """Return (parsed, effective) or None. `effective` unwraps IPv4-mapped IPv6
    so ::ffff:10.0.0.1 is classified as the private IPv4 it really is."""
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate or len(candidate) > _MAX_IP_LENGTH or "%" in candidate:
        return None
    try:
        parsed = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    effective = parsed
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
        effective = parsed.ipv4_mapped
    return parsed, effective


def _clean_str(value: object) -> Optional[str]:
    if isinstance(value, str):
        value = value.strip()
        if value:
            return value[:_MAX_FIELD_LENGTH]
    return None


def _as_bool(value: object) -> Optional[bool]:
    return value if isinstance(value, bool) else None


def _as_score(value: object) -> Optional[int]:
    # bool is a subclass of int; reject it explicitly
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value):
        return None
    return max(0, min(100, int(value)))


def _as_coord(value: object, limit: float) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value) or abs(value) > limit:
        return None
    return float(value)


def _section(result: dict, name: str) -> dict:
    value = result.get(name)
    return value if isinstance(value, dict) else {}


def _find_result(data: dict, ip: str) -> Optional[dict]:
    """The v3 response is keyed by IP, but IPv6 text forms can differ from what
    we sent (compressed vs expanded), so fall back to comparing parsed addresses."""
    direct = data.get(ip)
    if isinstance(direct, dict):
        return direct
    target = ipaddress.ip_address(ip)
    for key, value in data.items():
        if not isinstance(value, dict):
            continue
        try:
            if ipaddress.ip_address(key) == target:
                return value
        except ValueError:
            continue
    return None


def _parse_retry_after(resp: Any) -> Optional[float]:
    raw = resp.headers.get("Retry-After")
    if raw is None:
        return None
    try:
        return max(0.0, min(float(raw), _MAX_RETRY_AFTER_S))
    except ValueError:
        return None  # HTTP-date form not supported; fall back to backoff


def _parse_response(ip: str, resp: Any) -> Optional[ProxyCheckResult]:
    try:
        data = resp.json()
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None

    body_status = data.get("status")
    if isinstance(body_status, str) and body_status.lower() in {"denied", "error"}:
        return ProxyCheckResult(ip=ip, status=CheckStatus.LOOKUP_ERROR, error="api_error")

    result = _find_result(data, ip)
    if result is None:
        return None

    network = _section(result, "network")
    location = _section(result, "location")
    detections = _section(result, "detections")

    return ProxyCheckResult(
        ip=ip,
        status=CheckStatus.PUBLIC_IP,
        asn=_clean_str(network.get("asn")),
        organization=_clean_str(network.get("organisation")),
        provider=_clean_str(network.get("provider")),
        hostname=_clean_str(network.get("hostname")),
        connection_type=_clean_str(network.get("type")),
        country=_clean_str(location.get("country_name")),
        country_code=_clean_str(location.get("country_code")),
        region=_clean_str(location.get("region_name")),
        city=_clean_str(location.get("city_name")),
        postal_code=_clean_str(location.get("postal_code")),
        latitude=_as_coord(location.get("latitude"), 90),
        longitude=_as_coord(location.get("longitude"), 180),
        vpn=_as_bool(detections.get("vpn")),
        proxy=_as_bool(detections.get("proxy")),
        tor=_as_bool(detections.get("tor")),
        hosting=_as_bool(detections.get("hosting")),
        anonymous=_as_bool(detections.get("anonymous")),
        compromised=_as_bool(detections.get("compromised")),
        scraper=_as_bool(detections.get("scraper")),
        # In v3, risk and confidence live inside "detections", not at top level.
        risk_score=_as_score(detections.get("risk")),
        confidence=_as_score(detections.get("confidence")),
    )


class _TTLCache:
    """Bounded LRU cache with TTL. Thread-safe."""

    def __init__(self, max_entries: int) -> None:
        self._max = max_entries
        self._lock = threading.Lock()
        self._data: OrderedDict[str, tuple[float, ProxyCheckResult]] = OrderedDict()

    def get(self, key: str) -> Optional[ProxyCheckResult]:
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            expires_at, value = entry
            if expires_at <= time.monotonic():
                del self._data[key]
                return None
            self._data.move_to_end(key)
            return value

    def set(self, key: str, value: ProxyCheckResult, ttl_s: float) -> None:
        with self._lock:
            self._data[key] = (time.monotonic() + ttl_s, value)
            self._data.move_to_end(key)
            while len(self._data) > self._max:
                self._data.popitem(last=False)


# --------------------------------------------------------------------------
# Service
# --------------------------------------------------------------------------

class ProxyChecker:
    def __init__(
        self,
        api_key: Optional[str],
        *,
        base_url: str = "https://proxycheck.io/v3",
        connect_timeout_s: float = 3.0,
        read_timeout_s: float = 5.0,
        max_retries: int = 2,
        backoff_base_s: float = 0.5,
        max_concurrency: int = 20,
        cache_ttl_s: float = 60 * 60,
        error_ttl_s: float = 30.0,
        cache_max_entries: int = 10_000,
        session: Optional[requests.Session] = None,
    ) -> None:
        if not api_key:
            logger.warning("PROXYCHECK_API_KEY not set; proxy checks are disabled")
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout = (connect_timeout_s, read_timeout_s)
        self._max_retries = max(0, max_retries)
        self._backoff_base_s = backoff_base_s
        self._cache_ttl_s = cache_ttl_s
        self._error_ttl_s = error_ttl_s
        self._cache = _TTLCache(cache_max_entries)
        self._semaphore = threading.BoundedSemaphore(max_concurrency)
        self._lock = threading.Lock()
        self._inflight: dict[str, Future] = {}

        self._owns_session = session is None
        if session is None:
            session = requests.Session()
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=max_concurrency, pool_maxsize=max_concurrency
            )
            session.mount("https://", adapter)
            session.headers.update(
                {"Accept": "application/json", "User-Agent": "proxy-checker/1.0"}
            )
        self._session = session

    @classmethod
    def from_env(cls, **kwargs) -> "ProxyChecker":
        return cls(os.getenv("PROXYCHECK_API_KEY"), **kwargs)

    def close(self) -> None:
        if self._owns_session:
            self._session.close()

    def __enter__(self) -> "ProxyChecker":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # ---- public API ------------------------------------------------------

    def check(self, ip: object) -> ProxyCheckResult:
        """Check an IP. Never raises for bad input or upstream failures."""
        parsed = _parse_ip(ip)
        if parsed is None:
            logger.debug("Invalid IP input: %s", _safe_repr(ip))
            return ProxyCheckResult(
                ip=_safe_repr(ip), status=CheckStatus.INVALID_IP, error="invalid_ip"
            )

        ip_obj, effective = parsed
        display_ip = str(ip_obj)

        # is_global (not just `is_private`) also excludes loopback, link-local,
        # multicast, reserved and unspecified addresses -- none of which the
        # API can look up.
        if not effective.is_global:
            return ProxyCheckResult(ip=display_ip, status=CheckStatus.PRIVATE_IP)

        if not self._api_key:
            return ProxyCheckResult(
                ip=display_ip, status=CheckStatus.LOOKUP_ERROR, error="not_configured"
            )

        lookup_ip = str(effective)

        cached = self._cache.get(lookup_ip)
        if cached is not None:
            return replace(cached, ip=display_ip, cached=True)

        # Coalesce concurrent lookups for the same IP into one upstream call.
        with self._lock:
            future = self._inflight.get(lookup_ip)
            owner = future is None
            if owner:
                future = Future()
                self._inflight[lookup_ip] = future

        if not owner:
            return replace(future.result(), ip=display_ip)

        try:
            result = self._fetch_and_cache(lookup_ip)
        except BaseException as exc:            # never leave waiters hanging
            with self._lock:
                self._inflight.pop(lookup_ip, None)
            future.set_exception(exc)
            raise
        with self._lock:
            self._inflight.pop(lookup_ip, None)
        future.set_result(result)
        return replace(result, ip=display_ip)

    # ---- internals -------------------------------------------------------

    def _fetch_and_cache(self, ip: str) -> ProxyCheckResult:
        try:
            result = self._fetch_with_retries(ip)
        except Exception:
            logger.exception("Unexpected ProxyCheck failure for %s", ip)
            result = self._error(ip, "internal_error")
        # short negative cache stops hammering the API during outages
        failed = result.status is CheckStatus.LOOKUP_ERROR
        self._cache.set(ip, result, self._error_ttl_s if failed else self._cache_ttl_s)
        return result

    @staticmethod
    def _error(ip: str, reason: str) -> ProxyCheckResult:
        return ProxyCheckResult(ip=ip, status=CheckStatus.LOOKUP_ERROR, error=reason)

    def _backoff(self, attempt: int, retry_after: Optional[float]) -> float:
        base = min(8.0, self._backoff_base_s * (2 ** attempt))
        delay = base / 2 + random.uniform(0, base / 2)  # jitter avoids retry stampedes
        return max(delay, retry_after) if retry_after is not None else delay

    def _fetch_with_retries(self, ip: str) -> ProxyCheckResult:
        url = f"{self._base_url}/{ip}"
        # The key is sent as a query parameter, so `requests` exception messages
        # contain it. We therefore never log or return exception text -- only
        # stable error codes.
        params = {"key": self._api_key}

        reason = "unknown"
        for attempt in range(self._max_retries + 1):
            retry_after: Optional[float] = None
            try:
                with self._semaphore:
                    resp = self._session.get(
                        url, params=params, timeout=self._timeout, allow_redirects=False
                    )
            except requests.Timeout:
                reason = "timeout"
            except requests.RequestException:
                reason = "network_error"
            else:
                status = resp.status_code
                if status == 200:
                    result = _parse_response(ip, resp)
                    return result if result is not None else self._error(ip, "bad_response")
                if status == 429:
                    reason, retry_after = "rate_limited", _parse_retry_after(resp)
                elif status >= 500:
                    reason = f"upstream_{status}"
                elif status in (401, 403):
                    logger.error(
                        "ProxyCheck rejected credentials (HTTP %s); check PROXYCHECK_API_KEY",
                        status,
                    )
                    return self._error(ip, "auth_failed")   # retrying can't help
                else:
                    return self._error(ip, f"http_{status}")

            if attempt < self._max_retries:
                time.sleep(self._backoff(attempt, retry_after))

        logger.warning("ProxyCheck lookup failed for %s after %d attempts: %s",
                       ip, self._max_retries + 1, reason)
        return self._error(ip, reason)


# --------------------------------------------------------------------------
# Backward-compatible module-level API (same name/shape as the old module)
# --------------------------------------------------------------------------

_default: Optional[ProxyChecker] = None
_default_lock = threading.Lock()


def _get_default() -> ProxyChecker:
    global _default
    with _default_lock:
        if _default is None:
            # The old module called load_dotenv() at import time. Do it lazily
            # here so setups that rely on backend/.env keep working.
            try:
                from dotenv import load_dotenv
                load_dotenv()
            except ImportError:
                pass
            _default = ProxyChecker.from_env()
        return _default


def check_proxy(ip: str) -> dict:
    """Synchronous, dict-returning API identical in shape to the old function."""
    return _get_default().check(ip).to_dict()


async def acheck_proxy(ip: str) -> dict:
    """Async wrapper: runs the blocking call in a worker thread."""
    return await asyncio.to_thread(check_proxy, ip)


def close_proxy_session() -> None:
    """Call on app shutdown to release the shared HTTP session."""
    global _default
    with _default_lock:
        if _default is not None:
            _default.close()
            _default = None