"""IP geolocation via ipinfo.io with caching, retries, and request coalescing.

Requires Python 3.10+ and httpx.

Backward compatible with the old module: `get_ip_location(ip)` still returns a
dict and `close_client()` still exists. New code should use `IPGeolocator`.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import math
import os
import random
import time
from collections import OrderedDict
from dataclasses import asdict, dataclass, replace
from enum import Enum
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

_SOURCE = "ipinfo"
_MAX_IP_LENGTH = 45          # longest valid textual IP (IPv6 + embedded IPv4)
_MAX_FIELD_LENGTH = 256      # cap on strings accepted from the upstream API
_MAX_RETRY_AFTER_S = 10.0    # never sleep longer than this on a Retry-After


class LookupStatus(str, Enum):
    PUBLIC_IP = "public_ip"
    PRIVATE_IP = "private_ip"      # any non-globally-routable address
    INVALID_IP = "invalid_ip"
    LOOKUP_ERROR = "lookup_error"


@dataclass(frozen=True, slots=True)
class GeoResult:
    ip: str
    status: LookupStatus
    country: Optional[str] = None       # ipinfo's /json endpoint returns only the ISO code
    country_code: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[str] = None
    as_name: Optional[str] = None
    as_domain: Optional[str] = None
    source: Optional[str] = None
    reason: Optional[str] = None        # stable error code, never a raw exception string
    cached: bool = False

    def to_dict(self) -> dict:
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


def _parse_loc(loc: object) -> tuple[Optional[float], Optional[float]]:
    if not isinstance(loc, str):
        return None, None
    try:
        lat_s, lon_s = loc.split(",")
        lat, lon = float(lat_s), float(lon_s)
    except ValueError:
        return None, None
    if not (math.isfinite(lat) and math.isfinite(lon)
            and -90 <= lat <= 90 and -180 <= lon <= 180):
        return None, None
    return lat, lon


def _split_org(org: object) -> tuple[Optional[str], Optional[str]]:
    """'AS15169 Google LLC' -> ('AS15169', 'Google LLC')."""
    org = _clean_str(org)
    if org is None:
        return None, None
    head, _, tail = org.partition(" ")
    if head[:2].upper() == "AS" and head[2:].isdigit():
        return head.upper(), (tail.strip() or None)
    return None, org


def _parse_retry_after(resp: httpx.Response) -> Optional[float]:
    raw = resp.headers.get("retry-after")
    if raw is None:
        return None
    try:
        return max(0.0, min(float(raw), _MAX_RETRY_AFTER_S))
    except ValueError:
        return None  # HTTP-date form not supported; fall back to backoff


def _parse_response(ip: str, resp: httpx.Response) -> Optional[GeoResult]:
    try:
        data = resp.json()
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    if data.get("bogon"):
        return GeoResult(ip=ip, status=LookupStatus.PRIVATE_IP, source=_SOURCE)

    lat, lon = _parse_loc(data.get("loc"))
    asn, as_name = _split_org(data.get("org"))
    country_code = _clean_str(data.get("country"))
    return GeoResult(
        ip=ip,
        status=LookupStatus.PUBLIC_IP,
        country=country_code,
        country_code=country_code,
        city=_clean_str(data.get("city")),
        latitude=lat,
        longitude=lon,
        asn=asn,
        as_name=as_name,
        source=_SOURCE,
    )


class _TTLCache:
    """Bounded LRU cache with TTL. Safe within one event loop (no awaits inside)."""

    def __init__(self, max_entries: int) -> None:
        self._max = max_entries
        self._data: OrderedDict[str, tuple[float, GeoResult]] = OrderedDict()

    def get(self, key: str) -> Optional[GeoResult]:
        entry = self._data.get(key)
        if entry is None:
            return None
        expires_at, value = entry
        if expires_at <= time.monotonic():
            del self._data[key]
            return None
        self._data.move_to_end(key)
        return value

    def set(self, key: str, value: GeoResult, ttl_s: float) -> None:
        self._data[key] = (time.monotonic() + ttl_s, value)
        self._data.move_to_end(key)
        while len(self._data) > self._max:
            self._data.popitem(last=False)


# --------------------------------------------------------------------------
# Service
# --------------------------------------------------------------------------

class IPGeolocator:
    def __init__(
        self,
        token: Optional[str],
        *,
        base_url: str = "https://ipinfo.io",
        timeout_s: float = 10.0,
        connect_timeout_s: float = 3.0,
        max_retries: int = 2,
        backoff_base_s: float = 0.5,
        max_concurrency: int = 20,
        cache_ttl_s: float = 6 * 60 * 60,
        error_ttl_s: float = 30.0,
        cache_max_entries: int = 10_000,
        client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        if not token:
            logger.warning("IPINFO_TOKEN not set; requests will be heavily rate limited")
        self._token = token
        self._base_url = base_url.rstrip("/")
        self._max_retries = max(0, max_retries)
        self._backoff_base_s = backoff_base_s
        self._cache_ttl_s = cache_ttl_s
        self._error_ttl_s = error_ttl_s
        self._cache = _TTLCache(cache_max_entries)
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._inflight: dict[str, asyncio.Task[GeoResult]] = {}

        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_s, connect=connect_timeout_s),
            limits=httpx.Limits(
                max_connections=max_concurrency,
                max_keepalive_connections=max_concurrency,
            ),
            follow_redirects=False,
        )

    @classmethod
    def from_env(cls, **kwargs) -> "IPGeolocator":
        return cls(os.getenv("IPINFO_TOKEN"), **kwargs)

    async def __aenter__(self) -> "IPGeolocator":
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        tasks = list(self._inflight.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if self._owns_client:
            await self._client.aclose()

    # ---- public API ------------------------------------------------------

    async def lookup(self, ip: object, *, retries: Optional[int] = None) -> GeoResult:
        """Geolocate an IP. Never raises for bad input or upstream failures.

        `retries` overrides the instance default for this call. If several
        callers look up the same IP concurrently, the first caller's value wins.
        """
        parsed = _parse_ip(ip)
        if parsed is None:
            logger.debug("Invalid IP input: %s", _safe_repr(ip))
            return GeoResult(ip=_safe_repr(ip), status=LookupStatus.INVALID_IP)

        ip_obj, effective = parsed
        display_ip = str(ip_obj)

        # is_global (not `not is_private`) also excludes loopback, link-local,
        # multicast, reserved and unspecified addresses.
        if not effective.is_global:
            return GeoResult(ip=display_ip, status=LookupStatus.PRIVATE_IP)

        lookup_ip = str(effective)

        cached = self._cache.get(lookup_ip)
        if cached is not None:
            return replace(cached, ip=display_ip, cached=True)

        # Coalesce concurrent lookups for the same IP into one upstream call.
        task = self._inflight.get(lookup_ip)
        if task is None:
            max_retries = self._max_retries if retries is None else max(0, retries)
            task = asyncio.create_task(self._fetch_and_cache(lookup_ip, max_retries))
            self._inflight[lookup_ip] = task
            task.add_done_callback(lambda _t, k=lookup_ip: self._inflight.pop(k, None))

        # shield: one caller being cancelled must not cancel the shared fetch
        result = await asyncio.shield(task)
        return replace(result, ip=display_ip)

    # ---- internals -------------------------------------------------------

    async def _fetch_and_cache(self, ip: str, max_retries: int) -> GeoResult:
        try:
            result = await self._fetch_with_retries(ip, max_retries)
        except Exception:
            logger.exception("Unexpected geolocation failure for %s", ip)
            result = self._error(ip, "internal_error")
        # short negative cache stops hammering the API during outages
        ttl = self._error_ttl_s if result.status is LookupStatus.LOOKUP_ERROR else self._cache_ttl_s
        self._cache.set(ip, result, ttl)
        return result

    def _error(self, ip: str, reason: str) -> GeoResult:
        return GeoResult(ip=ip, status=LookupStatus.LOOKUP_ERROR, source=_SOURCE, reason=reason)

    def _backoff(self, attempt: int, retry_after: Optional[float]) -> float:
        base = min(8.0, self._backoff_base_s * (2 ** attempt))
        delay = base / 2 + random.uniform(0, base / 2)  # jitter avoids retry stampedes
        return max(delay, retry_after) if retry_after is not None else delay

    async def _fetch_with_retries(self, ip: str, max_retries: int) -> GeoResult:
        headers = {"Accept": "application/json", "User-Agent": "ip-geolocator/1.0"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"  # header, not query string
        url = f"{self._base_url}/{ip}/json"

        reason = "unknown"
        for attempt in range(max_retries + 1):
            retry_after: Optional[float] = None
            try:
                async with self._semaphore:
                    resp = await self._client.get(url, headers=headers)
            except httpx.TimeoutException:
                reason = "timeout"
            except httpx.RequestError:
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
                    logger.error("ipinfo rejected credentials (HTTP %s); check IPINFO_TOKEN", status)
                    return self._error(ip, "auth_failed")   # retrying can't help
                else:
                    return self._error(ip, f"http_{status}")

            if attempt < max_retries:
                await asyncio.sleep(self._backoff(attempt, retry_after))

        logger.warning("Geolocation lookup failed for %s after %d attempts: %s",
                       ip, max_retries + 1, reason)
        return self._error(ip, reason)


# --------------------------------------------------------------------------
# Backward-compatible module-level API (same names/shape as the old module)
# --------------------------------------------------------------------------

_default: Optional[IPGeolocator] = None


def _get_default() -> IPGeolocator:
    global _default
    if _default is None:
        # The old module called load_dotenv() at import time. Do it lazily here
        # so existing setups that rely on backend/.env keep working.
        try:
            from dotenv import load_dotenv
            load_dotenv()
        except ImportError:
            pass
        _default = IPGeolocator.from_env()
    return _default


async def get_ip_location(ip: str, retries: int = 2) -> dict:
    return (await _get_default().lookup(ip, retries=retries)).to_dict()


async def close_client() -> None:
    """Call on app shutdown to release the shared httpx client."""
    global _default
    if _default is not None:
        await _default.aclose()
        _default = None