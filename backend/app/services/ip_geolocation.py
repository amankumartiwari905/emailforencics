import ipaddress
import os
import time
import asyncio
import logging

import httpx
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")
IPINFO_URL = "https://ipinfo.io/{ip}/json"  # full endpoint -> gives city/lat/lon, unlike /lite

# Simple in-memory TTL cache. IP geolocation rarely changes within a
# session, and this is what saves you from rate limits when the same
# IP shows up across multiple emails in a campaign.
_CACHE: dict[str, tuple[float, dict]] = {}
_CACHE_TTL_SECONDS = 60 * 60 * 6  # 6 hours

_client: httpx.AsyncClient | None = None


def _get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(timeout=10.0)
    return _client


def _private_ip_result(ip: str) -> dict:
    return {
        "ip": ip, "country": None, "country_code": None,
        "city": None, "latitude": None, "longitude": None,
        "asn": None, "as_name": None, "as_domain": None,
        "status": "private_ip", "source": None,
    }


def _cache_get(ip: str) -> dict | None:
    entry = _CACHE.get(ip)
    if not entry:
        return None
    ts, data = entry
    if time.time() - ts > _CACHE_TTL_SECONDS:
        _CACHE.pop(ip, None)
        return None
    return data


def _cache_set(ip: str, data: dict) -> None:
    _CACHE[ip] = (time.time(), data)


def _parse_loc(loc_str: str | None) -> tuple[float | None, float | None]:
    if not loc_str or "," not in loc_str:
        return None, None
    try:
        lat, lon = loc_str.split(",")
        return float(lat), float(lon)
    except ValueError:
        return None, None


async def _fetch_from_ipinfo(ip: str) -> dict:
    client = _get_client()
    resp = await client.get(
        IPINFO_URL.format(ip=ip),
        params={"token": IPINFO_TOKEN},
    )
    resp.raise_for_status()
    data = resp.json()

    lat, lon = _parse_loc(data.get("loc"))
    org = data.get("org", "")  # ipinfo returns "AS15169 Google LLC" style string
    asn, as_name = (org.split(" ", 1) + [None])[:2] if org else (None, None)

    return {
        "ip": ip,
        "country": data.get("country"),
        "country_code": data.get("country"),
        "city": data.get("city"),
        "latitude": lat,
        "longitude": lon,
        "asn": asn,
        "as_name": as_name,
        "as_domain": None,
        "status": "public_ip",
        "source": "ipinfo",
    }


async def get_ip_location(ip: str, retries: int = 2) -> dict:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return {"ip": ip, "status": "invalid_ip"}

    if ip_obj.is_private:
        return _private_ip_result(ip)

    cached = _cache_get(ip)
    if cached:
        return {**cached, "cached": True}

    last_error = None
    for attempt in range(retries + 1):
        try:
            result = await _fetch_from_ipinfo(ip)
            _cache_set(ip, result)
            return result
        except httpx.HTTPStatusError as e:
            last_error = e
            if e.response.status_code == 429:
                # Rate limited -- back off briefly and retry once or twice
                # rather than failing the whole analysis on demo day.
                await asyncio.sleep(1.5 * (attempt + 1))
                continue
            break
        except httpx.RequestError as e:
            last_error = e
            await asyncio.sleep(0.5 * (attempt + 1))

    logger.warning("Geolocation lookup failed for %s: %s", ip, last_error)
    return {
        "ip": ip,
        "status": "lookup_error",
        "reason": str(last_error),
        "source": "ipinfo",
    }


async def close_client():
    """Call this on app shutdown to release the shared httpx client."""
    global _client
    if _client:
        await _client.aclose()
        _client = None