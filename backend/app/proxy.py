"""
Standalone proxy/VPN/TOR intelligence lookup endpoint.

Production concerns addressed vs. a naive implementation:
- check_proxy() is a synchronous (requests-based) call -- calling it
  directly inside a `def` (not `async def`) route works in FastAPI
  because FastAPI runs sync route functions in a thread pool
  automatically, but that's easy to lose track of if this route is
  ever refactored to `async def` by mistake (a common mistake: making
  a route `async def` while still calling sync I/O inside it directly
  blocks the event loop for every other concurrent request). This
  version is explicit about the threading via asyncio.to_thread.
- The IP path parameter is validated before hitting the external
  ProxyCheck API at all -- your original passed any string straight
  through, so "not-an-ip" or "'; DROP TABLE" would still cost a wasted
  outbound API call and produce a confusing error from ProxyCheck's
  side instead of a clean, immediate 400.
- Error responses are split by actual cause: a malformed IP is a
  client error (400), a private/non-routable IP is not an error at all
  (200, with a "not applicable" status -- see ip_geolocation.py and
  proxy_check.py's existing private-IP handling), missing API key
  configuration is a server configuration error (503, since it's not
  the caller's fault), and a genuine upstream failure is a gateway
  error (502) -- all previously collapsed into one blanket 502.
"""

import ipaddress
import asyncio
import logging

from fastapi import APIRouter, HTTPException, Path

from app.services.proxy_check import check_proxy

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/proxy",
    tags=["Proxy Intelligence"],
)


def _validate_ip(ip: str) -> str:
    """Validates and normalizes an IP path parameter. Raises a 400
    HTTPException for anything that isn't a real IPv4/IPv6 address,
    rather than letting a malformed value reach the external API call."""
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"'{ip}' is not a valid IPv4 or IPv6 address",
        )


@router.get("/{ip}")
async def proxy_check(
    ip: str = Path(..., description="IPv4 or IPv6 address to check for VPN/proxy/TOR/hosting indicators"),
):
    """
    Returns VPN/proxy/TOR/hosting reputation data for a given IP via
    ProxyCheck.io.

    Status code semantics:
        200 -- lookup succeeded (includes the legitimate "private_ip,
               nothing to check" case)
        400 -- the supplied path parameter is not a valid IP address
        503 -- the service is not configured (missing API key) --
               a deployment/ops issue, not a client error
        502 -- the upstream ProxyCheck API call itself failed
               (timeout, network error, non-2xx response)
    """
    normalized_ip = _validate_ip(ip)

    try:
        # check_proxy is synchronous (uses `requests`, not `httpx`) --
        # running it via to_thread keeps this route non-blocking for
        # other concurrent requests, since a naive direct call inside
        # a route that's later changed to `async def` would otherwise
        # silently block the whole event loop on every proxy check.
        result = await asyncio.to_thread(check_proxy, normalized_ip)
    except Exception:
        logger.exception("Unexpected failure calling check_proxy for %s", normalized_ip)
        raise HTTPException(
            status_code=502,
            detail="Proxy intelligence lookup failed unexpectedly",
        )

    if not isinstance(result, dict):
        logger.error("check_proxy returned unexpected type %s for %s", type(result), normalized_ip)
        raise HTTPException(status_code=502, detail="Malformed response from proxy intelligence service")

    error = result.get("error")

    if error == "PROXYCHECK_API_KEY is not configured":
        # Not the caller's fault -- this is a deployment configuration
        # gap, so it should read as a service-unavailable condition,
        # not a generic upstream failure the caller might retry into.
        raise HTTPException(status_code=503, detail="Proxy intelligence service is not configured")

    if error:
        raise HTTPException(status_code=502, detail=error)

    return result