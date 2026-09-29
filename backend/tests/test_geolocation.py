import asyncio

import httpx
import pytest

from app.services.ip_geolocation import IPGeolocator, LookupStatus

OK = {"ip": "8.8.8.8", "city": "Mountain View", "country": "US",
      "loc": "37.4056,-122.0775", "org": "AS15169 Google LLC"}


def make(handler, **kw):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return IPGeolocator("secret-token", client=client, backoff_base_s=0, **kw)


async def test_success_and_token_sent_in_header_only():
    seen = []

    def handler(req):
        seen.append(req)
        return httpx.Response(200, json=OK)

    r = await make(handler).lookup("8.8.8.8")
    assert r.status is LookupStatus.PUBLIC_IP
    assert (r.city, r.country_code, r.asn, r.as_name) == ("Mountain View", "US", "AS15169", "Google LLC")
    assert r.latitude == pytest.approx(37.4056)
    assert "secret-token" not in str(seen[0].url)
    assert seen[0].headers["authorization"] == "Bearer secret-token"


async def test_non_public_addresses_never_hit_network():
    def handler(req):
        raise AssertionError("network call for non-public IP")

    geo = make(handler)
    for ip in ["10.0.0.1", "127.0.0.1", "169.254.169.254", "::1", "::ffff:10.0.0.1"]:
        assert (await geo.lookup(ip)).status is LookupStatus.PRIVATE_IP


@pytest.mark.parametrize("bad", ["999.1.1.1", "", None, 12345, "fe80::1%eth0"])
async def test_invalid_input(bad):
    r = await make(lambda req: httpx.Response(200)).lookup(bad)
    assert r.status is LookupStatus.INVALID_IP


async def test_concurrent_lookups_are_coalesced_and_cached():
    calls = 0

    async def handler(req):
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.01)
        return httpx.Response(200, json=OK)

    geo = make(handler)
    results = await asyncio.gather(*[geo.lookup("8.8.8.8") for _ in range(10)])
    assert calls == 1 and all(r.status is LookupStatus.PUBLIC_IP for r in results)
    assert (await geo.lookup("8.8.8.8")).cached and calls == 1


async def test_retries_on_429_then_succeeds():
    responses = iter([httpx.Response(429, headers={"Retry-After": "0"}),
                      httpx.Response(200, json=OK)])
    r = await make(lambda req: next(responses)).lookup("8.8.8.8")
    assert r.status is LookupStatus.PUBLIC_IP


async def test_5xx_retries_then_reports_stable_error_code():
    calls = 0

    def handler(req):
        nonlocal calls
        calls += 1
        return httpx.Response(503)

    r = await make(handler).lookup("8.8.8.8")
    assert calls == 3  # 1 try + 2 retries
    assert r.status is LookupStatus.LOOKUP_ERROR and r.reason == "upstream_503"


async def test_retries_override_per_call():
    calls = 0

    def handler(req):
        nonlocal calls
        calls += 1
        return httpx.Response(503)

    await make(handler).lookup("8.8.8.8", retries=0)
    assert calls == 1


async def test_auth_failure_is_not_retried_and_leaks_nothing():
    calls = 0

    def handler(req):
        nonlocal calls
        calls += 1
        return httpx.Response(403)

    r = await make(handler).lookup("8.8.8.8")
    assert calls == 1
    assert r.status is LookupStatus.LOOKUP_ERROR and r.reason == "auth_failed"
    assert "secret-token" not in str(r.to_dict())


async def test_bogon_response_maps_to_private():
    r = await make(lambda req: httpx.Response(200, json={"ip": "1.2.3.4", "bogon": True})).lookup("1.2.3.4")
    assert r.status is LookupStatus.PRIVATE_IP


async def test_to_dict_has_legacy_keys():
    d = (await make(lambda req: httpx.Response(200, json=OK)).lookup("8.8.8.8")).to_dict()
    for key in ("ip", "country", "country_code", "city", "latitude", "longitude",
                "asn", "as_name", "as_domain", "status", "source"):
        assert key in d
    assert d["status"] == "public_ip"