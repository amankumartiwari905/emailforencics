import pytest

from app.services.ip_validator import validate_ip


@pytest.mark.parametrize("value, version, is_global", [
    ("8.8.8.8", 4, True),
    ("192.168.1.1", 4, False),
    ("127.0.0.1", 4, False),
    ("169.254.169.254", 4, False),       # cloud metadata endpoint
    ("2001:4860:4860::8888", 6, True),
    ("::1", 6, False),
    ("::ffff:10.0.0.1", 6, False),       # mapped private address
    ("  8.8.8.8  ", 4, True),            # whitespace tolerated
])
def test_valid(value, version, is_global):
    r = validate_ip(value)
    assert r.valid and r.version == version and r.is_global is is_global


@pytest.mark.parametrize("value, error", [
    (None, "not_a_string"),
    (12345, "not_a_string"),
    ("", "empty"),
    ("999.1.1.1", "invalid_format"),
    ("1.2.3", "invalid_format"),
    ("fe80::1%eth0", "scope_id_not_supported"),
    ("1" * 100, "too_long"),
])
def test_invalid(value, error):
    r = validate_ip(value)
    assert not r.valid and r.error == error


def test_normalization():
    assert validate_ip("2001:0db8::0001").normalized == "2001:db8::1"


# ---- legacy dict-style access must keep working for old callers ----------

def test_legacy_dict_access_valid():
    r = validate_ip("8.8.8.8")
    assert r["valid"] is True
    assert r["version"] == 4
    assert r["public"] is True
    assert r["ip"] == "8.8.8.8"
    assert r.get("public") is True
    assert r.get("missing", "default") == "default"
    assert "valid" in r


def test_legacy_dict_access_invalid():
    r = validate_ip("nope")
    assert r["valid"] is False
    assert r.get("version") is None
    assert r["ip"] == "nope"


def test_to_dict_and_dict_conversion():
    r = validate_ip("10.0.0.1")
    d = r.to_dict()
    assert d["valid"] is True and d["public"] is False and d["version"] == 4
    assert dict(r) == d
    assert validate_ip("bad").to_dict() == {"ip": "bad", "valid": False, "error": "invalid_format"}