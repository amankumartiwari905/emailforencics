from __future__ import annotations

import ipaddress
import logging
from dataclasses import asdict, dataclass
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Longest valid textual form: full IPv6 with embedded IPv4
# ("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255" = 45 chars).
_MAX_IP_LENGTH = 45


@dataclass(frozen=True, slots=True)
class IPValidationResult:
    ip: Any                          # original input, unmodified
    valid: bool
    version: Optional[int] = None    # 4 or 6
    normalized: Optional[str] = None # canonical text form
    is_global: Optional[bool] = None # publicly routable on the internet
    is_private: Optional[bool] = None
    is_loopback: Optional[bool] = None
    is_link_local: Optional[bool] = None
    is_multicast: Optional[bool] = None
    is_reserved: Optional[bool] = None
    error: Optional[str] = None      # stable machine-readable error code

    @property
    def public(self) -> bool:
        """Backward-compatible alias. Prefer `is_global`."""
        return bool(self.is_global)

    def _mapping(self) -> dict[str, Any]:
        data: dict[str, Any] = {"ip": self.ip, "valid": self.valid}
        if self.valid:
            if self.version is not None:
                data["version"] = self.version
            if self.normalized is not None:
                data["normalized"] = self.normalized
            if self.is_global is not None:
                data["is_global"] = self.is_global
            if self.is_private is not None:
                data["is_private"] = self.is_private
            if self.is_loopback is not None:
                data["is_loopback"] = self.is_loopback
            if self.is_link_local is not None:
                data["is_link_local"] = self.is_link_local
            if self.is_multicast is not None:
                data["is_multicast"] = self.is_multicast
            if self.is_reserved is not None:
                data["is_reserved"] = self.is_reserved
            data["public"] = self.public
        else:
            if self.error is not None:
                data["error"] = self.error
        return data

    def __getitem__(self, key: str) -> Any:
        return self._mapping()[key]

    def __iter__(self):
        return iter(self._mapping().items())

    def __len__(self) -> int:
        return len(self._mapping())

    def __contains__(self, key: object) -> bool:
        return key in self._mapping()

    def get(self, key: str, default: Any = None) -> Any:
        return self._mapping().get(key, default)

    def keys(self):
        return self._mapping().keys()

    def items(self):
        return self._mapping().items()

    def to_dict(self) -> dict[str, Any]:
        return self._mapping()


def _invalid(value: Any, error: str) -> IPValidationResult:
    # repr() + truncation prevents log injection and log flooding
    logger.debug("Invalid IP input (%s): %.64r", error, value)
    return IPValidationResult(ip=value, valid=False, error=error)


def validate_ip(value: object) -> IPValidationResult:
    """Validate an IPv4/IPv6 address string and classify it.

    Never raises for bad input; failures are reported via `valid=False`
    and a stable `error` code:
        not_a_string | empty | too_long | scope_id_not_supported | invalid_format
    """
    # ipaddress.ip_address() silently accepts ints (5 -> 0.0.0.5), so
    # reject anything that is not a string.
    if not isinstance(value, str):
        return _invalid(value, "not_a_string")

    candidate = value.strip()
    if not candidate:
        return _invalid(value, "empty")
    if len(candidate) > _MAX_IP_LENGTH:
        return _invalid(value, "too_long")
    if "%" in candidate:  # IPv6 zone IDs (fe80::1%eth0) are interface-local
        return _invalid(value, "scope_id_not_supported")

    try:
        ip_obj = ipaddress.ip_address(candidate)
    except ValueError:
        return _invalid(value, "invalid_format")

    # Classify IPv4-mapped IPv6 (::ffff:10.0.0.1) by its embedded IPv4
    # address so it can't be used to sneak past private-range checks (SSRF).
    effective = ip_obj
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        effective = ip_obj.ipv4_mapped

    return IPValidationResult(
        ip=value,
        valid=True,
        version=ip_obj.version,
        normalized=str(ip_obj),
        is_global=effective.is_global,
        is_private=effective.is_private,
        is_loopback=effective.is_loopback,
        is_link_local=effective.is_link_local,
        is_multicast=effective.is_multicast,
        is_reserved=effective.is_reserved,
    )