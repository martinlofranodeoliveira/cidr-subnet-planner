"""Strict CIDR grammar, host-bit diagnostics, and integer interval utilities."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

from cidr_planner.errors import CIDRValidationError, NonCanonicalCIDRError
from cidr_planner.limits import DEFAULT_LIMITS, PlannerLimits, enforce_count_limit, validate_strict

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


@dataclass(frozen=True, slots=True)
class ParsedCIDR:
    input_cidr: str
    canonical_cidr: str
    network: IPNetwork
    family: str
    version: int
    prefix_length: int
    is_canonical_host_bits: bool
    host_bits_int: int
    host_bits_hex: str
    start_int: int
    end_int: int
    address_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_cidr": self.input_cidr,
            "canonical_cidr": self.canonical_cidr,
            "family": self.family,
            "version": self.version,
            "prefix_length": self.prefix_length,
            "is_canonical_host_bits": self.is_canonical_host_bits,
            "host_bits_hex": self.host_bits_hex,
            "address_count": str(self.address_count) if self.version == 6 else self.address_count,
            "address_count_str": str(self.address_count),
        }


def network_interval(net: IPNetwork) -> tuple[int, int]:
    """Inclusive integer interval, without address enumeration."""
    return int(net.network_address), int(net.broadcast_address)


def inspect_cidr(raw_cidr: object, *, limits: PlannerLimits = DEFAULT_LIMITS) -> ParsedCIDR:
    """Validate syntax and explicitly record host bits without rejecting them."""
    if not isinstance(raw_cidr, str):
        raise CIDRValidationError(
            code="invalid_cidr_type", message="CIDR input must be a string.",
            input_type=type(raw_cidr).__name__,
        )
    if not raw_cidr:
        raise CIDRValidationError(code="empty_cidr_string", message="CIDR string must not be empty.")
    enforce_count_limit("max_cidr_string_length", limits.max_cidr_string_length, len(raw_cidr))

    def invalid(code: str, message: str) -> None:
        raise CIDRValidationError(code=code, message=message, input_cidr=raw_cidr)

    if any(ch.isspace() for ch in raw_cidr):
        invalid("invalid_cidr_whitespace", "CIDR must not contain whitespace.")
    if "%" in raw_cidr:
        invalid("ipv6_scope_zone_not_supported", "IPv6 scope zone identifiers are not supported in CIDRs.")
    if raw_cidr.count("/") != 1:
        invalid("missing_or_invalid_prefix_separator", "CIDR requires exactly one '/' separator.")
    addr_part, prefix_part = raw_cidr.split("/", 1)
    if not addr_part:
        invalid("missing_ip_address", "CIDR is missing the address before '/'.")
    if not prefix_part:
        invalid("missing_prefix_length", "CIDR is missing the prefix length after '/'.")
    if "." in prefix_part or ":" in prefix_part:
        invalid("netmask_or_hostmask_not_supported", "Use an integer prefix length, not a netmask or hostmask.")
    if not prefix_part.isascii() or not prefix_part.isdigit():
        invalid("invalid_prefix_length", "Prefix length must contain base-10 ASCII digits only.")
    if len(prefix_part) > 1 and prefix_part.startswith("0"):
        invalid("leading_zero_in_prefix_length", "Prefix length must not contain leading zeros.")
    try:
        addr_obj: IPAddress = ipaddress.ip_address(addr_part)
    except ValueError as exc:
        raise CIDRValidationError(
            code="invalid_ip_address", message="Invalid IP address in CIDR.", input_cidr=raw_cidr,
        ) from exc
    version = addr_obj.version
    family = f"ipv{version}"
    max_prefix = 32 if version == 4 else 128
    # Check length before int(), even if a caller raises the string-length limit.
    if len(prefix_part) > len(str(max_prefix)):
        invalid("prefix_length_out_of_range", f"Prefix length is outside 0..{max_prefix} for {family}.")
    prefix_len = int(prefix_part)
    if prefix_len > max_prefix:
        invalid("prefix_length_out_of_range", f"Prefix length is outside 0..{max_prefix} for {family}.")
    canonical_net: IPNetwork = ipaddress.ip_network((addr_obj, prefix_len), strict=False)
    start_int, end_int = network_interval(canonical_net)
    host_bits = int(addr_obj) ^ start_int
    return ParsedCIDR(
        input_cidr=raw_cidr, canonical_cidr=str(canonical_net), network=canonical_net,
        family=family, version=version, prefix_length=prefix_len,
        is_canonical_host_bits=host_bits == 0, host_bits_int=host_bits,
        host_bits_hex=hex(host_bits), start_int=start_int, end_int=end_int,
        address_count=end_int - start_int + 1,
    )


def parse_cidr(
    raw_cidr: object, *, strict: bool = True, limits: PlannerLimits = DEFAULT_LIMITS,
) -> ParsedCIDR:
    validate_strict(strict)
    parsed = inspect_cidr(raw_cidr, limits=limits)
    if strict and not parsed.is_canonical_host_bits:
        raise NonCanonicalCIDRError(
            input_cidr=parsed.input_cidr, canonical_cidr=parsed.canonical_cidr,
            host_bits_hex=parsed.host_bits_hex, family=parsed.family,
        )
    return parsed
