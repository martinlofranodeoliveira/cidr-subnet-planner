"""Explicit usable-host profiles; no cloud-vendor reservations are assumed."""

from __future__ import annotations

import ipaddress
from typing import Any

from cidr_planner.errors import CIDRValidationError
from cidr_planner.parser import IPNetwork, parse_cidr

PROFILE_STANDARD_IPV4 = "standard_ipv4"
PROFILE_RFC3021_P2P = "rfc3021_p2p"
PROFILE_IPV6 = "ipv6"
VALID_PROFILES: frozenset[str] = frozenset({PROFILE_STANDARD_IPV4, PROFILE_RFC3021_P2P, PROFILE_IPV6})


def _validate_version(version: object) -> int:
    if type(version) is not int or version not in (4, 6):
        raise CIDRValidationError(code="invalid_ip_version", message="version must be the integer 4 or 6.")
    return version


def default_profile_for_version(version: int) -> str:
    _validate_version(version)
    return PROFILE_STANDARD_IPV4 if version == 4 else PROFILE_IPV6


def validate_profile_for_version(profile: object, version: int) -> str:
    _validate_version(version)
    if not isinstance(profile, str) or profile not in VALID_PROFILES:
        raise CIDRValidationError(
            code="invalid_addressing_profile",
            message="Profile must be standard_ipv4, rfc3021_p2p, or ipv6.",
        )
    if (version == 4 and profile == PROFILE_IPV6) or (version == 6 and profile != PROFILE_IPV6):
        raise CIDRValidationError(
            code="profile_family_mismatch", message="Addressing profile does not match the address family.",
            profile=profile, family=f"ipv{version}",
        )
    return profile


def calculate_addressing_metrics(net_or_cidr: IPNetwork | str, profile: str | None = None) -> dict[str, Any]:
    if isinstance(net_or_cidr, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        net = net_or_cidr
    else:
        net = parse_cidr(net_or_cidr, strict=True).network
    version = net.version
    prefix = net.prefixlen
    resolved = default_profile_for_version(version) if profile is None else validate_profile_for_version(profile, version)
    total = net.num_addresses
    if version == 6:
        usable = total
        first = str(net.network_address)
        last = str(net.broadcast_address)
    elif prefix == 32:
        usable = 1
        first = last = str(net.network_address)
    elif prefix == 31:
        usable = 2 if resolved == PROFILE_RFC3021_P2P else 0
        first = str(net.network_address) if usable else None
        last = str(net.broadcast_address) if usable else None
    else:
        usable = total - 2
        first = str(ipaddress.IPv4Address(int(net.network_address) + 1))
        last = str(ipaddress.IPv4Address(int(net.broadcast_address) - 1))
    result: dict[str, Any] = {
        "cidr": str(net), "family": f"ipv{version}", "prefix_length": prefix,
        "addressing_profile": resolved, "network_address": str(net.network_address),
        "first_usable_address": first, "last_usable_address": last,
        "total_addresses": str(total) if version == 6 else total,
        "usable_hosts": str(usable) if version == 6 else usable,
        "total_addresses_str": str(total), "usable_hosts_str": str(usable),
    }
    result["last_address" if version == 6 else "broadcast_address"] = str(net.broadcast_address)
    return result


def prefix_length_for_required_hosts(required_hosts: int, *, version: int, profile: str | None = None) -> int:
    """Most specific prefix with sufficient usable capacity, including /32 and /128."""
    _validate_version(version)
    if type(required_hosts) is not int or required_hosts < 1:
        raise CIDRValidationError(code="invalid_required_hosts", message="required_hosts must be a positive integer.")
    resolved = default_profile_for_version(version) if profile is None else validate_profile_for_version(profile, version)
    capacity = (1 << 32) - 2 if version == 4 else 1 << 128
    if required_hosts > capacity:
        # Do not stringify an arbitrarily large caller-supplied integer.
        raise CIDRValidationError(
            code="required_hosts_exceeds_family_capacity",
            message="required_hosts exceeds the address family's supported usable capacity.",
            family=f"ipv{version}",
        )
    if version == 6:
        return 128 - (required_hosts - 1).bit_length()
    if required_hosts == 1:
        return 32
    if required_hosts == 2 and resolved == PROFILE_RFC3021_P2P:
        return 31
    return 32 - max(2, (required_hosts + 1).bit_length())


# Preserve the original exported spelling for development 0.1.0 callers.
prefix_length_for_Required_hosts = prefix_length_for_required_hosts
