"""Bounded explicit scope snapshot, not an IANA registry or reachability test."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

from cidr_planner.parser import IPNetwork, network_interval, parse_cidr


@dataclass(frozen=True, slots=True)
class SpecialScopeRange:
    cidr: str
    scope: str
    rfc: str
    description: str
    start_int: int
    end_int: int


def _build_range(cidr: str, scope: str, rfc: str, description: str) -> SpecialScopeRange:
    start, end = network_interval(ipaddress.ip_network(cidr, strict=True))
    return SpecialScopeRange(cidr, scope, rfc, description, start, end)


# Disjoint ranges; docs/contract.md lists the complete selected snapshot.
IPV4_SPECIAL_RANGES: tuple[SpecialScopeRange, ...] = (
    _build_range("0.0.0.0/8", "this_network", "RFC 1122 / RFC 6890", "This host on this network"),
    _build_range("10.0.0.0/8", "private_rfc1918", "RFC 1918", "Private-Use networks"),
    _build_range("100.64.0.0/10", "shared_cgnat", "RFC 6598", "Shared Address Space (CGNAT)"),
    _build_range("127.0.0.0/8", "loopback", "RFC 1122", "Loopback"),
    _build_range("169.254.0.0/16", "link_local", "RFC 3927", "Link-Local"),
    _build_range("172.16.0.0/12", "private_rfc1918", "RFC 1918", "Private-Use networks"),
    _build_range("192.0.0.0/24", "ietf_protocol_assignments", "RFC 6890", "IETF Protocol Assignments"),
    _build_range("192.0.2.0/24", "documentation", "RFC 5737", "TEST-NET-1"),
    _build_range("192.168.0.0/16", "private_rfc1918", "RFC 1918", "Private-Use networks"),
    _build_range("198.18.0.0/15", "benchmarking", "RFC 2544", "Benchmarking"),
    _build_range("198.51.100.0/24", "documentation", "RFC 5737", "TEST-NET-2"),
    _build_range("203.0.113.0/24", "documentation", "RFC 5737", "TEST-NET-3"),
    _build_range("224.0.0.0/4", "multicast", "RFC 5771", "IPv4 Multicast"),
    _build_range("240.0.0.0/4", "future_reserved", "RFC 1112 / RFC 6890", "Future Use and Limited Broadcast"),
)
IPV6_SPECIAL_RANGES: tuple[SpecialScopeRange, ...] = (
    _build_range("::/128", "unspecified", "RFC 4291", "Unspecified"),
    _build_range("::1/128", "loopback", "RFC 4291", "Loopback"),
    _build_range("::ffff:0:0/96", "ipv4_mapped", "RFC 4291", "IPv4-mapped"),
    _build_range("64:ff9b::/96", "ipv4_translated", "RFC 6052", "Translation Well-Known Prefix"),
    _build_range("64:ff9b:1::/48", "ipv4_translated", "RFC 8215", "Translation Local-Use Prefix"),
    _build_range("100::/64", "discard_only", "RFC 6666", "Discard-Only"),
    _build_range("2001::/32", "teredo", "RFC 4380", "Teredo"),
    _build_range("2001:2::/48", "benchmarking", "RFC 5180", "Benchmarking"),
    _build_range("2001:db8::/32", "documentation", "RFC 3849", "Documentation"),
    _build_range("fc00::/7", "unique_local", "RFC 4193", "Unique-Local Unicast"),
    _build_range("fe80::/10", "link_local", "RFC 4291", "Link-Local Unicast"),
    _build_range("ff00::/8", "multicast", "RFC 4291", "IPv6 Multicast"),
)
FALLBACK_SCOPE = "other_or_reserved"
MIXED_SCOPE = "mixed"


@dataclass(frozen=True, slots=True)
class ScopeClassification:
    cidr: str
    family: str
    scope: str
    matched_scopes: tuple[str, ...]
    matched_ranges: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "cidr": self.cidr, "family": self.family, "scope": self.scope,
            "matched_scopes": list(self.matched_scopes), "matched_ranges": list(self.matched_ranges),
        }


def classify_prefix_scope(net_or_cidr: IPNetwork | str) -> ScopeClassification:
    """Intersect all selected ranges; reject host bits in standalone string inputs."""
    if isinstance(net_or_cidr, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        net = net_or_cidr
    else:
        net = parse_cidr(net_or_cidr, strict=True).network
    start, end = network_interval(net)
    table = IPV4_SPECIAL_RANGES if net.version == 4 else IPV6_SPECIAL_RANGES
    covered = 0
    scopes: list[str] = []
    ranges: list[str] = []
    for entry in table:
        left, right = max(start, entry.start_int), min(end, entry.end_int)
        if left <= right:
            covered += right - left + 1
            if entry.scope not in scopes:
                scopes.append(entry.scope)
            ranges.append(entry.cidr)
    if covered < end - start + 1:
        scopes.append(FALLBACK_SCOPE)
    return ScopeClassification(
        cidr=str(net), family=f"ipv{net.version}",
        scope=scopes[0] if len(scopes) == 1 else MIXED_SCOPE,
        matched_scopes=tuple(scopes), matched_ranges=tuple(ranges),
    )
