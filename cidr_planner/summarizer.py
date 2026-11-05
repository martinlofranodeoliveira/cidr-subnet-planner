"""Minimal CIDR cover of an exact IPv4/IPv6 address union."""

from __future__ import annotations

import ipaddress
from typing import Any, Sequence

from cidr_planner.errors import CIDRValidationError
from cidr_planner.limits import DEFAULT_LIMITS, PlannerLimits, enforce_count_limit, validate_strict
from cidr_planner.parser import IPNetwork, network_interval, parse_cidr


def _merge_intervals(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def _summarize_single_family(nets: list[IPNetwork], version: int) -> dict[str, Any]:
    intervals = _merge_intervals([network_interval(n) for n in nets])
    unique = sum(end - start + 1 for start, end in intervals)
    collapsed = list(ipaddress.collapse_addresses(nets))
    if unique != sum(n.num_addresses for n in collapsed):
        raise RuntimeError("Internal summarization invariant failure: address count mismatch.")
    return {
        "input_count": len(nets), "output_count": len(collapsed),
        "reduction_count": len(nets) - len(collapsed),
        "unique_addresses": str(unique) if version == 6 else unique,
        "unique_addresses_str": str(unique), "summarized_cidrs": [str(n) for n in collapsed],
    }


def summarize_cidrs(
    cidrs: Sequence[str], *, strict: bool = True, limits: PlannerLimits = DEFAULT_LIMITS,
) -> dict[str, Any]:
    validate_strict(strict)
    if not isinstance(cidrs, Sequence) or isinstance(cidrs, (str, bytes)):
        raise CIDRValidationError(code="invalid_cidr_collection", message="cidrs must be a sequence of CIDR strings.")
    enforce_count_limit("max_summarize_inputs", limits.max_summarize_inputs, len(cidrs))
    v4: list[IPNetwork] = []
    v6: list[IPNetwork] = []
    findings: list[dict[str, Any]] = []
    for index, raw in enumerate(cidrs):
        parsed = parse_cidr(raw, strict=strict, limits=limits)
        if not parsed.is_canonical_host_bits:
            findings.append({"index": index, "code": "non_canonical_host_bits", **parsed.to_dict()})
        (v4 if parsed.version == 4 else v6).append(parsed.network)
    r4, r6 = _summarize_single_family(v4, 4), _summarize_single_family(v6, 6)
    combined = r4["summarized_cidrs"] + r6["summarized_cidrs"]
    return {
        "input_count": len(cidrs), "output_count": len(combined),
        "reduction_count": len(cidrs) - len(combined), "summarized_cidrs": combined,
        "ipv4": r4, "ipv6": r6, "non_canonical_inputs": findings,
    }
