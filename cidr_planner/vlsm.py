"""Deterministic VLSM carving, reservation validation, and exact free inventory."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Sequence

from cidr_planner.errors import CIDRValidationError, VLSMAllocationError
from cidr_planner.limits import DEFAULT_LIMITS, PlannerLimits, enforce_count_limit, validate_label
from cidr_planner.parser import IPNetwork, network_interval, parse_cidr
from cidr_planner.profiles import (
    calculate_addressing_metrics, default_profile_for_version,
    prefix_length_for_required_hosts, validate_profile_for_version,
)
from cidr_planner.scopes import classify_prefix_scope


@dataclass(frozen=True, slots=True)
class SubnetDemand:
    name: str
    prefix_length: int | None = None
    required_hosts: int | None = None
    addressing_profile: str | None = None


@dataclass(frozen=True, slots=True)
class _ResolvedDemand:
    name: str
    requested_prefix_length: int
    required_hosts: int | None
    addressing_profile: str
    original_index: int


def _normalize_demand(
    item: SubnetDemand | dict[str, Any], index: int, parent_version: int,
    default_profile: str, limits: PlannerLimits,
) -> _ResolvedDemand:
    if isinstance(item, SubnetDemand):
        raw_name, raw_prefix, raw_hosts, raw_profile = (
            item.name, item.prefix_length, item.required_hosts, item.addressing_profile,
        )
    elif isinstance(item, dict):
        if "name" not in item:
            raise CIDRValidationError(code="missing_demand_name", message="Demand requires a name.", index=index)
        raw_name = item["name"]
        raw_prefix, raw_hosts, raw_profile = item.get("prefix_length"), item.get("required_hosts"), item.get("addressing_profile")
    else:
        raise CIDRValidationError(code="invalid_demand_entry", message="Demand must be a SubnetDemand or dict.", index=index)
    name = validate_label(raw_name, field_name=f"demands[{index}].name", limits=limits)
    profile = default_profile if raw_profile is None else validate_profile_for_version(raw_profile, parent_version)
    if (raw_prefix is not None) == (raw_hosts is not None):
        raise CIDRValidationError(
            code="invalid_demand_sizing", message="Demand must specify exactly one non-null prefix_length or required_hosts.",
            demand_name=name,
        )
    if raw_prefix is not None:
        if type(raw_prefix) is not int:
            raise CIDRValidationError(code="invalid_demand_prefix_length", message="prefix_length must be an integer.", demand_name=name)
        max_prefix = 32 if parent_version == 4 else 128
        if not 0 <= raw_prefix <= max_prefix:
            raise CIDRValidationError(
                code="demand_prefix_out_of_range", message=f"Demand prefix_length must be within 0..{max_prefix}.",
                demand_name=name,
            )
        prefix, hosts = raw_prefix, None
    else:
        prefix = prefix_length_for_required_hosts(raw_hosts, version=parent_version, profile=profile)
        hosts = raw_hosts
    return _ResolvedDemand(name, prefix, hosts, profile, index)


def _split_excluding_target(block: IPNetwork, target: IPNetwork) -> list[IPNetwork]:
    """Subtract a contained canonical target in at most 128 binary splits."""
    remaining: list[IPNetwork] = []
    current = block
    target_start, target_end = network_interval(target)
    constructor = ipaddress.IPv4Network if block.version == 4 else ipaddress.IPv6Network
    while current.prefixlen < target.prefixlen:
        start, end = network_interval(current)
        mid = (start + end) // 2
        lower = constructor((start, current.prefixlen + 1))
        upper = constructor((mid + 1, current.prefixlen + 1))
        if target_end <= mid:
            remaining.append(upper)
            current = lower
        elif target_start > mid:
            remaining.append(lower)
            current = upper
        else:
            raise RuntimeError("Internal error: canonical target straddles a binary split.")
    if current != target:
        raise RuntimeError("Internal error: subtraction target is not contained.")
    return sorted(remaining, key=lambda n: int(n.network_address))


def _carve_lowest_prefix(block: IPNetwork, desired_prefix: int) -> tuple[IPNetwork, list[IPNetwork]]:
    constructor = ipaddress.IPv4Network if block.version == 4 else ipaddress.IPv6Network
    allocated = constructor((int(block.network_address), desired_prefix))
    return allocated, _split_excluding_target(block, allocated)


def plan_vlsm(
    parent_supernet: str, demands: Sequence[SubnetDemand | dict[str, Any]], *,
    reserved_cidrs: Sequence[str] = (), default_addressing_profile: str | None = None,
    limits: PlannerLimits = DEFAULT_LIMITS,
) -> dict[str, Any]:
    """Allocate largest-first, name-tied, lowest-aligned-first; stop at first failure.

    Failed plans contain provisional successful allocations, unchanged reservations,
    exact remaining free space, and the first unfulfilled demand. Nothing is applied.
    """
    parent = parse_cidr(parent_supernet, strict=True, limits=limits)
    version, family = parent.version, parent.family
    max_bits = 32 if version == 4 else 128
    default_profile = (
        default_profile_for_version(version) if default_addressing_profile is None
        else validate_profile_for_version(default_addressing_profile, version)
    )
    if not isinstance(demands, Sequence) or isinstance(demands, (str, bytes)):
        raise CIDRValidationError(code="invalid_demands_collection", message="demands must be a sequence.")
    if not isinstance(reserved_cidrs, Sequence) or isinstance(reserved_cidrs, (str, bytes)):
        raise CIDRValidationError(code="invalid_reserved_collection", message="reserved_cidrs must be a sequence.")
    enforce_count_limit("max_vlsm_demands", limits.max_vlsm_demands, len(demands))
    enforce_count_limit("max_reserved_cidrs", limits.max_reserved_cidrs, len(reserved_cidrs))

    reservations = [parse_cidr(raw, strict=True, limits=limits) for raw in reserved_cidrs]
    for res in reservations:
        if res.version != version:
            raise VLSMAllocationError(
                code="mixed_family_reservation", message="Reservation and parent families differ.",
                reserved_cidr=res.canonical_cidr, parent_supernet=parent.canonical_cidr,
            )
        if res.start_int < parent.start_int or res.end_int > parent.end_int:
            raise VLSMAllocationError(
                code="reservation_outside_supernet", message="Reservation is outside the parent supernet.",
                reserved_cidr=res.canonical_cidr, parent_supernet=parent.canonical_cidr,
            )
    # Keep the original pair order for deterministic reservation diagnostics.
    for i, first in enumerate(reservations):
        for second in reservations[i + 1:]:
            if first.start_int <= second.end_int and second.start_int <= first.end_int:
                raise VLSMAllocationError(
                    code="overlapping_reservations", message="Reserved CIDRs overlap.",
                    first_reserved_cidr=first.canonical_cidr, second_reserved_cidr=second.canonical_cidr,
                )
    reservations.sort(key=lambda r: (r.start_int, r.prefix_length))
    resolved: list[_ResolvedDemand] = []
    names: set[str] = set()
    for index, item in enumerate(demands):
        demand = _normalize_demand(item, index, version, default_profile, limits)
        if demand.name in names:
            raise CIDRValidationError(code="duplicate_demand_name", message="Demand names must be unique after trimming.", demand_name=demand.name)
        names.add(demand.name)
        resolved.append(demand)
    resolved.sort(key=lambda d: (d.requested_prefix_length, d.name))

    def check_free(blocks: list[IPNetwork]) -> None:
        enforce_count_limit("max_free_blocks_output", limits.max_free_blocks_output, len(blocks))

    def count_value(count: int) -> int | str:
        return str(count) if version == 6 else count

    def requested_hosts(demand: _ResolvedDemand) -> int | str | None:
        return None if demand.required_hosts is None else count_value(demand.required_hosts)

    free: list[IPNetwork] = [parent.network]
    for res in reservations:
        next_free: list[IPNetwork] = []
        for block in free:
            start, end = network_interval(block)
            if res.end_int < start or res.start_int > end:
                next_free.append(block)
            else:
                next_free.extend(_split_excluding_target(block, res.network))
            check_free(next_free)
        free = next_free

    allocations: list[dict[str, Any]] = []
    diagnostic: dict[str, Any] | None = None
    for demand in resolved:
        prefix = demand.requested_prefix_length
        chosen = next((i for i, block in enumerate(free) if block.prefixlen <= prefix), None)
        if chosen is None:
            largest = min(free, key=lambda b: (b.prefixlen, int(b.network_address))) if free else None
            largest_count = largest.num_addresses if largest is not None else 0
            required_count = 1 << (max_bits - prefix)
            total_free = sum(b.num_addresses for b in free)
            diagnostic = {
                "code": "insufficient_contiguous_space",
                "message": (
                    f"Cannot satisfy demand '{demand.name}' requiring /{prefix} inside '{parent.canonical_cidr}'; "
                    f"largest remaining aligned free block is {str(largest) if largest is not None else 'none'}."
                ),
                "unfulfilled_demand": {
                    "name": demand.name, "requested_prefix_length": prefix,
                    "required_hosts": requested_hosts(demand), "addressing_profile": demand.addressing_profile,
                    "required_addresses": count_value(required_count), "required_addresses_str": str(required_count),
                },
                "largest_remaining_free_block": str(largest) if largest is not None else None,
                "largest_remaining_free_prefix_length": largest.prefixlen if largest is not None else None,
                "largest_remaining_free_addresses": count_value(largest_count),
                "largest_remaining_free_addresses_str": str(largest_count),
                "total_remaining_free_addresses": count_value(total_free),
                "total_remaining_free_addresses_str": str(total_free),
            }
            break
        carved, remainder = _carve_lowest_prefix(free[chosen], prefix)
        free = free[:chosen] + remainder + free[chosen + 1:]
        check_free(free)
        metrics = calculate_addressing_metrics(carved, profile=demand.addressing_profile)
        allocation: dict[str, Any] = {
            "name": demand.name, "cidr": str(carved), "family": family,
            "prefix_length": carved.prefixlen, "requested_prefix_length": prefix,
            "required_hosts": requested_hosts(demand), "addressing_profile": demand.addressing_profile,
            "scope": classify_prefix_scope(carved).scope,
        }
        for key in (
            "network_address", "first_usable_address", "last_usable_address",
            "total_addresses", "usable_hosts", "total_addresses_str", "usable_hosts_str",
        ):
            allocation[key] = metrics[key]
        allocations.append(allocation)

    check_free(free)
    reserved_total = sum(r.address_count for r in reservations)
    allocated_total = sum(1 << (max_bits - a["prefix_length"]) for a in allocations)
    free_total = sum(b.num_addresses for b in free)
    if reserved_total + allocated_total + free_total != parent.address_count:
        raise RuntimeError("Internal VLSM conservation invariant failure.")
    accounting: dict[str, Any] = {"conservation_verified": True}
    for key, value in (
        ("parent_total_addresses", parent.address_count), ("reserved_addresses", reserved_total),
        ("allocated_addresses", allocated_total), ("free_addresses", free_total),
    ):
        accounting[key] = count_value(value)
        accounting[key + "_str"] = str(value)
    return {
        "status": "allocated" if diagnostic is None else "insufficient_contiguous_space",
        "valid": diagnostic is None, "parent_supernet": parent.canonical_cidr, "family": family,
        "parent_prefix_length": parent.prefix_length, "parent_scope": classify_prefix_scope(parent.network).scope,
        "parent_total_addresses": count_value(parent.address_count),
        "parent_total_addresses_str": str(parent.address_count),
        "reserved_cidrs": [r.canonical_cidr for r in reservations], "allocations": allocations,
        "free_blocks": [str(b) for b in free],
        "free_block_details": [
            {"cidr": str(b), "prefix_length": b.prefixlen, "total_addresses": count_value(b.num_addresses),
             "total_addresses_str": str(b.num_addresses)} for b in free
        ],
        "accounting": accounting, "diagnostic": diagnostic,
    }
