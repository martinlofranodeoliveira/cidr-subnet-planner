"""Inventory host-bit diagnostics, bounded scope tagging, and all pair collisions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from cidr_planner.errors import CIDRValidationError
from cidr_planner.limits import DEFAULT_LIMITS, PlannerLimits, enforce_count_limit, validate_label, validate_strict
from cidr_planner.parser import ParsedCIDR, inspect_cidr
from cidr_planner.scopes import classify_prefix_scope


@dataclass(frozen=True, slots=True)
class InventoryEntry:
    label: str
    cidr: str


def _normalize_entry(
    item: InventoryEntry | dict[str, Any] | tuple[str, str] | str,
    index: int, limits: PlannerLimits,
) -> InventoryEntry:
    if isinstance(item, InventoryEntry):
        label, cidr = item.label, item.cidr
    elif isinstance(item, dict):
        if "cidr" not in item:
            raise CIDRValidationError(code="missing_cidr_field", message="Inventory entry requires cidr.", index=index)
        label, cidr = item.get("label", item.get("name", f"entry-{index}")), item["cidr"]
    elif isinstance(item, tuple) and len(item) == 2:
        label, cidr = item
    elif isinstance(item, str):
        label, cidr = f"entry-{index}", item
    else:
        raise CIDRValidationError(code="invalid_inventory_entry", message="Entry must be an InventoryEntry, dict, pair tuple, or CIDR string.", index=index)
    return InventoryEntry(validate_label(label, field_name=f"entries[{index}].label", limits=limits), cidr)


def _classify_pair_overlap(first: ParsedCIDR, second: ParsedCIDR) -> tuple[str, str, str, int] | None:
    if first.version != second.version or first.end_int < second.start_int or second.end_int < first.start_int:
        return None
    if first.prefix_length == second.prefix_length:
        return "exact_duplicate", "exact_duplicate", first.canonical_cidr, first.address_count
    if first.prefix_length > second.prefix_length:
        return "subnet_contained_by_supernet", "supernet_contains_subnet", first.canonical_cidr, first.address_count
    return "supernet_contains_subnet", "subnet_contained_by_supernet", second.canonical_cidr, second.address_count


def audit_inventory(
    entries: Sequence[InventoryEntry | dict[str, Any] | tuple[str, str] | str], *,
    strict: bool = False, limits: PlannerLimits = DEFAULT_LIMITS,
) -> dict[str, Any]:
    """Flag host bits always; strict mode excludes flagged entries from collisions.

    Malformed inputs raise structured exceptions rather than producing a partial audit.
    Pair orientation and output order follow the original inventory indices.
    """
    validate_strict(strict)
    if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes)):
        raise CIDRValidationError(code="invalid_inventory_collection", message="Inventory entries must be a sequence.")
    enforce_count_limit("max_inventory_items", limits.max_inventory_items, len(entries))
    normalized = [_normalize_entry(item, index, limits) for index, item in enumerate(entries)]
    records: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    active: list[tuple[int, InventoryEntry, ParsedCIDR]] = []
    for index, entry in enumerate(normalized):
        parsed = inspect_cidr(entry.cidr, limits=limits)
        scope = classify_prefix_scope(parsed.network)
        canonical = parsed.is_canonical_host_bits
        if not canonical:
            findings.append({
                "index": index, "label": entry.label, "code": "non_canonical_host_bits",
                "input_cidr": parsed.input_cidr, "canonical_cidr": parsed.canonical_cidr,
                "family": parsed.family, "host_bits_hex": parsed.host_bits_hex, "rejected": strict,
                "message": f"Allocation '{entry.label}' has non-zero host bits ({parsed.host_bits_hex}); canonical network is '{parsed.canonical_cidr}'.",
            })
        records.append({
            "index": index, "label": entry.label, "input_cidr": parsed.input_cidr,
            "canonical_cidr": parsed.canonical_cidr, "family": parsed.family,
            "prefix_length": parsed.prefix_length, "is_canonical_host_bits": canonical,
            "host_bits_hex": parsed.host_bits_hex,
            "status": "canonical" if canonical else ("rejected_non_canonical" if strict else "non_canonical_flagged"),
            "scope": scope.scope, "matched_scopes": list(scope.matched_scopes),
            "matched_ranges": list(scope.matched_ranges),
            "address_count": str(parsed.address_count) if parsed.version == 6 else parsed.address_count,
            "address_count_str": str(parsed.address_count),
        })
        if canonical or not strict:
            active.append((index, entry, parsed))
    collisions: list[dict[str, Any]] = []
    counts = {"exact_duplicate": 0, "subnet_contained_by_supernet": 0, "supernet_contains_subnet": 0}
    for position, (index_a, entry_a, parsed_a) in enumerate(active):
        for index_b, entry_b, parsed_b in active[position + 1:]:
            overlap = _classify_pair_overlap(parsed_a, parsed_b)
            if overlap is None:
                continue
            enforce_count_limit("max_collision_results", limits.max_collision_results, len(collisions) + 1)
            classification, inverse, cidr, count = overlap
            counts[classification] += 1
            collisions.append({
                "classification": classification, "inverse_classification": inverse, "family": parsed_a.family,
                "first_index": index_a, "second_index": index_b, "first_label": entry_a.label,
                "second_label": entry_b.label, "first_cidr": parsed_a.canonical_cidr,
                "second_cidr": parsed_b.canonical_cidr, "overlap_cidr": cidr,
                "overlapping_addresses": str(count) if parsed_a.version == 6 else count,
                "overlapping_addresses_str": str(count),
            })
    return {
        "strict_mode": strict, "strict_validation_passed": not findings,
        "valid": not findings and not collisions,
        "summary": {
            "total_entries": len(normalized), "ipv4_entries": sum(r["family"] == "ipv4" for r in records),
            "ipv6_entries": sum(r["family"] == "ipv6" for r in records),
            "non_canonical_count": len(findings), "collision_count": len(collisions), "collision_counts_by_type": counts,
        },
        "entries": records, "non_canonical_inputs": findings, "collisions": collisions,
    }
