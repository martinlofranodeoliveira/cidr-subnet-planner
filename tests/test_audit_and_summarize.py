"""Tests for CIDR overlap auditing and minimal contiguous prefix summarization."""

from __future__ import annotations

import ipaddress
import unittest

from cidr_planner.auditor import audit_inventory
from cidr_planner.errors import NonCanonicalCIDRError, ResourceLimitExceededError
from cidr_planner.limits import PlannerLimits
from cidr_planner.parser import network_interval
from cidr_planner.summarizer import summarize_cidrs


def _independent_interval_union(cidrs: list[str]) -> list[tuple[int, int]]:
    """Independent interval union helper for test verification."""
    intervals = [network_interval(ipaddress.ip_network(c, strict=True)) for c in cidrs]
    intervals.sort()
    merged: list[tuple[int, int]] = []
    for start, end in intervals:
        if not merged or start > merged[-1][1] + 1:
            merged.append((start, end))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    return merged


class InventoryAuditTests(unittest.TestCase):
    """Verify overlap detection, collision classifications, and strict host-bit rejection."""

    def test_detects_nested_overlaps_duplicates_and_non_canonical_host_bits(self) -> None:
        inventory = [
            {"label": "vpc-supernet", "cidr": "10.10.0.0/16"},
            {"label": "app-subnet", "cidr": "10.10.4.0/22"},
            {"label": "app-subnet-dup", "cidr": "10.10.4.0/22"},
            {"label": "bad-host-bits", "cidr": "192.168.1.42/24"},
        ]

        # In strict=True mode, 192.168.1.42/24 is rejected with diagnostic pointing to 192.168.1.0/24
        strict_report = audit_inventory(inventory, strict=True)
        self.assertFalse(strict_report["valid"])
        self.assertFalse(strict_report["strict_validation_passed"])
        self.assertEqual(len(strict_report["non_canonical_inputs"]), 1)

        nc = strict_report["non_canonical_inputs"][0]
        self.assertEqual(nc["code"], "non_canonical_host_bits")
        self.assertEqual(nc["input_cidr"], "192.168.1.42/24")
        self.assertEqual(nc["canonical_cidr"], "192.168.1.0/24")
        self.assertTrue(nc["rejected"])

        # Verify all 3 collisions among the 3 canonical entries:
        # (0, 1): supernet_contains_subnet (10.10.0.0/16 vs 10.10.4.0/22)
        # (0, 2): supernet_contains_subnet (10.10.0.0/16 vs 10.10.4.0/22)
        # (1, 2): exact_duplicate (10.10.4.0/22 vs 10.10.4.0/22)
        collisions = strict_report["collisions"]
        self.assertEqual(len(collisions), 3)
        self.assertEqual(collisions[0]["classification"], "supernet_contains_subnet")
        self.assertEqual(collisions[0]["first_label"], "vpc-supernet")
        self.assertEqual(collisions[0]["second_label"], "app-subnet")
        self.assertEqual(collisions[0]["overlapping_addresses"], 1024)

        self.assertEqual(collisions[2]["classification"], "exact_duplicate")
        self.assertEqual(collisions[2]["first_label"], "app-subnet")
        self.assertEqual(collisions[2]["second_label"], "app-subnet-dup")
        self.assertEqual(collisions[2]["overlapping_addresses"], 1024)

    def test_subnet_contained_by_supernet_direction_and_ipv6_overlap(self) -> None:
        inventory = [
            {"label": "child-v4", "cidr": "10.10.4.0/22"},
            {"label": "parent-v4", "cidr": "10.10.0.0/16"},
            {"label": "child-v6", "cidr": "2001:db8:1:2::/64"},
            {"label": "parent-v6", "cidr": "2001:db8:1::/48"},
        ]
        report = audit_inventory(inventory, strict=True)
        self.assertEqual(len(report["collisions"]), 2)

        c_v4 = report["collisions"][0]
        self.assertEqual(c_v4["classification"], "subnet_contained_by_supernet")
        self.assertEqual(c_v4["inverse_classification"], "supernet_contains_subnet")
        self.assertEqual(c_v4["family"], "ipv4")
        self.assertEqual(c_v4["overlapping_addresses"], 1024)

        c_v6 = report["collisions"][1]
        self.assertEqual(c_v6["classification"], "subnet_contained_by_supernet")
        self.assertEqual(c_v6["family"], "ipv6")
        self.assertEqual(c_v6["overlapping_addresses"], str(1 << 64))

    def test_audit_inventory_resource_limits(self) -> None:
        limits = PlannerLimits(max_inventory_items=3)
        with self.assertRaises(ResourceLimitExceededError) as ctx:
            audit_inventory(["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"], limits=limits)
        self.assertEqual(ctx.exception.limit_name, "max_inventory_items")


class RouteSummarizationTests(unittest.TestCase):
    """Verify minimal contiguous prefix aggregation and exact interval conservation."""

    def test_contiguous_siblings_collapse_while_non_aligned_remain_separate(self) -> None:
        # Aligned sibling pair: 10.0.0.0/25 and 10.0.0.128/25 -> 10.0.0.0/24
        res_aligned = summarize_cidrs(["10.0.0.0/25", "10.0.0.128/25"])
        self.assertEqual(res_aligned["summarized_cidrs"], ["10.0.0.0/24"])
        self.assertEqual(res_aligned["reduction_count"], 1)
        self.assertEqual(res_aligned["ipv4"]["unique_addresses"], 256)

        # Non-aligned adjacent blocks: 10.0.0.128/25 and 10.0.1.0/25 must remain separate
        res_unaligned = summarize_cidrs(["10.0.0.128/25", "10.0.1.0/25"])
        self.assertEqual(res_unaligned["summarized_cidrs"], ["10.0.0.128/25", "10.0.1.0/25"])
        self.assertEqual(res_unaligned["reduction_count"], 0)
        self.assertEqual(res_unaligned["ipv4"]["unique_addresses"], 256)

    def test_multi_step_cascade_and_independent_interval_equivalence(self) -> None:
        inputs = [
            "10.5.0.0/26",
            "10.5.0.64/26",
            "10.5.0.128/25",
            "10.5.1.0/24",
            "10.5.1.128/26",  # redundant subnet inside 10.5.1.0/24
            "10.5.3.0/24",    # non-aligned with 10.5.0.0/23
        ]
        result = summarize_cidrs(inputs)
        expected = ["10.5.0.0/23", "10.5.3.0/24"]
        self.assertEqual(result["summarized_cidrs"], expected)

        # Independent interval union verification
        input_union = _independent_interval_union(inputs)
        output_union = _independent_interval_union(result["summarized_cidrs"])
        self.assertEqual(input_union, output_union)

    def test_summarizer_rejects_non_canonical_in_strict_mode(self) -> None:
        with self.assertRaises(NonCanonicalCIDRError):
            summarize_cidrs(["10.0.0.1/25", "10.0.0.128/25"], strict=True)


if __name__ == "__main__":
    unittest.main()
