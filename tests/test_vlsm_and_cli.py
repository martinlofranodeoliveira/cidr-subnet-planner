"""Tests for deterministic VLSM carving, exact partition invariants, exhaustion, and CLI."""

from __future__ import annotations

import io
import ipaddress
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout

from cidr_planner.cli import build_demo_report, main
from cidr_planner.errors import CIDRValidationError, VLSMAllocationError
from cidr_planner.parser import network_interval
from cidr_planner.vlsm import plan_vlsm


def _verify_exact_supernet_partition(
    test_case: unittest.TestCase,
    parent_cidr: str,
    allocated_cidrs: list[str],
    reserved_cidrs: list[str],
    free_cidrs: list[str],
) -> None:
    """Independently verify that allocated + reserved + free forms an exact disjoint
    partition of parent_cidr with zero overlaps and zero uncounted gaps.
    """
    parent_net = ipaddress.ip_network(parent_cidr, strict=True)
    p_start, p_end = network_interval(parent_net)

    tagged_intervals: list[tuple[int, int, str]] = []
    for c in allocated_cidrs:
        net = ipaddress.ip_network(c, strict=True)
        s, e = network_interval(net)
        test_case.assertTrue(s >= p_start and e <= p_end, f"Allocated {c} outside {parent_cidr}")
        tagged_intervals.append((s, e, f"alloc:{c}"))

    for c in reserved_cidrs:
        net = ipaddress.ip_network(c, strict=True)
        s, e = network_interval(net)
        test_case.assertTrue(s >= p_start and e <= p_end, f"Reserved {c} outside {parent_cidr}")
        tagged_intervals.append((s, e, f"res:{c}"))

    for c in free_cidrs:
        net = ipaddress.ip_network(c, strict=True)
        s, e = network_interval(net)
        test_case.assertTrue(s >= p_start and e <= p_end, f"Free {c} outside {parent_cidr}")
        tagged_intervals.append((s, e, f"free:{c}"))

    tagged_intervals.sort(key=lambda item: (item[0], item[1]))
    test_case.assertGreater(len(tagged_intervals), 0)
    test_case.assertEqual(tagged_intervals[0][0], p_start, "Partition does not start at supernet base")

    for idx in range(len(tagged_intervals) - 1):
        cur_s, cur_e, cur_tag = tagged_intervals[idx]
        nxt_s, nxt_e, nxt_tag = tagged_intervals[idx + 1]
        test_case.assertLess(
            cur_e,
            nxt_s,
            f"Overlap detected between {cur_tag} [{cur_s}..{cur_e}] and {nxt_tag} [{nxt_s}..{nxt_e}]",
        )
        test_case.assertEqual(
            cur_e + 1,
            nxt_s,
            f"Uncounted gap detected between {cur_tag} and {nxt_tag}",
        )

    test_case.assertEqual(tagged_intervals[-1][1], p_end, "Partition does not end at supernet broadcast")
    total_covered = sum((e - s) + 1 for s, e, _ in tagged_intervals)
    test_case.assertEqual(total_covered, (p_end - p_start) + 1)


class VLSMPlannerTests(unittest.TestCase):
    """Verify VLSM packing, deterministic ordering, exact partition invariants, and exhaustion."""

    def test_mixed_size_vlsm_with_reserved_middle_block_and_partition_invariant(self) -> None:
        parent = "10.100.0.0/22"  # 1024 addresses: 10.100.0.0 .. 10.100.3.255
        reserved = ["10.100.1.0/24"]  # Middle /24 pre-reserved
        demands = [
            {"name": "small-mgmt", "prefix_length": 28},
            {"name": "web-tier", "prefix_length": 24},
            {"name": "db-tier", "prefix_length": 26},
            {"name": "app-tier", "prefix_length": 25},
            {"name": "auth-tier", "prefix_length": 26},
        ]

        plan = plan_vlsm(parent, demands, reserved_cidrs=reserved)
        self.assertTrue(plan["valid"])
        self.assertEqual(plan["status"], "allocated")
        self.assertIsNone(plan["diagnostic"])

        # Deterministic order: /24 (web-tier), /25 (app-tier), /26 (auth-tier, then db-tier), /28 (small-mgmt)
        alloc_names = [a["name"] for a in plan["allocations"]]
        self.assertEqual(
            alloc_names,
            ["web-tier", "app-tier", "auth-tier", "db-tier", "small-mgmt"],
        )

        # Lowest available aligned addresses avoiding reserved 10.100.1.0/24:
        # - web-tier (/24) gets 10.100.0.0/24
        # - 10.100.1.0/24 is reserved
        # - app-tier (/25) gets 10.100.2.0/25
        # - auth-tier (/26) gets 10.100.2.128/26
        # - db-tier (/26) gets 10.100.2.192/26
        # - small-mgmt (/28) gets 10.100.3.0/28
        alloc_map = {a["name"]: a["cidr"] for a in plan["allocations"]}
        self.assertEqual(alloc_map["web-tier"], "10.100.0.0/24")
        self.assertEqual(alloc_map["app-tier"], "10.100.2.0/25")
        self.assertEqual(alloc_map["auth-tier"], "10.100.2.128/26")
        self.assertEqual(alloc_map["db-tier"], "10.100.2.192/26")
        self.assertEqual(alloc_map["small-mgmt"], "10.100.3.0/28")

        # Verify exact interval coverage invariant across allocated + reserved + free_blocks
        _verify_exact_supernet_partition(
            self,
            parent,
            [a["cidr"] for a in plan["allocations"]],
            plan["reserved_cidrs"],
            plan["free_blocks"],
        )

    def test_ipv6_vlsm_carving_and_partition_invariant(self) -> None:
        parent = "2001:db8:cafe::/48"
        reserved = ["2001:db8:cafe:4000::/50"]
        demands = [
            {"name": "v6-core", "prefix_length": 50},
            {"name": "v6-edge-b", "prefix_length": 52},
            {"name": "v6-edge-a", "prefix_length": 52},
        ]
        plan = plan_vlsm(parent, demands, reserved_cidrs=reserved)
        self.assertTrue(plan["valid"])
        self.assertEqual(
            [a["name"] for a in plan["allocations"]],
            ["v6-core", "v6-edge-a", "v6-edge-b"],
        )
        _verify_exact_supernet_partition(
            self,
            parent,
            [a["cidr"] for a in plan["allocations"]],
            plan["reserved_cidrs"],
            plan["free_blocks"],
        )

    def test_exhaustion_returns_structured_insufficient_contiguous_space_diagnostic(self) -> None:
        # Parent /24 (256 addresses) with 10.0.0.64/26 reserved -> free blocks are 10.0.0.0/26 and 10.0.0.128/25
        # Requesting two /25 blocks: first /25 takes 10.0.0.128/25, second /25 fails because only 10.0.0.0/26 remains
        plan = plan_vlsm(
            parent_supernet="10.0.0.0/24",
            reserved_cidrs=["10.0.0.64/26"],
            demands=[
                {"name": "subnet-alpha", "prefix_length": 25},
                {"name": "subnet-beta", "prefix_length": 25},
            ],
        )
        self.assertFalse(plan["valid"])
        self.assertEqual(plan["status"], "insufficient_contiguous_space")
        diag = plan["diagnostic"]
        self.assertIsNotNone(diag)
        self.assertEqual(diag["code"], "insufficient_contiguous_space")
        self.assertEqual(diag["unfulfilled_demand"]["name"], "subnet-beta")
        self.assertEqual(diag["unfulfilled_demand"]["requested_prefix_length"], 25)
        self.assertEqual(diag["largest_remaining_free_block"], "10.0.0.0/26")
        self.assertEqual(diag["largest_remaining_free_prefix_length"], 26)
        self.assertEqual(diag["largest_remaining_free_addresses"], 64)

    def test_rejects_invalid_reservations_and_duplicate_demand_names(self) -> None:
        # Outside supernet
        with self.assertRaises(VLSMAllocationError) as ctx1:
            plan_vlsm("10.0.0.0/24", [], reserved_cidrs=["10.0.1.0/24"])
        self.assertEqual(ctx1.exception.code, "reservation_outside_supernet")

        # Mixed family reservation
        with self.assertRaises(VLSMAllocationError) as ctx2:
            plan_vlsm("10.0.0.0/24", [], reserved_cidrs=["2001:db8::/64"])
        self.assertEqual(ctx2.exception.code, "mixed_family_reservation")

        # Overlapping reservations
        with self.assertRaises(VLSMAllocationError) as ctx3:
            plan_vlsm("10.0.0.0/24", [], reserved_cidrs=["10.0.0.0/25", "10.0.0.64/26"])
        self.assertEqual(ctx3.exception.code, "overlapping_reservations")

        # Duplicate demand name
        with self.assertRaises(CIDRValidationError) as ctx4:
            plan_vlsm(
                "10.0.0.0/24",
                [
                    {"name": "dup", "prefix_length": 26},
                    {"name": "dup", "prefix_length": 27},
                ],
            )
        self.assertEqual(ctx4.exception.code, "duplicate_demand_name")


class CLIDemoTests(unittest.TestCase):
    """Verify CLI demo output in JSON and text modes."""

    def test_cli_demo_json_and_text_outputs(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            exit_code = main(["demo"])
        self.assertEqual(exit_code, 0)
        parsed = json.loads(buf.getvalue())
        self.assertEqual(parsed, build_demo_report())
        self.assertEqual(parsed["inventory_audit"]["summary"]["collision_count"], 4)
        self.assertTrue(parsed["vlsm_plan"]["valid"])

        text_buf = io.StringIO()
        with redirect_stdout(text_buf):
            text_code = main(["demo", "--format", "text"])
        self.assertEqual(text_code, 0)
        self.assertIn("Inventory Audit", text_buf.getvalue())
        self.assertIn("Deterministic VLSM Plan", text_buf.getvalue())

    def test_cli_error_handling_emits_structured_stderr_json(self) -> None:
        err_buf = io.StringIO()
        with redirect_stderr(err_buf):
            # Summarize invalid CIDR from stdin
            in_buf = io.StringIO('["10.0.0.5/24"]')
            orig_stdin = __import__("sys").stdin
            try:
                __import__("sys").stdin = in_buf
                code = main(["summarize", "--input", "-"])
            finally:
                __import__("sys").stdin = orig_stdin
        self.assertEqual(code, 2)
        err_json = json.loads(err_buf.getvalue())
        self.assertFalse(err_json["valid"])
        self.assertEqual(err_json["error"]["code"], "non_canonical_host_bits")
        self.assertEqual(err_json["error"]["canonical_cidr"], "10.0.0.0/24")


if __name__ == "__main__":
    unittest.main()
