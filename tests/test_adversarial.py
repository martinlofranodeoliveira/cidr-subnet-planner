"""Independent small-space oracles, boundary cases, and hostile CLI inputs."""

from __future__ import annotations

import io
import ipaddress
import json
import os
import random
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from cidr_planner import (
    CIDRPlannerError, CIDRValidationError, NonCanonicalCIDRError,
    PlannerLimits, ResourceLimitExceededError, audit_inventory,
    calculate_addressing_metrics, classify_prefix_scope, parse_cidr,
    plan_vlsm, prefix_length_for_required_hosts, summarize_cidrs,
)
from cidr_planner.cli import MAX_INPUT_BYTES, main
from cidr_planner.limits import validate_label


def addresses(cidrs: list[str]) -> set[int]:
    # Used only for tiny synthetic IPv4 spaces in these tests.
    return {int(address) for cidr in cidrs for address in ipaddress.ip_network(cidr)}


def verify_partition(test: unittest.TestCase, parent: str, report: dict) -> None:
    network = ipaddress.ip_network(parent)
    blocks = report["reserved_cidrs"] + [a["cidr"] for a in report["allocations"]] + report["free_blocks"]
    intervals = sorted((int(n.network_address), int(n.broadcast_address)) for n in map(ipaddress.ip_network, blocks))
    test.assertTrue(intervals)
    cursor = int(network.network_address)
    for start, end in intervals:
        test.assertEqual(start, cursor, "Independent interval sweep found overlap or gap")
        cursor = end + 1
    test.assertEqual(cursor, int(network.broadcast_address) + 1)
    free = [ipaddress.ip_network(cidr) for cidr in report["free_blocks"]]
    test.assertEqual(free, sorted(free, key=lambda n: int(n.network_address)))
    for i, block in enumerate(free):
        for other in free[i + 1:]:
            test.assertFalse(block.overlaps(other))
            if block.prefixlen and block.prefixlen == other.prefixlen:
                test.assertNotEqual(block.supernet(), other.supernet(), "Free siblings should be merged")


class BoundaryTests(unittest.TestCase):
    def test_flags_are_not_truthiness_switches(self) -> None:
        for value in (0, 1, "false", [], None):
            for function, args in ((parse_cidr, ("10.0.0.0/8",)), (audit_inventory, ([],)), (summarize_cidrs, ([],))):
                with self.subTest(function=function.__name__, value=value):
                    with self.assertRaises(CIDRValidationError) as caught:
                        function(*args, strict=value)
                    self.assertEqual(caught.exception.code, "invalid_strict_flag")

    def test_text_normalization_is_not_host_bit_normalization(self) -> None:
        parsed = parse_cidr("2001:0DB8:0000:0000::/64")
        self.assertTrue(parsed.is_canonical_host_bits)
        self.assertEqual(parsed.canonical_cidr, "2001:db8::/64")
        with self.assertRaises(NonCanonicalCIDRError):
            classify_prefix_scope("2001:db8::1/64")
        for cidr in ("10.0.0.0/٢٤", "10.0.0.0/００", "010.0.0.0/8", "10.0.0.0/24\x00"):
            with self.subTest(cidr=cidr), self.assertRaises(CIDRValidationError):
                parse_cidr(cidr)
        with self.assertRaises(CIDRValidationError) as caught:
            parse_cidr("::/" + "9" * 5000, limits=PlannerLimits(max_cidr_string_length=6000))
        self.assertEqual(caught.exception.code, "prefix_length_out_of_range")

    def test_label_bounds_precede_trimming_and_reject_terminal_controls(self) -> None:
        for label in ("a\nline", "\x1b[31mred", "a\u202eb", "a\ud800"):
            with self.subTest(label=repr(label)), self.assertRaises(CIDRValidationError):
                validate_label(label)
        with self.assertRaises(ResourceLimitExceededError):
            validate_label(" " * 129 + "a")
        self.assertEqual(validate_label("  região-a  "), "região-a")
        with self.assertRaises(CIDRValidationError) as caught:
            plan_vlsm("10.0.0.0/24", [{"name": "a", "prefix_length": 26}, {"name": " a ", "prefix_length": 27}])
        self.assertEqual(caught.exception.code, "duplicate_demand_name")

    def test_invalid_versions_and_enormous_values_remain_structured(self) -> None:
        for version in (True, 0, 5, "6", None):
            with self.assertRaises(CIDRValidationError) as caught:
                prefix_length_for_required_hosts(1, version=version)
            self.assertEqual(caught.exception.code, "invalid_ip_version")
        for operation in (
            lambda: prefix_length_for_required_hosts(10 ** 5000, version=4),
            lambda: plan_vlsm("10.0.0.0/24", [{"name": "big", "prefix_length": 10 ** 5000}]),
            lambda: calculate_addressing_metrics("::/0", profile=object()),
        ):
            with self.assertRaises(CIDRPlannerError) as caught:
                operation()
            json.dumps(caught.exception.to_dict())

    def test_host_sizing_is_minimal_under_each_profile(self) -> None:
        def capacity(prefix: int, p2p: bool) -> int:
            if prefix == 32:
                return 1
            if prefix == 31:
                return 2 if p2p else 0
            return (1 << (32 - prefix)) - 2
        for profile in ("standard_ipv4", "rfc3021_p2p"):
            for required in list(range(1, 260)) + [4294967294]:
                prefix = prefix_length_for_required_hosts(required, version=4, profile=profile)
                self.assertGreaterEqual(capacity(prefix, profile == "rfc3021_p2p"), required)
                for smaller in range(prefix + 1, 33):
                    self.assertLess(capacity(smaller, profile == "rfc3021_p2p"), required)
        self.assertEqual(prefix_length_for_required_hosts(1 << 128, version=6), 0)
        self.assertEqual(prefix_length_for_required_hosts((1 << 64) + 1, version=6), 63)

    def test_scope_boundaries_do_not_imply_global_reachability(self) -> None:
        for cidr, expected in (
            ("100.63.255.255/32", "other_or_reserved"), ("100.64.0.0/32", "shared_cgnat"),
            ("100.127.255.255/32", "shared_cgnat"), ("100.128.0.0/32", "other_or_reserved"),
            ("192.0.0.9/32", "ietf_protocol_assignments"),
            ("::ffff:c000:201/128", "ipv4_mapped"),
            ("64:ff9b:1::/48", "ipv4_translated"), ("2001:db9::/32", "other_or_reserved"),
        ):
            with self.subTest(cidr=cidr):
                self.assertEqual(classify_prefix_scope(cidr).scope, expected)

    def test_every_audit_pair_and_collision_limit(self) -> None:
        cidrs = ["0.0.0.0/0", "10.0.0.0/8", "10.1.0.0/16", "10.1.0.0/16", "10.2.0.0/16", "::/0", "::/128"]
        nets = list(map(ipaddress.ip_network, cidrs))
        report = audit_inventory(cidrs, strict=True)
        actual = {(c["first_index"], c["second_index"]): c for c in report["collisions"]}
        expected = set()
        for i, first in enumerate(nets):
            for j in range(i + 1, len(nets)):
                second = nets[j]
                if first.version != second.version:
                    continue
                left = max(int(first.network_address), int(second.network_address))
                right = min(int(first.broadcast_address), int(second.broadcast_address))
                if left <= right:
                    expected.add((i, j))
                    self.assertEqual(int(actual[i, j]["overlapping_addresses"]), right - left + 1)
        self.assertEqual(set(actual), expected)
        with self.assertRaises(ResourceLimitExceededError) as caught:
            audit_inventory(["10.0.0.0/8"] * 3, limits=PlannerLimits(max_collision_results=2))
        self.assertEqual(caught.exception.actual_value, 3)
        strict = audit_inventory(["10.0.0.1/24", "10.0.0.0/24"], strict=True)
        lenient = audit_inventory(["10.0.0.1/24", "10.0.0.0/24"])
        self.assertEqual(strict["collisions"], [])
        self.assertEqual(lenient["collisions"][0]["classification"], "exact_duplicate")
        normalized = summarize_cidrs(["10.0.0.1/24"], strict=False)
        self.assertEqual(normalized["non_canonical_inputs"][0]["canonical_cidr"], "10.0.0.0/24")


class IndependentPlanningTests(unittest.TestCase):
    def test_hand_calculated_middle_reservation(self) -> None:
        report = plan_vlsm("10.20.0.0/22", [
            {"name": "d", "prefix_length": 28}, {"name": "b", "prefix_length": 25},
            {"name": "a", "prefix_length": 24}, {"name": "c", "prefix_length": 26},
        ], reserved_cidrs=["10.20.1.0/24"])
        self.assertEqual([a["cidr"] for a in report["allocations"]], ["10.20.0.0/24", "10.20.2.0/25", "10.20.2.128/26", "10.20.2.192/28"])
        self.assertEqual(report["free_blocks"], ["10.20.2.208/28", "10.20.2.224/27", "10.20.3.0/24"])
        acc = report["accounting"]
        self.assertEqual((acc["allocated_addresses"], acc["reserved_addresses"], acc["free_addresses"]), (464, 256, 304))
        verify_partition(self, "10.20.0.0/22", report)

    def test_tiny_space_bitset_oracle(self) -> None:
        base = int(ipaddress.IPv4Address("10.0.0.0"))
        for seed in range(40):
            rng = random.Random(seed)
            reserved_offsets = set(rng.sample(range(64), rng.randrange(0, 10)))
            reservations = [f"{ipaddress.IPv4Address(base + offset)}/32" for offset in sorted(reserved_offsets)]
            demands = [{"name": f"n{i}", "prefix_length": rng.randrange(26, 33)} for i in range(8)]
            rng.shuffle(demands)
            occupied = set(reserved_offsets)
            expected = []
            failed = None
            for demand in sorted(demands, key=lambda d: (d["prefix_length"], d["name"])):
                size = 1 << (32 - demand["prefix_length"])
                candidate = next((start for start in range(0, 64, size) if not occupied.intersection(range(start, start + size))), None)
                if candidate is None:
                    failed = demand["name"]
                    break
                occupied.update(range(candidate, candidate + size))
                expected.append((demand["name"], f"{ipaddress.IPv4Address(base + candidate)}/{demand['prefix_length']}"))
            with self.subTest(seed=seed):
                report = plan_vlsm("10.0.0.0/26", demands, reserved_cidrs=reservations)
                self.assertEqual([(a["name"], a["cidr"]) for a in report["allocations"]], expected)
                self.assertEqual(addresses(report["free_blocks"]), {base + i for i in range(64) if i not in occupied})
                self.assertEqual(report["valid"], failed is None)
                if failed is not None:
                    self.assertEqual(report["diagnostic"]["unfulfilled_demand"]["name"], failed)
                verify_partition(self, "10.0.0.0/26", report)
                self.assertEqual(report, plan_vlsm("10.0.0.0/26", list(reversed(demands)), reserved_cidrs=list(reversed(reservations))))

    def test_fragmentation_and_no_space_diagnostics(self) -> None:
        report = plan_vlsm("10.0.0.0/24", [{"name": "aligned", "prefix_length": 25}], reserved_cidrs=["10.0.0.64/26", "10.0.0.192/26"])
        diagnostic = report["diagnostic"]
        self.assertEqual(diagnostic["total_remaining_free_addresses"], 128)
        self.assertEqual(diagnostic["largest_remaining_free_block"], "10.0.0.0/26")
        self.assertEqual(diagnostic["unfulfilled_demand"]["name"], "aligned")
        verify_partition(self, "10.0.0.0/24", report)
        full = plan_vlsm("10.0.0.0/24", [{"name": "host", "required_hosts": 1}], reserved_cidrs=["10.0.0.0/24"])
        self.assertIsNone(full["diagnostic"]["largest_remaining_free_block"])
        self.assertEqual(full["diagnostic"]["largest_remaining_free_addresses"], 0)
        equal = plan_vlsm("10.0.0.0/24", [{"name": "whole", "prefix_length": 24}])
        self.assertEqual(equal["free_blocks"], [])
        self.assertTrue(equal["valid"])

    def test_intermediate_free_limit_is_not_only_a_final_output_check(self) -> None:
        with self.assertRaises(ResourceLimitExceededError) as caught:
            plan_vlsm("10.0.0.0/30", [{"name": "pair", "prefix_length": 31}, {"name": "host", "prefix_length": 32}], reserved_cidrs=["10.0.0.0/32"], limits=PlannerLimits(max_free_blocks_output=1))
        self.assertEqual(caught.exception.limit_name, "max_free_blocks_output")

    def test_ipv6_zero_space_and_required_host_precision(self) -> None:
        report = plan_vlsm("::/0", [{"name": "large", "required_hosts": 1 << 80}], reserved_cidrs=["8000::/1"])
        self.assertEqual(report["allocations"][0]["cidr"], "::/48")
        self.assertEqual(report["allocations"][0]["required_hosts"], str(1 << 80))
        self.assertEqual(report["parent_total_addresses"], str(1 << 128))
        verify_partition(self, "::/0", report)
        failed = plan_vlsm("::/128", [{"name": "two", "required_hosts": 2}])
        self.assertEqual(failed["diagnostic"]["unfulfilled_demand"]["required_hosts"], "2")
        summary = summarize_cidrs(["::/1", "8000::/1", "::1/128"])
        self.assertEqual(summary["summarized_cidrs"], ["::/0"])
        self.assertEqual(summary["ipv6"]["unique_addresses"], str(1 << 128))

    def test_all_subsets_of_eight_hosts_have_exact_minimal_summaries(self) -> None:
        base = int(ipaddress.IPv4Address("10.9.0.0"))
        for mask in range(256):
            selected = {base + i for i in range(8) if mask & (1 << i)}
            inputs = [f"{ipaddress.IPv4Address(value)}/32" for value in sorted(selected)]
            result = summarize_cidrs(inputs + inputs)
            self.assertEqual(addresses(result["summarized_cidrs"]), selected)
            nets = list(map(ipaddress.ip_network, result["summarized_cidrs"]))
            for i, net in enumerate(nets):
                for other in nets[i + 1:]:
                    self.assertFalse(net.overlaps(other))
                    if net.prefixlen == other.prefixlen:
                        self.assertNotEqual(net.supernet(), other.supernet())


class HostileCLITests(unittest.TestCase):
    def invoke(self, command: str, raw: str | bytes) -> tuple[int, str, str]:
        stdin = io.StringIO(raw) if isinstance(raw, str) else io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8")
        out, err = io.StringIO(), io.StringIO()
        with patch("sys.stdin", stdin), redirect_stdout(out), redirect_stderr(err):
            code = main([command, "--input", "-"])
        return code, out.getvalue(), err.getvalue()

    def test_malformed_input_is_structured_without_partial_stdout(self) -> None:
        for command, raw, expected in (
            ("audit", "{", "invalid_json"), ("plan", "[]", "invalid_input_schema"),
            ("plan", "{}", "invalid_input_schema"), ("audit", "null", "invalid_input_schema"),
            ("summarize", '{"cidrs":[],"cidrs":[]}', "invalid_json"),
            ("audit", "[NaN]", "invalid_json"), ("audit", "[1e9999]", "invalid_json"),
            ("audit", "[" + "9" * 40 + "]", "invalid_json"),
            ("audit", b"[\xff]", "input_encoding_error"),
            ("audit", "[" * 65 + "]" * 65, "resource_limit_exceeded"),
            ("audit", '[{"label":"a\\u001bb","cidr":"10.0.0.0/8"}]', "invalid_label_characters"),
        ):
            with self.subTest(command=command, raw=repr(raw)):
                code, out, err = self.invoke(command, raw)
                self.assertEqual((code, out), (2, ""))
                self.assertEqual(json.loads(err)["error"]["code"], expected)
                self.assertNotIn("Traceback", err)

    def test_read_is_bounded_before_decoding(self) -> None:
        stream = io.BytesIO(b" " * (MAX_INPUT_BYTES + 100))
        stdin = io.TextIOWrapper(stream, encoding="utf-8")
        err = io.StringIO()
        with patch("sys.stdin", stdin), redirect_stderr(err):
            code = main(["audit", "--input", "-"])
        self.assertEqual(code, 2)
        self.assertEqual(stream.tell(), MAX_INPUT_BYTES + 1)
        self.assertEqual(json.loads(err.getvalue())["error"]["limit_name"], "max_input_bytes")

    def test_selected_file_read_errors_and_exit_statuses(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            err = io.StringIO()
            with redirect_stderr(err):
                self.assertEqual(main(["audit", "--input", directory]), 2)
            self.assertEqual(json.loads(err.getvalue())["error"]["code"], "input_io_error")
        code, out, err = self.invoke("audit", '["10.0.0.0/8","10.0.0.0/8"]')
        self.assertEqual((code, err), (1, ""))
        self.assertEqual(json.loads(out)["summary"]["collision_count"], 1)
        code, out, err = self.invoke("plan", '{"parent_supernet":"10.0.0.0/32","demands":[{"name":"pair","prefix_length":31}]}')
        self.assertEqual((code, err), (1, ""))
        self.assertEqual(json.loads(out)["status"], "insufficient_contiguous_space")
        self.assertEqual(self.invoke("summarize", "[]"), (0, json.dumps(summarize_cidrs([]), indent=2) + "\n", ""))

    def test_real_module_demo_is_deterministic(self) -> None:
        command = [sys.executable, "-m", "cidr_planner", "demo"]
        first = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
        second = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
        self.assertEqual((first.returncode, first.stderr), (0, ""))
        self.assertEqual((second.returncode, second.stderr), (0, ""))
        self.assertEqual(first.stdout, second.stdout)
        report = json.loads(first.stdout)
        self.assertEqual(report["inventory_audit"]["summary"]["collision_count"], 4)
        self.assertEqual(report["route_summarization"]["summarized_cidrs"], ["10.80.0.0/23", "10.80.2.128/25", "10.80.3.0/25", "2001:db8:10::/48"])
        text = subprocess.run(command + ["--format", "text"], capture_output=True, text=True, timeout=15, check=False)
        self.assertEqual((text.returncode, text.stderr), (0, ""))
        self.assertIn("Summarized: 4 (reduced by 3)", text.stdout)
        self.assertIn("reserved=128 + allocated=259 + free=125 = 512", text.stdout)

    @unittest.skipUnless(os.path.exists("/dev/full"), "requires a failing POSIX output device")
    def test_stdout_and_stderr_failure_returns_two_without_traceback(self) -> None:
        command = [sys.executable, "-m", "cidr_planner"]
        with open("/dev/full", "wb") as full:
            for args in (["demo"], ["--help"]):
                with self.subTest(args=args):
                    result = subprocess.run(command + args, stdout=full, stderr=subprocess.PIPE, timeout=5, check=False)
                    self.assertEqual(result.returncode, 2)
                    diagnostic = json.loads(result.stderr)
                    self.assertEqual(diagnostic["error"]["code"], "output_io_error")
                    self.assertNotIn(b"Traceback", result.stderr)
            result = subprocess.run(command + ["audit", "--input", "missing-private-sentinel"],
                                    stdout=subprocess.PIPE, stderr=full, timeout=5, check=False)
            self.assertEqual((result.returncode, result.stdout), (2, b""))

    @unittest.skipUnless(hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"), "requires POSIX FIFO support")
    def test_named_fifo_rejected_before_any_blocking_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "private-sentinel.fifo")
            os.mkfifo(path)
            result = subprocess.run([sys.executable, "-m", "cidr_planner", "audit", "--input", path],
                                    capture_output=True, timeout=5, check=False)
            self.assertEqual((result.returncode, result.stdout), (2, b""))
            self.assertEqual(json.loads(result.stderr)["error"]["code"], "input_io_error")
            self.assertNotIn(b"sentinel", result.stderr)


if __name__ == "__main__":
    unittest.main()
