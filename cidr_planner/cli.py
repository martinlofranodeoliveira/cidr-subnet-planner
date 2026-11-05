"""Bounded JSON CLI and deterministic synthetic offline demo."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from typing import Any, Sequence

from cidr_planner.auditor import audit_inventory
from cidr_planner.errors import CIDRPlannerError, CIDRValidationError, ResourceLimitExceededError
from cidr_planner.summarizer import summarize_cidrs
from cidr_planner.vlsm import plan_vlsm

MAX_INPUT_BYTES = 1_048_576
MAX_JSON_DEPTH = 64
MAX_JSON_INTEGER_DIGITS = 39


def build_demo_report() -> dict[str, Any]:
    inventory = [
        {"label": "sa-east-1-prod-supernet", "cidr": "10.20.0.0/16"},
        {"label": "sa-east-1-eks-workers", "cidr": "10.20.4.0/22"},
        {"label": "sa-east-1-eks-duplicate", "cidr": "10.20.4.0/22"},
        {"label": "us-east-1-shared-services", "cidr": "172.16.32.5/20"},
        {"label": "wan-cgnat-transit", "cidr": "100.64.0.0/24"},
        {"label": "edge-anycast-test", "cidr": "198.51.100.0/24"},
        {"label": "unclassified-wan-block", "cidr": "198.51.101.0/24"},
        {"label": "ipv6-ula-core", "cidr": "fd00:10:20::/48"},
        {"label": "ipv6-ula-subnet-a", "cidr": "fd00:10:20:1::/64"},
    ]
    demands = [
        {"name": "app-workers-a", "prefix_length": 25},
        {"name": "db-cluster-primary", "prefix_length": 26},
        {"name": "ingress-alb", "prefix_length": 27},
        {"name": "cache-nodes", "prefix_length": 27},
        {"name": "wan-uplink-p2p", "required_hosts": 2, "addressing_profile": "rfc3021_p2p"},
        {"name": "loopback-router-id", "required_hosts": 1, "addressing_profile": "standard_ipv4"},
    ]
    routes = [
        "10.80.0.0/25", "10.80.0.128/25", "10.80.1.0/24",
        "10.80.2.128/25", "10.80.3.0/25",
        "2001:db8:10::/49", "2001:db8:10:8000::/49",
    ]
    return {
        "tool": "cidr-subnet-planner", "version": "0.1.0",
        "scenario": "multi-region-vpc-audit-and-vlsm-plan",
        "inventory_audit": audit_inventory(inventory, strict=False),
        "vlsm_plan": plan_vlsm("10.40.0.0/23", demands, reserved_cidrs=["10.40.0.128/25"]),
        "route_summarization": summarize_cidrs(routes),
    }


def format_demo_text(report: dict[str, Any]) -> str:
    lines = [f"=== {report['tool']} v{report['version']} ({report['scenario']}) ===", "", "[1] Inventory Audit"]
    audit = report["inventory_audit"]
    summary = audit["summary"]
    lines.append(f"  Entries: {summary['total_entries']} (IPv4: {summary['ipv4_entries']}, IPv6: {summary['ipv6_entries']})")
    lines.append(f"  Non-canonical inputs flagged: {summary['non_canonical_count']}")
    for finding in audit["non_canonical_inputs"]:
        lines.append(f"    - {finding['label']}: {finding['input_cidr']} -> canonical {finding['canonical_cidr']} (host bits {finding['host_bits_hex']})")
    lines.append(f"  Pairwise collisions detected: {summary['collision_count']}")
    for collision in audit["collisions"]:
        lines.append(
            f"    - [{collision['classification']}] {collision['first_label']} ({collision['first_cidr']}) vs "
            f"{collision['second_label']} ({collision['second_cidr']}) -> {collision['overlapping_addresses_str']} overlapping addresses"
        )
    plan = report["vlsm_plan"]
    lines.extend(["", f"[2] Deterministic VLSM Plan (Parent: {plan['parent_supernet']})", f"  Status: {plan['status']}"])
    lines.append(f"  Reserved: {', '.join(plan['reserved_cidrs']) or 'none'}")
    lines.append("  Carved Subnets:")
    for allocation in plan["allocations"]:
        lines.append(f"    - {allocation['name']}: {allocation['cidr']} (profile={allocation['addressing_profile']}, usable={allocation['usable_hosts_str']})")
    lines.append(f"  Remaining Free Blocks: {', '.join(plan['free_blocks']) or 'none'}")
    acc = plan["accounting"]
    lines.append(f"  Accounting: reserved={acc['reserved_addresses_str']} + allocated={acc['allocated_addresses_str']} + free={acc['free_addresses_str']} = {acc['parent_total_addresses_str']}")
    summary_routes = report["route_summarization"]
    lines.extend(["", "[3] Contiguous Prefix Summarization"])
    lines.append(f"  Input prefixes: {summary_routes['input_count']} -> Summarized: {summary_routes['output_count']} (reduced by {summary_routes['reduction_count']})")
    lines.extend(f"    - {cidr}" for cidr in summary_routes["summarized_cidrs"])
    return "\n".join(lines)


def _reject_json(message: str) -> None:
    raise CIDRValidationError(code="invalid_json", message=message)


def _json_integer(token: str) -> int:
    if len(token.lstrip("-")) > MAX_JSON_INTEGER_DIGITS:
        _reject_json("JSON integer tokens are limited to 39 decimal digits.")
    return int(token)


def _json_noninteger(token: str) -> Any:
    _reject_json("Only integer JSON numbers are supported; floats and non-finite constants are rejected.")


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _reject_json("Duplicate JSON object keys are not supported.")
        result[key] = value
    return result


def _check_json_depth(text: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
        elif character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ResourceLimitExceededError("max_json_depth", MAX_JSON_DEPTH, depth)
        elif character in "]}":
            depth -= 1


def _load_json_input(path_arg: str) -> Any:
    try:
        if path_arg == "-":
            # Real stdin is bounded in bytes; StringIO supports embedded library use.
            raw = getattr(sys.stdin, "buffer", sys.stdin).read(MAX_INPUT_BYTES + 1)
        else:
            descriptor = os.open(path_arg, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise CIDRValidationError(
                        code="input_io_error", message="Selected input must be a regular local file.",
                    )
                with os.fdopen(descriptor, "rb", closefd=False) as stream:
                    raw = stream.read(MAX_INPUT_BYTES + 1)
            finally:
                os.close(descriptor)
        if isinstance(raw, str):
            raw = raw.encode("utf-8", errors="strict")
        if len(raw) > MAX_INPUT_BYTES:
            raise ResourceLimitExceededError("max_input_bytes", MAX_INPUT_BYTES, len(raw))
        text = raw.decode("utf-8", errors="strict")
    except OSError as exc:
        raise CIDRValidationError(code="input_io_error", message="Unable to read the selected input.", errno=exc.errno) from exc
    except UnicodeError as exc:
        raise CIDRValidationError(code="input_encoding_error", message="Input must be valid UTF-8 without a BOM.") from exc
    _check_json_depth(text)
    try:
        return json.loads(
            text, parse_int=_json_integer, parse_float=_json_noninteger,
            parse_constant=_json_noninteger, object_pairs_hook=_json_object,
        )
    except json.JSONDecodeError as exc:
        raise CIDRValidationError(
            code="invalid_json", message="Malformed JSON input.", line=exc.lineno, column=exc.colno,
        ) from exc
    except RecursionError as exc:
        raise CIDRValidationError(code="invalid_json", message="JSON nesting cannot be decoded safely.") from exc


def _envelope(payload: Any, key: str) -> Any:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and key in payload:
        return payload[key]
    raise CIDRValidationError(code="invalid_input_schema", message=f"Expected an array or an object containing '{key}'.")


def _run(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cidr_planner", description="Offline IPv4/IPv6 subnet planning and auditing.")
    commands = parser.add_subparsers(dest="command", required=True)
    demo = commands.add_parser("demo", help="Run the deterministic synthetic demo.")
    demo.add_argument("--format", choices=("json", "text"), default="json")
    audit = commands.add_parser("audit", help="Audit a JSON inventory.")
    audit.add_argument("--input", required=True, help="Selected JSON file or '-' for stdin.")
    audit.add_argument("--strict", action="store_true")
    plan = commands.add_parser("plan", help="Plan a JSON VLSM specification.")
    plan.add_argument("--input", required=True)
    summarize = commands.add_parser("summarize", help="Summarize JSON CIDRs strictly.")
    summarize.add_argument("--input", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "demo":
            result = build_demo_report()
            print(format_demo_text(result) if args.format == "text" else json.dumps(result, indent=2, allow_nan=False))
            return 0
        payload = _load_json_input(args.input)
        if args.command == "audit":
            result = audit_inventory(_envelope(payload, "entries"), strict=args.strict)
        elif args.command == "summarize":
            result = summarize_cidrs(_envelope(payload, "cidrs"))
        else:
            if not isinstance(payload, dict) or not {"parent_supernet", "demands"} <= payload.keys():
                raise CIDRValidationError(code="invalid_input_schema", message="Plan requires an object with parent_supernet and demands.")
            result = plan_vlsm(
                payload["parent_supernet"], payload["demands"],
                reserved_cidrs=payload.get("reserved_cidrs", []),
                default_addressing_profile=payload.get("default_addressing_profile"),
            )
        print(json.dumps(result, indent=2, allow_nan=False))
        return 0 if result.get("valid", True) else 1
    except CIDRPlannerError as exc:
        print(json.dumps({"valid": False, "error": exc.to_dict()}, indent=2, allow_nan=False), file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 2


def _discard_failed_stream(stream: Any) -> None:
    """Prevent interpreter shutdown from retrying an already failed OS stream."""
    try:
        descriptor = stream.fileno()
        sink = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(sink, descriptor)
        finally:
            os.close(sink)
    except (OSError, ValueError, AttributeError):
        # Caller-supplied in-memory streams need no OS descriptor cleanup.
        pass


def main(argv: Sequence[str] | None = None) -> int:
    try:
        try:
            code = _run(argv)
        except SystemExit as exc:
            # Preserve argparse's conventional help/usage status and text.
            code = exc.code if isinstance(exc.code, int) else 2
        sys.stdout.flush()
        sys.stderr.flush()
        return code
    except OSError:
        _discard_failed_stream(sys.stdout)
        try:
            print(json.dumps({
                "valid": False,
                "error": {"code": "output_io_error", "message": "Unable to write output."},
            }), file=sys.stderr, flush=True)
        except OSError:
            _discard_failed_stream(sys.stderr)
        return 2
