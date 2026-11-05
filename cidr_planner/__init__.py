"""Deterministic offline CIDR auditing, subnet planning, and summarization."""

from cidr_planner.auditor import InventoryEntry, audit_inventory
from cidr_planner.cli import build_demo_report, format_demo_text
from cidr_planner.errors import (
    CIDRPlannerError,
    CIDRValidationError,
    NonCanonicalCIDRError,
    ResourceLimitExceededError,
    VLSMAllocationError,
)
from cidr_planner.limits import DEFAULT_LIMITS, PlannerLimits
from cidr_planner.parser import ParsedCIDR, inspect_cidr, network_interval, parse_cidr
from cidr_planner.profiles import (
    VALID_PROFILES,
    calculate_addressing_metrics,
    prefix_length_for_required_hosts,
    prefix_length_for_Required_hosts,
)
from cidr_planner.scopes import (
    IPV4_SPECIAL_RANGES,
    IPV6_SPECIAL_RANGES,
    ScopeClassification,
    classify_prefix_scope,
)
from cidr_planner.summarizer import summarize_cidrs
from cidr_planner.vlsm import SubnetDemand, plan_vlsm

__version__ = "0.1.0"

__all__ = [
    "__version__", "CIDRPlannerError", "CIDRValidationError",
    "NonCanonicalCIDRError", "ResourceLimitExceededError", "VLSMAllocationError",
    "PlannerLimits", "DEFAULT_LIMITS", "ParsedCIDR", "parse_cidr", "inspect_cidr",
    "network_interval", "ScopeClassification", "classify_prefix_scope",
    "IPV4_SPECIAL_RANGES", "IPV6_SPECIAL_RANGES", "VALID_PROFILES",
    "calculate_addressing_metrics", "prefix_length_for_required_hosts",
    "prefix_length_for_Required_hosts", "InventoryEntry", "audit_inventory",
    "summarize_cidrs", "SubnetDemand", "plan_vlsm", "build_demo_report",
    "format_demo_text",
]
