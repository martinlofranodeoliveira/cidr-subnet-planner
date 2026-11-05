"""Structured exceptions and diagnostics for cidr-subnet-planner."""

from __future__ import annotations

from typing import Any


class CIDRPlannerError(Exception):
    """Base exception for all planner errors with structured diagnostic payload."""

    def __init__(self, code: str, message: str, **details: Any) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details: dict[str, Any] = dict(details)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
        }
        payload.update(self.details)
        return payload


class CIDRValidationError(CIDRPlannerError):
    """Raised when a CIDR string, profile, or parameter fails strict validation."""


class NonCanonicalCIDRError(CIDRValidationError):
    """Raised in strict mode when a CIDR string has non-zero host bits set."""

    def __init__(
        self,
        input_cidr: str,
        canonical_cidr: str,
        host_bits_hex: str,
        family: str,
    ) -> None:
        message = (
            f"CIDR '{input_cidr}' has non-zero host bits set ({host_bits_hex}); "
            f"use canonical network address '{canonical_cidr}'."
        )
        super().__init__(
            code="non_canonical_host_bits",
            message=message,
            input_cidr=input_cidr,
            canonical_cidr=canonical_cidr,
            host_bits_hex=host_bits_hex,
            family=family,
        )
        self.input_cidr = input_cidr
        self.canonical_cidr = canonical_cidr
        self.host_bits_hex = host_bits_hex
        self.family = family


class ResourceLimitExceededError(CIDRPlannerError):
    """Raised when an input collection or output bound exceeds configured PlannerLimits."""

    def __init__(self, limit_name: str, limit_value: int, actual_value: int) -> None:
        message = (
            f"Resource limit '{limit_name}' exceeded: "
            f"maximum allowed is {limit_value}, got {actual_value}."
        )
        super().__init__(
            code="resource_limit_exceeded",
            message=message,
            limit_name=limit_name,
            limit_value=limit_value,
            actual_value=actual_value,
        )
        self.limit_name = limit_name
        self.limit_value = limit_value
        self.actual_value = actual_value


class VLSMAllocationError(CIDRPlannerError):
    """Raised when VLSM reservations or parameters are invalid."""
