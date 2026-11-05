"""Bounded resource usage configuration and validation helpers."""

from __future__ import annotations

from dataclasses import dataclass, fields

from cidr_planner.errors import CIDRValidationError, ResourceLimitExceededError


@dataclass(frozen=True, slots=True)
class PlannerLimits:
    """Positive limits; the free-block limit also bounds intermediate inventories."""

    max_inventory_items: int = 2_000
    max_collision_results: int = 10_000
    max_vlsm_demands: int = 1_000
    max_reserved_cidrs: int = 1_000
    max_summarize_inputs: int = 4_096
    max_free_blocks_output: int = 8_192
    max_cidr_string_length: int = 64
    max_label_length: int = 128

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            if type(value) is not int or value < 1:
                raise CIDRValidationError(
                    code="invalid_limit_configuration",
                    message=f"Limit '{field.name}' must be a positive integer.",
                    field_name=field.name,
                )


DEFAULT_LIMITS = PlannerLimits()


def enforce_count_limit(limit_name: str, limit_value: int, actual_value: int) -> None:
    if actual_value > limit_value:
        raise ResourceLimitExceededError(limit_name, limit_value, actual_value)


def validate_strict(strict: object) -> bool:
    if type(strict) is not bool:
        raise CIDRValidationError(
            code="invalid_strict_flag",
            message="strict must be a boolean, not a truthy or falsy substitute.",
        )
    return strict


def validate_label(
    label: object,
    *,
    field_name: str = "label",
    limits: PlannerLimits = DEFAULT_LIMITS,
) -> str:
    if not isinstance(label, str):
        raise CIDRValidationError(
            code="invalid_label_type",
            message=f"Field '{field_name}' must be a string.",
            field_name=field_name,
        )
    # Bound the original input, not only the stripped result.
    enforce_count_limit("max_label_length", limits.max_label_length, len(label))
    if not label.strip():
        raise CIDRValidationError(
            code="empty_label",
            message=f"Field '{field_name}' must not be empty or whitespace-only.",
            field_name=field_name,
        )
    if not label.isprintable():
        raise CIDRValidationError(
            code="invalid_label_characters",
            message=f"Field '{field_name}' must contain only printable characters.",
            field_name=field_name,
        )
    return label.strip()
