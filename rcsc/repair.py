"""Exact pair-level repair membership and nuisance-surface normalization.

This module is intentionally independent of the corpus constructors.  It checks
one of six finite root-edit relations directly between supplied instruction
sequences.  Semantic closure remains a separate checker obligation.
"""
from __future__ import annotations

from typing import Any, Mapping

from .model import JSON, freeze_value, stable_json

REPAIR_FOR_FAMILY = {
    "bounds_write": "insert-root-guard",
    "divide_zero": "insert-root-guard",
    "fixed_overflow": "insert-root-guard",
    "access_control": "insert-root-guard",
    "reentrancy": "effects-before-interaction",
    "unchecked_call": "check-call-result",
}

_GUARDED_ROOT_OP = {
    "bounds_write": "buf_write",
    "divide_zero": "divide",
    "fixed_overflow": "add_fixed",
    "access_control": "protected_store",
}


def expected_repair(family: str) -> str:
    try:
        return REPAIR_FOR_FAMILY[family]
    except KeyError as exc:  # validate_program normally makes this unreachable.
        raise ValueError(f"unsupported repair family {family!r}") from exc


def _same(left: Any, right: Any) -> bool:
    return stable_json(left) == stable_json(right)


def _first_difference(left: Any, right: Any, path: str = "instructions") -> JSON | None:
    """Return the lexicographically first structural difference."""
    if type(left) is not type(right):
        return {"path": path, "left": freeze_value(left), "right": freeze_value(right)}
    if isinstance(left, dict):
        for key in sorted(set(left) | set(right)):
            if key not in left or key not in right:
                return {"path": f"{path}.{key}", "left": left.get(key), "right": right.get(key)}
            difference = _first_difference(left[key], right[key], f"{path}.{key}")
            if difference is not None:
                return difference
        return None
    if isinstance(left, list):
        if len(left) != len(right):
            return {"path": f"{path}.length", "left": len(left), "right": len(right)}
        for index, (a, b) in enumerate(zip(left, right)):
            difference = _first_difference(a, b, f"{path}[{index}]")
            if difference is not None:
                return difference
        return None
    if left != right:
        return {"path": path, "left": freeze_value(left), "right": freeze_value(right)}
    return None


def _failure(kind: str, **details: Any) -> tuple[str, JSON]:
    return "root-repair-mismatch", {"kind": kind, **details}


def _expr_same(left: Any, right: Any) -> bool:
    return stable_json(left) == stable_json(right)


def _constant(value: Any) -> JSON:
    return {"const": value}


def _binary(op: str, left: Any, right: Any) -> JSON:
    return {"op": op, "left": left, "right": right}


def _comparison_matches(expr: Any, direct_op: str, left: Any, right: Any) -> bool:
    """Match a comparison or its direction-reversed spelling exactly."""
    reverse = {"lt": "gt", "le": "ge", "gt": "lt", "ge": "le", "eq": "eq", "ne": "ne"}
    if type(expr) is not dict:
        return False
    if expr.get("op") == direct_op and _expr_same(expr.get("left"), left) and _expr_same(expr.get("right"), right):
        return True
    return (
        expr.get("op") == reverse[direct_op]
        and _expr_same(expr.get("left"), right)
        and _expr_same(expr.get("right"), left)
    )


def _all_integer_domain(
    program: Mapping[str, Any], expr: Any, predicate, *, before_site: int
) -> bool:
    """Discharge a bound from an input domain only while that input is unchanged.

    The language permits assignments to an existing input name.  A declared
    domain constrains the entry value, not a later overwritten local.  Therefore
    domain-based discharge is sound only when no preceding instruction writes the
    variable consumed by the protected operation.
    """
    if type(expr) is not dict or set(expr) != {"var"}:
        return False
    name = expr["var"]
    if any(instruction.get("dst") == name for instruction in program["instructions"][:before_site]):
        return False
    values = program["input_domains"].get(name, [])
    return bool(values) and all(type(value) is int and predicate(value) for value in values)


def _conjuncts(expr: Any) -> list[Any]:
    if type(expr) is dict and expr.get("op") == "and" and set(expr) == {"op", "left", "right"}:
        return _conjuncts(expr["left"]) + _conjuncts(expr["right"])
    return [expr]


def _bounds_guard_matches(
    program: Mapping[str, Any], protected: Mapping[str, Any], pred: Any, *, protected_site: int
) -> tuple[bool, JSON]:
    index = protected["index"]
    buffer_name = protected["buffer"]
    buffer_value = program["initial_public_state"][buffer_name]
    length = len(buffer_value)
    lower = lambda expr: _comparison_matches(expr, "ge", index, _constant(0))
    upper = lambda expr: _comparison_matches(expr, "lt", index, _constant(length))
    parts = _conjuncts(pred)
    lower_count = sum(lower(part) for part in parts)
    upper_count = sum(upper(part) for part in parts)
    has_lower = lower_count > 0
    has_upper = upper_count > 0
    exact_bounds = has_lower and has_upper
    upper_with_nonnegative_domain = has_upper and _all_integer_domain(
        program, index, lambda x: x >= 0, before_site=protected_site
    )
    lower_with_bounded_domain = has_lower and _all_integer_domain(
        program, index, lambda x: x < length, before_site=protected_site
    )
    matched = exact_bounds or upper_with_nonnegative_domain or lower_with_bounded_domain
    required_count = 2 if exact_bounds else 1 if matched else 0
    return matched, {
        "family": "bounds_write",
        "index": freeze_value(index),
        "buffer": buffer_name,
        "length": length,
        "lower_bound": has_lower,
        "upper_bound": has_upper,
        "domain_discharged_bound": matched and not exact_bounds,
        "extra_conjuncts": max(0, len(parts) - required_count),
    }


def _divide_guard_matches(protected: Mapping[str, Any], pred: Any) -> tuple[bool, JSON]:
    denominator = protected["denominator"]
    parts = _conjuncts(pred)
    matched_count = sum(_comparison_matches(part, "ne", denominator, _constant(0)) for part in parts)
    return matched_count > 0, {
        "family": "divide_zero",
        "denominator": freeze_value(denominator),
        "canonical_relation": "denominator != 0",
        "extra_conjuncts": max(0, len(parts) - 1) if matched_count else len(parts),
    }


def _overflow_bound_forms(operand: Any, other: Any, bound: int, *, upper: bool) -> list[JSON]:
    rhs = _binary("sub", _constant(bound), other)
    op = "le" if upper else "ge"
    forms = [_binary(op, operand, rhs)]
    if type(other) is dict and set(other) == {"const"} and type(other["const"]) is int:
        forms.append(_binary(op, operand, _constant(bound - other["const"])))
    return forms


def _comparison_form_matches(expr: Any, form: Mapping[str, Any]) -> bool:
    """Match a canonical comparison form in either operand direction."""
    return _comparison_matches(expr, form["op"], form["left"], form["right"])


def _overflow_guard_matches(protected: Mapping[str, Any], pred: Any) -> tuple[bool, JSON]:
    width = protected["width"]
    signed = protected["signed"]
    low, high = (
        (-(2 ** (width - 1)), 2 ** (width - 1) - 1)
        if signed else (0, 2 ** width - 1)
    )
    left, right = protected["left"], protected["right"]
    upper_forms = _overflow_bound_forms(left, right, high, upper=True) + _overflow_bound_forms(right, left, high, upper=True)
    lower_forms = _overflow_bound_forms(left, right, low, upper=False) + _overflow_bound_forms(right, left, low, upper=False)
    parts = _conjuncts(pred)
    has_upper = any(any(_comparison_form_matches(part, form) for form in upper_forms) for part in parts)
    has_lower = any(any(_comparison_form_matches(part, form) for form in lower_forms) for part in parts)
    matched = has_upper or has_lower
    required_count = int(has_upper) + int(has_lower)
    return matched, {
        "family": "fixed_overflow",
        "width": width,
        "signed": signed,
        "range": [low, high],
        "upper_bound": has_upper,
        "lower_bound": has_lower,
        "extra_conjuncts": max(0, len(parts) - required_count),
    }


def _access_guard_matches(protected: Mapping[str, Any], pred: Any) -> tuple[bool, JSON]:
    sender = {"var": "sender"}
    owner = {"public": protected["owner_key"]}
    parts = _conjuncts(pred)
    matched_count = sum(_comparison_matches(part, "eq", sender, owner) for part in parts)
    return matched_count > 0, {
        "family": "access_control",
        "sender": "sender",
        "owner_key": protected["owner_key"],
        "canonical_relation": "sender == owner",
        "extra_conjuncts": max(0, len(parts) - 1) if matched_count else len(parts),
    }


def _guard_binding(
    program: Mapping[str, Any],
    protected: Mapping[str, Any],
    pred: Any,
    *,
    protected_site: int,
) -> tuple[bool, JSON]:
    family = program["family"]
    if family == "bounds_write":
        return _bounds_guard_matches(
            program, protected, pred, protected_site=protected_site
        )
    if family == "divide_zero":
        return _divide_guard_matches(protected, pred)
    if family == "fixed_overflow":
        return _overflow_guard_matches(protected, pred)
    if family == "access_control":
        return _access_guard_matches(protected, pred)
    return False, {"family": family, "error": "family has no root guard relation"}


def check_repair_membership(
    vulnerable: Mapping[str, Any],
    patched: Mapping[str, Any],
    declared_repair: str,
) -> tuple[str | None, JSON]:
    """Check the exact designated root edit without invoking a constructor.

    The relation is deliberately syntactic: after erasing the single designated
    repair edit (or undoing the designated swap), the complete ordered
    instruction sequences must be type-exactly equal.  Context/declaration
    equality and semantic closure are checked by the caller.
    """
    family = vulnerable["family"]
    expected = expected_repair(family)
    if declared_repair != expected:
        return _failure(
            "declared-repair",
            declared=declared_repair,
            expected=expected,
        )

    source = vulnerable["instructions"]
    target = patched["instructions"]

    if family in _GUARDED_ROOT_OP:
        if len(target) != len(source) + 1:
            return _failure(
                "edit-cardinality",
                expected="one inserted root guard",
                vulnerable_length=len(source),
                patched_length=len(target),
            )
        protected_op = _GUARDED_ROOT_OP[family]
        candidates = []
        for site, instruction in enumerate(target):
            if not (
                instruction.get("op") == "guard"
                and instruction.get("role") == "root"
                and site + 1 < len(target)
                and target[site + 1].get("op") == protected_op
                and target[site + 1].get("role") == "root"
            ):
                continue
            erased = target[:site] + target[site + 1 :]
            if _same(erased, source):
                candidates.append(site)
        if len(candidates) != 1:
            best = None
            if len(target) == len(source) + 1:
                for site in range(len(target)):
                    difference = _first_difference(source, target[:site] + target[site + 1 :])
                    candidate = {
                        "erased_site": site,
                        "difference": difference,
                    }
                    if best is None or stable_json(candidate) < stable_json(best):
                        best = candidate
            return _failure(
                "insert-root-guard",
                protected_operation=protected_op,
                matching_sites=candidates,
                closest_erasure=best,
            )
        site = candidates[0]
        binding_matches, binding = _guard_binding(
            vulnerable, target[site + 1], target[site]["pred"], protected_site=site
        )
        if not binding_matches:
            return _failure(
                "guard-predicate-binding",
                protected_operation=protected_op,
                site=site,
                predicate=freeze_value(target[site]["pred"]),
                expected_binding=binding,
            )
        return None, {
            "repair": expected,
            "site": site,
            "protected_operation": protected_op,
            "guard_binding": binding,
        }

    if family == "reentrancy":
        if len(target) != len(source):
            return _failure(
                "edit-cardinality",
                expected="one adjacent root swap",
                vulnerable_length=len(source),
                patched_length=len(target),
            )
        candidates = []
        for site in range(len(source) - 1):
            first, second = source[site], source[site + 1]
            if not (
                first.get("op") == "external_call"
                and first.get("role") == "root"
                and second.get("op") == "update_balance"
                and second.get("role") == "root"
            ):
                continue
            swapped = source[:site] + [second, first] + source[site + 2 :]
            if _same(swapped, target):
                candidates.append(site)
        if len(candidates) != 1:
            return _failure(
                "effects-before-interaction",
                matching_sites=candidates,
                difference=_first_difference(source, target),
            )
        return None, {
            "repair": expected,
            "sites": [candidates[0], candidates[0] + 1],
            "vulnerable_order": ["external_call", "update_balance"],
            "patched_order": ["update_balance", "external_call"],
        }

    if family == "unchecked_call":
        if len(target) != len(source) + 1:
            return _failure(
                "edit-cardinality",
                expected="one inserted check_call",
                vulnerable_length=len(source),
                patched_length=len(target),
            )
        candidates = []
        for site, instruction in enumerate(target):
            if not (
                instruction.get("op") == "check_call"
                and instruction.get("role") == "root"
                and site > 0
                and site + 1 < len(target)
                and target[site - 1].get("op") == "low_call"
                and target[site - 1].get("role") == "root"
                and target[site + 1].get("op") == "commit_after_call"
                and target[site + 1].get("role") == "root"
            ):
                continue
            erased = target[:site] + target[site + 1 :]
            if _same(erased, source):
                candidates.append(site)
        if len(candidates) != 1:
            return _failure(
                "check-call-result",
                matching_sites=candidates,
                difference=_first_difference(source, target),
            )
        return None, {
            "repair": expected,
            "site": candidates[0],
            "predecessor": "low_call",
            "successor": "commit_after_call",
        }

    return _failure("unsupported-family", family=family)


def nuisance_surface(
    vulnerable: Mapping[str, Any],
    patched: Mapping[str, Any],
    declared_repair: str,
) -> JSON:
    """Return the common representation after erasing label, id and repair polarity.

    This function succeeds only when exact repair membership holds.  The result
    contains every declaration and the complete vulnerable instruction sequence;
    the latter is exactly the patched sequence after undoing the designated edit.
    """
    reason, derivation = check_repair_membership(vulnerable, patched, declared_repair)
    if reason is not None:
        raise ValueError(stable_json({"reason": reason, "details": derivation}))
    return {
        "schema": vulnerable["schema"],
        "profile": vulnerable["profile"],
        "family": vulnerable["family"],
        "declared_repair": declared_repair,
        "parameters": vulnerable["parameters"],
        "input_domains": vulnerable["input_domains"],
        "context": vulnerable["context"],
        "initial_public_state": vulnerable["initial_public_state"],
        "public_projection": vulnerable["public_projection"],
        "normalized_instructions": vulnerable["instructions"],
    }
