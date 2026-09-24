"""Whole-IR comparison against the immutable reference semantics."""
from __future__ import annotations

import csv
from itertools import product
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from .checker import execute as checker_execute
from .producer import run as producer_execute
from .reference_semantics import encode, execute as reference_execute


def _inputs(program: Mapping[str, Any]) -> Iterable[dict[str, Any]]:
    """Enumerate the declared Cartesian domain without project schema helpers."""
    names = sorted(program["input_domains"])
    domains = [program["input_domains"][name] for name in names]
    for values in product(*domains):
        yield dict(zip(names, values))


def _implementation_key(result: Any) -> tuple[Any, ...]:
    return (
        result.violation,
        result.aborted,
        encode(result.returned),
        tuple((name, encode(value)) for name, value in result.events),
        tuple((name, encode(value)) for name, value in result.public_state),
        result.steps,
        result.trace,
    )


def _walk_expression(expr: Any, operations: set[str], forms: set[str]) -> None:
    if type(expr) is not dict:
        forms.add("literal")
        return
    if set(expr) == {"const"}:
        forms.add("const")
        return
    if set(expr) == {"var"}:
        forms.add("var")
        return
    if set(expr) == {"public"}:
        forms.add("public")
        return
    operation = expr.get("op")
    operations.add(operation)
    if operation == "not":
        _walk_expression(expr["arg"], operations, forms)
    else:
        _walk_expression(expr["left"], operations, forms)
        _walk_expression(expr["right"], operations, forms)


def _coverage(program: Mapping[str, Any], instruction_ops: set[str], expression_ops: set[str], expression_forms: set[str]) -> None:
    instruction_ops.update(instruction["op"] for instruction in program["instructions"])
    for instruction in program["instructions"]:
        for field in ("expr", "pred", "index", "value", "numerator", "denominator", "left", "right", "amount", "set"):
            if field in instruction:
                _walk_expression(instruction[field], expression_ops, expression_forms)


def _coverage_programs() -> list[dict[str, Any]]:
    """Admitted microprograms covering forms absent from pair constructors."""
    v = lambda name: {"var": name}
    c = lambda value: {"const": value}
    b = lambda op, left, right: {"op": op, "left": left, "right": right}
    expression_program = {
        "schema": "rcsc-program",
        "program_id": "reference-expression-coverage",
        "profile": "c",
        "family": "bounds_write",
        "label": "patched",
        "parameters": {"purpose": "reference expression coverage"},
        "input_domains": {"idx": [0], "value": [0, 1], "x": [0, 1]},
        "context": {"scope": "owned finite implementation cross-check"},
        "initial_public_state": {"buffer": [0], "audit": 0},
        "public_projection": ["buffer", "audit"],
        "instructions": [
            {"op": "assign", "role": "context", "dst": "literal", "expr": 1},
            {"op": "assign", "role": "context", "dst": "a", "expr": b("mul", b("add", v("x"), c(1)), b("sub", c(3), c(1)))},
            {"op": "branch_abort", "role": "context", "pred": b("and", b("gt", v("a"), c(100)), b("or", b("eq", v("x"), c(0)), b("ne", v("x"), c(0))))},
            {"op": "guard", "role": "context", "pred": b("or", b("le", v("x"), c(1)), {"op": "not", "arg": b("ge", v("x"), c(2))})},
            {"op": "buf_write", "role": "root", "buffer": "buffer", "index": v("idx"), "value": v("value")},
            {"op": "emit", "role": "context", "name": "less", "value": b("lt", v("x"), c(2))},
            {"op": "return", "role": "context", "value": {"public": "buffer"}},
        ],
    }
    optional_program = {
        "schema": "rcsc-program",
        "program_id": "reference-optional-result-coverage",
        "profile": "c",
        "family": "bounds_write",
        "label": "patched",
        "parameters": {"purpose": "reference optional result coverage"},
        "input_domains": {"x": [0]},
        "context": {"scope": "owned finite implementation cross-check"},
        "initial_public_state": {"audit": 0},
        "public_projection": ["audit"],
        "instructions": [
            {"op": "nop", "role": "root"},
            {"op": "emit", "role": "context", "name": "void"},
            {"op": "return", "role": "context"},
        ],
    }
    return [expression_program, optional_program]


def run_reference_campaign(
    output: Path,
    constructor_pairs: list[dict[str, Any]],
    description_pairs: list[dict[str, Any]],
    transform_targets: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compare both implementations with the immutable reference over every valuation."""
    from .observation_oracle import cases, pair_from_case

    programs: list[tuple[str, dict[str, Any]]] = []
    programs.extend(("constructor-endpoint", pair[side]) for pair in constructor_pairs for side in ("vulnerable", "patched"))
    programs.extend(("description-endpoint", pair[side]) for pair in description_pairs for side in ("vulnerable", "patched"))
    programs.extend(("preserving-target", target) for target in transform_targets)
    for case in cases():
        pair = pair_from_case(case)
        programs.extend(("observation-endpoint", pair[side]) for side in ("vulnerable", "patched"))
    programs.extend(("grammar-coverage", program) for program in _coverage_programs())

    identifiers = [program["program_id"] for _, program in programs]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("reference campaign program identifiers must be unique")

    rows: list[dict[str, Any]] = []
    mismatches: list[dict[str, Any]] = []
    instruction_ops: set[str] = set()
    expression_ops: set[str] = set()
    expression_forms: set[str] = set()
    per_stratum: dict[str, dict[str, int]] = {}

    for stratum, program in programs:
        _coverage(program, instruction_ops, expression_ops, expression_forms)
        counts = per_stratum.setdefault(stratum, {"programs": 0, "valuations": 0, "interpreter_comparisons": 0})
        counts["programs"] += 1
        for inputs in _inputs(program):
            counts["valuations"] += 1
            reference = reference_execute(program, inputs)
            expected = reference.operational_key()
            outcomes: dict[str, bool] = {}
            semantic_outcomes: dict[str, bool] = {}
            actual_payloads: dict[str, Any] = {}
            for name, evaluator in (("producer", producer_execute), ("checker", checker_execute)):
                try:
                    result = evaluator(program, inputs)
                    actual = _implementation_key(result)
                    operational_match = actual == expected
                    semantic_match = actual[:5] == expected[:5]
                    actual_payloads[name] = result.to_json()
                except Exception as exc:  # retained as evidence rather than hidden by the campaign
                    operational_match = False
                    semantic_match = False
                    actual_payloads[name] = {"exception": type(exc).__name__, "message": str(exc)}
                outcomes[name] = operational_match
                semantic_outcomes[name] = semantic_match
                counts["interpreter_comparisons"] += 1
                if not operational_match:
                    mismatches.append({
                        "stratum": stratum,
                        "program_id": program["program_id"],
                        "input": inputs,
                        "interpreter": name,
                        "semantic_match": semantic_match,
                        "reference": reference.to_json(),
                        "actual": actual_payloads[name],
                    })
            rows.append({
                "stratum": stratum,
                "program_id": program["program_id"],
                "input": json.dumps(inputs, sort_keys=True, separators=(",", ":")),
                "producer_semantic_match": semantic_outcomes["producer"],
                "checker_semantic_match": semantic_outcomes["checker"],
                "producer_operational_match": outcomes["producer"],
                "checker_operational_match": outcomes["checker"],
                "reference_result": json.dumps(reference.to_json(), sort_keys=True, separators=(",", ":")),
            })

    output.mkdir(parents=True, exist_ok=True)
    with (output / "reference_semantics.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (output / "reference_mismatches.json").write_text(json.dumps(mismatches, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = {
        "programs": len(programs),
        "endpoint_valuations": len(rows),
        "interpreter_comparisons": 2 * len(rows),
        "semantic_mismatches": sum(
            not row["producer_semantic_match"] or not row["checker_semantic_match"] for row in rows
        ),
        "operational_mismatches": len(mismatches),
        "instruction_operations": sorted(instruction_ops),
        "expression_operations": sorted(expression_ops),
        "expression_forms": sorted(expression_forms),
        "strata": per_stratum,
        "scope": "already-admitted finite IR; independent immutable execution, not schema or resource-bound verification",
    }
    (output / "reference_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary
