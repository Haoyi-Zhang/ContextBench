"""Deterministic boundary matrices for expression and instruction semantics.

The retained whole-IR campaign exercises every operation on generated programs,
but its corpus is not designed to enumerate dynamic type failures.  This module
adds two small, frozen matrices:

* every unary/binary expression operator over a twelve-value typed boundary set;
* twenty admitted microprograms spanning all fifteen instructions, including
  successful, violating, aborting, and dynamically ill-typed executions.

For successful cases, the producer, consumer, and immutable reference must agree
on the exact type-tagged result.  For invalid executions, all three must agree on
definedness.  Exception classes and messages are recorded but are not equated,
because the three implementations intentionally use different error classes.
"""
from __future__ import annotations

from collections import Counter
import csv
import json
from pathlib import Path
from typing import Any, Callable, Mapping

from .checker import eval_expr as checker_eval_expr
from .checker import execute as checker_execute
from .model import ValueBudget, enumerate_inputs, validate_program
from .producer import eval_expr as producer_eval_expr
from .producer import run as producer_execute
from .reference_semantics import encode
from .reference_semantics import eval_expr as reference_eval_expr
from .reference_semantics import execute as reference_execute


TYPED_VALUES: tuple[Any, ...] = (
    None,
    False,
    True,
    -1,
    0,
    1,
    "",
    "x",
    [],
    [1],
    {},
    {"a": 1},
)
BINARY_EXPRESSION_OPS: tuple[str, ...] = (
    "add", "sub", "mul", "eq", "ne", "lt", "le", "gt", "ge", "and", "or",
)


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _expression_outcome(
    evaluator: Callable[..., Any],
    expression: Mapping[str, Any],
    *,
    reference: bool = False,
) -> dict[str, Any]:
    try:
        if reference:
            value = evaluator(expression, {}, {})
            key = value
        else:
            value = evaluator(expression, {}, {}, ValueBudget())
            key = encode(value)
        return {"status": "defined", "value": key, "error_type": "", "error_message": ""}
    except Exception as exc:  # recorded as retained negative evidence
        return {
            "status": "error",
            "value": None,
            "error_type": type(exc).__name__,
            "error_message": str(exc),
        }


def expression_matrix() -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    mismatches: list[dict[str, Any]] = []
    outcome_counts: Counter[str] = Counter()
    per_operator: dict[str, Counter[str]] = {}

    cases: list[tuple[str, Any, Any | None, dict[str, Any]]] = []
    for op in BINARY_EXPRESSION_OPS:
        for left in TYPED_VALUES:
            for right in TYPED_VALUES:
                cases.append((op, left, right, {
                    "op": op,
                    "left": {"const": left},
                    "right": {"const": right},
                }))
    for value in TYPED_VALUES:
        cases.append(("not", value, None, {"op": "not", "arg": {"const": value}}))

    for case_index, (op, left, right, expression) in enumerate(cases):
        outcomes = {
            "producer": _expression_outcome(producer_eval_expr, expression),
            "checker": _expression_outcome(checker_eval_expr, expression),
            "reference": _expression_outcome(reference_eval_expr, expression, reference=True),
        }
        statuses = {item["status"] for item in outcomes.values()}
        definedness_match = len(statuses) == 1
        if statuses == {"defined"}:
            encoded_values = {repr(item["value"]) for item in outcomes.values()}
            value_match = len(encoded_values) == 1
            category = "defined"
        elif statuses == {"error"}:
            value_match = True
            category = "error"
        else:
            value_match = False
            category = "mixed-definedness"
        matched = definedness_match and value_match
        outcome_counts[category] += 1
        per_operator.setdefault(op, Counter())[category] += 1

        row = {
            "case_index": case_index,
            "operator": op,
            "left": _json(left),
            # Null is a real binary operand; only unary not has no right operand.
            "right": "" if op == "not" else _json(right),
            "producer_status": outcomes["producer"]["status"],
            "checker_status": outcomes["checker"]["status"],
            "reference_status": outcomes["reference"]["status"],
            "producer_value": _json(outcomes["producer"]["value"]),
            "checker_value": _json(outcomes["checker"]["value"]),
            "reference_value": _json(outcomes["reference"]["value"]),
            "producer_error_type": outcomes["producer"]["error_type"],
            "checker_error_type": outcomes["checker"]["error_type"],
            "reference_error_type": outcomes["reference"]["error_type"],
            "definedness_match": definedness_match,
            "value_match_when_defined": value_match,
            "matched": matched,
        }
        rows.append(row)
        if not matched:
            mismatches.append({
                "layer": "expression",
                "case_index": case_index,
                "expression": expression,
                "outcomes": outcomes,
            })

    summary = {
        "cases": len(rows),
        "typed_values": len(TYPED_VALUES),
        "operators": list(BINARY_EXPRESSION_OPS) + ["not"],
        "defined_cases": outcome_counts["defined"],
        "error_cases": outcome_counts["error"],
        "mixed_definedness_cases": outcome_counts["mixed-definedness"],
        "mismatches": len(mismatches),
        "per_operator": {
            op: {
                "defined": counts["defined"],
                "error": counts["error"],
                "mixed_definedness": counts["mixed-definedness"],
            }
            for op, counts in sorted(per_operator.items())
        },
        "comparison_rule": "exact type-tagged value equality when defined; definedness equality otherwise",
    }
    return rows, mismatches, summary


def _var(name: str) -> dict[str, str]:
    return {"var": name}


def _public(name: str) -> dict[str, str]:
    return {"public": name}


def _base_program(
    program_id: str,
    profile: str,
    family: str,
    domains: dict[str, list[Any]],
    state: dict[str, Any],
    projection: list[str],
    instructions: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema": "rcsc-program",
        "program_id": f"semantic-boundary-{program_id}",
        "profile": profile,
        "family": family,
        "label": "patched",
        "parameters": {"purpose": "frozen semantic boundary matrix"},
        "input_domains": domains,
        "context": {"scope": "owned finite semantic boundary matrix"},
        "initial_public_state": state,
        "public_projection": projection,
        "instructions": instructions,
    }


def instruction_programs() -> list[dict[str, Any]]:
    scalar_values = [None, False, True, -1, 0, 1, "", "x"]
    programs: list[dict[str, Any]] = []

    programs.append(_base_program(
        "assign", "c", "bounds_write", {"x": scalar_values}, {"audit": 0}, ["audit"],
        [
            {"op": "assign", "role": "root", "dst": "y", "expr": _var("x")},
            {"op": "return", "role": "context", "value": _var("y")},
        ],
    ))
    programs.append(_base_program(
        "guard", "c", "bounds_write", {"x": scalar_values}, {"audit": 0}, ["audit"],
        [
            {"op": "guard", "role": "root", "pred": _var("x")},
            {"op": "return", "role": "context", "value": _var("x")},
        ],
    ))
    programs.append(_base_program(
        "branch-abort", "c", "bounds_write", {"x": scalar_values}, {"audit": 0}, ["audit"],
        [
            {"op": "branch_abort", "role": "root", "pred": _var("x")},
            {"op": "return", "role": "context", "value": _var("x")},
        ],
    ))
    programs.append(_base_program(
        "emit", "c", "bounds_write", {"x": scalar_values}, {"audit": 0}, ["audit"],
        [
            {"op": "emit", "role": "root", "name": "event", "value": _var("x")},
            {"op": "return", "role": "context"},
        ],
    ))
    programs.append(_base_program(
        "return", "c", "bounds_write", {"x": scalar_values}, {"audit": 0}, ["audit"],
        [{"op": "return", "role": "root", "value": _var("x")}],
    ))
    programs.append(_base_program(
        "buffer-write", "c", "bounds_write",
        {"idx": [-1, 0, 1, True, "x"], "value": scalar_values},
        {"buffer": [0]}, ["buffer"],
        [
            {"op": "buf_write", "role": "root", "buffer": "buffer", "index": _var("idx"), "value": _var("value")},
            {"op": "return", "role": "context", "value": _public("buffer")},
        ],
    ))
    programs.append(_base_program(
        "divide", "c", "divide_zero",
        {"numerator": [-2, -1, 0, 1, 2, True, "x"], "denominator": [-2, -1, 0, 1, 2, True, "x"]},
        {"audit": 0}, ["audit"],
        [
            {"op": "divide", "role": "root", "dst": "quotient", "numerator": _var("numerator"), "denominator": _var("denominator")},
            {"op": "return", "role": "context", "value": _var("quotient")},
        ],
    ))
    fixed_values = [-4, -2, -1, 0, 1, 2, 4, True, "x"]
    for signed in (False, True):
        for width in (1, 2, 3):
            programs.append(_base_program(
                f"add-fixed-{'signed' if signed else 'unsigned'}-{width}", "c", "fixed_overflow",
                {"left": fixed_values, "right": fixed_values}, {"audit": 0}, ["audit"],
                [
                    {"op": "add_fixed", "role": "root", "dst": "sum", "left": _var("left"), "right": _var("right"), "width": width, "signed": signed},
                    {"op": "return", "role": "context", "value": _var("sum")},
                ],
            ))
    programs.append(_base_program(
        "protected-store", "solidity", "access_control",
        {"sender": scalar_values, "value": scalar_values}, {"owner": 1, "slot": 0}, ["owner", "slot"],
        [
            {"op": "protected_store", "role": "root", "owner_key": "owner", "key": "slot", "value": _var("value")},
            {"op": "return", "role": "context", "value": _public("slot")},
        ],
    ))
    programs.append(_base_program(
        "external-call", "solidity", "reentrancy",
        {"account": ["a", "b", 1, True, None], "amount": [-1, 0, 1, 2, True, "x"], "reenter": scalar_values},
        {"balances": {"a": 1, "b": 0}}, ["balances"],
        [
            {"op": "external_call", "role": "root", "account_var": "account", "balances_key": "balances", "amount": _var("amount")},
            {"op": "return", "role": "context"},
        ],
    ))
    programs.append(_base_program(
        "update-balance", "solidity", "reentrancy",
        {"account": ["a", 1, True, None], "amount": [-1, 0, 1, True, "x"]},
        {"balances": {"a": 1}}, ["balances"],
        [
            {"op": "update_balance", "role": "root", "account_var": "account", "balances_key": "balances", "set": _var("amount")},
            {"op": "return", "role": "context"},
        ],
    ))
    programs.append(_base_program(
        "call-sequence", "solidity", "unchecked_call",
        {"success": scalar_values, "value": scalar_values}, {"slot": 0}, ["slot"],
        [
            {"op": "low_call", "role": "root", "success_var": "success"},
            {"op": "check_call", "role": "root"},
            {"op": "commit_after_call", "role": "root", "key": "slot", "value": _var("value")},
            {"op": "return", "role": "context", "value": _public("slot")},
        ],
    ))
    programs.append(_base_program(
        "commit-without-call", "solidity", "unchecked_call",
        {"value": scalar_values}, {"slot": 0}, ["slot"],
        [
            {"op": "commit_after_call", "role": "root", "key": "slot", "value": _var("value")},
            {"op": "return", "role": "context", "value": _public("slot")},
        ],
    ))
    programs.append(_base_program(
        "check-without-call", "solidity", "unchecked_call",
        {"x": [0]}, {"slot": 0}, ["slot"],
        [
            {"op": "check_call", "role": "root"},
            {"op": "return", "role": "context"},
        ],
    ))
    programs.append(_base_program(
        "nop", "c", "bounds_write", {"x": [0]}, {"audit": 0}, ["audit"],
        [
            {"op": "nop", "role": "root", "tag": "boundary"},
            {"op": "return", "role": "context"},
        ],
    ))

    for program in programs:
        validate_program(program)
    return programs


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


def _execution_outcome(
    evaluator: Callable[[Mapping[str, Any], Mapping[str, Any]], Any],
    program: Mapping[str, Any],
    inputs: Mapping[str, Any],
    *,
    reference: bool = False,
) -> dict[str, Any]:
    try:
        result = evaluator(program, inputs)
        key = result.operational_key() if reference else _implementation_key(result)
        return {"status": "defined", "value": key, "error_type": "", "error_message": ""}
    except Exception as exc:  # dynamic errors are retained, not hidden
        return {
            "status": "error",
            "value": None,
            "error_type": type(exc).__name__,
            "error_message": str(exc),
        }


def instruction_matrix() -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    programs = instruction_programs()
    rows: list[dict[str, Any]] = []
    mismatches: list[dict[str, Any]] = []
    outcome_counts: Counter[str] = Counter()
    instruction_ops = sorted({inst["op"] for program in programs for inst in program["instructions"]})
    profile_counts: Counter[str] = Counter(program["profile"] for program in programs)

    case_index = 0
    for program in programs:
        for inputs in enumerate_inputs(program):
            outcomes = {
                "producer": _execution_outcome(producer_execute, program, inputs),
                "checker": _execution_outcome(checker_execute, program, inputs),
                "reference": _execution_outcome(reference_execute, program, inputs, reference=True),
            }
            statuses = {item["status"] for item in outcomes.values()}
            definedness_match = len(statuses) == 1
            if statuses == {"defined"}:
                values = {repr(item["value"]) for item in outcomes.values()}
                operational_match = len(values) == 1
                category = "defined"
            elif statuses == {"error"}:
                operational_match = True
                category = "error"
            else:
                operational_match = False
                category = "mixed-definedness"
            matched = definedness_match and operational_match
            outcome_counts[category] += 1

            row = {
                "case_index": case_index,
                "program_id": program["program_id"],
                "profile": program["profile"],
                "family": program["family"],
                "input": _json(inputs),
                "producer_status": outcomes["producer"]["status"],
                "checker_status": outcomes["checker"]["status"],
                "reference_status": outcomes["reference"]["status"],
                "producer_error_type": outcomes["producer"]["error_type"],
                "checker_error_type": outcomes["checker"]["error_type"],
                "reference_error_type": outcomes["reference"]["error_type"],
                "definedness_match": definedness_match,
                "operational_match_when_defined": operational_match,
                "matched": matched,
            }
            rows.append(row)
            if not matched:
                mismatches.append({
                    "layer": "instruction",
                    "case_index": case_index,
                    "program_id": program["program_id"],
                    "input": inputs,
                    "outcomes": outcomes,
                })
            case_index += 1

    summary = {
        "programs": len(programs),
        "valuations": len(rows),
        "interpreter_runs": 3 * len(rows),
        "instruction_operations": instruction_ops,
        "profiles": dict(sorted(profile_counts.items())),
        "defined_cases": outcome_counts["defined"],
        "error_cases": outcome_counts["error"],
        "mixed_definedness_cases": outcome_counts["mixed-definedness"],
        "mismatches": len(mismatches),
        "comparison_rule": "exact operational equality when defined; definedness equality otherwise",
    }
    return rows, mismatches, summary


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def run_semantic_boundary_campaign(output: Path) -> dict[str, Any]:
    expression_rows, expression_mismatches, expression_summary = expression_matrix()
    instruction_rows, instruction_mismatches, instruction_summary = instruction_matrix()
    mismatches = expression_mismatches + instruction_mismatches

    output.mkdir(parents=True, exist_ok=True)
    _write_csv(output / "semantic_expression_matrix.csv", expression_rows)
    _write_csv(output / "semantic_instruction_matrix.csv", instruction_rows)
    (output / "semantic_boundary_mismatches.json").write_text(
        json.dumps(mismatches, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    summary = {
        "expression_matrix": expression_summary,
        "instruction_matrix": instruction_summary,
        "total_cases": len(expression_rows) + len(instruction_rows),
        "total_interpreter_evaluations": 3 * (len(expression_rows) + len(instruction_rows)),
        "mismatches": len(mismatches),
        "scope": (
            "frozen typed boundary matrices; exhaustive over the declared value/operator matrix "
            "and the retained instruction microprogram valuations, not over all admitted programs"
        ),
    }
    (output / "semantic_boundary_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary
