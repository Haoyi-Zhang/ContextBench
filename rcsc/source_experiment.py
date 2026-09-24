"""Finite source-capsule translation and semantics campaign."""
from __future__ import annotations

from collections import Counter
import copy
import csv
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from .checker import execute as checker_execute
from .model import stable_json
from .producer import run as producer_run
from .reference_semantics import execute as immutable_execute
from .source_bridge import check_source_pair
from .source_cases import generate_source_corpus
from .source_compile import parse_and_compile
from .source_reference import encode, enumerate_inputs, execute as source_execute
from .source_syntax import Expr, parse_source


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    fields = list(rows[0]) if rows else []
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _production_semantic(result: Any) -> tuple[Any, ...]:
    return (
        result.violation,
        result.aborted,
        encode(result.returned),
        tuple((name, encode(value)) for name, value in result.events),
        tuple((name, encode(value)) for name, value in result.public_state),
    )


def _production_operational(result: Any) -> tuple[Any, ...]:
    return _production_semantic(result) + (result.steps, result.trace)


def _coverage(
    corpus: list[dict[str, Any]],
) -> tuple[list[str], list[str], list[str], list[str], list[str], list[str]]:
    instructions: set[str] = set()
    operations: set[str] = set()
    forms: set[str] = set()
    source_operations: set[str] = set()
    source_forms: set[str] = set()
    source_literal_types: set[str] = set()

    def visit(expr: Any) -> None:
        if not isinstance(expr, dict):
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
        if expr.get("op") == "not":
            operations.add("not")
            visit(expr["arg"])
            return
        if "op" in expr:
            operations.add(expr["op"])
            visit(expr["left"])
            visit(expr["right"])

    def visit_source(expr: Expr) -> None:
        source_forms.add(expr.kind)
        if expr.kind == "literal":
            source_literal_types.add(
                "null" if expr.value is None else type(expr.value).__name__
            )
        elif expr.kind in {"unary", "binary"}:
            source_operations.add(str(expr.value))
        if expr.left is not None:
            visit_source(expr.left)
        if expr.right is not None:
            visit_source(expr.right)

    for pair in corpus:
        for side in ("vulnerable", "patched"):
            for instruction in pair[side]["instructions"]:
                instructions.add(instruction["op"])
                for field in (
                    "expr", "pred", "index", "value", "numerator", "denominator",
                    "left", "right", "amount", "set",
                ):
                    if field in instruction:
                        visit(instruction[field])
        for source_field in ("vulnerable_source", "patched_source"):
            source = parse_source(pair[source_field])
            for statement in source.statements:
                for argument in statement.args:
                    if isinstance(argument, Expr):
                        visit_source(argument)
    return (
        sorted(instructions),
        sorted(operations),
        sorted(forms),
        sorted(source_operations),
        sorted(source_forms),
        sorted(source_literal_types),
    )


def _insert_extra_root(text: str) -> str:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.startswith("root:"):
            lines.insert(index, 'root: nop "extra-root";')
            return "\n".join(lines) + "\n"
    raise AssertionError("source case has no root statement")






def _pre_root_abort_only_safe_sources(vulnerable_text: str, patched_text: str) -> tuple[str, str, dict[str, Any]]:
    """Keep one violating input and make the only nonviolating input abort before root."""
    def rewrite(text: str) -> str:
        lines = text.splitlines()
        replaced = False
        for index, line in enumerate(lines):
            if line.startswith("input idx = "):
                lines[index] = "input idx = [-1,0];"
                replaced = True
                break
        if not replaced:
            raise AssertionError("bounds source case has no idx input")
        for index, line in enumerate(lines):
            if line.startswith("root:"):
                lines.insert(index, "context: abort_if(idx == 0);")
                return "\n".join(lines) + "\n"
        raise AssertionError("source case has no root statement")

    vulnerable = rewrite(vulnerable_text)
    patched = rewrite(patched_text)
    return vulnerable, patched, {"idx": -1, "value": 0}

def _insert_type_error(text: str) -> str:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.startswith(("context:", "root:")):
            lines.insert(index, 'context: let source_type_error = "text" + 1;')
            return "\n".join(lines) + "\n"
    raise AssertionError("source case has no statement")

def _safe_input(source_text: str) -> dict[str, Any]:
    source, _ = parse_and_compile(source_text)
    for inputs in enumerate_inputs(source):
        if source_execute(source, inputs).violation is None:
            return inputs
    raise AssertionError("source case has no safe input")


def _controls(corpus: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    by_family = {family: next(pair for pair in corpus if pair["family"] == family) for family in sorted({p["family"] for p in corpus})}
    for family, pair in by_family.items():
        cases: list[tuple[str, str, str | None, dict[str, Any]]] = []

        certificate = copy.deepcopy(pair["source_certificate"])
        certificate["declared_family"] = next(name for name in by_family if name != family)
        cases.append(("wrong-source-family", "source-certificate-family-mismatch", None, {"source_certificate": certificate}))

        certificate = copy.deepcopy(pair["source_certificate"])
        certificate["declared_profile"] = "solidity" if pair["profile"] == "c" else "c"
        cases.append(("wrong-source-profile", "source-certificate-profile-mismatch", None, {"source_certificate": certificate}))

        certificate = copy.deepcopy(pair["source_certificate"])
        certificate["source_language"] = "other-source"
        cases.append(("wrong-source-language", "source-certificate-language-mismatch", None, {"source_certificate": certificate}))

        certificate = copy.deepcopy(pair["source_certificate"])
        certificate["patched_program_id"] = "substituted-patched"
        cases.append(("source-endpoint-substitution", "source-certificate-pair-mismatch", None, {"source_certificate": certificate}))

        patched = copy.deepcopy(pair["patched"])
        patched["context"]["shape"] = 999
        cases.append(("compiled-ir-substitution", "source-ir-mismatch", None, {"patched": patched}))

        malformed = pair["patched_source"].replace(
            "label patched;", "label patched;\nlabel patched;", 1
        )
        cases.append(("duplicate-source-declaration", "source-parse-or-admission-error", None, {"patched_source": malformed}))

        extra_source = _insert_extra_root(pair["patched_source"])
        _, extra_ir = parse_and_compile(extra_source)
        cases.append(("extra-root-source-edit", "source-pair-rejected", "root-repair-mismatch", {"patched_source": extra_source, "patched": extra_ir}))

        pair_certificate = copy.deepcopy(pair["certificate"])
        pair_certificate["witness_input"] = _safe_input(pair["vulnerable_source"])
        cases.append(("pair-witness-substitution", "source-pair-rejected", "contradictory-witness", {"certificate": pair_certificate}))

        invalid_vulnerable_source = _insert_type_error(pair["vulnerable_source"])
        invalid_patched_source = _insert_type_error(pair["patched_source"])
        _, invalid_vulnerable_ir = parse_and_compile(invalid_vulnerable_source)
        _, invalid_patched_ir = parse_and_compile(invalid_patched_source)
        cases.append((
            "source-execution-type-error",
            "source-execution-error",
            None,
            {
                "vulnerable_source": invalid_vulnerable_source,
                "patched_source": invalid_patched_source,
                "vulnerable": invalid_vulnerable_ir,
                "patched": invalid_patched_ir,
            },
        ))

        if family == "bounds_write":
            degenerate_vulnerable, degenerate_patched, witness = _pre_root_abort_only_safe_sources(
                pair["vulnerable_source"], pair["patched_source"]
            )
            _, degenerate_vulnerable_ir = parse_and_compile(degenerate_vulnerable)
            _, degenerate_patched_ir = parse_and_compile(degenerate_patched)
            degenerate_certificate = copy.deepcopy(pair["certificate"])
            degenerate_certificate["witness_input"] = witness
            cases.append((
                "pre-root-abort-only-safe-partition",
                "source-pair-rejected",
                "missing-productive-safe-input",
                {
                    "vulnerable_source": degenerate_vulnerable,
                    "patched_source": degenerate_patched,
                    "vulnerable": degenerate_vulnerable_ir,
                    "patched": degenerate_patched_ir,
                    "certificate": degenerate_certificate,
                },
            ))

        for name, expected, expected_pair, changes in cases:
            values = {
                "vulnerable_source": pair["vulnerable_source"],
                "patched_source": pair["patched_source"],
                "vulnerable": pair["vulnerable"],
                "patched": pair["patched"],
                "source_certificate": pair["source_certificate"],
                "certificate": pair["certificate"],
            }
            values.update(changes)
            report = check_source_pair(
                values["vulnerable_source"], values["patched_source"],
                values["vulnerable"], values["patched"],
                values["source_certificate"], values["certificate"],
            )
            detected = (
                not report.accepted
                and report.reason == expected
                and (expected_pair is None or report.pair_reason == expected_pair)
            )
            rows.append(
                {
                    "family": family,
                    "control": name,
                    "expected_reason": expected,
                    "expected_pair_reason": expected_pair or "none",
                    "accepted": report.accepted,
                    "actual_reason": report.reason,
                    "actual_pair_reason": report.pair_reason or "none",
                    "detected": detected,
                }
            )
    return rows


def run_source_campaign(output: Path, per_family: int = 10) -> dict[str, Any]:
    corpus = generate_source_corpus(per_family)
    pair_rows: list[dict[str, Any]] = []
    semantic_rows: list[dict[str, Any]] = []
    mismatches: list[dict[str, Any]] = []

    for pair in corpus:
        report = check_source_pair(
            pair["vulnerable_source"], pair["patched_source"],
            pair["vulnerable"], pair["patched"],
            pair["source_certificate"], pair["certificate"],
        )
        pair_rows.append(
            {
                "pair_id": pair["pair_id"],
                "profile": pair["profile"],
                "family": pair["family"],
                "accepted": report.accepted,
                "reason": report.reason,
                "pair_reason": report.pair_reason or "none",
                "endpoint_valuations": report.endpoint_valuations,
                "source_ir_comparisons": report.source_ir_comparisons,
                "semantic_mismatches": report.semantic_mismatches,
                "operational_mismatches": report.operational_mismatches,
                "safe_inputs_compared": int((report.details or {}).get("safe_inputs_compared", 0)),
                "productive_safe_inputs": int((report.details or {}).get("productive_safe_inputs", 0)),
                "vulnerable_inputs": int((report.details or {}).get("vulnerable_inputs", 0)),
                "elapsed_ms": round(report.elapsed_ms, 6),
            }
        )

        for side in ("vulnerable", "patched"):
            source, compiled = parse_and_compile(pair[side + "_source"])
            for inputs in sorted(enumerate_inputs(source), key=stable_json):
                source_result = source_execute(source, inputs)
                producer_result = producer_run(compiled, inputs)
                checker_result = checker_execute(compiled, inputs)
                immutable_result = immutable_execute(compiled, inputs)
                source_semantic = source_result.semantic_key()
                source_operational = source_result.operational_key()
                matches = {
                    "producer_semantic_match": source_semantic == _production_semantic(producer_result),
                    "checker_semantic_match": source_semantic == _production_semantic(checker_result),
                    "immutable_semantic_match": source_semantic == immutable_result.semantic_key(),
                    "producer_operational_match": source_operational == _production_operational(producer_result),
                    "checker_operational_match": source_operational == _production_operational(checker_result),
                    "immutable_operational_match": source_operational == immutable_result.operational_key(),
                }
                row = {
                    "pair_id": pair["pair_id"],
                    "profile": pair["profile"],
                    "family": pair["family"],
                    "side": side,
                    "input": stable_json(inputs),
                    **matches,
                }
                semantic_rows.append(row)
                if not all(matches.values()):
                    mismatches.append(
                        {
                            "pair_id": pair["pair_id"],
                            "side": side,
                            "input": inputs,
                            "matches": matches,
                            "source": source_result.to_json(),
                            "producer": producer_result.to_json(),
                            "checker": checker_result.to_json(),
                            "immutable": immutable_result.to_json(),
                        }
                    )

    controls = _controls(corpus)
    (
        instruction_operations,
        expression_operations,
        expression_forms,
        source_expression_operations,
        source_expression_forms,
        source_literal_types,
    ) = _coverage(corpus)
    endpoint_valuations = len(semantic_rows)
    semantic_mismatch_count = sum(
        not row["producer_semantic_match"]
        or not row["checker_semantic_match"]
        or not row["immutable_semantic_match"]
        for row in semantic_rows
    )
    operational_mismatch_count = sum(
        not row["producer_operational_match"]
        or not row["checker_operational_match"]
        or not row["immutable_operational_match"]
        for row in semantic_rows
    )
    summary = {
        "pairs": len(corpus),
        "programs": 2 * len(corpus),
        "accepted_pairs": sum(row["accepted"] for row in pair_rows),
        "families": sorted({pair["family"] for pair in corpus}),
        "profiles": sorted({pair["profile"] for pair in corpus}),
        "endpoint_valuations": endpoint_valuations,
        "interpreter_comparisons": 3 * endpoint_valuations,
        "semantic_mismatches": semantic_mismatch_count,
        "operational_mismatches": operational_mismatch_count,
        "instruction_operations": instruction_operations,
        "expression_operations": expression_operations,
        "expression_forms": expression_forms,
        "source_expression_operations": source_expression_operations,
        "source_expression_forms": source_expression_forms,
        "source_literal_types": source_literal_types,
        "controls": len(controls),
        "controls_detected": sum(row["detected"] for row in controls),
        "control_families": dict(Counter(row["control"] for row in controls)),
        "source_language": "rcsc-source-1",
        "native_language_claim": False,
    }

    _write_json(output / "source_corpus.json", corpus)
    _write_csv(output / "source_pair_results.csv", pair_rows)
    _write_csv(output / "source_semantics.csv", semantic_rows)
    _write_csv(output / "source_controls.csv", controls)
    _write_json(output / "source_mismatches.json", mismatches)
    _write_json(output / "source_summary.json", summary)
    return summary
