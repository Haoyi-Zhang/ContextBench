"""Checkable bridge from textual source capsules to admitted RCSC pairs."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import time
from typing import Any, Mapping

from .checker import check_pair, execute as execute_consumer
from .model import (
    SchemaError, enumerate_inputs, stable_json, validate_json_tree, validate_program,
)
from .producer import run as execute_producer
from .reference_semantics import execute as execute_immutable
from .source_compile import parse_and_compile
from .source_reference import SourceResult, encode, execute as execute_source
from .source_syntax import SourceProgram, SourceSyntaxError


SOURCE_PAIR_CERTIFICATE_FIELDS = {
    "schema",
    "pair_id",
    "vulnerable_program_id",
    "patched_program_id",
    "declared_profile",
    "declared_family",
    "source_language",
}


@dataclass(frozen=True)
class SourcePairReport:
    accepted: bool
    reason: str
    endpoint_valuations: int
    source_ir_comparisons: int
    semantic_mismatches: int
    operational_mismatches: int
    elapsed_ms: float
    pair_reason: str | None = None
    details: dict[str, Any] | None = None

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


def _first_difference(left: Any, right: Any, path: str = "value") -> dict[str, Any] | None:
    if type(left) is not type(right):
        return {"path": path, "left_type": type(left).__name__, "right_type": type(right).__name__}
    if isinstance(left, dict):
        left_keys, right_keys = set(left), set(right)
        if left_keys != right_keys:
            return {
                "path": path,
                "missing": sorted(left_keys - right_keys),
                "unexpected": sorted(right_keys - left_keys),
            }
        for key in sorted(left):
            difference = _first_difference(left[key], right[key], f"{path}.{key}")
            if difference:
                return difference
        return None
    if isinstance(left, (list, tuple)):
        if len(left) != len(right):
            return {"path": path, "left_length": len(left), "right_length": len(right)}
        for index, (left_item, right_item) in enumerate(zip(left, right)):
            difference = _first_difference(left_item, right_item, f"{path}[{index}]")
            if difference:
                return difference
        return None
    if left != right:
        return {"path": path, "left": left, "right": right}
    return None


def _ir_semantic_key(result: Any) -> tuple[Any, ...]:
    return (
        result.violation,
        result.aborted,
        encode(result.returned),
        tuple((name, encode(value)) for name, value in result.events),
        tuple((name, encode(value)) for name, value in result.public_state),
    )


def _ir_operational_key(result: Any) -> tuple[Any, ...]:
    return _ir_semantic_key(result) + (result.steps, result.trace)


def compare_source_to_ir(source: SourceProgram, ir: Mapping[str, Any]) -> dict[str, Any]:
    """Compare source execution with all three retained IR semantics.

    The producer and consumer interpreters have different control structure;
    the immutable reference uses a separate value representation and imports no
    project admission, generator, repair, or checker implementation.  A
    source-bound packet is accepted only when the direct source interpreter
    agrees semantically and operationally with every one of them on the full
    declared input domain.
    """
    endpoint_valuations = 0
    comparisons = 0
    execution_errors: list[dict[str, Any]] = []
    semantic_mismatches: list[dict[str, Any]] = []
    operational_mismatches: list[dict[str, Any]] = []
    evaluators = (
        ("producer", execute_producer, _ir_semantic_key, _ir_operational_key),
        ("consumer", lambda program, inputs: execute_consumer(program, inputs, _validated=True),
         _ir_semantic_key, _ir_operational_key),
        ("immutable", execute_immutable,
         lambda result: result.semantic_key(), lambda result: result.operational_key()),
    )
    for inputs in sorted(enumerate_inputs(ir), key=stable_json):
        endpoint_valuations += 1
        try:
            source_result = execute_source(source, inputs)
        except Exception as exc:
            execution_errors.append(
                {
                    "input": inputs,
                    "layer": "source",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                }
            )
            continue
        for layer, evaluator, semantic_key, operational_key in evaluators:
            try:
                ir_result = evaluator(ir, inputs)
            except Exception as exc:
                execution_errors.append(
                    {
                        "input": inputs,
                        "layer": layer,
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                    }
                )
                continue
            comparisons += 1
            if source_result.semantic_key() != semantic_key(ir_result):
                semantic_mismatches.append(
                    {
                        "input": inputs,
                        "layer": layer,
                        "source": source_result.to_json(),
                        "ir": ir_result.to_json(),
                    }
                )
            if source_result.operational_key() != operational_key(ir_result):
                operational_mismatches.append(
                    {
                        "input": inputs,
                        "layer": layer,
                        "source": source_result.to_json(),
                        "ir": ir_result.to_json(),
                    }
                )
    return {
        "endpoint_valuations": endpoint_valuations,
        "source_ir_comparisons": comparisons,
        "execution_errors": execution_errors,
        "semantic_mismatches": semantic_mismatches,
        "operational_mismatches": operational_mismatches,
    }


def _validate_source_certificate(
    certificate: Any,
    vulnerable_source: SourceProgram,
    patched_source: SourceProgram,
) -> tuple[str | None, dict[str, Any] | None]:
    if not isinstance(certificate, Mapping):
        return "source-certificate-schema-error", {"error": "source certificate must be a mapping"}
    try:
        validate_json_tree(certificate)
    except Exception as exc:
        return "source-certificate-schema-error", {"error": str(exc)}
    keys = set(certificate)
    if keys != SOURCE_PAIR_CERTIFICATE_FIELDS or certificate.get("schema") != "rcsc-source-pair-certificate":
        return "source-certificate-schema-error", {
            "missing": sorted(SOURCE_PAIR_CERTIFICATE_FIELDS - keys),
            "unexpected": sorted(keys - SOURCE_PAIR_CERTIFICATE_FIELDS),
            "schema": certificate.get("schema"),
        }
    vulnerable_suffix = "-vulnerable"
    patched_suffix = "-patched"
    vulnerable_id = vulnerable_source.program_id
    patched_id = patched_source.program_id
    if not vulnerable_id.endswith(vulnerable_suffix) or not patched_id.endswith(patched_suffix):
        return "source-certificate-pair-mismatch", {
            "vulnerable_program_id": vulnerable_id,
            "patched_program_id": patched_id,
        }
    vulnerable_pair = vulnerable_id[: -len(vulnerable_suffix)]
    patched_pair = patched_id[: -len(patched_suffix)]
    if (
        not vulnerable_pair
        or vulnerable_pair != patched_pair
        or certificate["pair_id"] != vulnerable_pair
        or certificate["vulnerable_program_id"] != vulnerable_id
        or certificate["patched_program_id"] != patched_id
    ):
        return "source-certificate-pair-mismatch", {
            "declared_pair": certificate.get("pair_id"),
            "actual_vulnerable_pair": vulnerable_pair,
            "actual_patched_pair": patched_pair,
            "declared_vulnerable_program_id": certificate.get("vulnerable_program_id"),
            "declared_patched_program_id": certificate.get("patched_program_id"),
        }
    if certificate["source_language"] != "rcsc-source-1":
        return "source-certificate-language-mismatch", {
            "declared": certificate["source_language"],
            "expected": "rcsc-source-1",
        }
    if (
        vulnerable_source.profile != patched_source.profile
        or certificate["declared_profile"] != vulnerable_source.profile
    ):
        return "source-certificate-profile-mismatch", {
            "declared": certificate["declared_profile"],
            "vulnerable": vulnerable_source.profile,
            "patched": patched_source.profile,
        }
    if (
        vulnerable_source.family != patched_source.family
        or certificate["declared_family"] != vulnerable_source.family
    ):
        return "source-certificate-family-mismatch", {
            "declared": certificate["declared_family"],
            "vulnerable": vulnerable_source.family,
            "patched": patched_source.family,
        }
    if vulnerable_source.label != "vulnerable" or patched_source.label != "patched":
        return "source-label-mismatch", {
            "vulnerable": vulnerable_source.label,
            "patched": patched_source.label,
        }
    return None, None


def check_source_pair(
    vulnerable_text: str,
    patched_text: str,
    vulnerable_ir: Mapping[str, Any],
    patched_ir: Mapping[str, Any],
    source_certificate: Mapping[str, Any],
    pair_certificate: Mapping[str, Any],
) -> SourcePairReport:
    """Verify source binding, finite source/IR semantics, and the IR pair relation."""
    started = time.perf_counter()
    endpoint_valuations = 0
    comparisons = 0
    try:
        vulnerable_source, compiled_vulnerable = parse_and_compile(vulnerable_text)
        patched_source, compiled_patched = parse_and_compile(patched_text)
    except (SourceSyntaxError, ValueError, TypeError, RecursionError, MemoryError) as exc:
        return SourcePairReport(
            False,
            "source-parse-or-admission-error",
            0,
            0,
            0,
            0,
            (time.perf_counter() - started) * 1000,
            details={"error": str(exc)},
        )

    reason, details = _validate_source_certificate(
        source_certificate, vulnerable_source, patched_source
    )
    if reason is not None:
        return SourcePairReport(
            False,
            reason,
            0,
            0,
            0,
            0,
            (time.perf_counter() - started) * 1000,
            details=details,
        )

    # The exact tree comparison below is recursive.  Admit each supplied IR
    # endpoint first so arbitrary library callers cannot smuggle cyclic,
    # over-deep, non-JSON, or otherwise malformed Python objects into it.
    # The command-line verifier already receives bounded JSON, but this check
    # makes the public library entry point fail closed with a structured
    # diagnostic as well.
    for side, supplied in (("vulnerable", vulnerable_ir), ("patched", patched_ir)):
        try:
            validate_program(supplied)
        except (SchemaError, ValueError, TypeError, RecursionError, MemoryError) as exc:
            return SourcePairReport(
                False,
                "source-ir-admission-error",
                0,
                0,
                0,
                0,
                (time.perf_counter() - started) * 1000,
                details={
                    "side": side,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
            )

    for side, compiled, supplied in (
        ("vulnerable", compiled_vulnerable, vulnerable_ir),
        ("patched", compiled_patched, patched_ir),
    ):
        difference = _first_difference(compiled, supplied, side)
        if difference is not None:
            return SourcePairReport(
                False,
                "source-ir-mismatch",
                0,
                0,
                0,
                0,
                (time.perf_counter() - started) * 1000,
                details={"side": side, "difference": difference},
            )

    semantic_mismatches = 0
    operational_mismatches = 0
    for source, compiled, side in (
        (vulnerable_source, compiled_vulnerable, "vulnerable"),
        (patched_source, compiled_patched, "patched"),
    ):
        comparison = compare_source_to_ir(source, compiled)
        endpoint_valuations += comparison["endpoint_valuations"]
        comparisons += comparison["source_ir_comparisons"]
        semantic_mismatches += len(comparison["semantic_mismatches"])
        operational_mismatches += len(comparison["operational_mismatches"])
        if comparison["execution_errors"]:
            return SourcePairReport(
                False,
                "source-execution-error",
                endpoint_valuations,
                comparisons,
                semantic_mismatches,
                operational_mismatches,
                (time.perf_counter() - started) * 1000,
                details={"side": side, "error": comparison["execution_errors"][0]},
            )
        if comparison["semantic_mismatches"]:
            return SourcePairReport(
                False,
                "source-semantic-mismatch",
                endpoint_valuations,
                comparisons,
                semantic_mismatches,
                operational_mismatches,
                (time.perf_counter() - started) * 1000,
                details={"side": side, "mismatch": comparison["semantic_mismatches"][0]},
            )
        if comparison["operational_mismatches"]:
            return SourcePairReport(
                False,
                "source-operational-mismatch",
                endpoint_valuations,
                comparisons,
                semantic_mismatches,
                operational_mismatches,
                (time.perf_counter() - started) * 1000,
                details={"side": side, "mismatch": comparison["operational_mismatches"][0]},
            )

    pair_report = check_pair(
        compiled_vulnerable, compiled_patched, pair_certificate
    )
    if not pair_report.accepted:
        return SourcePairReport(
            False,
            "source-pair-rejected",
            endpoint_valuations,
            comparisons,
            semantic_mismatches,
            operational_mismatches,
            (time.perf_counter() - started) * 1000,
            pair_reason=pair_report.reason,
            details={"pair_report": pair_report.to_json()},
        )

    return SourcePairReport(
        True,
        "accepted",
        endpoint_valuations,
        comparisons,
        0,
        0,
        (time.perf_counter() - started) * 1000,
        pair_reason=pair_report.reason,
        details={
            "pair_obligations": pair_report.obligations,
            "safe_inputs_compared": pair_report.safe_inputs_compared,
            "productive_safe_inputs": pair_report.productive_safe_inputs,
            "vulnerable_inputs": pair_report.vulnerable_inputs,
        },
    )
