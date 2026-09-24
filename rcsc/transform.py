"""Catalogued root-preserving and root-flipping transformation certificates."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, List, Mapping, Tuple
import copy
import time

from .checker import execute
from .membership import check_preserving_membership
from .repair import check_repair_membership, expected_repair
from .model import (
    JSON,
    VIOLATION_FOR_FAMILY,
    context_skeleton,
    enumerate_inputs,
    freeze_value,
    is_productive_root_safe,
    json_size,
    stable_json,
    validate_program,
    validate_json_tree,
)


@dataclass
class TransformReport:
    accepted: bool
    reason: str
    witness: JSON | None
    obligations: int
    elapsed_ms: float
    certificate_bytes: int
    details: JSON | None = None

    def to_json(self) -> JSON:
        return asdict(self)


def _root_index(program: Mapping[str, Any]) -> int:
    return next(
        index
        for index, instruction in enumerate(program["instructions"])
        if instruction.get("role", "context") == "root"
    )


def _expression_reads_variable(expr: Any, name: str) -> bool:
    if not isinstance(expr, dict):
        return False
    if set(expr) == {"var"}:
        return expr["var"] == name
    if set(expr) in ({"const"}, {"public"}):
        return False
    if expr.get("op") == "not":
        return _expression_reads_variable(expr["arg"], name)
    return _expression_reads_variable(expr.get("left"), name) or _expression_reads_variable(
        expr.get("right"), name
    )


def _instruction_reads_variable(instruction: Mapping[str, Any], name: str) -> bool:
    for field in (
        "expr", "pred", "index", "value", "numerator", "denominator",
        "left", "right", "amount", "set",
    ):
        if field in instruction and _expression_reads_variable(instruction[field], name):
            return True
    if instruction.get("account_var") == name or instruction.get("success_var") == name:
        return True
    if instruction.get("op") == "protected_store" and name == "sender":
        return True
    if instruction.get("op") == "external_call" and name == "reenter":
        return True
    return False


def _declared_variable_names(program: Mapping[str, Any]) -> set[str]:
    names = set(program["input_domains"])
    for instruction in program["instructions"]:
        if instruction.get("op") in {"assign", "divide", "add_fixed"}:
            names.add(instruction["dst"])
    return names


def preserve_root_nop(program: Mapping[str, Any]) -> Tuple[JSON, JSON]:
    target = copy.deepcopy(program)
    index = _root_index(target)
    target["instructions"].insert(
        index, {"op": "nop", "tag": "certified-root-stutter", "role": "root"}
    )
    target["program_id"] += "-root-stutter"
    certificate = {
        "schema": "rcsc-transform-certificate",
        "class": "root-preserving",
        "transform": "root-stutter",
        "source_id": program["program_id"],
        "target_id": target["program_id"],
        "site": index,
    }
    return target, certificate


def preserve_guard_dual(program: Mapping[str, Any]) -> Tuple[JSON, JSON] | None:
    index = next(
        (
            i
            for i, instruction in enumerate(program["instructions"])
            if instruction.get("role", "context") == "root" and instruction["op"] == "guard"
        ),
        None,
    )
    if index is None:
        return None
    target = copy.deepcopy(program)
    predicate = target["instructions"][index]["pred"]
    target["instructions"][index] = {
        "op": "branch_abort",
        "pred": {"op": "not", "arg": predicate},
        "role": "root",
    }
    target["program_id"] += "-guard-dual"
    certificate = {
        "schema": "rcsc-transform-certificate",
        "class": "root-preserving",
        "transform": "guard-dual",
        "source_id": program["program_id"],
        "target_id": target["program_id"],
        "site": index,
    }
    return target, certificate


def preserve_alpha_unused(program: Mapping[str, Any]) -> Tuple[JSON, JSON]:
    target = copy.deepcopy(program)
    index = next(
        i
        for i, instruction in enumerate(target["instructions"])
        if instruction["op"] == "assign" and instruction.get("role", "context") == "context"
    )
    old = target["instructions"][index]["dst"]
    if old in program["input_domains"] or any(
        _instruction_reads_variable(instruction, old)
        for instruction in program["instructions"][index + 1 :]
    ):
        raise ValueError("alpha-unused requires an unread context temporary")
    new = old + "_fresh"
    if new in _declared_variable_names(program):
        raise ValueError("alpha-unused target name is not fresh")
    target["instructions"][index]["dst"] = new
    target["program_id"] += "-alpha-unused"
    certificate = {
        "schema": "rcsc-transform-certificate",
        "class": "root-preserving",
        "transform": "alpha-unused",
        "source_id": program["program_id"],
        "target_id": target["program_id"],
        "site": index,
        "old": old,
        "new": new,
    }
    return target, certificate


def preserve_swap_independent(program: Mapping[str, Any]) -> Tuple[JSON, JSON]:
    instructions = program["instructions"]
    if len(instructions) < 2 or not (
        instructions[0].get("op") == "assign"
        and instructions[0].get("role") == "context"
        and instructions[1].get("op") == "nop"
        and instructions[1].get("role") == "context"
    ):
        raise ValueError("swap-independent requires an initial context assignment followed by a context no-op")
    target = copy.deepcopy(program)
    target["instructions"][0], target["instructions"][1] = (
        target["instructions"][1],
        target["instructions"][0],
    )
    target["program_id"] += "-swap-independent"
    certificate = {
        "schema": "rcsc-transform-certificate",
        "class": "root-preserving",
        "transform": "swap-independent",
        "source_id": program["program_id"],
        "target_id": target["program_id"],
        "sites": [0, 1],
    }
    return target, certificate


def flip_certificate(source: Mapping[str, Any], target: Mapping[str, Any], kind: str) -> JSON:
    return {
        "schema": "rcsc-transform-certificate",
        "class": "root-flipping",
        "transform": kind,
        "source_id": source["program_id"],
        "target_id": target["program_id"],
    }


def _size(certificate: Any) -> int:
    try:
        return json_size(certificate)
    except Exception:
        return 0


def _report(
    started: float,
    certificate: Any,
    accepted: bool,
    reason: str,
    witness: JSON | None,
    obligations: int,
    details: JSON | None = None,
) -> TransformReport:
    return TransformReport(
        accepted,
        reason,
        witness,
        obligations,
        (time.perf_counter() - started) * 1000,
        _size(certificate),
        details,
    )


_ROOT_FLIP_DIAGNOSTIC_ORDER = {
    "execution-error": 0,
    "wrong-root-cause": 1,
    "flip-does-not-close-root": 2,
    "flip-changes-safe-observation": 3,
    "missing-flip-witness": 4,
    "missing-safe-input": 5,
    "missing-productive-safe-input": 6,
}


def _root_flip_diagnostic_key(item: tuple[str, JSON | None]) -> tuple[int, str]:
    reason, witness = item
    input_value = witness.get("input") if isinstance(witness, Mapping) else None
    return _ROOT_FLIP_DIAGNOSTIC_ORDER[reason], stable_json(input_value)


def check_transform(
    source: Mapping[str, Any], target: Mapping[str, Any], certificate: Mapping[str, Any]
) -> TransformReport:
    started = time.perf_counter()
    obligations = 0
    try:
        validate_json_tree(certificate)
        validate_program(source)
        validate_program(target)
    except Exception as exc:
        return _report(started, certificate, False, "schema-error", {"error": str(exc)}, 0)
    if not isinstance(certificate, Mapping) or certificate.get("schema") != "rcsc-transform-certificate":
        return _report(
            started,
            certificate,
            False,
            "certificate-schema-error",
            {"schema": certificate.get("schema") if isinstance(certificate, Mapping) else None},
            obligations,
        )
    if certificate.get("source_id") != source["program_id"] or certificate.get("target_id") != target["program_id"]:
        return _report(started, certificate, False, "identifier-mismatch", None, obligations)

    certificate_class = certificate.get("class")
    if certificate_class == "root-preserving":
        obligations += 1
        reason = check_preserving_membership(source, target, certificate)
        if reason is not None:
            return _report(started, certificate, False, reason, None, obligations)
        for inputs in sorted(enumerate_inputs(source), key=stable_json):
            try:
                left, right = execute(source, inputs, _validated=True), execute(target, inputs, _validated=True)
            except Exception as exc:
                return _report(
                    started,
                    certificate,
                    False,
                    "execution-error",
                    {"input": inputs, "error": str(exc)},
                    obligations,
                )
            obligations += 3
            if left.semantic() != right.semantic():
                return _report(
                    started,
                    certificate,
                    False,
                    "semantic-change",
                    {
                        "input": inputs,
                        "source": freeze_value(left.semantic()),
                        "target": freeze_value(right.semantic()),
                    },
                    obligations,
                )
        return _report(
            started,
            certificate,
            True,
            "accepted",
            {"derivation": certificate["transform"]},
            obligations,
        )

    if certificate_class == "root-flipping":
        kind = certificate.get("transform")
        if type(kind) is not str or kind not in {"close-root", "open-root"}:
            return _report(started, certificate, False, "unknown-class", None, obligations)
        obligations += 1
        if stable_json({"schema": "rcsc-transform-certificate", "class": "root-flipping",
                        "transform": kind, "source_id": source["program_id"],
                        "target_id": target["program_id"]}) != stable_json(certificate):
            return _report(
                started,
                certificate,
                False,
                "certificate-derivation-mismatch",
                None,
                obligations,
            )
        if stable_json(context_skeleton(source)) != stable_json(context_skeleton(target)):
            return _report(started, certificate, False, "context-change", None, obligations)
        vulnerable, patched = (source, target) if kind == "close-root" else (target, source)
        if vulnerable["label"] != "vulnerable" or patched["label"] != "patched":
            return _report(started, certificate, False, "direction-mismatch", None, obligations)

        # A root flip is not merely any finite-domain semantic change that closes
        # the monitor.  It must be the exact designated pair repair in the chosen
        # direction.  This check is constructor-independent and is the same
        # source/target membership relation used by the pair verifier.
        obligations += 1
        repair_reason, repair_details = check_repair_membership(
            vulnerable, patched, expected_repair(vulnerable["family"])
        )
        if repair_reason is not None:
            return _report(
                started,
                certificate,
                False,
                repair_reason,
                repair_details,
                obligations,
                {"direction": kind, "repair": repair_details},
            )

        expected = VIOLATION_FOR_FAMILY[vulnerable["family"]]
        first = None
        safe = 0
        productive_safe = 0
        failures: list[tuple[str, JSON | None]] = []
        for inputs in sorted(enumerate_inputs(vulnerable), key=stable_json):
            try:
                left, right = execute(vulnerable, inputs, _validated=True), execute(patched, inputs, _validated=True)
            except Exception as exc:
                failures.append(("execution-error", {"input": inputs, "error": str(exc)}))
                obligations += 2
                continue
            obligations += 2
            if left.violation:
                if left.violation != expected:
                    failures.append((
                        "wrong-root-cause",
                        {"input": inputs, "observed": left.violation, "expected": expected},
                    ))
                elif first is None:
                    first = {"input": inputs, "violation": left.violation}
            if right.violation:
                failures.append((
                    "flip-does-not-close-root",
                    {"input": inputs, "result": right.to_json()},
                ))
            if not left.violation:
                safe += 1
                if is_productive_root_safe(vulnerable, left):
                    productive_safe += 1
                obligations += 1
                if left.observation() != right.observation():
                    failures.append((
                        "flip-changes-safe-observation",
                        {
                            "input": inputs,
                            "vulnerable": freeze_value(left.observation()),
                            "patched": freeze_value(right.observation()),
                        },
                    ))
        if first is None:
            failures.append(("missing-flip-witness", None))
        if safe == 0:
            failures.append(("missing-safe-input", None))
        elif productive_safe == 0:
            failures.append(("missing-productive-safe-input", None))
        if failures:
            reason, witness = min(failures, key=_root_flip_diagnostic_key)
            return _report(
                started,
                certificate,
                False,
                reason,
                witness,
                obligations,
                {
                    "direction": kind,
                    "repair": repair_details,
                    "safe_inputs": safe,
                    "productive_safe_inputs": productive_safe,
                },
            )
        return _report(
            started,
            certificate,
            True,
            "accepted",
            first,
            obligations,
            {
                "direction": kind,
                "repair": repair_details,
                "safe_inputs": safe,
                "productive_safe_inputs": productive_safe,
            },
        )

    return _report(started, certificate, False, "unknown-class", None, obligations)


def preserving_variants(program: Mapping[str, Any]) -> List[Tuple[JSON, JSON]]:
    out = [
        preserve_root_nop(program),
        preserve_alpha_unused(program),
        preserve_swap_independent(program),
    ]
    dual = preserve_guard_dual(program)
    if dual:
        out.append(dual)
    return out
