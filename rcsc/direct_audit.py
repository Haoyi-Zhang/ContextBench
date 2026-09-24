"""Certificate-free baseline for the strengthened finite pair relation.

This implementation deliberately shares the declared interpreter but not the
incoming certificate schema.  It reconstructs the expected repair declaration,
checks exact repair membership, and discovers its own root witness.
"""
from __future__ import annotations
from typing import Any, Mapping

from .model import (
    validate_program,
    context_skeleton,
    stable_json,
    enumerate_inputs,
    is_productive_root_safe,
    VIOLATION_FOR_FAMILY,
)
from .checker import execute
from .repair import check_repair_membership, expected_repair


def audit_pair(vulnerable: Mapping[str, Any], patched: Mapping[str, Any]) -> dict[str, Any]:
    executions = 0
    safe = 0
    productive_safe = 0
    try:
        validate_program(vulnerable)
        validate_program(patched)
        if vulnerable["label"] != "vulnerable" or patched["label"] != "patched":
            return {"accepted": False, "reason": "contradictory-label", "executions": 0}
        # Program identifiers are certificate-binding metadata, not a clause of
        # the underlying endpoint relation.  The production certificate verifier
        # checks its pair-id naming convention; this direct audit deliberately
        # ignores identifiers so that renaming alone cannot change relation truth.
        if stable_json(context_skeleton(vulnerable)) != stable_json(context_skeleton(patched)):
            return {"accepted": False, "reason": "declaration-mismatch", "executions": 0}
        repair = expected_repair(vulnerable["family"])
        repair_reason, repair_details = check_repair_membership(vulnerable, patched, repair)
        if repair_reason is not None:
            return {
                "accepted": False,
                "reason": repair_reason,
                "repair": repair_details,
                "executions": 0,
            }
        expected = VIOLATION_FOR_FAMILY[vulnerable["family"]]
        first = None
        failures: list[tuple[int, str, str, dict[str, Any] | None]] = []
        ranks = {
            "input-or-execution-error": 0,
            "wrong-root-cause": 1,
            "patched-still-vulnerable": 2,
            "safe-observation-mismatch": 3,
        }
        for inputs in sorted(enumerate_inputs(vulnerable), key=stable_json):
            try:
                left = execute(vulnerable, inputs, _validated=True)
                right = execute(patched, inputs, _validated=True)
            except Exception as exc:
                failures.append((ranks["input-or-execution-error"], stable_json(inputs),
                                 "input-or-execution-error", {"input": inputs, "error": str(exc)}))
                executions += 2
                continue
            executions += 2
            if left.violation is not None:
                if left.violation != expected:
                    failures.append((ranks["wrong-root-cause"], stable_json(inputs),
                                     "wrong-root-cause", {"input": inputs}))
                elif first is None:
                    first = dict(inputs)
            else:
                safe += 1
                if is_productive_root_safe(vulnerable, left):
                    productive_safe += 1
                if left.observation() != right.observation():
                    failures.append((ranks["safe-observation-mismatch"], stable_json(inputs),
                                     "safe-observation-mismatch", {"input": inputs}))
            if right.violation is not None:
                failures.append((ranks["patched-still-vulnerable"], stable_json(inputs),
                                 "patched-still-vulnerable", {"input": inputs}))
        if failures:
            _, _, reason, witness = min(failures)
            return {"accepted": False, "reason": reason, "witness": witness,
                    "executions": executions, "safe_inputs": safe,
                    "productive_safe_inputs": productive_safe}
        if first is None:
            return {"accepted": False, "reason": "missing-root-witness",
                    "executions": executions, "safe_inputs": safe,
                    "productive_safe_inputs": productive_safe}
        if safe == 0:
            return {"accepted": False, "reason": "missing-safe-input",
                    "executions": executions, "safe_inputs": safe,
                    "productive_safe_inputs": productive_safe}
        if productive_safe == 0:
            return {"accepted": False, "reason": "missing-productive-safe-input",
                    "executions": executions, "safe_inputs": safe,
                    "productive_safe_inputs": productive_safe}
        return {"accepted": True, "reason": "accepted", "witness_input": first,
                "executions": executions, "safe_inputs": safe,
                "productive_safe_inputs": productive_safe, "repair": repair_details}
    except Exception as exc:
        return {"accepted": False, "reason": "input-or-execution-error",
                "executions": executions, "error": str(exc)}
