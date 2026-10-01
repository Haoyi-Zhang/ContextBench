"""Independent full-Cartesian semantic replay for context transport.

This module deliberately does not import the transport checker, its footprint
analysis, its abstract interpreter, its root-table machinery, or the exact repair
checker.  It classifies only the finite execution semantics of a supplied pair
under an expanded context domain.  Exact declarations and repair membership are
checked separately by :mod:`rcsc.transport_contract_gate`.
"""
from __future__ import annotations

import copy
import json
import time
from itertools import product
from typing import Any, Mapping

from .checker import execute
from .model import (
    VIOLATION_FOR_FAMILY,
    is_productive_root_safe,
    stable_json,
    validate_program,
    value_key,
)
from .reference_semantics import execute as reference_execute


def _json_value(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=True, allow_nan=False))


def _valuations(domains: Mapping[str, list[Any]]):
    names = sorted(domains)
    for values in product(*(sorted(domains[name], key=stable_json) for name in names)):
        yield dict(zip(names, values))


def _instantiate(program: Mapping[str, Any], context_input: Mapping[str, Any]) -> dict[str, Any]:
    point = copy.deepcopy(program)
    for name, value in context_input.items():
        point["input_domains"][name] = [copy.deepcopy(value)]
    return point


def direct_oracle(packet: Mapping[str, Any], *, reference: bool = False, retain: bool = False) -> dict[str, Any]:
    """Replay every root/context point without factorization.

    The returned ``semantic_relation`` includes declared-monitor consistency,
    patched closure, within-context observation equality, and vulnerable/productive
    support.  ``security_invariant`` separately records whether each endpoint's
    violation/abort profile is constant across contexts for each root input.

    This function does *not* establish exact repair membership, declaration
    equality, certificate binding, framing, root-table coverage, or abstract
    totality.  Those components are intentionally outside this independent
    semantic path and must be conjoined explicitly by the caller.
    """
    started = time.perf_counter()
    vulnerable_program = packet["vulnerable"]
    patched_program = packet["patched"]
    context_domains = packet["context_domains"]
    root_domains = {
        name: values
        for name, values in vulnerable_program["input_domains"].items()
        if name not in context_domains
    }
    declared_monitor = VIOLATION_FOR_FAMILY.get(vulnerable_program.get("family"))

    seen_security: dict[str, tuple[Any, ...]] = {}
    seen_observation: dict[str, tuple[dict[str, Any], Any]] = {}
    semantic_relation = True
    security_invariant = True
    monitor_consistent = declared_monitor is not None
    defined = True
    reference_comparisons = 0
    reference_mismatches = 0
    endpoint_executions = 0
    rows: list[dict[str, Any]] = []
    first_failure: dict[str, Any] | None = None
    functional_variation: dict[str, Any] | None = None
    failure_counts = {
        "execution_error": 0,
        "declared_monitor_mismatch": 0,
        "patched_violation": 0,
        "safe_observation_mismatch": 0,
        "security_profile_change": 0,
        "missing_context_vulnerable_support": 0,
        "missing_context_productive_safe_support": 0,
    }

    for context_input in _valuations(context_domains):
        vulnerable_point = _instantiate(vulnerable_program, context_input)
        patched_point = _instantiate(patched_program, context_input)
        validate_program(vulnerable_point)
        validate_program(patched_point)
        productive_count = 0
        vulnerable_count = 0
        for root_input in _valuations(root_domains):
            inputs = dict(root_input, **context_input)
            row = {
                "root_input": stable_json(root_input),
                "context_input": stable_json(context_input),
                "defined": True,
                "declared_monitor": declared_monitor or "",
                "v_violation": "",
                "p_violation": "",
                "monitor_consistent": True,
                "patched_closed": True,
                "safe_observations_equal": True,
                "root_invariant": True,
                "reference_comparisons": 0,
                "reference_mismatches": 0,
            }
            try:
                vulnerable_result = execute(vulnerable_point, inputs, _validated=True)
                patched_result = execute(patched_point, inputs, _validated=True)
                endpoint_executions += 2
                if reference:
                    for program, result in (
                        (vulnerable_point, vulnerable_result),
                        (patched_point, patched_result),
                    ):
                        reference_result = reference_execute(program, inputs)
                        reference_comparisons += 1
                        row["reference_comparisons"] += 1
                        match = value_key(_json_value(result.to_json())) == value_key(reference_result.to_json())
                        reference_mismatches += int(not match)
                        row["reference_mismatches"] += int(not match)

                vulnerable_monitor_ok = (
                    vulnerable_result.violation is None
                    or vulnerable_result.violation == declared_monitor
                )
                monitor_consistent &= vulnerable_monitor_ok
                semantic_relation &= vulnerable_monitor_ok
                if not vulnerable_monitor_ok:
                    failure_counts["declared_monitor_mismatch"] += 1

                patched_closed = patched_result.violation is None
                semantic_relation &= patched_closed
                if not patched_closed:
                    failure_counts["patched_violation"] += 1

                if vulnerable_result.violation == declared_monitor:
                    vulnerable_count += 1
                if is_productive_root_safe(vulnerable_point, vulnerable_result):
                    productive_count += 1

                root_key = stable_json(root_input)
                security = (
                    vulnerable_result.violation,
                    patched_result.violation,
                    vulnerable_result.aborted,
                    patched_result.aborted,
                )
                profile_unchanged = security == seen_security.setdefault(root_key, security)
                security_invariant &= profile_unchanged
                if not profile_unchanged:
                    failure_counts["security_profile_change"] += 1

                observations_equal = (
                    vulnerable_result.violation is not None
                    or vulnerable_result.observation() == patched_result.observation()
                )
                semantic_relation &= observations_equal
                if not observations_equal:
                    failure_counts["safe_observation_mismatch"] += 1

                row.update(
                    v_violation=vulnerable_result.violation or "",
                    p_violation=patched_result.violation or "",
                    monitor_consistent=vulnerable_monitor_ok,
                    patched_closed=patched_closed,
                    safe_observations_equal=observations_equal,
                    root_invariant=profile_unchanged,
                )

                if vulnerable_result.violation is None and not vulnerable_result.aborted:
                    prior_context, prior_result = seen_observation.setdefault(
                        root_key,
                        (copy.deepcopy(context_input), _json_value(vulnerable_result.to_json())),
                    )
                    current_result = _json_value(vulnerable_result.to_json())
                    if (
                        functional_variation is None
                        and value_key(prior_result["events"]) != value_key(current_result["events"])
                    ):
                        functional_variation = {
                            "root_input": copy.deepcopy(root_input),
                            "first_context": prior_context,
                            "second_context": copy.deepcopy(context_input),
                            "first_result": prior_result,
                            "second_result": current_result,
                        }

                if first_failure is None:
                    if not vulnerable_monitor_ok:
                        first_failure = {
                            "component": "declared-monitor-consistency",
                            "input": inputs,
                            "observed": vulnerable_result.violation,
                            "expected": declared_monitor,
                        }
                    elif not patched_closed:
                        first_failure = {
                            "component": "patched-closure",
                            "input": inputs,
                            "vulnerable": vulnerable_result.to_json(),
                            "patched": patched_result.to_json(),
                        }
                    elif not observations_equal:
                        first_failure = {
                            "component": "safe-observation-equality",
                            "input": inputs,
                            "vulnerable": vulnerable_result.to_json(),
                            "patched": patched_result.to_json(),
                        }
                    elif not profile_unchanged:
                        first_failure = {
                            "component": "security-profile-invariance",
                            "input": inputs,
                            "vulnerable": vulnerable_result.to_json(),
                            "patched": patched_result.to_json(),
                        }
            except (ValueError, TypeError, KeyError, OverflowError) as exc:
                defined = False
                semantic_relation = False
                row["defined"] = False
                failure_counts["execution_error"] += 1
                if first_failure is None:
                    first_failure = {
                        "component": "defined-execution",
                        "input": inputs,
                        "error": type(exc).__name__,
                    }
            if retain:
                rows.append(row)

        if vulnerable_count == 0:
            semantic_relation = False
            failure_counts["missing_context_vulnerable_support"] += 1
            if first_failure is None:
                first_failure = {
                    "component": "vulnerable-support",
                    "context_input": copy.deepcopy(context_input),
                    "expected_monitor": declared_monitor,
                }
        if productive_count == 0:
            semantic_relation = False
            failure_counts["missing_context_productive_safe_support"] += 1
            if first_failure is None:
                first_failure = {
                    "component": "productive-safe-support",
                    "context_input": copy.deepcopy(context_input),
                }

    semantic_relation = bool(semantic_relation)
    security_invariant = bool(security_invariant)
    monitor_consistent = bool(monitor_consistent)
    return {
        # ``relation`` is retained as a compatibility alias for old callers.
        "relation": semantic_relation,
        "semantic_relation": semantic_relation,
        "security_invariant": security_invariant,
        "monitor_consistent": monitor_consistent,
        "defined": bool(defined),
        "semantic_contract_holds": bool(
            defined and semantic_relation and security_invariant and monitor_consistent
        ),
        "declared_monitor": declared_monitor,
        "endpoint_executions": endpoint_executions,
        "reference_comparisons": reference_comparisons,
        "reference_mismatches": reference_mismatches,
        "elapsed_ms": (time.perf_counter() - started) * 1000,
        "first_failure": first_failure,
        "failure_counts": failure_counts,
        "functional_variation": functional_variation,
        "rows": rows,
        "scope": {
            "full_cartesian_semantic_replay": True,
            "uses_transport_footprint": False,
            "uses_context_abstract_interpreter": False,
            "uses_root_table": False,
            "checks_declared_monitor_consistency": True,
            "checks_exact_repair_membership": False,
            "checks_certificate_claims": False,
        },
    }
