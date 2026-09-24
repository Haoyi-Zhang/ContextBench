"""Independently structured small-step checker and pair-certificate verifier."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, List, Mapping
import time

from .model import (
    JSON,
    ValueBudget,
    bounded_result,
    require_integer,
    value_key,
    validate_json_tree,
    RunResult,
    VIOLATION_FOR_FAMILY,
    context_skeleton,
    enumerate_inputs,
    freeze_value,
    input_count,
    input_in_domain,
    is_productive_root_safe,
    json_size,
    project_public,
    stable_json,
    validate_input,
    validate_program,
)
from .repair import check_repair_membership, expected_repair

PAIR_CERTIFICATE_FIELDS = {
    "schema",
    "pair_id",
    "vulnerable_id",
    "patched_id",
    "declared_family",
    "declared_repair",
    "witness_input",
}


@dataclass
class CheckReport:
    accepted: bool
    reason: str
    witness: JSON | None
    obligations: int
    elapsed_ms: float
    certificate_bytes: int
    safe_inputs_compared: int = 0
    productive_safe_inputs: int = 0
    vulnerable_inputs: int = 0
    details: JSON | None = None

    def to_json(self) -> JSON:
        return asdict(self)


def _snapshot(value: Any) -> Any:
    """Iteratively materialize a fresh JSON tree; no identity memo is retained."""
    holder = [None]
    pending = [(holder, 0, value)]
    while pending:
        parent, key, node = pending.pop()
        if type(node) is dict:
            target = {}
            parent[key] = target
            pending.extend((target, name, item) for name, item in node.items())
        elif type(node) is list:
            target = [None] * len(node)
            parent[key] = target
            pending.extend((target, index, item) for index, item in enumerate(node))
        else:
            parent[key] = node
    return holder[0]


def _postfix(expr: Any, out: List[Any]) -> None:
    if not isinstance(expr, dict):
        out.append(("lit", expr))
    elif "const" in expr:
        out.append(("lit", expr["const"]))
    elif "var" in expr:
        out.append(("var", expr["var"]))
    elif "public" in expr:
        out.append(("public", expr["public"]))
    elif expr["op"] == "not":
        _postfix(expr["arg"], out)
        out.append(("unary", "not"))
    else:
        _postfix(expr["left"], out)
        _postfix(expr["right"], out)
        out.append(("binary", expr["op"]))


def eval_expr(expr: Any, env: Mapping[str, Any], public: Mapping[str, Any],
              budget: ValueBudget | None = None) -> Any:
    if budget is None:
        budget = ValueBudget()
    code: List[Any] = []
    _postfix(expr, code)
    stack: List[Any] = []
    for kind, value in code:
        if kind == "lit":
            stack.append(_snapshot(budget.charge(value)))
        elif kind == "var":
            stack.append(_snapshot(budget.charge(env[value])))
        elif kind == "public":
            stack.append(_snapshot(budget.charge(public[value])))
        elif kind == "unary":
            stack.append(not bool(stack.pop()))
        else:
            right, left = stack.pop(), stack.pop()
            if value in {"add", "sub", "mul", "lt", "le", "gt", "ge"}:
                require_integer(left)
                require_integer(right)
            if value == "add":
                result = left + right
            elif value == "sub":
                result = left - right
            elif value == "mul":
                result = left * right
            elif value == "eq":
                result = value_key(left) == value_key(right)
            elif value == "ne":
                result = value_key(left) != value_key(right)
            elif value == "lt":
                result = left < right
            elif value == "le":
                result = left <= right
            elif value == "gt":
                result = left > right
            elif value == "ge":
                result = left >= right
            elif value == "and":
                result = bool(left) and bool(right)
            elif value == "or":
                result = bool(left) or bool(right)
            else:  # validate_program makes this unreachable.
                raise AssertionError(value)
            stack.append(budget.charge(bounded_result(result)))
    if len(stack) != 1:
        raise ValueError("malformed expression")
    return stack[0]


def _trunc_div(numerator: int, denominator: int) -> int:
    magnitude = abs(numerator) // abs(denominator)
    if (numerator >= 0 and denominator >= 0) or (numerator < 0 and denominator < 0):
        return magnitude
    return -magnitude


def execute(
    program: Mapping[str, Any],
    inputs: Mapping[str, Any],
    mutant: str | None = None,
    *,
    _validated: bool = False,
) -> RunResult:
    if not _validated:
        validate_program(program)
        validate_input(program, inputs)
    budget = ValueBudget()
    machine = {
        "pc": 0,
        "env": dict(budget.charge(dict(inputs))),
        "public": _snapshot(budget.charge(program["initial_public_state"])),
        "events": [],
        "trace": [],
        "returned": None,
        "did_return": False,
        "violation": None,
        "aborted": False,
        "last_call_success": True,
        "call_checked": False,
    }
    instructions = program["instructions"]
    while machine["pc"] < len(instructions):
        if machine["violation"] or machine["aborted"] or machine["did_return"]:
            break
        pc = machine["pc"]
        inst = instructions[pc]
        op = inst["op"]
        machine["trace"].append(f"{pc}:{op}")
        env, public = machine["env"], machine["public"]
        if op == "nop":
            pass
        elif op == "assign":
            env[inst["dst"]] = eval_expr(inst["expr"], env, public, budget)
        elif op == "guard":
            if not bool(eval_expr(inst["pred"], env, public, budget)):
                machine["aborted"] = True
        elif op == "branch_abort":
            if bool(eval_expr(inst["pred"], env, public, budget)):
                machine["aborted"] = True
        elif op == "buf_write":
            index = require_integer(eval_expr(inst["index"], env, public, budget))
            value = eval_expr(inst["value"], env, public, budget)
            buf = public[inst["buffer"]]
            bad = index < 0 or index >= len(buf)
            if mutant == "bounds_inclusive" and index == len(buf):
                bad = False
                buf.append(0)
            if bad:
                machine["violation"] = "OOB_WRITE"
            else:
                buf[index] = value
        elif op == "divide":
            numerator = require_integer(eval_expr(inst["numerator"], env, public, budget))
            denominator = require_integer(eval_expr(inst["denominator"], env, public, budget))
            if denominator == 0 and mutant == "zero_over_zero_safe" and numerator == 0:
                env[inst["dst"]] = 0
            elif denominator == 0:
                machine["violation"] = "DIVIDE_BY_ZERO"
            else:
                env[inst["dst"]] = _trunc_div(numerator, denominator)
        elif op == "add_fixed":
            left = require_integer(eval_expr(inst["left"], env, public, budget))
            right = require_integer(eval_expr(inst["right"], env, public, budget))
            result = left + right
            width = int(inst["width"])
            low, high = (
                (-(2 ** (width - 1)), 2 ** (width - 1) - 1)
                if inst["signed"] else (0, 2 ** width - 1)
            )
            if result < low or result > high:
                if mutant == "wrap_without_event":
                    env[inst["dst"]] = result % (2 ** width)
                else:
                    machine["violation"] = "INTEGER_OVERFLOW"
            else:
                env[inst["dst"]] = result
        elif op == "protected_store":
            authorized = value_key(env["sender"]) == value_key(public[inst["owner_key"]])
            if mutant == "friend_is_owner" and env["sender"] == "user":
                authorized = True
            if not authorized:
                machine["violation"] = "UNAUTHORIZED_WRITE"
            else:
                public[inst["key"]] = eval_expr(inst["value"], env, public, budget)
        elif op == "external_call":
            account = env[inst["account_var"]]
            if type(account) is not str:
                raise TypeError("account keys must be strings")
            amount = require_integer(eval_expr(inst["amount"], env, public, budget))
            balance = require_integer(public[inst["balances_key"]].get(account, 0))
            if (
                mutant != "ignore_callback"
                and bool(env.get("reenter", False))
                and balance >= amount
                and balance > 0
            ):
                machine["violation"] = "REENTRANT_WITHDRAWAL"
        elif op == "update_balance":
            account = env[inst["account_var"]]
            if type(account) is not str:
                raise TypeError("account keys must be strings")
            public[inst["balances_key"]][account] = require_integer(eval_expr(inst["set"], env, public, budget))
        elif op == "low_call":
            machine["last_call_success"] = (
                True if mutant == "force_call_success" else bool(env[inst["success_var"]])
            )
            machine["call_checked"] = False
        elif op == "check_call":
            machine["call_checked"] = True
            if not machine["last_call_success"]:
                machine["aborted"] = True
        elif op == "commit_after_call":
            if not machine["last_call_success"] and not machine["call_checked"]:
                machine["violation"] = "UNCHECKED_CALL_FAILURE"
            else:
                public[inst["key"]] = eval_expr(inst["value"], env, public, budget)
        elif op == "emit":
            value = eval_expr(inst["value"], env, public, budget) if "value" in inst else None
            machine["events"].append((inst["name"], _snapshot(budget.charge(value))))
        elif op == "return":
            machine["returned"] = eval_expr(inst["value"], env, public, budget) if "value" in inst else None
            machine["did_return"] = True
        else:  # validate_program makes this unreachable.
            raise AssertionError(op)
        machine["pc"] += 1
    for name in program["public_projection"]:
        budget.charge(machine["public"][name])
    return RunResult(
        machine["violation"],
        machine["aborted"],
        machine["returned"],
        tuple(machine["events"]),
        project_public(machine["public"], program["public_projection"]),
        len(machine["trace"]),
        tuple(machine["trace"]),
    )


def _first_difference(left: Any, right: Any, path: str = "context") -> JSON | None:
    if type(left) is not type(right):
        return {"path": path, "left": freeze_value(left), "right": freeze_value(right)}
    if isinstance(left, dict):
        for key in sorted(set(left) | set(right)):
            if key not in left or key not in right:
                return {"path": f"{path}.{key}", "left": left.get(key), "right": right.get(key)}
            difference = _first_difference(left[key], right[key], f"{path}.{key}")
            if difference:
                return difference
        return None
    if isinstance(left, list):
        if len(left) != len(right):
            return {"path": f"{path}.length", "left": len(left), "right": len(right)}
        for index, (first, second) in enumerate(zip(left, right)):
            difference = _first_difference(first, second, f"{path}[{index}]")
            if difference:
                return difference
        return None
    if left != right:
        return {"path": path, "left": left, "right": right}
    return None


def _certificate_size(certificate: Any) -> int:
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
    safe: int = 0,
    productive_safe: int = 0,
    vulnerable: int = 0,
    details: JSON | None = None,
) -> CheckReport:
    return CheckReport(
        accepted=accepted,
        reason=reason,
        witness=witness,
        obligations=obligations,
        elapsed_ms=(time.perf_counter() - started) * 1000,
        certificate_bytes=_certificate_size(certificate),
        safe_inputs_compared=safe,
        productive_safe_inputs=productive_safe,
        vulnerable_inputs=vulnerable,
        details=details,
    )


def _endpoint_pair_id(program_id: Any, label: str) -> str | None:
    if not isinstance(program_id, str):
        return None
    suffix = f"-{label}"
    if not program_id.endswith(suffix):
        return None
    pair_id = program_id[: -len(suffix)]
    return pair_id or None


def _validate_pair_certificate(
    vulnerable: Mapping[str, Any], patched: Mapping[str, Any], certificate: Any
) -> tuple[str | None, JSON | None]:
    if not isinstance(certificate, Mapping):
        return "certificate-schema-error", {"error": "certificate must be a mapping"}
    keys = set(certificate)
    if keys != PAIR_CERTIFICATE_FIELDS or certificate.get("schema") != "rcsc-pair-certificate":
        return "certificate-schema-error", {
            "missing": sorted(PAIR_CERTIFICATE_FIELDS.difference(keys)),
            "unexpected": sorted(keys.difference(PAIR_CERTIFICATE_FIELDS)),
            "schema": certificate.get("schema"),
        }
    vulnerable_pair = _endpoint_pair_id(vulnerable["program_id"], "vulnerable")
    patched_pair = _endpoint_pair_id(patched["program_id"], "patched")
    if (
        vulnerable_pair is None
        or patched_pair is None
        or vulnerable_pair != patched_pair
        or certificate["pair_id"] != vulnerable_pair
        or certificate["vulnerable_id"] != vulnerable["program_id"]
        or certificate["patched_id"] != patched["program_id"]
    ):
        return "certificate-pair-mismatch", {
            "declared_pair": certificate.get("pair_id"),
            "vulnerable_id": certificate.get("vulnerable_id"),
            "patched_id": certificate.get("patched_id"),
            "actual_vulnerable_id": vulnerable["program_id"],
            "actual_patched_id": patched["program_id"],
        }
    if certificate["declared_family"] != vulnerable["family"]:
        return "certificate-family-mismatch", {
            "declared": certificate["declared_family"],
            "actual": vulnerable["family"],
        }
    repair = expected_repair(vulnerable["family"])
    if certificate["declared_repair"] != repair:
        return "certificate-repair-mismatch", {
            "declared": certificate["declared_repair"],
            "expected": repair,
        }
    witness = certificate["witness_input"]
    if witness is None:
        return "certificate-missing-witness", None
    if not input_in_domain(vulnerable, witness):
        return "certificate-witness-out-of-domain", {"input": witness}
    return None, None


_SEMANTIC_DIAGNOSTIC_ORDER = {
    "execution-error": 0,
    "wrong-root-cause": 1,
    "patched-still-vulnerable": 2,
    "safe-observation-mismatch": 3,
    "missing-root-witness": 4,
    "missing-safe-input": 5,
    "missing-productive-safe-input": 6,
}


def _semantic_diagnostic_key(item: tuple[str, JSON | None]) -> tuple[int, str]:
    reason, witness = item
    input_value = witness.get("input") if isinstance(witness, Mapping) else None
    return _SEMANTIC_DIAGNOSTIC_ORDER[reason], stable_json(input_value)


def _check_pair_for_testing(
    vulnerable: Mapping[str, Any],
    patched: Mapping[str, Any],
    certificate: Mapping[str, Any],
    *,
    mutant: str | None = None,
    skip_context: bool = False,
    skip_observations: bool = False,
    require_repair: bool = True,
    require_safe: bool = True,
    require_productive_safe: bool = True,
) -> CheckReport:
    """Finite pair checker with explicit test-only ablation switches.

    The production entry point below exposes none of these switches.  Semantic
    diagnostics are selected by a documented total order over relation clauses
    and then by canonical input encoding, rather than by accidental domain-list
    order.
    """
    started = time.perf_counter()
    obligations = safe = productive_safe = vulnerable_count = 0
    try:
        validate_json_tree(certificate)
        validate_program(vulnerable)
        validate_program(patched)
    except Exception as exc:
        return _report(started, certificate, False, "schema-error", {"error": str(exc)}, 0)
    if vulnerable["label"] != "vulnerable" or patched["label"] != "patched":
        return _report(
            started,
            certificate,
            False,
            "contradictory-label",
            {"left": vulnerable["label"], "right": patched["label"]},
            obligations,
        )
    if vulnerable["profile"] != patched["profile"] or vulnerable["family"] != patched["family"]:
        return _report(started, certificate, False, "family-mismatch", None, obligations)
    if stable_json(vulnerable["input_domains"]) != stable_json(patched["input_domains"]):
        return _report(started, certificate, False, "input-domain-mismatch", None, obligations)
    if not skip_context:
        obligations += 1
        difference = _first_difference(context_skeleton(vulnerable), context_skeleton(patched))
        if difference:
            return _report(started, certificate, False, "context-leakage", difference, obligations)

    obligations += 1
    certificate_reason, certificate_witness = _validate_pair_certificate(vulnerable, patched, certificate)
    if certificate_reason:
        return _report(
            started,
            certificate,
            False,
            certificate_reason,
            certificate_witness,
            obligations,
        )

    repair_details: JSON = {"repair": "semantic-layer-ablation"}
    if require_repair:
        obligations += 1
        repair_reason, repair_details = check_repair_membership(
            vulnerable, patched, certificate["declared_repair"]
        )
        if repair_reason is not None:
            return _report(
                started,
                certificate,
                False,
                repair_reason,
                repair_details,
                obligations,
            )

    expected = VIOLATION_FOR_FAMILY[vulnerable["family"]]
    first = None
    failures: list[tuple[str, JSON | None]] = []
    inputs_list = sorted(enumerate_inputs(vulnerable), key=stable_json)
    for inputs in inputs_list:
        try:
            left = execute(vulnerable, inputs, mutant, _validated=True)
            right = execute(patched, inputs, mutant, _validated=True)
        except Exception as exc:
            failures.append(("execution-error", {"input": inputs, "error": str(exc)}))
            obligations += 2
            continue
        obligations += 2
        if left.violation:
            vulnerable_count += 1
            if left.violation == expected and first is None:
                first = {"input": inputs, "result": left.to_json()}
            if left.violation != expected:
                failures.append((
                    "wrong-root-cause",
                    {"input": inputs, "observed": left.violation, "expected": expected},
                ))
        else:
            safe += 1
            if is_productive_root_safe(vulnerable, left):
                productive_safe += 1
            if not skip_observations:
                obligations += 1
                if left.observation() != right.observation():
                    failures.append((
                        "safe-observation-mismatch",
                        {
                            "input": inputs,
                            "vulnerable": freeze_value(left.observation()),
                            "patched": freeze_value(right.observation()),
                        },
                    ))
        if right.violation:
            failures.append((
                "patched-still-vulnerable",
                {"input": inputs, "result": right.to_json()},
            ))

    if first is None:
        failures.append(("missing-root-witness", None))
    if require_safe:
        if safe == 0:
            failures.append(("missing-safe-input", None))
        elif require_productive_safe and productive_safe == 0:
            failures.append(("missing-productive-safe-input", None))
    if failures:
        reason, witness = min(failures, key=_semantic_diagnostic_key)
        return _report(
            started,
            certificate,
            False,
            reason,
            witness,
            obligations,
            safe,
            productive_safe,
            vulnerable_count,
            {
                "input_count": input_count(vulnerable),
                "diagnostic_policy": "relation-clause order then canonical input",
                "repair": repair_details,
            },
        )

    witness = certificate["witness_input"]
    try:
        result = execute(vulnerable, witness, mutant, _validated=True)
    except Exception as exc:
        return _report(
            started,
            certificate,
            False,
            "execution-error",
            {"input": witness, "error": str(exc)},
            obligations,
            safe,
            productive_safe,
            vulnerable_count,
        )
    obligations += 1
    if result.violation != expected:
        return _report(
            started,
            certificate,
            False,
            "contradictory-witness",
            {"input": witness, "result": result.to_json(), "expected": expected},
            obligations,
            safe,
            productive_safe,
            vulnerable_count,
        )
    return _report(
        started,
        certificate,
        True,
        "accepted",
        {"input": witness, "violation": result.violation},
        obligations,
        safe,
        productive_safe,
        vulnerable_count,
        {
            "input_count": input_count(vulnerable),
            "repair": repair_details,
            "diagnostic_policy": "relation-clause order then canonical input",
        },
    )


def check_pair(vulnerable: Mapping[str, Any], patched: Mapping[str, Any],
               certificate: Mapping[str, Any]) -> CheckReport:
    """Production verifier: context, exact repair, nonvacuity and semantics are mandatory."""
    return _check_pair_for_testing(vulnerable, patched, certificate)
