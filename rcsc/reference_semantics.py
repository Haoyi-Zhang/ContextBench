"""Immutable denotational reference semantics for the complete admitted IR.

This module deliberately imports no project schema, evaluator, generator, or
checker code.  It is a small executable specification used only after packet
admission.  Values are represented by immutable, type-tagged tuples so Python
object identity and bool/int equality cannot influence the result.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


class ReferenceExecutionError(ValueError):
    """The admitted program asks the reference machine for an invalid operation."""


Tagged = tuple[Any, ...]


def encode(value: Any) -> Tagged:
    """Encode a JSON value as an immutable and injectively type-tagged tree."""
    typ = type(value)
    if value is None:
        return ("null",)
    if typ is bool:
        return ("bool", value)
    if typ is int:
        return ("int", value)
    if typ is str:
        return ("str", value)
    if typ in (list, tuple):
        return ("array", tuple(encode(item) for item in value))
    if typ is dict:
        if any(type(key) is not str for key in value):
            raise ReferenceExecutionError("object keys must be strings")
        return ("object", tuple((key, encode(value[key])) for key in sorted(value)))
    raise ReferenceExecutionError("reference values must be JSON values")


def decode(value: Tagged) -> Any:
    """Decode a tagged reference value into a fresh JSON tree."""
    tag = value[0]
    if tag == "null":
        return None
    if tag in {"bool", "int", "str"}:
        return value[1]
    if tag == "array":
        return [decode(item) for item in value[1]]
    if tag == "object":
        return {key: decode(item) for key, item in value[1]}
    raise ReferenceExecutionError(f"unknown value tag {tag!r}")


def _truth(value: Tagged) -> bool:
    tag = value[0]
    if tag == "null":
        return False
    if tag == "bool":
        return value[1]
    if tag == "int":
        return value[1] != 0
    if tag == "str":
        return value[1] != ""
    if tag in {"array", "object"}:
        return len(value[1]) != 0
    raise ReferenceExecutionError(f"unknown value tag {tag!r}")


def _integer(value: Tagged) -> int:
    if value[0] != "int":
        raise ReferenceExecutionError("an integer operand is required")
    return value[1]


def _string(value: Tagged) -> str:
    if value[0] != "str":
        raise ReferenceExecutionError("a string operand is required")
    return value[1]


def _array(value: Tagged) -> tuple[Tagged, ...]:
    if value[0] != "array":
        raise ReferenceExecutionError("an array value is required")
    return value[1]


def _object(value: Tagged) -> tuple[tuple[str, Tagged], ...]:
    if value[0] != "object":
        raise ReferenceExecutionError("an object value is required")
    return value[1]


def _object_get(value: Tagged, key: str, default: Tagged | None = None) -> Tagged:
    for name, item in _object(value):
        if name == key:
            return item
    if default is not None:
        return default
    raise ReferenceExecutionError(f"missing object key {key!r}")


def _object_set(value: Tagged, key: str, item: Tagged) -> Tagged:
    mapping = dict(_object(value))
    mapping[key] = item
    return ("object", tuple((name, mapping[name]) for name in sorted(mapping)))


def _array_set(value: Tagged, index: int, item: Tagged) -> Tagged:
    items = list(_array(value))
    items[index] = item
    return ("array", tuple(items))


def _trunc_div(numerator: int, denominator: int) -> int:
    magnitude = abs(numerator) // abs(denominator)
    return -magnitude if (numerator < 0) != (denominator < 0) else magnitude


def eval_expr(expr: Any, env: Mapping[str, Tagged], public: Mapping[str, Tagged]) -> Tagged:
    """Evaluate the full expression grammar without using project helpers."""
    if type(expr) is not dict:
        return encode(expr)
    if set(expr) == {"const"}:
        return encode(expr["const"])
    if set(expr) == {"var"}:
        return env[expr["var"]]
    if set(expr) == {"public"}:
        return public[expr["public"]]
    op = expr.get("op")
    if op == "not":
        return ("bool", not _truth(eval_expr(expr["arg"], env, public)))
    left = eval_expr(expr["left"], env, public)
    right = eval_expr(expr["right"], env, public)
    if op == "add":
        return ("int", _integer(left) + _integer(right))
    if op == "sub":
        return ("int", _integer(left) - _integer(right))
    if op == "mul":
        return ("int", _integer(left) * _integer(right))
    if op == "eq":
        return ("bool", left == right)
    if op == "ne":
        return ("bool", left != right)
    if op == "lt":
        return ("bool", _integer(left) < _integer(right))
    if op == "le":
        return ("bool", _integer(left) <= _integer(right))
    if op == "gt":
        return ("bool", _integer(left) > _integer(right))
    if op == "ge":
        return ("bool", _integer(left) >= _integer(right))
    if op == "and":
        return ("bool", _truth(left) and _truth(right))
    if op == "or":
        return ("bool", _truth(left) or _truth(right))
    raise ReferenceExecutionError(f"unsupported expression operation {op!r}")


@dataclass(frozen=True)
class ReferenceResult:
    violation: str | None
    aborted: bool
    returned: Tagged
    events: tuple[tuple[str, Tagged], ...]
    public_state: tuple[tuple[str, Tagged], ...]
    steps: int
    trace: tuple[str, ...]

    def semantic_key(self) -> tuple[Any, ...]:
        return (
            self.violation,
            self.aborted,
            self.returned,
            self.events,
            self.public_state,
        )

    def operational_key(self) -> tuple[Any, ...]:
        return self.semantic_key() + (self.steps, self.trace)

    def to_json(self) -> dict[str, Any]:
        return {
            "violation": self.violation,
            "aborted": self.aborted,
            "returned": decode(self.returned),
            "events": [[name, decode(value)] for name, value in self.events],
            "public_state": [[name, decode(value)] for name, value in self.public_state],
            "steps": self.steps,
            "trace": list(self.trace),
        }


def execute(program: Mapping[str, Any], inputs: Mapping[str, Any]) -> ReferenceResult:
    """Execute an already-admitted program in immutable state.

    Admission and resource bounds are intentionally outside this reference
    module.  The comparison harness first admits each packet with the production
    schema and then supplies only finite JSON programs and complete inputs here.
    """
    env = {name: encode(value) for name, value in inputs.items()}
    public = {name: encode(value) for name, value in program["initial_public_state"].items()}
    events: tuple[tuple[str, Tagged], ...] = ()
    trace: tuple[str, ...] = ()
    returned = encode(None)
    did_return = False
    violation: str | None = None
    aborted = False
    last_call_success = True
    call_checked = False

    for pc, instruction in enumerate(program["instructions"]):
        if violation is not None or aborted or did_return:
            break
        op = instruction["op"]
        trace = trace + (f"{pc}:{op}",)
        if op == "nop":
            continue
        if op == "assign":
            env = dict(env)
            env[instruction["dst"]] = eval_expr(instruction["expr"], env, public)
            continue
        if op == "guard":
            if not _truth(eval_expr(instruction["pred"], env, public)):
                aborted = True
            continue
        if op == "branch_abort":
            if _truth(eval_expr(instruction["pred"], env, public)):
                aborted = True
            continue
        if op == "buf_write":
            index = _integer(eval_expr(instruction["index"], env, public))
            value = eval_expr(instruction["value"], env, public)
            buffer_name = instruction["buffer"]
            buffer_value = public[buffer_name]
            if index < 0 or index >= len(_array(buffer_value)):
                violation = "OOB_WRITE"
            else:
                public = dict(public)
                public[buffer_name] = _array_set(buffer_value, index, value)
            continue
        if op == "divide":
            numerator = _integer(eval_expr(instruction["numerator"], env, public))
            denominator = _integer(eval_expr(instruction["denominator"], env, public))
            if denominator == 0:
                violation = "DIVIDE_BY_ZERO"
            else:
                env = dict(env)
                env[instruction["dst"]] = ("int", _trunc_div(numerator, denominator))
            continue
        if op == "add_fixed":
            left = _integer(eval_expr(instruction["left"], env, public))
            right = _integer(eval_expr(instruction["right"], env, public))
            result = left + right
            width = instruction["width"]
            if instruction["signed"]:
                low, high = -(2 ** (width - 1)), 2 ** (width - 1) - 1
            else:
                low, high = 0, 2 ** width - 1
            if result < low or result > high:
                violation = "INTEGER_OVERFLOW"
            else:
                env = dict(env)
                env[instruction["dst"]] = ("int", result)
            continue
        if op == "protected_store":
            if env["sender"] != public[instruction["owner_key"]]:
                violation = "UNAUTHORIZED_WRITE"
            else:
                public = dict(public)
                public[instruction["key"]] = eval_expr(instruction["value"], env, public)
            continue
        if op == "external_call":
            account = _string(env[instruction["account_var"]])
            amount = _integer(eval_expr(instruction["amount"], env, public))
            balances = public[instruction["balances_key"]]
            balance = _integer(_object_get(balances, account, ("int", 0)))
            reenter = _truth(env.get("reenter", ("bool", False)))
            if reenter and balance >= amount and balance > 0:
                violation = "REENTRANT_WITHDRAWAL"
            continue
        if op == "update_balance":
            account = _string(env[instruction["account_var"]])
            amount = _integer(eval_expr(instruction["set"], env, public))
            balances_key = instruction["balances_key"]
            public = dict(public)
            public[balances_key] = _object_set(public[balances_key], account, ("int", amount))
            continue
        if op == "low_call":
            last_call_success = _truth(env[instruction["success_var"]])
            call_checked = False
            continue
        if op == "check_call":
            call_checked = True
            if not last_call_success:
                aborted = True
            continue
        if op == "commit_after_call":
            if not last_call_success and not call_checked:
                violation = "UNCHECKED_CALL_FAILURE"
            else:
                public = dict(public)
                public[instruction["key"]] = eval_expr(instruction["value"], env, public)
            continue
        if op == "emit":
            value = eval_expr(instruction["value"], env, public) if "value" in instruction else encode(None)
            events = events + ((instruction["name"], value),)
            continue
        if op == "return":
            returned = eval_expr(instruction["value"], env, public) if "value" in instruction else encode(None)
            did_return = True
            continue
        raise ReferenceExecutionError(f"unsupported instruction operation {op!r}")

    projection = tuple((name, public[name]) for name in program["public_projection"])
    return ReferenceResult(
        violation=violation,
        aborted=aborted,
        returned=returned,
        events=events,
        public_state=projection,
        steps=len(trace),
        trace=trace,
    )
