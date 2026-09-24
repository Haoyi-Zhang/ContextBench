"""Immutable reference semantics for the concrete source-capsule AST.

This module interprets source statements directly.  It does not import the IR
compiler, either production evaluator, the pair checker, the repair relation, or
corpus constructors.
"""
from __future__ import annotations

from dataclasses import dataclass
from itertools import product
from typing import Any, Iterator, Mapping

from .source_syntax import Expr, SourceProgram, Statement


class SourceExecutionError(ValueError):
    """A source capsule or input requests an operation outside its semantics."""


Tagged = tuple[Any, ...]
MAX_RESULT_BITS = 4096


def encode(value: Any) -> Tagged:
    typ = type(value)
    if value is None:
        return ("null",)
    if typ is bool:
        return ("bool", value)
    if typ is int:
        if value.bit_length() > MAX_RESULT_BITS:
            raise SourceExecutionError("integer exceeds the source execution bound")
        return ("int", value)
    if typ is str:
        return ("str", value)
    if typ in (list, tuple):
        return ("array", tuple(encode(item) for item in value))
    if typ is dict:
        if any(type(key) is not str for key in value):
            raise SourceExecutionError("object keys must be strings")
        return ("object", tuple((key, encode(value[key])) for key in sorted(value)))
    raise SourceExecutionError("source values must be JSON values")


def decode(value: Tagged) -> Any:
    tag = value[0]
    if tag == "null":
        return None
    if tag in {"bool", "int", "str"}:
        return value[1]
    if tag == "array":
        return [decode(item) for item in value[1]]
    if tag == "object":
        return {key: decode(item) for key, item in value[1]}
    raise SourceExecutionError(f"unknown source value tag {tag!r}")


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
    raise SourceExecutionError(f"unknown source value tag {tag!r}")


def _integer(value: Tagged) -> int:
    if value[0] != "int":
        raise SourceExecutionError("an integer operand is required")
    return value[1]


def _string(value: Tagged) -> str:
    if value[0] != "str":
        raise SourceExecutionError("a string operand is required")
    return value[1]


def _array(value: Tagged) -> tuple[Tagged, ...]:
    if value[0] != "array":
        raise SourceExecutionError("an array value is required")
    return value[1]


def _object(value: Tagged) -> tuple[tuple[str, Tagged], ...]:
    if value[0] != "object":
        raise SourceExecutionError("an object value is required")
    return value[1]


def _object_get(value: Tagged, key: str, default: Tagged | None = None) -> Tagged:
    for name, item in _object(value):
        if name == key:
            return item
    if default is not None:
        return default
    raise SourceExecutionError(f"missing object key {key!r}")


def _object_set(value: Tagged, key: str, item: Tagged) -> Tagged:
    mapping = dict(_object(value))
    mapping[key] = item
    return ("object", tuple((name, mapping[name]) for name in sorted(mapping)))


def _array_set(value: Tagged, index: int, item: Tagged) -> Tagged:
    values = list(_array(value))
    values[index] = item
    return ("array", tuple(values))


def _trunc_div(numerator: int, denominator: int) -> int:
    magnitude = abs(numerator) // abs(denominator)
    return -magnitude if (numerator < 0) != (denominator < 0) else magnitude


def _int_result(value: int) -> Tagged:
    if value.bit_length() > MAX_RESULT_BITS:
        raise SourceExecutionError("integer exceeds the source execution bound")
    return ("int", value)


def eval_expr(expr: Expr, env: Mapping[str, Tagged], public: Mapping[str, Tagged]) -> Tagged:
    if expr.kind == "literal":
        return encode(expr.value)
    if expr.kind == "variable":
        try:
            return env[expr.value]
        except KeyError as exc:
            raise SourceExecutionError(f"unknown source variable {expr.value!r}") from exc
    if expr.kind == "state":
        try:
            return public[expr.value]
        except KeyError as exc:
            raise SourceExecutionError(f"unknown source state key {expr.value!r}") from exc
    if expr.kind == "unary":
        argument = eval_expr(expr.left, env, public)
        if expr.value == "not":
            return ("bool", not _truth(argument))
        if expr.value == "neg":
            return _int_result(-_integer(argument))
        raise SourceExecutionError(f"unsupported source unary operation {expr.value!r}")
    if expr.kind != "binary":
        raise SourceExecutionError(f"unsupported source expression kind {expr.kind!r}")
    left = eval_expr(expr.left, env, public)
    right = eval_expr(expr.right, env, public)
    op = expr.value
    if op == "add":
        return _int_result(_integer(left) + _integer(right))
    if op == "sub":
        return _int_result(_integer(left) - _integer(right))
    if op == "mul":
        return _int_result(_integer(left) * _integer(right))
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
    raise SourceExecutionError(f"unsupported source binary operation {op!r}")


@dataclass(frozen=True)
class SourceResult:
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


def input_in_domain(program: SourceProgram, inputs: Any) -> bool:
    if not isinstance(inputs, Mapping) or set(inputs) != set(program.input_domains):
        return False
    for name, value in inputs.items():
        encoded = encode(value)
        if not any(encoded == encode(candidate) for candidate in program.input_domains[name]):
            return False
    return True


def enumerate_inputs(program: SourceProgram) -> Iterator[dict[str, Any]]:
    names = sorted(program.input_domains)
    domains = [program.input_domains[name] for name in names]
    for values in product(*domains):
        yield dict(zip(names, values))


def instruction_name(statement: Statement) -> str:
    return {
        "nop": "nop",
        "assign": "assign",
        "guard": "guard",
        "branch_abort": "branch_abort",
        "buf_write": "buf_write",
        "divide": "divide",
        "add_fixed": "add_fixed",
        "protected_store": "protected_store",
        "external_call": "external_call",
        "update_balance": "update_balance",
        "low_call": "low_call",
        "check_call": "check_call",
        "commit_after_call": "commit_after_call",
        "emit": "emit",
        "return": "return",
    }[statement.kind]


def execute(program: SourceProgram, inputs: Mapping[str, Any]) -> SourceResult:
    if not input_in_domain(program, inputs):
        raise SourceExecutionError("input is not an exact source-domain member")
    env = {name: encode(value) for name, value in inputs.items()}
    public = {name: encode(value) for name, value in program.initial_public_state.items()}
    events: tuple[tuple[str, Tagged], ...] = ()
    trace: tuple[str, ...] = ()
    returned = encode(None)
    did_return = False
    violation: str | None = None
    aborted = False
    last_call_success = True
    call_checked = False

    for pc, statement in enumerate(program.statements):
        if violation is not None or aborted or did_return:
            break
        op = instruction_name(statement)
        trace = trace + (f"{pc}:{op}",)
        args = statement.args
        if statement.kind == "nop":
            continue
        if statement.kind == "assign":
            env = dict(env)
            env[args[0]] = eval_expr(args[1], env, public)
            continue
        if statement.kind == "guard":
            if not _truth(eval_expr(args[0], env, public)):
                aborted = True
            continue
        if statement.kind == "branch_abort":
            if _truth(eval_expr(args[0], env, public)):
                aborted = True
            continue
        if statement.kind == "buf_write":
            buffer_name = args[0]
            index = _integer(eval_expr(args[1], env, public))
            value = eval_expr(args[2], env, public)
            buffer_value = public[buffer_name]
            if index < 0 or index >= len(_array(buffer_value)):
                violation = "OOB_WRITE"
            else:
                public = dict(public)
                public[buffer_name] = _array_set(buffer_value, index, value)
            continue
        if statement.kind == "divide":
            numerator = _integer(eval_expr(args[1], env, public))
            denominator = _integer(eval_expr(args[2], env, public))
            if denominator == 0:
                violation = "DIVIDE_BY_ZERO"
            else:
                env = dict(env)
                env[args[0]] = _int_result(_trunc_div(numerator, denominator))
            continue
        if statement.kind == "add_fixed":
            left = _integer(eval_expr(args[1], env, public))
            right = _integer(eval_expr(args[2], env, public))
            result = left + right
            width = args[3]
            low, high = (
                (-(2 ** (width - 1)), 2 ** (width - 1) - 1)
                if args[4]
                else (0, 2 ** width - 1)
            )
            if result < low or result > high:
                violation = "INTEGER_OVERFLOW"
            else:
                env = dict(env)
                env[args[0]] = _int_result(result)
            continue
        if statement.kind == "protected_store":
            if env.get("sender") != public[args[0]]:
                violation = "UNAUTHORIZED_WRITE"
            else:
                public = dict(public)
                public[args[1]] = eval_expr(args[2], env, public)
            continue
        if statement.kind == "external_call":
            account = _string(env[args[0]])
            amount = _integer(eval_expr(args[2], env, public))
            balances = public[args[1]]
            balance = _integer(_object_get(balances, account, ("int", 0)))
            reenter = _truth(env.get("reenter", ("bool", False)))
            if reenter and balance >= amount and balance > 0:
                violation = "REENTRANT_WITHDRAWAL"
            continue
        if statement.kind == "update_balance":
            account = _string(env[args[0]])
            amount = _integer(eval_expr(args[2], env, public))
            public = dict(public)
            public[args[1]] = _object_set(public[args[1]], account, _int_result(amount))
            continue
        if statement.kind == "low_call":
            last_call_success = _truth(env[args[0]])
            call_checked = False
            continue
        if statement.kind == "check_call":
            call_checked = True
            if not last_call_success:
                aborted = True
            continue
        if statement.kind == "commit_after_call":
            if not last_call_success and not call_checked:
                violation = "UNCHECKED_CALL_FAILURE"
            else:
                public = dict(public)
                public[args[0]] = eval_expr(args[1], env, public)
            continue
        if statement.kind == "emit":
            value = eval_expr(args[1], env, public) if len(args) == 2 else encode(None)
            events = events + ((args[0], value),)
            continue
        if statement.kind == "return":
            returned = eval_expr(args[0], env, public) if args else encode(None)
            did_return = True
            continue
        raise SourceExecutionError(f"unsupported source statement kind {statement.kind!r}")

    projection = tuple((name, public[name]) for name in program.public_projection)
    return SourceResult(
        violation=violation,
        aborted=aborted,
        returned=returned,
        events=events,
        public_state=projection,
        steps=len(trace),
        trace=trace,
    )
