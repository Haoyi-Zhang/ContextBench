"""Certificate-producer semantics: recursive expressions and a direct interpreter."""
from __future__ import annotations

from typing import Any, Mapping

from .model import (RunResult, project_public, validate_input, validate_program,
                    bounded_result, require_integer, value_key, ValueBudget)


def _snapshot(value: Any) -> Any:
    """Copy the JSON tree by value, expanding acyclic sharing at each occurrence."""
    if type(value) is list:
        return [_snapshot(item) for item in value]
    if type(value) is dict:
        return {key: _snapshot(item) for key, item in value.items()}
    return value


def eval_expr(expr: Any, env: Mapping[str, Any], public: Mapping[str, Any],
              budget: ValueBudget | None = None) -> Any:
    if budget is None:
        budget = ValueBudget()
    if not isinstance(expr, dict):
        return _snapshot(budget.charge(expr))
    if "const" in expr:
        return _snapshot(budget.charge(expr["const"]))
    if "var" in expr:
        return _snapshot(budget.charge(env[expr["var"]]))
    if "public" in expr:
        return _snapshot(budget.charge(public[expr["public"]]))
    op = expr["op"]
    if op == "not":
        return not bool(eval_expr(expr["arg"], env, public, budget))
    left = eval_expr(expr["left"], env, public, budget)
    right = eval_expr(expr["right"], env, public, budget)
    if op in {"add", "sub", "mul", "lt", "le", "gt", "ge"}:
        require_integer(left)
        require_integer(right)
    return budget.charge(bounded_result({
        "add": lambda: left + right,
        "sub": lambda: left - right,
        "mul": lambda: left * right,
        "eq": lambda: value_key(left) == value_key(right),
        "ne": lambda: value_key(left) != value_key(right),
        "lt": lambda: left < right,
        "le": lambda: left <= right,
        "gt": lambda: left > right,
        "ge": lambda: left >= right,
        "and": lambda: bool(left) and bool(right),
        "or": lambda: bool(left) or bool(right),
    }[op]()))


def _trunc_div(numerator: int, denominator: int) -> int:
    quotient = abs(numerator) // abs(denominator)
    return -quotient if (numerator < 0) != (denominator < 0) else quotient


def run(program: Mapping[str, Any], inputs: Mapping[str, Any]) -> RunResult:
    validate_program(program)
    validate_input(program, inputs)
    budget = ValueBudget()
    env = dict(budget.charge(dict(inputs)))
    public = _snapshot(budget.charge(program["initial_public_state"]))
    events, trace = [], []
    returned = None
    did_return = False
    violation = None
    aborted = False
    last_call_success = True
    call_checked = False
    for pc, inst in enumerate(program["instructions"]):
        if violation or aborted or did_return:
            break
        op = inst["op"]
        trace.append(f"{pc}:{op}")
        if op == "nop":
            pass
        elif op == "assign":
            env[inst["dst"]] = eval_expr(inst["expr"], env, public, budget)
        elif op == "guard":
            if not bool(eval_expr(inst["pred"], env, public, budget)):
                aborted = True
        elif op == "branch_abort":
            if bool(eval_expr(inst["pred"], env, public, budget)):
                aborted = True
        elif op == "buf_write":
            index = require_integer(eval_expr(inst["index"], env, public, budget))
            value = eval_expr(inst["value"], env, public, budget)
            buf = public[inst["buffer"]]
            if index < 0 or index >= len(buf):
                violation = "OOB_WRITE"
            else:
                buf[index] = value
        elif op == "divide":
            numerator = require_integer(eval_expr(inst["numerator"], env, public, budget))
            denominator = require_integer(eval_expr(inst["denominator"], env, public, budget))
            if denominator == 0:
                violation = "DIVIDE_BY_ZERO"
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
                violation = "INTEGER_OVERFLOW"
            else:
                env[inst["dst"]] = result
        elif op == "protected_store":
            if value_key(env["sender"]) != value_key(public[inst["owner_key"]]):
                violation = "UNAUTHORIZED_WRITE"
            else:
                public[inst["key"]] = eval_expr(inst["value"], env, public, budget)
        elif op == "external_call":
            account = env[inst["account_var"]]
            if type(account) is not str:
                raise TypeError("account keys must be strings")
            amount = require_integer(eval_expr(inst["amount"], env, public, budget))
            balances = public[inst["balances_key"]]
            balance = require_integer(balances.get(account, 0))
            if bool(env.get("reenter", False)) and balance >= amount and balance > 0:
                violation = "REENTRANT_WITHDRAWAL"
        elif op == "update_balance":
            account = env[inst["account_var"]]
            if type(account) is not str:
                raise TypeError("account keys must be strings")
            public[inst["balances_key"]][account] = require_integer(eval_expr(inst["set"], env, public, budget))
        elif op == "low_call":
            last_call_success = bool(env[inst["success_var"]])
            call_checked = False
        elif op == "check_call":
            call_checked = True
            if not last_call_success:
                aborted = True
        elif op == "commit_after_call":
            if not last_call_success and not call_checked:
                violation = "UNCHECKED_CALL_FAILURE"
            else:
                public[inst["key"]] = eval_expr(inst["value"], env, public, budget)
        elif op == "emit":
            value = eval_expr(inst["value"], env, public, budget) if "value" in inst else None
            events.append((inst["name"], _snapshot(budget.charge(value))))
        elif op == "return":
            returned = eval_expr(inst["value"], env, public, budget) if "value" in inst else None
            did_return = True
        else:  # validate_program makes this unreachable.
            raise AssertionError(f"unreachable instruction {op}")
    for name in program["public_projection"]:
        budget.charge(public[name])
    return RunResult(
        violation,
        aborted,
        returned,
        tuple(events),
        project_public(public, program["public_projection"]),
        len(trace),
        tuple(trace),
    )
