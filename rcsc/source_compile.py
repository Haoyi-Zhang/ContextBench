"""Deterministic translation from the concrete source capsule into RCSC IR."""
from __future__ import annotations

from typing import Any

from .model import JSON, validate_program
from .source_syntax import Expr, SourceProgram, Statement, parse_source


def compile_expr(expr: Expr) -> Any:
    if expr.kind == "literal":
        return {"const": expr.value}
    if expr.kind == "variable":
        return {"var": expr.value}
    if expr.kind == "state":
        return {"public": expr.value}
    if expr.kind == "unary":
        if expr.value == "not":
            return {"op": "not", "arg": compile_expr(expr.left)}
        if expr.value == "neg":
            return {"op": "sub", "left": {"const": 0}, "right": compile_expr(expr.left)}
        raise ValueError(f"unsupported source unary operation {expr.value!r}")
    if expr.kind == "binary":
        return {
            "op": expr.value,
            "left": compile_expr(expr.left),
            "right": compile_expr(expr.right),
        }
    raise ValueError(f"unsupported source expression kind {expr.kind!r}")


def compile_statement(statement: Statement) -> JSON:
    role = statement.role
    kind = statement.kind
    args = statement.args
    if kind == "nop":
        out: JSON = {"op": "nop", "role": role}
        if args:
            out["tag"] = args[0]
        return out
    if kind == "assign":
        return {"op": "assign", "role": role, "dst": args[0], "expr": compile_expr(args[1])}
    if kind == "guard":
        return {"op": "guard", "role": role, "pred": compile_expr(args[0])}
    if kind == "branch_abort":
        return {"op": "branch_abort", "role": role, "pred": compile_expr(args[0])}
    if kind == "buf_write":
        return {
            "op": "buf_write",
            "role": role,
            "buffer": args[0],
            "index": compile_expr(args[1]),
            "value": compile_expr(args[2]),
        }
    if kind == "divide":
        return {
            "op": "divide",
            "role": role,
            "dst": args[0],
            "numerator": compile_expr(args[1]),
            "denominator": compile_expr(args[2]),
        }
    if kind == "add_fixed":
        return {
            "op": "add_fixed",
            "role": role,
            "dst": args[0],
            "left": compile_expr(args[1]),
            "right": compile_expr(args[2]),
            "width": args[3],
            "signed": args[4],
        }
    if kind == "protected_store":
        return {
            "op": "protected_store",
            "role": role,
            "owner_key": args[0],
            "key": args[1],
            "value": compile_expr(args[2]),
        }
    if kind == "external_call":
        return {
            "op": "external_call",
            "role": role,
            "account_var": args[0],
            "balances_key": args[1],
            "amount": compile_expr(args[2]),
        }
    if kind == "update_balance":
        return {
            "op": "update_balance",
            "role": role,
            "account_var": args[0],
            "balances_key": args[1],
            "set": compile_expr(args[2]),
        }
    if kind == "low_call":
        return {"op": "low_call", "role": role, "success_var": args[0]}
    if kind == "check_call":
        return {"op": "check_call", "role": role}
    if kind == "commit_after_call":
        return {
            "op": "commit_after_call",
            "role": role,
            "key": args[0],
            "value": compile_expr(args[1]),
        }
    if kind == "emit":
        out = {"op": "emit", "role": role, "name": args[0]}
        if len(args) == 2:
            out["value"] = compile_expr(args[1])
        return out
    if kind == "return":
        out = {"op": "return", "role": role}
        if args:
            out["value"] = compile_expr(args[0])
        return out
    raise ValueError(f"unsupported source statement kind {kind!r}")


def compile_program(source: SourceProgram) -> JSON:
    program: JSON = {
        "schema": "rcsc-program",
        "program_id": source.program_id,
        "profile": source.profile,
        "family": source.family,
        "label": source.label,
        "parameters": source.parameters,
        "input_domains": source.input_domains,
        "context": source.context,
        "initial_public_state": source.initial_public_state,
        "public_projection": list(source.public_projection),
        "instructions": [compile_statement(statement) for statement in source.statements],
    }
    validate_program(program)
    return program


def parse_and_compile(text: str) -> tuple[SourceProgram, JSON]:
    source = parse_source(text)
    return source, compile_program(source)
