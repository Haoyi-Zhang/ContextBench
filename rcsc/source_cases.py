"""Owned concrete source-capsule pairs used for the source-to-IR bridge."""
from __future__ import annotations

import json
from typing import Any, Callable

from .repair import expected_repair
from .source_compile import parse_and_compile
from .source_reference import enumerate_inputs, execute


def _literal(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _source_text(
    *,
    program_id: str,
    profile: str,
    family: str,
    label: str,
    parameters: dict[str, Any],
    inputs: dict[str, list[Any]],
    context: dict[str, Any],
    state: dict[str, Any],
    projection: list[str],
    statements: list[str],
) -> str:
    lines = [
        "rcsc-source 1;",
        f"program {program_id};",
        f"profile {profile};",
        f"family {family};",
        f"label {label};",
    ]
    lines.extend(f"parameter {name} = {_literal(value)};" for name, value in parameters.items())
    lines.extend(f"input {name} = {_literal(values)};" for name, values in inputs.items())
    lines.extend(f"context {name} = {_literal(value)};" for name, value in context.items())
    lines.extend(f"state {name} = {_literal(value)};" for name, value in state.items())
    lines.extend(f"project {name};" for name in projection)
    lines.append("")
    lines.extend(statements)
    return "\n".join(lines) + "\n"


def _prefix(seed: int) -> list[str]:
    left = seed % 5
    right = (seed * 3 + 1) % 7
    return [
        f"context: let aux = {left} + {right};",
        f"context: let product_probe = {1 + seed % 3} * {2 + seed % 4};",
        "context: let difference_probe = product_probe - aux;",
        "context: let negative_probe = -1;",
        "context: let string_probe = \"capsule\";",
        "context: let null_probe = null;",
        "context: let typed_probe = true != 1;",
        "context: let order_probe = !(1 > 2) || (1 < 2 && 2 >= 2);",
        "context: abort_if(false);",
        "context: nop;",
        f"context: nop {_literal('shape-' + str(seed % 4))};",
    ]


def _finish(event: str, expression: str) -> list[str]:
    return [
        f"context: emit({_literal(event)}, {expression});",
        f"context: return {expression};",
    ]


def _headers(pair_id: str, label: str, profile: str, family: str, seed: int) -> dict[str, Any]:
    return {
        "program_id": f"{pair_id}-{label}",
        "profile": profile,
        "family": family,
        "label": label,
        "context": {
            "origin": "owned-concrete-source-capsule",
            "scenario": family.replace("_", " "),
            "shape": seed % 5,
        },
    }


def _bounds(pair_id: str, seed: int) -> tuple[str, str]:
    n = 2 + seed % 4
    values = [0, 1 + seed % 3]
    common = {
        "profile": "c",
        "family": "bounds_write",
        "parameters": {"length": n, "element_domain": [0, max(values)]},
        "inputs": {"idx": [-1, 0, n - 1, n], "value": values},
        "state": {"buffer": [seed % 3 for _ in range(n)], "audit": seed % 2},
        "projection": ["buffer", "audit"],
    }
    root = "root: buffer[idx] = value;"
    if seed % 2:
        guard = f"root: require(0 <= idx && {n} > idx);"
    else:
        guard = f"root: require(idx >= 0 && idx < {n});"
    suffix = _finish("write", "state.buffer")
    vulnerable = _source_text(
        **_headers(pair_id, "vulnerable", "c", "bounds_write", seed),
        parameters=common["parameters"], inputs=common["inputs"], state=common["state"],
        projection=common["projection"], statements=_prefix(seed) + [root] + suffix,
    )
    patched = _source_text(
        **_headers(pair_id, "patched", "c", "bounds_write", seed),
        parameters=common["parameters"], inputs=common["inputs"], state=common["state"],
        projection=common["projection"], statements=_prefix(seed) + [guard, root] + suffix,
    )
    return vulnerable, patched


def _divide(pair_id: str, seed: int) -> tuple[str, str]:
    common = {
        "parameters": {"rounding": "toward-zero", "result_name": "quotient"},
        "inputs": {"denominator": [-1, 0, 1, 2 + seed % 2], "numerator": [-2 - seed % 2, 0, 3 + seed % 3]},
        "state": {"audit": seed % 3},
        "projection": ["audit"],
    }
    root = "root: let quotient = div(numerator, denominator);"
    guard = "root: require(denominator != 0);" if seed % 2 == 0 else "root: require(0 != denominator);"
    suffix = _finish("quotient", "quotient")
    vulnerable = _source_text(
        **_headers(pair_id, "vulnerable", "c", "divide_zero", seed),
        parameters=common["parameters"], inputs=common["inputs"], state=common["state"],
        projection=common["projection"], statements=_prefix(seed) + [root] + suffix,
    )
    patched = _source_text(
        **_headers(pair_id, "patched", "c", "divide_zero", seed),
        parameters=common["parameters"], inputs=common["inputs"], state=common["state"],
        projection=common["projection"], statements=_prefix(seed) + [guard, root] + suffix,
    )
    return vulnerable, patched


def _overflow(pair_id: str, seed: int) -> tuple[str, str]:
    width = 3 + seed % 4
    signed = seed % 2 == 1
    low = -(2 ** (width - 1)) if signed else 0
    high = 2 ** (width - 1) - 1 if signed else 2 ** width - 1
    common = {
        "parameters": {"width": width, "signed": signed},
        "inputs": {
            "delta": [-1, 0, 1] if signed else [0, 1, 2],
            "x": [low, 0, high] if signed else [0, max(1, high - 1), high],
        },
        "state": {"audit": seed % 4},
        "projection": ["audit"],
    }
    mode = "signed" if signed else "unsigned"
    root = f"root: let sum = add_fixed(x, delta, {width}, {mode});"
    if signed:
        guard = (
            f"root: require(x <= {high} - delta && x >= ({low}) - delta);"
            if seed % 4 == 1
            else f"root: require({high} - delta >= x && ({low}) - delta <= x);"
        )
    else:
        guard = (
            f"root: require(x <= {high} - delta);"
            if seed % 4 == 0
            else f"root: require({high} - delta >= x);"
        )
    suffix = _finish("sum", "sum")
    vulnerable = _source_text(
        **_headers(pair_id, "vulnerable", "c", "fixed_overflow", seed),
        parameters=common["parameters"], inputs=common["inputs"], state=common["state"],
        projection=common["projection"], statements=_prefix(seed) + [root] + suffix,
    )
    patched = _source_text(
        **_headers(pair_id, "patched", "c", "fixed_overflow", seed),
        parameters=common["parameters"], inputs=common["inputs"], state=common["state"],
        projection=common["projection"], statements=_prefix(seed) + [guard, root] + suffix,
    )
    return vulnerable, patched


def _access(pair_id: str, seed: int) -> tuple[str, str]:
    owner = f"owner{seed % 3}"
    common = {
        "parameters": {"owner_key": "owner", "protected_key": "setting"},
        "inputs": {"sender": [owner, "user", "attacker"], "value": [0, 1 + seed % 3]},
        "state": {"owner": owner, "setting": seed % 2, "audit": seed % 3},
        "projection": ["owner", "setting", "audit"],
    }
    root = "root: protected_store(owner, setting, value);"
    guard = "root: require(sender == state.owner);" if seed % 2 == 0 else "root: require(state.owner == sender);"
    suffix = _finish("setting", "state.setting")
    vulnerable = _source_text(
        **_headers(pair_id, "vulnerable", "solidity", "access_control", seed),
        parameters=common["parameters"], inputs=common["inputs"], state=common["state"],
        projection=common["projection"], statements=_prefix(seed) + [root] + suffix,
    )
    patched = _source_text(
        **_headers(pair_id, "patched", "solidity", "access_control", seed),
        parameters=common["parameters"], inputs=common["inputs"], state=common["state"],
        projection=common["projection"], statements=_prefix(seed) + [guard, root] + suffix,
    )
    return vulnerable, patched


def _reentrancy(pair_id: str, seed: int) -> tuple[str, str]:
    balance = 2 + seed % 3
    common = {
        "parameters": {"repair": "checks-effects-interactions", "balances_key": "balances"},
        "inputs": {"amount": [1, balance], "reenter": [False, True], "sender": ["user"]},
        "state": {"balances": {"user": balance}, "audit": seed % 2},
        "projection": ["balances", "audit"],
    }
    call = "root: external_call(sender, balances, amount);"
    effect = "root: update_balance(sender, balances, 0);"
    suffix = _finish("withdraw", "state.balances")
    vulnerable = _source_text(
        **_headers(pair_id, "vulnerable", "solidity", "reentrancy", seed),
        parameters=common["parameters"], inputs=common["inputs"], state=common["state"],
        projection=common["projection"], statements=_prefix(seed) + [call, effect] + suffix,
    )
    patched = _source_text(
        **_headers(pair_id, "patched", "solidity", "reentrancy", seed),
        parameters=common["parameters"], inputs=common["inputs"], state=common["state"],
        projection=common["projection"], statements=_prefix(seed) + [effect, call] + suffix,
    )
    return vulnerable, patched


def _unchecked(pair_id: str, seed: int) -> tuple[str, str]:
    common = {
        "parameters": {"status_key": "committed"},
        "inputs": {"call_ok": [False, True], "value": [0, 1 + seed % 4]},
        "state": {"committed": 0, "audit": seed % 2},
        "projection": ["committed", "audit"],
    }
    call = "root: low_call(call_ok);"
    check = "root: check_call();"
    commit = "root: commit_after_call(committed, value);"
    suffix = _finish("commit", "state.committed")
    vulnerable = _source_text(
        **_headers(pair_id, "vulnerable", "solidity", "unchecked_call", seed),
        parameters=common["parameters"], inputs=common["inputs"], state=common["state"],
        projection=common["projection"], statements=_prefix(seed) + [call, commit] + suffix,
    )
    patched = _source_text(
        **_headers(pair_id, "patched", "solidity", "unchecked_call", seed),
        parameters=common["parameters"], inputs=common["inputs"], state=common["state"],
        projection=common["projection"], statements=_prefix(seed) + [call, check, commit] + suffix,
    )
    return vulnerable, patched


SOURCE_MAKERS: dict[str, Callable[[str, int], tuple[str, str]]] = {
    "bounds_write": _bounds,
    "divide_zero": _divide,
    "fixed_overflow": _overflow,
    "access_control": _access,
    "reentrancy": _reentrancy,
    "unchecked_call": _unchecked,
}


def make_source_pair(family: str, index: int, seed: int = 7331) -> dict[str, Any]:
    if family not in SOURCE_MAKERS:
        raise ValueError(f"unsupported source family {family!r}")
    pair_id = f"source-{family}-{index:02d}"
    vulnerable_text, patched_text = SOURCE_MAKERS[family](pair_id, seed + index)
    vulnerable_source, vulnerable = parse_and_compile(vulnerable_text)
    patched_source, patched = parse_and_compile(patched_text)
    witness = None
    for inputs in enumerate_inputs(vulnerable_source):
        if execute(vulnerable_source, inputs).violation is not None:
            witness = inputs
            break
    if witness is None:
        raise AssertionError("owned source case lacks a vulnerable witness")
    pair_certificate = {
        "schema": "rcsc-pair-certificate",
        "pair_id": pair_id,
        "vulnerable_id": vulnerable["program_id"],
        "patched_id": patched["program_id"],
        "declared_family": family,
        "declared_repair": expected_repair(family),
        "witness_input": witness,
    }
    source_certificate = {
        "schema": "rcsc-source-pair-certificate",
        "pair_id": pair_id,
        "vulnerable_program_id": vulnerable["program_id"],
        "patched_program_id": patched["program_id"],
        "declared_profile": vulnerable["profile"],
        "declared_family": family,
        "source_language": "rcsc-source-1",
    }
    return {
        "pair_id": pair_id,
        "family": family,
        "profile": vulnerable["profile"],
        "source_kind": "owned-concrete-source-capsule",
        "vulnerable_source": vulnerable_text,
        "patched_source": patched_text,
        "vulnerable": vulnerable,
        "patched": patched,
        "source_certificate": source_certificate,
        "certificate": pair_certificate,
    }


def generate_source_corpus(per_family: int = 10) -> list[dict[str, Any]]:
    if not 1 <= per_family <= 20:
        raise ValueError("source corpus per-family count must be between 1 and 20")
    return [
        make_source_pair(family, index)
        for family in SOURCE_MAKERS
        for index in range(per_family)
    ]
