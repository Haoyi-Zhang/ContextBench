"""Two transparent syntax rules used only as transformation-sensitivity probes."""
from __future__ import annotations
from typing import Mapping, Any

def _ordered(program: Mapping[str,Any], first: str, second: str) -> bool:
    ops=[i["op"] for i in program["instructions"] if i.get("role","context")=="root"]
    return first in ops and second in ops and ops.index(first)<ops.index(second)

def canonical_rule(program: Mapping[str,Any]) -> str:
    roots=[i for i in program["instructions"] if i.get("role","context")=="root"]
    if any(i["op"]=="guard" for i in roots):return "patched"
    if _ordered(program,"update_balance","external_call"):return "patched"
    if any(i["op"]=="check_call" for i in roots):return "patched"
    return "vulnerable"

def duality_aware_rule(program: Mapping[str,Any]) -> str:
    roots=[i for i in program["instructions"] if i.get("role","context")=="root"]
    if any(i["op"] in {"guard","branch_abort"} for i in roots):return "patched"
    if _ordered(program,"update_balance","external_call"):return "patched"
    if any(i["op"]=="check_call" for i in roots):return "patched"
    return "vulnerable"
