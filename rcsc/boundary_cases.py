"""Benign adversarial packets used to isolate relation-boundary clauses."""
from __future__ import annotations

from typing import Any

from .generate import make_bounds


def make_pre_root_abort_safe_pair(
    pair_id: str = "pre-root-abort-safe",
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Return an exact repair whose only non-violating input aborts before root.

    The vulnerable endpoint still has a real bounds violation at ``idx=-1``.
    At ``idx=0``, however, identical context aborts before any root-role
    instruction.  A plain ``violation is None`` nonvacuity test therefore counts
    one nominally safe input even though no successful safe execution exercises
    the declared root slice.
    """
    vulnerable, patched, certificate = make_bounds(pair_id, 0)
    pre_root_abort = {
        "op": "branch_abort",
        "role": "context",
        "pred": {
            "op": "eq",
            "left": {"var": "idx"},
            "right": {"const": 0},
        },
    }
    for endpoint in (vulnerable, patched):
        endpoint["input_domains"] = {"idx": [-1, 0], "value": [0]}
        first_root = next(
            index
            for index, instruction in enumerate(endpoint["instructions"])
            if instruction.get("role", "context") == "root"
        )
        endpoint["instructions"].insert(first_root, pre_root_abort.copy())
    certificate["witness_input"] = {"idx": -1, "value": 0}
    return vulnerable, patched, certificate
