"""Ablations showing why repair-surface and safe-domain gates are required."""
import csv
from pathlib import Path

from .generate import make_bounds, make_divide
from .checker import check_pair, _check_pair_for_testing
from .boundary_cases import make_pre_root_abort_safe_pair


def run_boundary_campaign(output: Path) -> dict:
    rows = []

    vulnerable, patched, certificate = make_bounds("empty-benign", 0)
    for endpoint in (vulnerable, patched):
        endpoint["input_domains"] = {"idx": [-1, 2], "value": [1]}
    certificate["witness_input"] = {"idx": -1, "value": 1}
    weak = _check_pair_for_testing(
        vulnerable, patched, certificate, require_repair=False, require_safe=False
    )
    strong = check_pair(vulnerable, patched, certificate)
    rows.append({
        "case": "empty-benign-domain",
        "ablation_accepted": weak.accepted,
        "strengthened_accepted": strong.accepted,
        "strengthened_reason": strong.reason,
        "safe_inputs_compared": strong.safe_inputs_compared,
        "productive_safe_inputs": strong.productive_safe_inputs,
        "expected_property": weak.accepted and not strong.accepted and strong.reason == "missing-safe-input",
    })

    vulnerable, patched, certificate = make_bounds("root-label", 0)
    for endpoint in (vulnerable, patched):
        endpoint["instructions"].insert(
            0, {"op": "nop", "role": "root", "tag": endpoint["label"]}
        )
    weak = _check_pair_for_testing(
        vulnerable, patched, certificate, require_repair=False, require_safe=False
    )
    strong = check_pair(vulnerable, patched, certificate)
    encoded = all(
        endpoint["instructions"][0]["tag"] == endpoint["label"]
        for endpoint in (vulnerable, patched)
    )
    rows.append({
        "case": "root-role-label-channel",
        "ablation_accepted": weak.accepted,
        "strengthened_accepted": strong.accepted,
        "strengthened_reason": strong.reason,
        "safe_inputs_compared": strong.safe_inputs_compared,
        "productive_safe_inputs": strong.productive_safe_inputs,
        "expected_property": weak.accepted and encoded and not strong.accepted and strong.reason == "root-repair-mismatch",
    })

    vulnerable, patched, certificate = make_divide("undeclared-guard", 0)
    guard = next(instruction for instruction in patched["instructions"] if instruction["op"] == "guard")
    guard["pred"] = {
        "op": "not",
        "arg": {"op": "eq", "left": {"var": "denominator"}, "right": {"const": 0}},
    }
    weak = _check_pair_for_testing(
        vulnerable, patched, certificate, require_repair=False, require_safe=False
    )
    strong = check_pair(vulnerable, patched, certificate)
    rows.append({
        "case": "semantically-equivalent-undeclared-guard",
        "ablation_accepted": weak.accepted,
        "strengthened_accepted": strong.accepted,
        "strengthened_reason": strong.reason,
        "safe_inputs_compared": strong.safe_inputs_compared,
        "productive_safe_inputs": strong.productive_safe_inputs,
        "expected_property": weak.accepted and not strong.accepted and strong.reason == "root-repair-mismatch",
    })

    vulnerable, patched, certificate = make_pre_root_abort_safe_pair()
    weak = _check_pair_for_testing(
        vulnerable,
        patched,
        certificate,
        require_productive_safe=False,
    )
    strong = check_pair(vulnerable, patched, certificate)
    rows.append({
        "case": "pre-root-abort-only-safe-partition",
        "ablation_accepted": weak.accepted,
        "strengthened_accepted": strong.accepted,
        "strengthened_reason": strong.reason,
        "safe_inputs_compared": strong.safe_inputs_compared,
        "productive_safe_inputs": strong.productive_safe_inputs,
        "expected_property": (
            weak.accepted
            and weak.safe_inputs_compared == 1
            and weak.productive_safe_inputs == 0
            and not strong.accepted
            and strong.reason == "missing-productive-safe-input"
        ),
    })

    with (output / "boundary_results.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return {
        "cases": len(rows),
        "ablation_accepts": sum(row["ablation_accepted"] for row in rows),
        "strengthened_rejects": sum(not row["strengthened_accepted"] for row in rows),
        "matched_expectation": sum(row["expected_property"] for row in rows),
    }
