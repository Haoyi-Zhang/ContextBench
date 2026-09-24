"""Benign source/target controls for both transformation classes.

The controls are constructed independently of the transformation verifier.  They
separate exact edit membership from semantic replay and exercise root flips in
both directions across every vulnerability family.
"""
from __future__ import annotations

import copy
import csv
import json
from pathlib import Path
from typing import Any, Mapping

from .generate import MAKERS, make_bounds, make_divide
from .boundary_cases import make_pre_root_abort_safe_pair
from .transform import check_transform, flip_certificate, preserving_variants


def _record(
    rows: list[dict[str, Any]],
    *,
    family: str,
    transform_class: str,
    transform: str,
    control: str,
    source: Mapping[str, Any],
    target: Mapping[str, Any],
    certificate: Mapping[str, Any],
    expected_accepted: bool,
    expected_reason: str,
) -> None:
    report = check_transform(source, target, certificate)
    rows.append(
        {
            "family": family,
            "class": transform_class,
            "transform": transform,
            "control": control,
            "expected_accepted": expected_accepted,
            "expected_reason": expected_reason,
            "accepted": report.accepted,
            "reason": report.reason,
            "obligations": report.obligations,
            "matched_expectation": (
                expected_accepted == report.accepted and expected_reason == report.reason
            ),
        }
    )


def run_membership_campaign(output: Path) -> dict[str, int]:
    rows: list[dict[str, Any]] = []

    # Four preserving relations, each with one valid derivation and three
    # independently malformed target/derivation controls.
    _, source, _ = make_bounds("membership-preserving", 0)
    for target, certificate in preserving_variants(source):
        variants: list[tuple[str, Mapping[str, Any], Mapping[str, Any], bool, str]] = [
            ("valid", target, certificate, True, "accepted"),
        ]
        identity = copy.deepcopy(source)
        identity["program_id"] = target["program_id"]
        variants.append(("missing-edit", identity, copy.deepcopy(certificate), False, "invalid-transformation"))

        wrong = copy.deepcopy(certificate)
        if "site" in wrong:
            wrong["site"] += 1
        else:
            wrong["sites"] = [1, 0]
        variants.append(("wrong-derivation", copy.deepcopy(target), wrong, False, "certificate-derivation-mismatch"))

        extra = copy.deepcopy(target)
        extra["instructions"].append({"op": "nop", "role": "root"})
        variants.append(("extra-no-op", extra, copy.deepcopy(certificate), False, "invalid-transformation"))

        for control, submitted, cert, expected, expected_reason in variants:
            _record(
                rows,
                family=source["family"],
                transform_class="root-preserving",
                transform=certificate["transform"],
                control=control,
                source=source,
                target=submitted,
                certificate=cert,
                expected_accepted=expected,
                expected_reason=expected_reason,
            )

    # Root flips must instantiate the exact designated pair repair and the full
    # nonvacuous semantic relation, in both close-root and open-root directions.
    for index, (family, maker) in enumerate(MAKERS.items()):
        vulnerable, patched, _ = maker(f"membership-flip-{family}", 2100 + index)
        for source, target, kind in (
            (vulnerable, patched, "close-root"),
            (patched, vulnerable, "open-root"),
        ):
            _record(
                rows,
                family=family,
                transform_class="root-flipping",
                transform=kind,
                control="valid-exact-repair",
                source=source,
                target=target,
                certificate=flip_certificate(source, target, kind),
                expected_accepted=True,
                expected_reason="accepted",
            )

            # This target is semantically unchanged at the observation level but
            # contains an extra root edit.  A semantic-only flip checker admits it.
            extra = copy.deepcopy(target)
            extra["instructions"].append({"op": "nop", "role": "root"})
            _record(
                rows,
                family=family,
                transform_class="root-flipping",
                transform=kind,
                control="extra-root-no-op",
                source=source,
                target=extra,
                certificate=flip_certificate(source, extra, kind),
                expected_accepted=False,
                expected_reason="root-repair-mismatch",
            )

    # An alternative but finite-domain-equivalent nonzero test is deliberately
    # outside the named guard algebra.  Exercise the same endpoint pair in both
    # directions so direction reversal cannot bypass edit membership.
    vulnerable, patched, _ = make_divide("membership-flip-undeclared-guard", 0)
    guard = next(
        instruction
        for instruction in patched["instructions"]
        if instruction["op"] == "guard" and instruction["role"] == "root"
    )
    guard["pred"] = {
        "op": "not",
        "arg": {
            "op": "eq",
            "left": {"var": "denominator"},
            "right": {"const": 0},
        },
    }
    for source, target, kind in (
        (vulnerable, patched, "close-root"),
        (patched, vulnerable, "open-root"),
    ):
        _record(
            rows,
            family="divide_zero",
            transform_class="root-flipping",
            transform=kind,
            control="semantically-equivalent-undeclared-guard",
            source=source,
            target=target,
            certificate=flip_certificate(source, target, kind),
            expected_accepted=False,
            expected_reason="root-repair-mismatch",
        )

    # Exact repair and closure are still insufficient on an all-vulnerable
    # declared domain.  Both directions must retain the pair relation's safe-input
    # nonvacuity clause.
    vulnerable, patched, _ = make_bounds("membership-flip-empty-safe", 0)
    upper = len(vulnerable["initial_public_state"]["buffer"])
    for endpoint in (vulnerable, patched):
        endpoint["input_domains"]["idx"] = [-1, upper]
    for source, target, kind in (
        (vulnerable, patched, "close-root"),
        (patched, vulnerable, "open-root"),
    ):
        _record(
            rows,
            family="bounds_write",
            transform_class="root-flipping",
            transform=kind,
            control="empty-safe-domain",
            source=source,
            target=target,
            certificate=flip_certificate(source, target, kind),
            expected_accepted=False,
            expected_reason="missing-safe-input",
        )

    # A non-violating input that aborts in context before the root is not a
    # productive safe witness.  Both flip directions inherit this stronger
    # nonvacuity clause from the pair relation.
    vulnerable, patched, _ = make_pre_root_abort_safe_pair(
        "membership-flip-pre-root-abort"
    )
    for source, target, kind in (
        (vulnerable, patched, "close-root"),
        (patched, vulnerable, "open-root"),
    ):
        _record(
            rows,
            family="bounds_write",
            transform_class="root-flipping",
            transform=kind,
            control="pre-root-abort-only-safe-partition",
            source=source,
            target=target,
            certificate=flip_certificate(source, target, kind),
            expected_accepted=False,
            expected_reason="missing-productive-safe-input",
        )

    with (output / "membership_results.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    preserving = [row for row in rows if row["class"] == "root-preserving"]
    flipping = [row for row in rows if row["class"] == "root-flipping"]
    summary = {
        "controls": len(rows),
        "matched_expectation": sum(row["matched_expectation"] for row in rows),
        "valid_accepted": sum(row["expected_accepted"] and row["accepted"] for row in rows),
        "invalid_rejected": sum(not row["expected_accepted"] and not row["accepted"] for row in rows),
        "root_preserving_controls": len(preserving),
        "root_preserving_valid_accepted": sum(row["expected_accepted"] and row["accepted"] for row in preserving),
        "root_preserving_invalid_rejected": sum(not row["expected_accepted"] and not row["accepted"] for row in preserving),
        "root_flipping_controls": len(flipping),
        "root_flipping_valid_accepted": sum(row["expected_accepted"] and row["accepted"] for row in flipping),
        "root_flipping_invalid_rejected": sum(not row["expected_accepted"] and not row["accepted"] for row in flipping),
        "obligations": sum(row["obligations"] for row in rows),
    }
    (output / "membership_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary
