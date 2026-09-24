"""Exact balance of the pair-conditioned repair quotient.

The quotient is computed only after a supplied pair passes exact repair
membership. It is not an endpoint-local feature extractor: construction uses
both endpoints and the validated repair derivation to erase the designated
polarity. The experiment therefore supports a theorem about classifiers that
receive only this quotient representation, not classifiers over raw endpoints.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import csv
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from .checker import check_pair
from .model import stable_json
from .repair import nuisance_surface


def run_surface_campaign(output: Path, pairs: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Verify balance after pair-conditioned erasure of repair polarity.

    A cell is the complete declared IR surface after a validated pair and its
    named repair derivation are used to quotient away the one allowed edit. The
    quotient is deliberately not computable from an arbitrary raw endpoint in
    isolation. A deterministic classifier receiving only the quotient emits one
    label per cell; equal vulnerable/patched multiplicities force its optimum to
    one half.
    """
    entries: list[dict[str, Any]] = []
    cells: dict[str, Counter[str]] = defaultdict(Counter)
    for pair in pairs:
        report = check_pair(pair["vulnerable"], pair["patched"], pair["certificate"])
        if not report.accepted:
            raise AssertionError((pair["pair_id"], report.reason))
        surface = nuisance_surface(
            pair["vulnerable"], pair["patched"], pair["certificate"]["declared_repair"]
        )
        key = stable_json(surface)
        for side in ("vulnerable", "patched"):
            label = pair[side]["label"]
            cells[key][label] += 1
            entries.append({
                "pair_id": pair["pair_id"],
                "source_kind": pair["source_kind"],
                "family": pair["family"],
                "label": label,
                "side": side,
                "surface_key": key,
                "declared_repair": pair["certificate"]["declared_repair"],
            })

    cell_ids = {key: f"surface-{index:04d}" for index, key in enumerate(sorted(cells), 1)}
    rows = []
    for entry in entries:
        row = dict(entry)
        row["surface_cell"] = cell_ids[row.pop("surface_key")]
        rows.append(row)

    total = sum(sum(counts.values()) for counts in cells.values())
    balanced_cells = sum(
        counts["vulnerable"] == counts["patched"] and counts["vulnerable"] > 0
        for counts in cells.values()
    )
    optimal_correct = sum(max(counts["vulnerable"], counts["patched"]) for counts in cells.values())
    root_correct = sum(entry["side"] == entry["label"] for entry in entries)
    summary = {
        "pairs": len(pairs),
        "endpoints": total,
        "surface_cells": len(cells),
        "balanced_cells": balanced_cells,
        "all_cells_balanced": balanced_cells == len(cells),
        "optimal_deterministic_surface_only_correct": optimal_correct,
        "optimal_deterministic_surface_only_accuracy": optimal_correct / total if total else 0.0,
        "declared_root_polarity_correct": root_correct,
        "declared_root_polarity_accuracy": root_correct / total if total else 0.0,
        "normalization_scope": "pair-conditioned quotient after validated repair erasure",
        "normalization_is_endpoint_local": False,
        "polarity_channel": "validated pair side / designated repair derivation",
    }
    output.mkdir(parents=True, exist_ok=True)
    with (output / "surface_balance.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]) if rows else [])
        writer.writeheader()
        writer.writerows(rows)
    (output / "surface_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary
