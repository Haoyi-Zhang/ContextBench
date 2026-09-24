"""Root-blind leakage features, exact witnesses, and pair-disjoint lookup probes."""
from __future__ import annotations
from collections import Counter, defaultdict
from itertools import combinations
from typing import Any, Dict, List, Mapping, Sequence, Tuple
import copy
from .model import JSON


def context_features(program: Mapping[str, Any], source_kind: str) -> Dict[str, str]:
    context = program["context"]
    inst = [i for i in program["instructions"] if i.get("role", "context") == "context"]
    return {
        "profile": str(program["profile"]),
        "family": str(program["family"]),
        "source_kind": source_kind,
        "scenario": str(context.get("scenario", "")),
        "shape": str(context.get("shape", "")),
        "provenance_record": str((context.get("provenance") or {}).get("record", "none")),
        "parameter_shape": ",".join(sorted(program["parameters"])),
        "domain_cardinalities": ",".join(
            f"{k}:{len(v)}" for k, v in sorted(program["input_domains"].items())
        ),
        "public_keys": ",".join(sorted(program["initial_public_state"])),
        "context_ops": ",".join(i["op"] for i in inst),
        "context_count": str(len(inst)),
        "context_tags": ",".join(str(i.get("tag", "")) for i in inst),
        "label_hint": str(context.get("label_hint", "none")),
        "source_partition": str(context.get("source_partition", "shared")),
    }


def rows_from_pairs(pairs: Sequence[Mapping[str, Any]]) -> List[JSON]:
    out = []
    for pair in pairs:
        for side in ("vulnerable", "patched"):
            program = pair[side]
            out.append({
                "pair_id": pair["pair_id"],
                "label": program["label"],
                "features": context_features(program, pair["source_kind"]),
            })
    return out


def contaminate(pairs: Sequence[Mapping[str, Any]], attack: str) -> List[JSON]:
    out = copy.deepcopy(list(pairs))
    for index, pair in enumerate(out):
        vulnerable, patched = pair["vulnerable"], pair["patched"]
        if attack == "label-token":
            vulnerable["context"]["label_hint"] = "unsafe"
            patched["context"]["label_hint"] = "safe"
        elif attack == "context-length":
            vulnerable["instructions"].insert(
                0, {"op": "nop", "tag": "label-shaped", "role": "context"}
            )
        elif attack == "partition-skew":
            vulnerable["context"]["source_partition"] = "legacy"
            patched["context"]["source_partition"] = "modern"
        elif attack == "mixed-two-feature":
            if index % 2 == 0:
                vulnerable["context"]["label_hint"], vulnerable["context"]["source_partition"] = "a", "x"
                patched["context"]["label_hint"], patched["context"]["source_partition"] = "a", "y"
            else:
                vulnerable["context"]["label_hint"], vulnerable["context"]["source_partition"] = "b", "y"
                patched["context"]["label_hint"], patched["context"]["source_partition"] = "b", "x"
        elif attack != "none":
            raise ValueError(attack)
    return out


def perfect_witness_search(
    rows: Sequence[Mapping[str, Any]], max_size: int | None = None
) -> tuple[JSON | None, int, int]:
    """Exhaustively search the fixed feature universe in cardinality/lexical order."""
    names = sorted(rows[0]["features"]) if rows else []
    limit = len(names) if max_size is None else min(max_size, len(names))
    examined = 0
    for size in range(1, limit + 1):
        for subset in combinations(names, size):
            examined += 1
            cells: Dict[Tuple[str, ...], set[str]] = defaultdict(set)
            for row in rows:
                cells[tuple(row["features"][name] for name in subset)].add(row["label"])
            if all(len(labels) == 1 for labels in cells.values()):
                return ({
                    "features": list(subset),
                    "size": size,
                    "observed_cells": len(cells),
                    "subsets_examined": examined,
                    "search_limit": limit,
                }, examined, limit)
    return None, examined, limit


def minimal_perfect_witness(
    rows: Sequence[Mapping[str, Any]], max_size: int | None = None
) -> JSON | None:
    return perfect_witness_search(rows, max_size)[0]


def _lookup(train: Sequence[Mapping[str, Any]], test: Sequence[Mapping[str, Any]], names: Sequence[str]):
    counts = defaultdict(Counter)
    global_counts = Counter(row["label"] for row in train)
    for row in train:
        counts[tuple(row["features"][name] for name in names)][row["label"]] += 1
    fallback = sorted(global_counts, key=lambda value: (-global_counts[value], value))[0]
    out = []
    for row in test:
        key = tuple(row["features"][name] for name in names)
        cell = counts.get(key)
        out.append(sorted(cell, key=lambda value: (-cell[value], value))[0] if cell else fallback)
    return out


def grouped_lookup_accuracy(
    rows: Sequence[Mapping[str, Any]], names: Sequence[str], folds: int = 5
) -> JSON:
    ids = sorted({row["pair_id"] for row in rows})
    actual, predicted = [], []
    for fold in range(folds):
        test_ids = {pair_id for index, pair_id in enumerate(ids) if index % folds == fold}
        train = [row for row in rows if row["pair_id"] not in test_ids]
        test = [row for row in rows if row["pair_id"] in test_ids]
        actual.extend(row["label"] for row in test)
        predicted.extend(_lookup(train, test, names))
    correct = sum(a == b for a, b in zip(actual, predicted))
    return {
        "accuracy": correct / len(actual),
        "correct": correct,
        "total": len(actual),
        "features": list(names),
        "grouping": "pair-disjoint",
    }


def all_context_feature_names() -> List[str]:
    return [
        "profile", "family", "source_kind", "scenario", "shape",
        "provenance_record", "parameter_shape", "domain_cardinalities",
        "public_keys", "context_ops", "context_count", "context_tags",
        "label_hint", "source_partition",
    ]
