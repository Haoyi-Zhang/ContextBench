"""Check published default counts against every claim-critical raw result table."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import json
import math
import statistics
from pathlib import Path


def check_results(root: Path) -> dict:
    def load(name: str):
        return json.loads((root / name).read_text())

    checked_tables: set[str] = set()

    def rows(name: str):
        checked_tables.add(name)
        with (root / name).open(newline="") as stream:
            return list(csv.DictReader(stream))

    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    def truth(value: str) -> bool:
        require(value in ("True", "False"), "invalid boolean cell")
        return value == "True"

    summary = load("summary.json")
    corpus = load("corpus.json")
    observations = load("observation_corpus.json")
    descriptions = load("description_corpus.json")
    require((len(corpus), len(observations), len(descriptions)) == (258, 288, 10), "primary corpus counts")
    identifiers = [item["pair_id"] for item in corpus + observations + descriptions]
    require(len(set(identifiers)) == 556, "unique primary pairs")
    require(
        all("declared_repair" in item["certificate"] for item in corpus + observations + descriptions),
        "repair declaration missing from pair certificate",
    )

    checks = [
        ("pair_results.csv", 258, "accepted"),
        ("transform_results.csv", 2236, "accepted"),
        ("negative_controls.csv", 72, "detected"),
        ("mutation_results.csv", 11, "killed"),
        ("tiny_exhaustive_results.csv", 384, "matched_expectation"),
        ("membership_results.csv", 46, "matched_expectation"),
        ("description_pair_results.csv", 10, "accepted"),
        ("description_semantics.csv", 184, "matched"),
        ("description_controls.csv", 10, "detected"),
        ("direct_audit_results.csv", 556, "matched"),
        ("boundary_results.csv", 4, "expected_property"),
    ]
    for name, count, column in checks:
        data = rows(name)
        require(len(data) == count, name + ": count")
        require(all(truth(row[column]) for row in data), name + ": expected outcomes")

    pairs = rows("pair_results.csv")
    transforms = rows("transform_results.csv")
    require(summary["corpus"]["pairs"] == 258 and summary["corpus"]["programs"] == 516, "main corpus summary")
    require(
        all(
            int(row["productive_safe_inputs"]) > 0
            for row in pairs
            if truth(row["accepted"])
        ),
        "accepted constructor pair lacks a productive safe root execution",
    )
    require(
        summary["pair_certificates"]["accepted"] == 258
        and summary["transformation_certificates"]["accepted"] == 2236,
        "acceptance summaries",
    )
    for raw, prefix in (("elapsed_ms", "replay_ms"), ("certificate_bytes", "certificate_bytes")):
        values = sorted(float(row[raw]) for row in pairs)
        require(all(math.isfinite(value) and value >= 0 for value in values), "nonfinite or negative measurement")
        require(statistics.median(values) == summary["pair_certificates"]["median_" + prefix], "median " + prefix)
        require(values[(95 * len(values) + 99) // 100 - 1] == summary["pair_certificates"]["p95_" + prefix], "nearest-rank p95 " + prefix)

    provenance = rows("provenance_audit.csv")
    require(len(provenance) == 18 and len({row["record"] for row in provenance}) == 12, "provenance rows and anchors")
    require(sum(row["status"] == "pattern-reference-only" for row in provenance) == 16, "pattern-only provenance count")
    require(
        sum(row["status"] == "unsupported-operator" for row in provenance) == 1
        and sum(row["status"] == "suite-not-instance" for row in provenance) == 1,
        "invalid public annotations",
    )
    require(all(not truth(row["source_equivalence_established"]) for row in provenance), "no source-equivalence claim")
    require(
        sum(int(row["obligations"]) for row in pairs)
        == summary["pair_certificates"]["obligations"]
        == 5805,
        "pair obligations",
    )
    require(
        sum(int(row["obligations"]) for row in transforms)
        == summary["transformation_certificates"]["obligations"]
        == 50095,
        "transform obligations",
    )
    require(sum(row["class"] == "root-preserving" for row in transforms) == 1720, "preserving count")
    require(sum(row["class"] == "root-flipping" for row in transforms) == 516, "root-flipping count")

    membership = rows("membership_results.csv")
    require(
        Counter(row["class"] for row in membership)
        == Counter({"root-preserving": 16, "root-flipping": 30}),
        "membership class counts",
    )
    require(
        sum(truth(row["expected_accepted"]) and truth(row["accepted"]) for row in membership) == 16
        and sum(not truth(row["expected_accepted"]) and not truth(row["accepted"]) for row in membership) == 30,
        "membership valid/invalid outcomes",
    )
    require(
        Counter(row["control"] for row in membership if row["class"] == "root-flipping")
        == Counter({
            "valid-exact-repair": 12,
            "extra-root-no-op": 12,
            "semantically-equivalent-undeclared-guard": 2,
            "empty-safe-domain": 2,
            "pre-root-abort-only-safe-partition": 2,
        }),
        "root-flipping membership controls",
    )

    observation_rows = rows("observation_results.csv")
    require(len(observation_rows) == 288, "order/type count")
    require(sum(truth(row["oracle_accepted"]) for row in observation_rows) == 20, "exact positive count")
    require(all(row["oracle_accepted"] == row["checker_accepted"] for row in observation_rows), "oracle-checker decisions")
    false_acceptances = {
        name: sum(truth(row[name + "_accepted"]) and not truth(row["oracle_accepted"]) for row in observation_rows)
        for name in ("alias", "untyped", "combined")
    }
    require(false_acceptances == {"alias": 16, "untyped": 20, "combined": 52}, "observer ablations")
    require(load("observation_mismatches.json") == [], "semantic oracle disagreement")
    require(
        summary["observation_oracle"]["interpreter_comparisons"] == 9216
        and summary["observation_oracle"]["interpreter_mismatches"] == 0,
        "semantic comparison summary",
    )

    certificate_controls = rows("certificate_only_controls.csv")
    require(
        len(certificate_controls) == 36
        and all(truth(row["direct_accept"]) and not truth(row["certificate_accept"]) for row in certificate_controls),
        "certificate-only controls",
    )
    require(
        Counter(row["case"] for row in certificate_controls)
        == Counter({
            "wrong-certificate-family": 6,
            "contradictory-witness": 6,
            "certificate-endpoint-substitution": 6,
            "certificate-witness-out-of-domain": 6,
            "wrong-certificate-repair": 6,
            "endpoint-id-convention": 6,
        }),
        "certificate-only control families",
    )
    direct = rows("direct_audit_results.csv")
    require(sum(truth(row["direct_accept"]) for row in direct) == 274, "direct acceptance count")
    require(
        all(
            int(row["direct_productive_safe_inputs"]) > 0
            and int(row["checked_productive_safe_inputs"]) > 0
            for row in direct
            if truth(row["direct_accept"])
        ),
        "accepted direct/certificate relation lacks productive safe root execution",
    )
    require(
        summary["direct_audit"]["pairs"] == 556
        and summary["direct_audit"]["direct_accepted"] == 274
        and summary["direct_audit"]["certificate_accepted"] == 274
        and summary["direct_audit"]["decision_disagreements"] == 0,
        "direct summary",
    )

    leakage = rows("leakage_results.csv")
    require(len(leakage) == 5 and sum(int(row["certificate_rejections"]) for row in leakage) == 1032, "contamination counts")
    clean = next(row for row in leakage if row["scenario"] == "none")
    require(float(clean["best_single_accuracy"]) == 0.5 and clean["minimal_witness_features"] == "none", "clean leakage")
    require(
        int(clean["feature_universe_size"]) == 14
        and int(clean["search_limit"]) == 14
        and int(clean["subsets_examined"]) == 2**14 - 1
        and truth(clean["search_complete"]),
        "complete finite leakage search",
    )

    surface_rows = rows("surface_balance.csv")
    require(len(surface_rows) == 536, "surface endpoint count")
    by_cell: dict[str, Counter[str]] = defaultdict(Counter)
    for row in surface_rows:
        by_cell[row["surface_cell"]][row["label"]] += 1
        require(row["side"] == row["label"], "declared root polarity label")
    require(
        all(counts["vulnerable"] == counts["patched"] and counts["vulnerable"] > 0 for counts in by_cell.values()),
        "nuisance-surface cell balance",
    )
    surface_summary = load("surface_summary.json")
    require(summary["surface_balance"] == surface_summary, "surface summary mismatch")
    require(
        surface_summary["pairs"] == 268
        and surface_summary["endpoints"] == 536
        and surface_summary["surface_cells"] == 268
        and surface_summary["balanced_cells"] == 268
        and surface_summary["all_cells_balanced"]
        and surface_summary["optimal_deterministic_surface_only_correct"] == 268
        and surface_summary["optimal_deterministic_surface_only_accuracy"] == 0.5
        and surface_summary["declared_root_polarity_correct"] == 536
        and surface_summary["declared_root_polarity_accuracy"] == 1.0,
        "surface balance result",
    )

    boundary = rows("boundary_results.csv")
    require(
        {row["case"]: row["strengthened_reason"] for row in boundary}
        == {
            "empty-benign-domain": "missing-safe-input",
            "root-role-label-channel": "root-repair-mismatch",
            "semantically-equivalent-undeclared-guard": "root-repair-mismatch",
            "pre-root-abort-only-safe-partition": "missing-productive-safe-input",
        },
        "strengthened boundary controls",
    )

    reference_rows = rows("reference_semantics.csv")
    require(len(reference_rows) == 21002, "whole-IR reference valuation count")
    for column in (
        "producer_semantic_match",
        "checker_semantic_match",
        "producer_operational_match",
        "checker_operational_match",
    ):
        require(all(truth(row[column]) for row in reference_rows), "whole-IR reference mismatch: " + column)
    require(load("reference_mismatches.json") == [], "whole-IR reference mismatch details")
    reference_summary = load("reference_summary.json")
    require(summary["reference_semantics"] == reference_summary, "whole-IR reference summary mismatch")
    require(
        reference_summary["programs"] == 2834
        and reference_summary["endpoint_valuations"] == 21002
        and reference_summary["interpreter_comparisons"] == 42004
        and reference_summary["semantic_mismatches"] == 0
        and reference_summary["operational_mismatches"] == 0,
        "whole-IR reference totals",
    )
    require(
        reference_summary["instruction_operations"]
        == [
            "add_fixed", "assign", "branch_abort", "buf_write", "check_call",
            "commit_after_call", "divide", "emit", "external_call", "guard",
            "low_call", "nop", "protected_store", "return", "update_balance",
        ],
        "whole-IR instruction coverage",
    )
    require(
        reference_summary["expression_operations"]
        == ["add", "and", "eq", "ge", "gt", "le", "lt", "mul", "ne", "not", "or", "sub"]
        and reference_summary["expression_forms"] == ["const", "literal", "public", "var"],
        "whole-IR expression coverage",
    )

    expression_matrix = rows("semantic_expression_matrix.csv")
    require(len(expression_matrix) == 1596, "expression semantic boundary count")
    require(all(truth(row["matched"]) for row in expression_matrix), "expression semantic boundary mismatch")
    expression_defined = sum(row["reference_status"] == "defined" for row in expression_matrix)
    expression_errors = sum(row["reference_status"] == "error" for row in expression_matrix)
    require((expression_defined, expression_errors) == (651, 945), "expression semantic outcome partition")
    require(all(truth(row["definedness_match"]) for row in expression_matrix), "expression definedness disagreement")
    require(all(truth(row["value_match_when_defined"]) for row in expression_matrix), "expression value disagreement")

    instruction_matrix = rows("semantic_instruction_matrix.csv")
    require(len(instruction_matrix) == 1013, "instruction semantic boundary count")
    require(all(truth(row["matched"]) for row in instruction_matrix), "instruction semantic boundary mismatch")
    instruction_defined = sum(row["reference_status"] == "defined" for row in instruction_matrix)
    instruction_errors = sum(row["reference_status"] == "error" for row in instruction_matrix)
    require((instruction_defined, instruction_errors) == (588, 425), "instruction semantic outcome partition")
    require(all(truth(row["definedness_match"]) for row in instruction_matrix), "instruction definedness disagreement")
    require(all(truth(row["operational_match_when_defined"]) for row in instruction_matrix), "instruction operational disagreement")
    require(load("semantic_boundary_mismatches.json") == [], "semantic boundary mismatch details")
    semantic_boundary_summary = load("semantic_boundary_summary.json")
    require(summary["semantic_boundary_matrix"] == semantic_boundary_summary, "semantic boundary summary mismatch")
    require(
        semantic_boundary_summary["total_cases"] == 2609
        and semantic_boundary_summary["total_interpreter_evaluations"] == 7827
        and semantic_boundary_summary["mismatches"] == 0
        and semantic_boundary_summary["expression_matrix"]["cases"] == 1596
        and semantic_boundary_summary["expression_matrix"]["defined_cases"] == 651
        and semantic_boundary_summary["expression_matrix"]["error_cases"] == 945
        and semantic_boundary_summary["instruction_matrix"]["programs"] == 20
        and semantic_boundary_summary["instruction_matrix"]["valuations"] == 1013
        and semantic_boundary_summary["instruction_matrix"]["defined_cases"] == 588
        and semantic_boundary_summary["instruction_matrix"]["error_cases"] == 425,
        "semantic boundary totals",
    )
    require(
        semantic_boundary_summary["instruction_matrix"]["instruction_operations"]
        == [
            "add_fixed", "assign", "branch_abort", "buf_write", "check_call",
            "commit_after_call", "divide", "emit", "external_call", "guard",
            "low_call", "nop", "protected_store", "return", "update_balance",
        ],
        "semantic boundary instruction coverage",
    )

    source_corpus = load("source_corpus.json")
    require(len(source_corpus) == 60, "source-capsule corpus count")
    require(len({item["pair_id"] for item in source_corpus}) == 60, "unique source-capsule pairs")
    require(all(item["source_certificate"]["source_language"] == "rcsc-source-1" for item in source_corpus), "source language binding")
    source_pairs = rows("source_pair_results.csv")
    require(len(source_pairs) == 60 and all(truth(row["accepted"]) for row in source_pairs), "source pair outcomes")
    require(sum(int(row["endpoint_valuations"]) for row in source_pairs) == 860, "source pair valuation total")
    require(sum(int(row["source_ir_comparisons"]) for row in source_pairs) == 2580, "source pair bridge comparisons")
    require(sum(int(row["semantic_mismatches"]) for row in source_pairs) == 0, "source pair semantic mismatches")
    require(sum(int(row["operational_mismatches"]) for row in source_pairs) == 0, "source pair operational mismatches")
    require(
        all(
            int(row["safe_inputs_compared"]) > 0
            and int(row["productive_safe_inputs"]) > 0
            and int(row["vulnerable_inputs"]) > 0
            for row in source_pairs
        ),
        "source pair productive semantic partitions",
    )

    source_semantics = rows("source_semantics.csv")
    require(len(source_semantics) == 860, "source semantics valuation count")
    for column in (
        "producer_semantic_match", "checker_semantic_match", "immutable_semantic_match",
        "producer_operational_match", "checker_operational_match", "immutable_operational_match",
    ):
        require(all(truth(row[column]) for row in source_semantics), "source bridge mismatch: " + column)
    require(load("source_mismatches.json") == [], "source bridge mismatch details")

    source_controls = rows("source_controls.csv")
    require(len(source_controls) == 55 and all(truth(row["detected"]) for row in source_controls), "source bridge controls")
    require(
        Counter(row["control"] for row in source_controls)
        == Counter({
            "wrong-source-family": 6,
            "wrong-source-profile": 6,
            "wrong-source-language": 6,
            "source-endpoint-substitution": 6,
            "compiled-ir-substitution": 6,
            "duplicate-source-declaration": 6,
            "extra-root-source-edit": 6,
            "pair-witness-substitution": 6,
            "source-execution-type-error": 6,
            "pre-root-abort-only-safe-partition": 1,
        }),
        "source bridge control families",
    )
    source_summary = load("source_summary.json")
    require(summary["source_bridge"] == source_summary, "source bridge summary mismatch")
    require(
        source_summary["pairs"] == 60
        and source_summary["accepted_pairs"] == 60
        and source_summary["programs"] == 120
        and source_summary["endpoint_valuations"] == 860
        and source_summary["interpreter_comparisons"] == 2580
        and source_summary["semantic_mismatches"] == 0
        and source_summary["operational_mismatches"] == 0
        and source_summary["controls"] == 55
        and source_summary["controls_detected"] == 55
        and source_summary["source_language"] == "rcsc-source-1"
        and source_summary["native_language_claim"] is False,
        "source bridge totals",
    )
    require(
        source_summary["instruction_operations"]
        == [
            "add_fixed", "assign", "branch_abort", "buf_write", "check_call",
            "commit_after_call", "divide", "emit", "external_call", "guard",
            "low_call", "nop", "protected_store", "return", "update_balance",
        ],
        "source instruction coverage",
    )
    require(
        source_summary["expression_operations"]
        == ["add", "and", "eq", "ge", "gt", "le", "lt", "mul", "ne", "not", "or", "sub"]
        and source_summary["expression_forms"] == ["const", "public", "var"],
        "source expression coverage",
    )
    require(
        source_summary["source_expression_operations"]
        == ["add", "and", "eq", "ge", "gt", "le", "lt", "mul", "ne", "neg", "not", "or", "sub"]
        and source_summary["source_expression_forms"]
        == ["binary", "literal", "state", "unary", "variable"]
        and source_summary["source_literal_types"] == ["bool", "int", "null", "str"],
        "source syntax coverage",
    )

    selection = rows("description_selection.csv")
    require(len(selection) == 12 and sum(truth(row["mapped"]) for row in selection) == 10, "description selection")
    require(
        {row["reason"] for row in selection if not truth(row["mapped"])}
        == {"unsupported-operator", "suite-not-instance"},
        "description exclusions",
    )
    require(summary["description_abstractions"]["source_equivalent_programs"] == 0, "source-equivalence non-claim")

    agreement = load("producer_checker_agreement.json")
    require(agreement["runs"] == 3698 and agreement["mismatches"] == [], "main evaluator agreement")
    scale = rows("scaling_results.csv")
    require([int(row["buffer_length"]) for row in scale] == [4, 8, 16, 32, 64, 128, 256], "scaling selection")
    require(all(truth(row["accepted"]) for row in scale), "scaling acceptance")
    require(float(scale[-1]["median_replay_ms"]) == summary["scaling"]["largest_median_replay_ms"], "scaling summary")

    surface_scope = load("surface_summary.json")
    require(
        surface_scope.get("normalization_is_endpoint_local") is False
        and surface_scope.get("normalization_scope")
        == "pair-conditioned quotient after validated repair erasure"
        and surface_scope.get("declared_root_polarity_accuracy") == 1.0,
        "surface quotient scope",
    )

    for section, filename in (
        ("observation_oracle", "observation_summary.json"),
        ("membership_controls", "membership_summary.json"),
        ("direct_audit", "direct_audit_summary.json"),
        ("description_abstractions", "description_summary.json"),
        ("provenance_audit", "provenance_summary.json"),
        ("surface_balance", "surface_summary.json"),
        ("reference_semantics", "reference_summary.json"),
        ("semantic_boundary_matrix", "semantic_boundary_summary.json"),
        ("source_bridge", "source_summary.json"),
    ):
        require(summary[section] == load(filename), section + ": raw summary mismatch")

    return {
        "logical_results": "consistent",
        "primary_pairs": 556,
        "accepted_primary_pairs": 274,
        "rejected_primary_pairs": 282,
        "balanced_pair_conditioned_quotient_cells": 268,
        "checked_raw_tables": len(checked_tables),
        "scope": "published default finite experiment plus whole-IR, typed semantic-boundary, and bounded source-capsule cross-checks",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    args = parser.parse_args()
    print(json.dumps(check_results(args.results), indent=2))


if __name__ == "__main__":
    main()
