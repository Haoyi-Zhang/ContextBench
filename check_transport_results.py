"""Reconcile retained context-transport evidence, including oracle scope and raw timings."""
from __future__ import annotations

import argparse
import copy
import csv
import json
import math
import statistics
from collections import Counter
from pathlib import Path

from rcsc.checker import execute
from rcsc.model import is_productive_root_safe, validate_program, value_key, VIOLATION_FOR_FAMILY
from rcsc.transport import cardinality, check_transport, stable_json, valuations


def check(root: Path) -> dict:
    def load(name):
        return json.loads((root / name).read_text(encoding="utf-8"))

    def rows(name):
        with (root / name).open(newline="", encoding="utf-8") as stream:
            return list(csv.DictReader(stream))

    def require(ok, message):
        if not ok:
            raise ValueError(message)

    def yes(value):
        require(value in ("True", "False"), "invalid Boolean cell")
        return value == "True"

    def finite_nonnegative(value, message):
        number = float(value)
        require(math.isfinite(number) and number >= 0, message)
        return number

    summary = load("transport_summary.json")
    primary = rows("transport_primary.csv")
    oracle = rows("transport_oracle.csv")
    scale = rows("transport_scaling.csv")
    controls = rows("transport_controls.csv")
    app = rows("transport_applicability.csv")
    scope = rows("transport_oracle_scope_controls.csv")
    packets = load("transport_packets.json")
    control_packets = load("transport_control_packets.json")
    variation = load("transport_functional_variation.json")

    require(len(primary) == len(packets) == summary["primary_pairs"] == 36, "primary count")
    require(len({row["case"] for row in primary}) == 36, "primary identities")
    require(len({row["family"] for row in primary}) == summary["families"] == 6, "family count")
    require(len({row["wrapper"] for row in primary}) == summary["wrapper_templates"] == 6, "wrapper count")
    require(len({(row["family"], row["wrapper"]) for row in primary}) == 36, "family/wrapper coverage")
    require(
        len(variation) == len({item["case"] for item in variation}) == 36
        and {item["case"] for item in variation} == {row["case"] for row in primary},
        "functional variation witness coverage",
    )
    variation_by_case = {item["case"]: item for item in variation}
    require({item["case"] for item in oracle} == {row["case"] for row in primary}, "oracle case coverage")
    certificates = []
    for row, packet_record in zip(primary, packets):
        packet = packet_record.get("packet", packet_record)
        require(packet_record.get("case") == row["case"], "primary packet identity")
        require(row["family"] == packet["vulnerable"]["family"], "primary packet family")
        actual = check_transport(packet)
        require(actual.accepted, "primary packet no longer accepted")
        require(
            yes(row["accepted"])
            and yes(row["oracle_semantic_relation"])
            and yes(row["oracle_security_invariant"])
            and yes(row["oracle_monitor_consistent"])
            and yes(row["oracle_defined"])
            and yes(row["relation_preconditions"])
            and yes(row["repair_membership_precondition"])
            and yes(row["full_contract_classification"])
            and yes(row["functional_variation"]),
            "primary result",
        )
        require(yes(row["factored_audit_accepted"]), "factored baseline disagreement")
        roots = {
            key: value
            for key, value in packet["vulnerable"]["input_domains"].items()
            if key not in packet["context_domains"]
        }
        root_count = cardinality(roots)
        context_count = cardinality(packet["context_domains"])
        require(
            root_count == int(row["core_valuations"])
            and context_count == int(row["context_valuations"]),
            "domain product",
        )
        require(
            int(row["core_executions"])
            == int(row["factored_audit_core_executions"])
            == 2 * root_count,
            "root replay count",
        )
        require(
            int(row["full_endpoint_executions"]) == 2 * root_count * context_count,
            "primary full replay count",
        )
        certificate = stable_json(packet["transport_certificate"])
        require(len(certificate.encode("utf-8")) == int(row["certificate_bytes"]), "certificate size")
        certificates.append(certificate)
        selected = [item for item in oracle if item["case"] == row["case"]]
        require(len(selected) == root_count * context_count, "oracle row coverage")
        expected_points = {(stable_json(r), stable_json(n))
                           for r in valuations(roots) for n in valuations(packet["context_domains"])}
        observed_points = {(item["root_input"], item["context_input"]) for item in selected}
        require(observed_points == expected_points, "oracle input/domain coverage")
        require(len(observed_points) == len(selected), "duplicate oracle row")
        require(
            all(
                yes(item["defined"])
                and yes(item["monitor_consistent"])
                and yes(item["patched_closed"])
                and yes(item["safe_observations_equal"])
                and yes(item["root_invariant"])
                and int(item["reference_mismatches"]) == 0
                for item in selected
            ),
            "oracle failure",
        )
        monitor = VIOLATION_FOR_FAMILY[row["family"]]
        require(all(item["declared_monitor"] == monitor
                    and item["v_violation"] in ("", monitor)
                    and item["p_violation"] == "" for item in selected), "oracle monitor record")
        require(all(int(item["reference_comparisons"]) == 2 for item in selected)
                and sum(int(item["reference_comparisons"]) for item in selected)
                    == int(row["reference_comparisons"]), "oracle reference comparison count")
        require(int(row["reference_mismatches"]) == 0, "primary reference mismatch count")

        # These are two explicit witnesses, not evidence for all Cartesian points.
        witness = variation_by_case[row["case"]]
        root_input = witness["root_input"]
        require(stable_json(root_input) in {stable_json(r) for r in valuations(roots)},
                "functional variation root domain")
        results = []
        for position in ("first", "second"):
            context = witness[position + "_context"]
            require(stable_json(context) in {stable_json(n) for n in valuations(packet["context_domains"])},
                    "functional variation context domain")
            point = copy.deepcopy(packet["vulnerable"])
            point["input_domains"].update({name: [value] for name, value in context.items()})
            result = execute(point, dict(root_input, **context))
            require(is_productive_root_safe(point, result), "functional variation productive root")
            stored = json.loads(json.dumps(result.to_json()))
            require(value_key(stored) == value_key(witness[position + "_result"]),
                    "functional variation result binding")
            results.append(result)
        require(results[0].observation() != results[1].observation(), "functional variation absent")
    require(len(set(certificates)) == summary["core_certificates"] == 6, "reused root certificates")
    require(summary["primary_relation_precondition_passes"] == 36, "primary precondition summary")
    require(summary["primary_full_contract_classifications"] == 36, "primary contract summary")
    for field, column, expected in (
        ("primary_core_executions", "core_executions", 516),
        ("primary_full_endpoint_executions", "full_endpoint_executions", 8256),
        ("reference_comparisons", "reference_comparisons", 8256),
    ):
        require(summary[field] == sum(int(item[column]) for item in primary) == expected, field)
    require(
        summary["reference_mismatches"]
        == sum(int(item["reference_mismatches"]) for item in oracle)
        == 0,
        "reference disagreements",
    )
    require(
        summary["functionally_varying_cases"]
        == sum(yes(item["functional_variation"]) for item in primary)
        == 36,
        "functional variation",
    )
    require(summary["factored_audit_agreements"] == 36, "baseline agreement summary")

    require(len(scale) == summary["scaling_points"] == 42, "scaling count")
    require(
        Counter(int(item["nuisance_dimensions"]) for item in scale)
        == Counter({dimension: 6 for dimension in (0, 2, 4, 6, 8, 10, 20)}),
        "scaling dimensions",
    )
    require(summary["scaling_transport_trials_per_point"] == 3, "raw timing trial count")
    for row in scale:
        dimension = int(row["nuisance_dimensions"])
        root_count = int(row["core_valuations"])
        require(
            int(row["context_valuations"]) == 2**dimension
            and int(row["core_executions"]) == 2 * root_count,
            "scaling cardinality",
        )
        require(
            int(row["represented_endpoint_executions"]) == 2 * root_count * 2**dimension,
            "represented obligations",
        )
        require(yes(row["relation_preconditions"]), "scaling relation precondition")
        require(yes(row["repair_membership_precondition"]), "scaling repair precondition")
        raw_trials = [
            finite_nonnegative(row[f"transport_trial_{index}_ms"], "invalid raw transport timing")
            for index in (1, 2, 3)
        ]
        retained_median = finite_nonnegative(row["verification_ms"], "invalid retained timing")
        require(
            abs(retained_median - round(statistics.median(raw_trials), 6)) <= 5e-7,
            "transport median not derived from raw trials",
        )
        if dimension <= 10:
            require(
                row["direct_oracle_status"] == "exhaustive"
                and yes(row["direct_oracle_semantic_relation"])
                and yes(row["direct_oracle_security_invariant"])
                and yes(row["direct_oracle_monitor_consistent"])
                and yes(row["direct_oracle_contract_pass"]),
                "measured oracle",
            )
            require(
                int(row["direct_endpoint_executions"]) == 2 * root_count * 2**dimension,
                "measured full count",
            )
            finite_nonnegative(row["direct_oracle_ms"], "invalid Cartesian timing")
        else:
            require(
                row["direct_oracle_status"] == "not-run-symbolic-only"
                and int(row["direct_endpoint_executions"]) == 0,
                "symbolic-only point mislabeled",
            )
            require(
                row["direct_oracle_ms"] == ""
                and row["direct_oracle_semantic_relation"] == ""
                and row["direct_oracle_security_invariant"] == ""
                and row["direct_oracle_monitor_consistent"] == ""
                and row["direct_oracle_contract_pass"] == "",
                "symbolic-only semantic evidence fabricated",
            )
    require(
        summary["scaling_direct_endpoint_executions"]
        == sum(int(item["direct_endpoint_executions"]) for item in scale)
        == 117390,
        "scaling execution summary",
    )
    require(
        summary["max_symbolic_endpoint_obligations"]
        == max(int(item["represented_endpoint_executions"]) for item in scale),
        "symbolic obligations summary",
    )

    require(len(controls) == len(control_packets) == summary["controls"] == 76, "control count")
    require(len({(item["family"], item["control"]) for item in controls}) == 76,
            "duplicate control identity")
    for row, record in zip(controls, control_packets):
        require(all(record.get(key) == row[key] for key in ("family", "control", "kind")),
                "control packet identity")
        packet = record.get("packet")
        require(type(packet) is dict and set(packet) == {"vulnerable", "patched", "certificate",
                "context_domains", "transport_certificate"}, "control packet schema")
        validate_program(packet["vulnerable"])
        validate_program(packet["patched"])
        require(packet["vulnerable"]["family"] == row["family"], "control packet family")
        actual = check_transport(packet)
        require(actual.accepted == yes(row["transport_accepted"])
                and actual.reason == row["transport_reason"], "control packet result binding")
    require(all(not yes(item["transport_accepted"]) for item in controls), "control accepted")
    classes = Counter(item["oracle_class"] for item in controls)
    require(
        classes["valid-outside-fragment"] == summary["valid_outside_fragment"] == 13,
        "valid exclusions",
    )
    require(
        classes["invalid-contextual-relation"] == summary["invalid_contextual_relations"] == 27,
        "invalid relations",
    )
    require(
        sum(yes(item["factored_audit_accepted"]) for item in controls)
        == summary["certificate_claims_rejected_on_valid_factored_relation"]
        == 30,
        "certificate-only distinction",
    )
    extrapolation = sum(
        yes(item["anchor_pair_accepted"])
        and item["oracle_class"] == "invalid-contextual-relation"
        for item in controls
    )
    require(
        extrapolation == summary["observed_only_extrapolation_counterexamples"] == 22,
        "off-anchor counterexamples",
    )
    for row in controls:
        if row["oracle_class"] != "claim-not-semantically-replayed":
            require(yes(row["relation_preconditions"]), "replayed control declaration/repair precondition")
            require(yes(row["repair_membership_precondition"]), "replayed control repair precondition")
        if row["oracle_class"] == "valid-outside-fragment":
            require(
                yes(row["full_semantic_relation"])
                and yes(row["full_security_invariant"])
                and yes(row["full_monitor_consistent"])
                and yes(row["full_defined"])
                and yes(row["full_contract_classification"]),
                "valid exclusion oracle",
            )
        elif row["oracle_class"] == "invalid-contextual-relation":
            require(not yes(row["full_contract_classification"]), "invalid relation mislabeled valid")

    require(len(scope) == summary["oracle_scope_controls"] == 2, "oracle scope control count")
    scope_by_name = {row["control"]: row for row in scope}
    require(set(scope_by_name) == {
        "patched-root-trailing-nop",
        "divide-pair-declared-fixed-overflow",
    }, "oracle scope control identities")
    trailing = scope_by_name["patched-root-trailing-nop"]
    require(
        yes(trailing["semantic_relation"])
        and yes(trailing["security_invariant"])
        and yes(trailing["monitor_consistent"])
        and yes(trailing["defined"])
        and not yes(trailing["repair_membership_precondition"])
        and not yes(trailing["all_relation_preconditions"])
        and not yes(trailing["contract_classification"])
        and not yes(trailing["repair_check_independent"])
        and not yes(trailing["production_accepted"])
        and trailing["production_reason"] == "root-repair-mismatch",
        "trailing nop scope classification",
    )
    wrong = scope_by_name["divide-pair-declared-fixed-overflow"]
    require(
        not yes(wrong["semantic_relation"])
        and yes(wrong["security_invariant"])
        and not yes(wrong["monitor_consistent"])
        and yes(wrong["defined"])
        and not yes(wrong["repair_membership_precondition"])
        and not yes(wrong["all_relation_preconditions"])
        and not yes(wrong["contract_classification"])
        and not yes(wrong["repair_check_independent"])
        and not yes(wrong["production_accepted"])
        and wrong["production_reason"] == "root-repair-mismatch",
        "wrong family scope classification",
    )
    require(summary["oracle_scope_semantic_only_accepts"] == 1, "scope semantic-only count")
    require(summary["oracle_scope_monitor_mismatches"] == 1, "scope monitor mismatch count")
    require(summary["oracle_scope_repair_rejections"] == 2, "scope repair rejection count")

    require(len(app) == summary["applicability_cases"] == 556, "applicability count")
    require(len({item["pair_id"] for item in app}) == 556, "duplicate applicability pair")
    require(
        sum(yes(item["existing_pair_accepted"]) for item in app)
        == summary["applicability_existing_accepts"]
        == 274,
        "existing accept count",
    )
    require(
        sum(yes(item["framed_relation_accepted"]) for item in app)
        == summary["applicability_framed_accepts"]
        == 268,
        "framed accept count",
    )
    require(
        not any(
            yes(item["framed_relation_accepted"])
            and not yes(item["existing_pair_accepted"])
            for item in app
        ),
        "new invalid acceptance",
    )

    runtime = summary["runtime"]
    require(runtime["workers"] == 1, "worker count")
    for key in ("cpu_seconds", "wall_seconds", "max_rss_mib"):
        finite_nonnegative(runtime[key], f"invalid runtime {key}")
    environment = runtime.get("environment", {})
    for key in (
        "cpu_model",
        "logical_cpu_count",
        "operating_system",
        "os_release",
        "architecture",
        "python_implementation",
        "python_version",
    ):
        require(environment.get(key) not in (None, ""), f"missing measurement environment {key}")
    for key in (
        "measurement_scope",
        "cpu_measurement",
        "wall_measurement",
        "rss_measurement",
        "scaling_transport_measurement",
        "cartesian_measurement",
    ):
        require(type(runtime.get(key)) is str and runtime[key], f"missing measurement definition {key}")

    for table in (primary, scale):
        for row in table:
            for key, value in row.items():
                if key.endswith("_ms") and value:
                    finite_nonnegative(value, "invalid timing")

    return {
        "status": "consistent",
        "primary_pairs": 36,
        "raw_tables": 6,
        "valid_exclusions": 13,
        "off_anchor_counterexamples": 22,
        "oracle_scope_controls": 2,
        "symbolic_points_not_executed": 6,
        "raw_transport_trials_per_scaling_point": 3,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path, nargs="?", default=Path("results"))
    print(json.dumps(check(parser.parse_args().results), indent=2, sort_keys=True))
