"""Reconcile retained context-transport evidence, including valid exclusions."""
from __future__ import annotations
import argparse
import csv
import json
import math
from collections import Counter
from pathlib import Path
from rcsc.transport import cardinality, stable_json


def check(root: Path) -> dict:
    def load(name):
        return json.loads((root / name).read_text())
    def rows(name):
        with (root / name).open(newline="") as stream:
            return list(csv.DictReader(stream))
    def require(ok, message):
        if not ok:
            raise ValueError(message)
    def yes(value):
        require(value in ("True", "False"), "invalid Boolean cell")
        return value == "True"
    summary = load("transport_summary.json")
    primary = rows("transport_primary.csv")
    oracle = rows("transport_oracle.csv")
    scale = rows("transport_scaling.csv")
    controls = rows("transport_controls.csv")
    app = rows("transport_applicability.csv")
    packets = load("transport_packets.json")
    control_packets = load("transport_control_packets.json")
    require(len(primary) == len(packets) == summary["primary_pairs"] == 36, "primary count")
    require(len({row["case"] for row in primary}) == 36, "primary identities")
    require(len({row["family"] for row in primary}) == summary["families"] == 6, "family count")
    require(len({row["wrapper"] for row in primary}) == summary["wrapper_templates"] == 6, "wrapper count")
    certificates = []
    for row, packet in zip(primary, packets):
        # Rows are kept in construction order; the embedded endpoint family is authoritative.
        if "packet" in packet:
            packet = packet["packet"]
        require(row["family"] == packet["vulnerable"]["family"], "primary packet family")
        require(yes(row["accepted"]) and yes(row["oracle_relation"]) and
                yes(row["oracle_security_invariant"]) and yes(row["functional_variation"]), "primary result")
        require(yes(row["factored_audit_accepted"]), "factored baseline disagreement")
        roots = {k:v for k,v in packet["vulnerable"]["input_domains"].items()
                 if k not in packet["context_domains"]}
        nr, nn = cardinality(roots), cardinality(packet["context_domains"])
        require(nr == int(row["core_valuations"]) and nn == int(row["context_valuations"]), "domain product")
        require(int(row["core_executions"]) == int(row["factored_audit_core_executions"]) == 2*nr, "root replay count")
        require(int(row["full_endpoint_executions"]) == 2*nr*nn, "primary full replay count")
        cert = stable_json(packet["transport_certificate"])
        require(len(cert.encode("utf-8")) == int(row["certificate_bytes"]), "certificate size")
        certificates.append(cert)
        selected = [x for x in oracle if x["case"] == row["case"]]
        require(len(selected) == nr*nn, "oracle row coverage")
        require(len({(x["root_input"], x["context_input"]) for x in selected}) == nr*nn, "duplicate oracle row")
        require(all(yes(x["defined"]) and yes(x["safe_observations_equal"]) and
                    yes(x["root_invariant"]) and int(x["reference_mismatches"]) == 0 for x in selected), "oracle failure")
    require(len(set(certificates)) == summary["core_certificates"] == 6, "reused root certificates")
    for field, column, expected in (("primary_core_executions", "core_executions", 516),
                                  ("primary_full_endpoint_executions", "full_endpoint_executions", 8256),
                                  ("reference_comparisons", "reference_comparisons", 8256)):
        require(summary[field] == sum(int(x[column]) for x in primary) == expected, field)
    require(summary["reference_mismatches"] == sum(int(x["reference_mismatches"]) for x in oracle) == 0, "reference disagreements")
    require(summary["functionally_varying_cases"] == sum(yes(x["functional_variation"]) for x in primary) == 36, "functional variation")
    require(summary["factored_audit_agreements"] == 36, "baseline agreement summary")
    require(len(scale) == summary["scaling_points"] == 42, "scaling count")
    require(Counter(int(x["nuisance_dimensions"]) for x in scale) == Counter({d:6 for d in (0,2,4,6,8,10,20)}), "scaling dimensions")
    for row in scale:
        d, nr = int(row["nuisance_dimensions"]), int(row["core_valuations"])
        require(int(row["context_valuations"]) == 2**d and int(row["core_executions"]) == 2*nr, "scaling cardinality")
        require(int(row["represented_endpoint_executions"]) == 2*nr*2**d, "represented obligations")
        if d <= 10:
            require(row["direct_oracle_status"] == "exhaustive" and yes(row["direct_oracle_pass"]), "measured oracle")
            require(int(row["direct_endpoint_executions"]) == 2*nr*2**d, "measured full count")
        else:
            require(row["direct_oracle_status"] == "not-run-symbolic-only" and int(row["direct_endpoint_executions"]) == 0, "symbolic-only point mislabeled")
    require(summary["scaling_direct_endpoint_executions"] == sum(int(x["direct_endpoint_executions"]) for x in scale) == 117390, "scaling execution summary")
    require(summary["max_symbolic_endpoint_obligations"] == max(int(x["represented_endpoint_executions"]) for x in scale), "symbolic obligations summary")
    require(len(controls) == len(control_packets) == summary["controls"] == 76, "control count")
    require(all(not yes(x["transport_accepted"]) for x in controls), "control accepted")
    classes = Counter(x["oracle_class"] for x in controls)
    require(classes["valid-outside-fragment"] == summary["valid_outside_fragment"] == 13, "valid exclusions")
    require(classes["invalid-contextual-relation"] == summary["invalid_contextual_relations"] == 27, "invalid relations")
    require(sum(yes(x["factored_audit_accepted"]) for x in controls) == summary["certificate_claims_rejected_on_valid_factored_relation"] == 30, "certificate-only distinction")
    extrapolation = sum(yes(x["anchor_pair_accepted"]) and x["oracle_class"] == "invalid-contextual-relation" for x in controls)
    require(extrapolation == summary["observed_only_extrapolation_counterexamples"] == 22, "off-anchor counterexamples")
    for row in controls:
        if row["oracle_class"] == "valid-outside-fragment":
            require(yes(row["full_relation"]) and yes(row["full_security_invariant"]) and yes(row["full_defined"]), "valid exclusion oracle")
    require(len(app) == summary["applicability_cases"] == 556, "applicability count")
    require(len({x["pair_id"] for x in app}) == 556, "duplicate applicability pair")
    require(sum(yes(x["existing_pair_accepted"]) for x in app) == summary["applicability_existing_accepts"] == 274, "existing accept count")
    require(sum(yes(x["framed_relation_accepted"]) for x in app) == summary["applicability_framed_accepts"] == 268, "framed accept count")
    require(not any(yes(x["framed_relation_accepted"]) and not yes(x["existing_pair_accepted"]) for x in app), "new invalid acceptance")
    for table in (primary, scale):
        for row in table:
            for key, val in row.items():
                if key.endswith("_ms") and val:
                    require(math.isfinite(float(val)) and float(val) >= 0, "invalid timing")
    return {"status":"consistent", "primary_pairs":36, "raw_tables":5,
            "valid_exclusions":13, "off_anchor_counterexamples":22,
            "symbolic_points_not_executed":6}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path, nargs="?", default=Path("results"))
    print(json.dumps(check(parser.parse_args().results), indent=2, sort_keys=True))
