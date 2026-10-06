"""Frozen owned-program evaluation of context transport and conservative exclusions."""
from __future__ import annotations

import copy
import csv
import json
import os
import platform
import statistics
import time
from pathlib import Path

from .checker import check_pair
from .generate import B, C, MAKERS, V
from .repair import expected_repair
from .transport import audit_transport, check_transport, footprint, split_root
from .transport_cases import make_case
from .transport_contract_gate import relation_preconditions
from .transport_oracle import direct_oracle


def dump(path, obj):
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def csv_dump(path, rows):
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace").splitlines():
            if line.lower().startswith("model name") and ":" in line:
                value = line.split(":", 1)[1].strip()
                if value:
                    return value
    except OSError:
        pass
    return platform.processor().strip() or "unavailable"


def measurement_environment() -> dict:
    return {
        "cpu_model": _cpu_model(),
        "logical_cpu_count": os.cpu_count(),
        "operating_system": platform.system(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
    }


def max_rss_mib() -> float:
    # Keep owned fixture/oracle helpers importable where POSIX RSS is unavailable.
    # The measured campaign still requires this genuine resource measurement.
    import resource
    raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Linux reports KiB; macOS reports bytes.  The retained run records the OS.
    return raw / (1024 * 1024) if platform.system() == "Darwin" else raw / 1024


def contract_classification(preconditions: dict, oracle: dict | None) -> bool | None:
    if oracle is None:
        return None
    return bool(preconditions["preconditions_ok"] and oracle["semantic_contract_holds"])


def controls(packet):
    out = []

    def add(name, kind, value):
        out.append((name, kind, value))

    p = copy.deepcopy(packet)
    for side in ("vulnerable", "patched"):
        p[side]["instructions"].insert(
            0, {"op": "branch_abort", "role": "context", "pred": B("eq", V("noise_0"), C(1))}
        )
    add("pre-root-abort", "semantic-failure", p)

    p = copy.deepcopy(packet)
    root_read, _ = footprint(split_root(p["vulnerable"])[1])
    target = sorted(root_read.intersection(p["vulnerable"]["input_domains"]))[0]
    for side in ("vulnerable", "patched"):
        p[side]["instructions"].insert(
            0, {"op": "assign", "role": "context", "dst": target, "expr": V("noise_0")}
        )
    add("root-input-overwrite", "frame-failure", p)

    p = copy.deepcopy(packet)
    p["context_domains"]["noise_0"] = [0, True]
    for side in ("vulnerable", "patched"):
        p[side]["instructions"][0]["expr"] = B("add", V("noise_0"), C(1))
    add("unseen-context-type", "semantic-failure", p)

    p = copy.deepcopy(packet)
    growth = [{"op": "assign", "role": "context", "dst": "growth", "expr": B("add", V("noise_0"), C(1))}]
    growth += [
        {"op": "assign", "role": "context", "dst": "growth", "expr": B("mul", V("growth"), V("growth"))}
        for _ in range(13)
    ]
    for side in ("vulnerable", "patched"):
        p[side]["instructions"] = growth + p[side]["instructions"]
    add("unseen-integer-growth", "semantic-failure", p)

    p = copy.deepcopy(packet)
    p["transport_certificate"]["rows"].pop()
    add("missing-row", "claim-failure", p)

    p = copy.deepcopy(packet)
    p["transport_certificate"]["rows"][1] = copy.deepcopy(p["transport_certificate"]["rows"][0])
    add("duplicate-row", "claim-failure", p)

    p = copy.deepcopy(packet)
    p["transport_certificate"]["rows"][0]["patched"]["aborted"] = 0
    add("bool-int-row", "claim-failure", p)

    p = copy.deepcopy(packet)
    p["transport_certificate"]["core_binding"]["read_variables"] = []
    add("false-footprint", "claim-failure", p)

    p = copy.deepcopy(packet)
    p["certificate"]["pair_id"] = "unrelated"
    add("pair-binding", "claim-failure", p)

    p = copy.deepcopy(packet)
    p["context_domains"]["noise_0"] = [1]
    add("missing-anchor", "claim-failure", p)

    p = copy.deepcopy(packet)
    for side in ("vulnerable", "patched"):
        p[side]["instructions"].insert(
            0, {"op": "assign", "role": "context", "dst": target, "expr": V(target)}
        )
    add("identity-prefix-write", "valid-outside-fragment", p)

    p = copy.deepcopy(packet)
    for side in ("vulnerable", "patched"):
        p[side]["instructions"].insert(0, {"op": "guard", "role": "context", "pred": C(True)})
    add("true-prefix-guard", "valid-outside-fragment", p)

    if packet["vulnerable"]["family"] in (
        "bounds_write",
        "divide_zero",
        "fixed_overflow",
        "access_control",
    ):
        p = copy.deepcopy(packet)
        guard = next(instruction for instruction in p["patched"]["instructions"] if instruction["op"] == "guard")
        guard["pred"] = B("and", guard["pred"], B("eq", V("noise_0"), C(0)))
        add("nuisance-guard-conjunct", "semantic-failure", p)
    return out


def oracle_scope_controls() -> list[dict]:
    """Two small mutations that separate semantic replay from contract entry."""
    base = make_case("divide_zero", dimensions=1, wrapper=0)

    trailing_nop = copy.deepcopy(base)
    root_indices = [
        index
        for index, instruction in enumerate(trailing_nop["patched"]["instructions"])
        if instruction["role"] == "root"
    ]
    trailing_nop["patched"]["instructions"].insert(
        max(root_indices) + 1,
        {"op": "nop", "role": "root", "tag": "scope-control-trailing-root-nop"},
    )

    wrong_monitor = copy.deepcopy(base)
    for side in ("vulnerable", "patched"):
        wrong_monitor[side]["family"] = "fixed_overflow"
    wrong_monitor["certificate"]["declared_family"] = "fixed_overflow"
    wrong_monitor["certificate"]["declared_repair"] = expected_repair("fixed_overflow")

    rows = []
    for name, packet in (
        ("patched-root-trailing-nop", trailing_nop),
        ("divide-pair-declared-fixed-overflow", wrong_monitor),
    ):
        preconditions = relation_preconditions(packet)
        oracle = direct_oracle(packet)
        production = check_transport(packet)
        rows.append(
            {
                "control": name,
                "semantic_relation": oracle["semantic_relation"],
                "security_invariant": oracle["security_invariant"],
                "monitor_consistent": oracle["monitor_consistent"],
                "defined": oracle["defined"],
                "admission_precondition": preconditions["admission_ok"],
                "declaration_precondition": preconditions["declarations_ok"],
                "context_domain_precondition": preconditions["context_domains_ok"],
                "repair_membership_precondition": preconditions["repair_membership_ok"],
                "all_relation_preconditions": preconditions["preconditions_ok"],
                "contract_classification": contract_classification(preconditions, oracle),
                "repair_check_independent": preconditions["repair_check_independent"],
                "repair_reason": preconditions.get("repair_reason", ""),
                "production_accepted": production.accepted,
                "production_reason": production.reason,
            }
        )
    return rows


def run_transport(output, base_results=None):
    # Fail before doing campaign work on an unsupported measurement platform.
    max_rss_mib()
    output.mkdir(parents=True, exist_ok=True)
    environment = measurement_environment()
    cpu_started = time.process_time()
    wall_started = time.perf_counter()
    primary = []
    raw = []
    packets = []
    variation = []
    proofs = []

    for family in MAKERS:
        for wrapper in range(6):
            generation_started = time.perf_counter()
            packet = make_case(family, dimensions=4, wrapper=wrapper)
            generation_ms = (time.perf_counter() - generation_started) * 1000
            preconditions = relation_preconditions(packet)
            assert preconditions["preconditions_ok"], (family, wrapper, preconditions)
            result = check_transport(packet)
            assert result.accepted, (family, wrapper, result)
            factored = audit_transport(packet["vulnerable"], packet["patched"], packet["context_domains"])
            assert factored.accepted and factored.core_executions == result.core_executions
            oracle = direct_oracle(packet, reference=True, retain=True)
            assert oracle["semantic_contract_holds"] and oracle["reference_mismatches"] == 0
            assert contract_classification(preconditions, oracle)
            assert oracle["functional_variation"] is not None
            name = f"{family}-wrapper-{wrapper}"
            primary.append(
                {
                    "case": name,
                    "family": family,
                    "wrapper": wrapper,
                    "core_valuations": result.core_valuations,
                    "context_valuations": result.context_valuations,
                    "core_executions": result.core_executions,
                    "full_endpoint_executions": oracle["endpoint_executions"],
                    "accepted": result.accepted,
                    "oracle_semantic_relation": oracle["semantic_relation"],
                    "oracle_security_invariant": oracle["security_invariant"],
                    "oracle_monitor_consistent": oracle["monitor_consistent"],
                    "oracle_defined": oracle["defined"],
                    "relation_preconditions": preconditions["preconditions_ok"],
                    "repair_membership_precondition": preconditions["repair_membership_ok"],
                    "full_contract_classification": contract_classification(preconditions, oracle),
                    "functional_variation": True,
                    "reference_comparisons": oracle["reference_comparisons"],
                    "reference_mismatches": oracle["reference_mismatches"],
                    "certificate_bytes": result.certificate_bytes,
                    "allocation_upper_bound": result.allocation_upper_bound,
                    "generation_ms": round(generation_ms, 6),
                    "verification_ms": round(result.elapsed_ms, 6),
                    "factored_audit_accepted": factored.accepted,
                    "factored_audit_core_executions": factored.core_executions,
                    "factored_audit_ms": round(factored.elapsed_ms, 6),
                }
            )
            raw.extend(dict(case=name, **row) for row in oracle["rows"])
            packets.append(dict(case=name, packet=packet))
            proofs.append(packet["transport_certificate"])
            variation.append(dict(case=name, **oracle["functional_variation"]))

    scales = []
    for family in MAKERS:
        for dimensions in (0, 2, 4, 6, 8, 10, 20):
            packet = make_case(family, dimensions=dimensions)
            preconditions = relation_preconditions(packet)
            assert preconditions["preconditions_ok"], (family, dimensions, preconditions)
            trials = [check_transport(packet) for _ in range(3)]
            assert all(result.accepted for result in trials)
            result = trials[0]
            trial_ms = [round(item.elapsed_ms, 6) for item in trials]
            transport_median_ms = round(statistics.median(trial_ms), 6)
            oracle = direct_oracle(packet) if dimensions <= 10 else None
            if oracle:
                assert oracle["semantic_contract_holds"]
                assert contract_classification(preconditions, oracle)
            scales.append(
                {
                    "family": family,
                    "nuisance_dimensions": dimensions,
                    "core_valuations": result.core_valuations,
                    "context_valuations": result.context_valuations,
                    "core_executions": result.core_executions,
                    "represented_endpoint_executions": result.represented_endpoint_executions,
                    "transport_trial_1_ms": trial_ms[0],
                    "transport_trial_2_ms": trial_ms[1],
                    "transport_trial_3_ms": trial_ms[2],
                    "verification_ms": transport_median_ms,
                    "certificate_bytes": result.certificate_bytes,
                    "relation_preconditions": preconditions["preconditions_ok"],
                    "repair_membership_precondition": preconditions["repair_membership_ok"],
                    "direct_endpoint_executions": oracle["endpoint_executions"] if oracle else 0,
                    "direct_oracle_ms": round(oracle["elapsed_ms"], 6) if oracle else "",
                    "direct_oracle_semantic_relation": oracle["semantic_relation"] if oracle else "",
                    "direct_oracle_security_invariant": oracle["security_invariant"] if oracle else "",
                    "direct_oracle_monitor_consistent": oracle["monitor_consistent"] if oracle else "",
                    "direct_oracle_contract_pass": contract_classification(preconditions, oracle) if oracle else "",
                    "direct_oracle_status": "exhaustive" if oracle else "not-run-symbolic-only",
                }
            )

    control_rows = []
    control_packets = []
    failures = []
    for family in MAKERS:
        for name, kind, packet in controls(make_case(family, dimensions=2)):
            result = check_transport(packet)
            anchor = check_pair(packet["vulnerable"], packet["patched"], packet["certificate"])
            factored = audit_transport(packet["vulnerable"], packet["patched"], packet["context_domains"])
            preconditions = relation_preconditions(packet)
            oracle = direct_oracle(packet) if kind != "claim-failure" else None
            if oracle:
                # All replayed controls preserve the base declarations and named repair.
                assert preconditions["preconditions_ok"], (family, name, preconditions)
            if kind == "valid-outside-fragment":
                assert oracle and oracle["semantic_contract_holds"]
            assert not result.accepted, (family, name, result)
            semantic_valid = bool(oracle and oracle["semantic_contract_holds"])
            control_rows.append(
                {
                    "family": family,
                    "control": name,
                    "kind": kind,
                    "transport_accepted": result.accepted,
                    "transport_reason": result.reason,
                    "anchor_pair_accepted": anchor.accepted,
                    "relation_preconditions": preconditions["preconditions_ok"],
                    "repair_membership_precondition": preconditions["repair_membership_ok"],
                    "full_semantic_relation": oracle["semantic_relation"] if oracle else "",
                    "full_security_invariant": oracle["security_invariant"] if oracle else "",
                    "full_monitor_consistent": oracle["monitor_consistent"] if oracle else "",
                    "full_defined": oracle["defined"] if oracle else "",
                    "full_contract_classification": contract_classification(preconditions, oracle) if oracle else "",
                    "direct_endpoint_executions": oracle["endpoint_executions"] if oracle else 0,
                    "factored_audit_accepted": factored.accepted,
                    "oracle_class": (
                        "valid-outside-fragment"
                        if semantic_valid
                        else "invalid-contextual-relation"
                        if oracle
                        else "claim-not-semantically-replayed"
                    ),
                }
            )
            control_packets.append({"family": family, "control": name, "kind": kind, "packet": packet})
            if oracle and oracle["first_failure"]:
                failures.append({"family": family, "control": name, **oracle["first_failure"]})

    applicability = []
    if base_results is not None:
        for source in ("corpus.json", "description_corpus.json", "observation_corpus.json"):
            for record in json.loads((base_results / source).read_text()):
                vulnerable, patched, certificate = (
                    record["vulnerable"],
                    record["patched"],
                    record["certificate"],
                )
                existing = check_pair(vulnerable, patched, certificate)
                result = audit_transport(vulnerable, patched, {})
                assert not result.accepted or existing.accepted, (record["pair_id"], result)
                applicability.append(
                    {
                        "pair_id": record["pair_id"],
                        "source_file": source,
                        "family": vulnerable["family"],
                        "existing_pair_accepted": existing.accepted,
                        "framed_relation_accepted": result.accepted,
                        "framed_reason": result.reason,
                        "nuisance_dimensions": 0,
                    }
                )

    scope_rows = oracle_scope_controls()
    by_scope_name = {row["control"]: row for row in scope_rows}
    assert by_scope_name["patched-root-trailing-nop"]["semantic_relation"]
    assert by_scope_name["patched-root-trailing-nop"]["monitor_consistent"]
    assert not by_scope_name["patched-root-trailing-nop"]["repair_membership_precondition"]
    assert not by_scope_name["patched-root-trailing-nop"]["contract_classification"]
    assert not by_scope_name["divide-pair-declared-fixed-overflow"]["semantic_relation"]
    assert not by_scope_name["divide-pair-declared-fixed-overflow"]["monitor_consistent"]
    assert not by_scope_name["divide-pair-declared-fixed-overflow"]["repair_membership_precondition"]
    assert not by_scope_name["divide-pair-declared-fixed-overflow"]["contract_classification"]

    unique_proofs = []
    for proof in proofs:
        if proof not in unique_proofs:
            unique_proofs.append(proof)

    summary = {
        "primary_pairs": len(primary),
        "core_certificates": len(unique_proofs),
        "families": len(MAKERS),
        "wrapper_templates": 6,
        "primary_core_executions": sum(row["core_executions"] for row in primary),
        "primary_full_endpoint_executions": sum(row["full_endpoint_executions"] for row in primary),
        "primary_relation_precondition_passes": sum(row["relation_preconditions"] for row in primary),
        "primary_full_contract_classifications": sum(row["full_contract_classification"] for row in primary),
        "reference_comparisons": sum(row["reference_comparisons"] for row in primary),
        "reference_mismatches": sum(row["reference_mismatches"] for row in primary),
        "functionally_varying_cases": len(variation),
        "factored_audit_agreements": sum(row["factored_audit_accepted"] == row["accepted"] for row in primary),
        "certificate_claims_rejected_on_valid_factored_relation": sum(
            not row["transport_accepted"] and row["factored_audit_accepted"] for row in control_rows
        ),
        "applicability_cases": len(applicability),
        "applicability_existing_accepts": sum(row["existing_pair_accepted"] for row in applicability),
        "applicability_framed_accepts": sum(row["framed_relation_accepted"] for row in applicability),
        "applicability_new_false_accepts": sum(
            row["framed_relation_accepted"] and not row["existing_pair_accepted"] for row in applicability
        ),
        "scaling_points": len(scales),
        "scaling_transport_trials_per_point": 3,
        "exhaustively_checked_scaling_points": sum(
            row["direct_oracle_status"] == "exhaustive" for row in scales
        ),
        "scaling_direct_endpoint_executions": sum(row["direct_endpoint_executions"] for row in scales),
        "max_symbolic_context_valuations": 2**20,
        "max_symbolic_endpoint_obligations": max(row["represented_endpoint_executions"] for row in scales),
        "controls": len(control_rows),
        "rejected_controls": sum(not row["transport_accepted"] for row in control_rows),
        "designed_valid_outside_fragment": sum(row["kind"] == "valid-outside-fragment" for row in control_rows),
        "valid_outside_fragment": sum(row["oracle_class"] == "valid-outside-fragment" for row in control_rows),
        "invalid_contextual_relations": sum(row["oracle_class"] == "invalid-contextual-relation" for row in control_rows),
        "invalid_claim_controls": sum(row["kind"] == "claim-failure" for row in control_rows),
        "semantic_or_frame_controls": sum(
            row["kind"] in ("semantic-failure", "frame-failure") for row in control_rows
        ),
        "observed_only_extrapolation_counterexamples": sum(
            row["anchor_pair_accepted"]
            and row["kind"] != "claim-failure"
            and (
                not row["full_semantic_relation"]
                or not row["full_security_invariant"]
                or not row["full_monitor_consistent"]
            )
            for row in control_rows
        ),
        "control_endpoint_executions": sum(row["direct_endpoint_executions"] for row in control_rows),
        "oracle_scope_controls": len(scope_rows),
        "oracle_scope_semantic_only_accepts": sum(row["semantic_relation"] for row in scope_rows),
        "oracle_scope_monitor_mismatches": sum(not row["monitor_consistent"] for row in scope_rows),
        "oracle_scope_repair_rejections": sum(not row["repair_membership_precondition"] for row in scope_rows),
        "median_certificate_bytes": statistics.median(row["certificate_bytes"] for row in primary),
        "max_certificate_bytes": max(row["certificate_bytes"] for row in primary),
        "runtime": {
            "cpu_seconds": time.process_time() - cpu_started,
            "wall_seconds": time.perf_counter() - wall_started,
            "max_rss_mib": max_rss_mib(),
            "workers": 1,
            "environment": environment,
            "measurement_scope": "one fresh single-process invocation of run_transport through construction of all primary, scaling, control, applicability, and scope-control result objects; output-file writing occurs after the CPU/wall snapshot",
            "cpu_measurement": "process-wide CPU time from time.process_time()",
            "wall_measurement": "monotonic elapsed time from time.perf_counter()",
            "rss_measurement": "process-lifetime peak ru_maxrss at the end of the fresh invocation, from resource.getrusage(RUSAGE_SELF), converted from KiB to MiB on Linux and bytes to MiB on macOS; it includes imports and campaign execution but is not a start/end delta",
            "scaling_transport_measurement": "three check_transport elapsed_ms values per packet; retained median recomputed from the three raw values",
            "cartesian_measurement": "one complete direct_oracle traversal per exhaustively measured point",
        },
        "oracle_scope": "Cartesian semantic replay independently avoids footprint, abstract interpretation, and root tables; relation declarations and exact repair membership are separately checked, with the repair gate shared with production and therefore non-independent.",
        "scope": "Owned abstract programs; no native-language or detector evaluation.",
        "large_product_status": "Dimensions 0 through 10 measured exhaustively; 20 checked symbolically only.",
        "completeness": "Sufficient framed fragment only; semantically valid excluded controls retained.",
    }

    for name, rows in (
        ("transport_primary", primary),
        ("transport_oracle", raw),
        ("transport_scaling", scales),
        ("transport_controls", control_rows),
        ("transport_applicability", applicability),
        ("transport_oracle_scope_controls", scope_rows),
    ):
        csv_dump(output / (name + ".csv"), rows)
    for name, rows in (
        ("transport_packets", packets),
        ("transport_control_packets", control_packets),
        ("transport_counterexamples", failures),
        ("transport_functional_variation", variation),
        ("transport_summary", summary),
    ):
        dump(output / (name + ".json"), rows)
    return summary
