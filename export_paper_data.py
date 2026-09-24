"""Export manuscript numerical macros and scaling data from retained results."""
from __future__ import annotations
import argparse
import csv
import json
from pathlib import Path
from check_results import check_results


def export(results: Path, output: Path) -> None:
    check_results(results)
    summary = json.loads((results / "summary.json").read_text())
    with (results / "scaling_results.csv").open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    pairs = summary["pair_certificates"]
    direct = summary["direct_audit"]
    oracle = summary["observation_oracle"]
    surface = summary["surface_balance"]
    execution = summary["execution"]
    scaling = summary["scaling"]
    reference = summary["reference_semantics"]
    boundary = summary["boundary_controls"]
    source = summary["source_bridge"]
    semantic_boundary = summary["semantic_boundary_matrix"]
    membership = summary["membership_controls"]
    transforms = summary["transformation_certificates"]
    negative = summary["negative_controls"]
    values = {
        "PairMedianMs": f"{pairs['median_replay_ms']:.3f}",
        "PairTailMs": f"{pairs['p95_replay_ms']:.3f}",
        "ScaleFirstMs": f"{float(rows[0]['median_replay_ms']):.3f}",
        "ScaleLastMs": f"{float(rows[-1]['median_replay_ms']):.3f}",
        "CampaignCpu": f"{execution['cpu_seconds']:.3f}",
        "CampaignWall": f"{execution['wall_seconds']:.3f}",
        "CampaignMemory": f"{execution['max_rss_kib']/1024:.1f}",
        "PrimaryPairs": str(direct["pairs"]),
        "NegativeControls": str(negative["controls"]),
        "CertificateOnlyControls": str(direct["certificate_only_controls"]),
        "MembershipControls": str(membership["controls"]),
        "MembershipValid": str(membership["valid_accepted"]),
        "MembershipInvalid": str(membership["invalid_rejected"]),
        "PreservingMembershipValid": str(membership["root_preserving_valid_accepted"]),
        "PreservingMembershipInvalid": str(membership["root_preserving_invalid_rejected"]),
        "FlippingMembershipValid": str(membership["root_flipping_valid_accepted"]),
        "FlippingMembershipInvalid": str(membership["root_flipping_invalid_rejected"]),
        "TransformObligations": str(transforms["obligations"]),
        "AcceptedPrimaryPairs": str(direct["certificate_accepted"]),
        "RejectedPrimaryPairs": str(direct["pairs"]-direct["certificate_accepted"]),
        "SurfacePairs": str(surface["pairs"]),
        "SurfaceEndpoints": str(surface["endpoints"]),
        "SurfaceCells": str(surface["surface_cells"]),
        "ObserverPairs": str(oracle["pairs"]),
        "ObserverComparisons": str(oracle["interpreter_comparisons"]),
        "CleanSubsets": str(summary["leakage_diagnostics"]["clean_subsets_exhausted"]),
        "LargestValuations": str(scaling["largest_input_valuations"]),
        "ReferencePrograms": str(reference["programs"]),
        "ReferenceValuations": str(reference["endpoint_valuations"]),
        "ReferenceComparisons": str(reference["interpreter_comparisons"]),
        "BoundaryCases": str(boundary["cases"]),
        "SourcePairs": str(source["pairs"]),
        "SourcePrograms": str(source["programs"]),
        "SourceValuations": str(source["endpoint_valuations"]),
        "SourceComparisons": str(source["interpreter_comparisons"]),
        "SourceControls": str(source["controls"]),
        "SemanticBoundaryCases": str(semantic_boundary["total_cases"]),
        "SemanticBoundaryEvaluations": str(semantic_boundary["total_interpreter_evaluations"]),
        "SemanticExpressionCases": str(semantic_boundary["expression_matrix"]["cases"]),
        "SemanticExpressionErrors": str(semantic_boundary["expression_matrix"]["error_cases"]),
        "SemanticInstructionPrograms": str(semantic_boundary["instruction_matrix"]["programs"]),
        "SemanticInstructionValuations": str(semantic_boundary["instruction_matrix"]["valuations"]),
        "SemanticInstructionErrors": str(semantic_boundary["instruction_matrix"]["error_cases"]),
        "RawTables": "24",
    }
    output.mkdir(parents=True, exist_ok=True)
    text = "% Numerical values exported from retained raw results.\n"
    text += "".join(f"\\newcommand{{\\{key}}}{{{value}}}\n" for key, value in values.items())
    (output / "data.tex").write_text(text)
    (output / "scaling.csv").write_bytes((results / "scaling_results.csv").read_bytes())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=Path("results"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    export(args.results, args.output)


if __name__ == "__main__":
    main()
