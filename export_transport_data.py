"""Export manuscript numbers and measured scaling data from checked evidence."""
from __future__ import annotations
import argparse
import csv
import json
import statistics
from pathlib import Path
from check_transport_results import check


def export(results: Path, output: Path) -> None:
    check(results)
    output.mkdir(parents=True, exist_ok=True)
    summary = json.loads((results / "transport_summary.json").read_text())
    with (results / "transport_scaling.csv").open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    names = {"primary_pairs":"TransportPairs", "core_certificates":"TransportTables",
             "primary_core_executions":"TransportCoreRuns", "primary_full_endpoint_executions":"TransportFullRuns",
             "reference_comparisons":"TransportReferenceRuns", "controls":"TransportControls",
             "valid_outside_fragment":"TransportValidExcluded", "observed_only_extrapolation_counterexamples":"TransportExtrapolationFailures",
             "scaling_direct_endpoint_executions":"TransportScalingRuns", "applicability_framed_accepts":"TransportApplicable"}
    macros = []
    for key, name in names.items():
        macros.append("\\newcommand{\\" + name + "}{" + f"{summary[key]:,}" + "}")
    macros += ["\\newcommand{\\TransportCPU}{"+f'{summary["runtime"]["cpu_seconds"]:.3f}'+"}",
               "\\newcommand{\\TransportRSS}{"+f'{summary["runtime"]["max_rss_mib"]:.1f}'+"}"]
    (output / "transport-data.tex").write_text("\n".join(macros)+"\n")
    measured = []
    for d in (0,2,4,6,8,10):
        group = [row for row in rows if int(row["nuisance_dimensions"]) == d]
        tr = [float(row["verification_ms"]) for row in group]
        direct = [float(row["direct_oracle_ms"]) for row in group]
        measured.append({"dimensions":d,"transport_median_ms":statistics.median(tr),
                         "transport_min_ms":min(tr),"transport_max_ms":max(tr),
                         "cartesian_median_ms":statistics.median(direct),
                         "cartesian_min_ms":min(direct),"cartesian_max_ms":max(direct)})
    with (output / "transport-scaling.csv").open("w", newline="") as stream:
        writer=csv.DictWriter(stream,fieldnames=list(measured[0]));writer.writeheader();writer.writerows(measured)
    labels={"bounds_write":"Bounds", "divide_zero":"Division", "fixed_overflow":"Overflow",
            "access_control":"Access", "reentrancy":"Reentrancy", "unchecked_call":"Call status"}
    lines=[]
    for row in rows:
        if int(row["nuisance_dimensions"]) != 10:
            continue
        cells=[labels[row["family"]],row["core_valuations"],row["core_executions"],
               f'{int(row["direct_endpoint_executions"]):,}',
               f'{float(row["verification_ms"]):.2f}', f'{float(row["direct_oracle_ms"]):.2f}',
               f'{int(row["certificate_bytes"]):,}']
        lines.append(" & ".join(cells)+" "+chr(92)*2)
    (output/"transport-family-table.tex").write_text(chr(92)+"newcommand{"+chr(92)+"TransportFamilyRows}{%\n"+"\n".join(lines)+"\n}\n")

if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=Path("results"))
    parser.add_argument("--output", type=Path, default=Path("paper-data"))
    args=parser.parse_args();export(args.results,args.output)
