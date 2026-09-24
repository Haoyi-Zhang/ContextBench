"""Deterministic evidence generation for the RCSC paper."""
from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence, Tuple
from collections import Counter
import copy,csv,json,math,statistics,time,resource
from .baselines import canonical_rule,duality_aware_rule
from .boundary_cases import make_pre_root_abort_safe_pair
from .checker import check_pair,execute,_check_pair_for_testing
from .generate import generate_corpus,MAKERS,make_bounds
from .leakage import (all_context_feature_names,contaminate,grouped_lookup_accuracy,
                      perfect_witness_search,rows_from_pairs)
from .model import JSON,enumerate_inputs
from .producer import run
from .transform import check_transform,flip_certificate,preserving_variants

def write_json(path:Path,value:Any)->None:path.write_text(json.dumps(value,indent=2,sort_keys=True),encoding="utf-8")
def write_csv(path:Path,rows:Sequence[Mapping[str,Any]],fieldnames:Sequence[str]|None=None)->None:
    if fieldnames is None:fieldnames=list(rows[0]) if rows else []
    with path.open("w",newline="",encoding="utf-8") as handle:
        writer=csv.DictWriter(handle,fieldnames=fieldnames);writer.writeheader();writer.writerows(rows)
def percentile(values:Sequence[float],p:float)->float:
    ordered=sorted(values);return ordered[max(0,min(len(ordered)-1,math.ceil(p*len(ordered))-1))]

def evaluate_pairs(pairs):
    rows=[]
    for pair in pairs:
        rep=check_pair(pair["vulnerable"],pair["patched"],pair["certificate"])
        rows.append({"pair_id":pair["pair_id"],"profile":pair["profile"],"family":pair["family"],"source_kind":pair["source_kind"],"accepted":rep.accepted,"reason":rep.reason,"input_count":rep.details["input_count"] if rep.details else 0,"obligations":rep.obligations,"safe_inputs_compared":rep.safe_inputs_compared,"productive_safe_inputs":rep.productive_safe_inputs,"vulnerable_inputs":rep.vulnerable_inputs,"certificate_bytes":rep.certificate_bytes,"elapsed_ms":round(rep.elapsed_ms,6)})
    times=[r["elapsed_ms"] for r in rows];sizes=[r["certificate_bytes"] for r in rows]
    summary={"pairs":len(rows),"accepted":sum(r["accepted"] for r in rows),"reference_tagged_pairs":sum(r["source_kind"]=="synthetic-reference-tagged" for r in rows),"reference_tagged_accepted":sum(r["source_kind"]=="synthetic-reference-tagged" and r["accepted"] for r in rows),"obligations":sum(r["obligations"] for r in rows),"median_certificate_bytes":statistics.median(sizes),"p95_certificate_bytes":percentile(sizes,.95),"median_replay_ms":statistics.median(times),"p95_replay_ms":percentile(times,.95)}
    return rows,summary

def producer_checker_agreement(pairs):
    runs=0;mismatches=[]
    for pair in pairs:
        for side in ("vulnerable","patched"):
            program=pair[side]
            for inputs in enumerate_inputs(program):
                runs+=1;a,b=run(program,inputs),execute(program,inputs)
                if a.semantic()!=b.semantic():mismatches.append({"program":program["program_id"],"input":inputs,"producer":a.to_json(),"checker":b.to_json()})
    return {"runs":runs,"agreed":not mismatches,"mismatches":mismatches}

def evaluate_transforms(pairs):
    rows=[];targets=[]
    for pair in pairs:
        for side in ("vulnerable","patched"):
            source=pair[side]
            for target,cert in preserving_variants(source):
                rep=check_transform(source,target,cert);targets.append(target)
                rows.append({"pair_id":pair["pair_id"],"family":pair["family"],"source_kind":pair["source_kind"],"class":"root-preserving","transform":cert["transform"],"source_label":source["label"],"accepted":rep.accepted,"reason":rep.reason,"obligations":rep.obligations,"certificate_bytes":rep.certificate_bytes,"elapsed_ms":round(rep.elapsed_ms,6)})
        for source,target,kind in ((pair["vulnerable"],pair["patched"],"close-root"),(pair["patched"],pair["vulnerable"],"open-root")):
            cert=flip_certificate(source,target,kind);rep=check_transform(source,target,cert)
            rows.append({"pair_id":pair["pair_id"],"family":pair["family"],"source_kind":pair["source_kind"],"class":"root-flipping","transform":kind,"source_label":source["label"],"accepted":rep.accepted,"reason":rep.reason,"obligations":rep.obligations,"certificate_bytes":rep.certificate_bytes,"elapsed_ms":round(rep.elapsed_ms,6)})
    original=[p[s] for p in pairs for s in ("vulnerable","patched")]
    clean=sum(canonical_rule(p)==p["label"] for p in original)/len(original)
    can=sum(canonical_rule(p)==p["label"] for p in targets)/len(targets);dual=sum(duality_aware_rule(p)==p["label"] for p in targets)/len(targets)
    return rows,{"certificates":len(rows),"accepted":sum(r["accepted"] for r in rows),"root_preserving":sum(r["class"]=="root-preserving" for r in rows),"root_flipping":sum(r["class"]=="root-flipping" for r in rows),"obligations":sum(r["obligations"] for r in rows),"canonical_rule_clean_accuracy":clean,"canonical_rule_preserved_accuracy":can,"duality_aware_rule_preserved_accuracy":dual},targets

def _safe_input(program):
    for inputs in enumerate_inputs(program):
        if run(program,inputs).violation is None:return inputs
    raise AssertionError

def negative_controls(pairs):
    rows=[];sets={}
    for family in sorted({pair["family"] for pair in pairs}):
        family_pairs=[pair for pair in pairs if pair["family"]==family]
        pair=family_pairs[0];other=family_pairs[1]
        vulnerable=pair["vulnerable"];patched=pair["patched"];certificate=pair["certificate"]
        cases=[]
        target=copy.deepcopy(patched);target["context"]["label_hint"]="leak"
        cases.append(("context-leakage","context-leakage",vulnerable,target,copy.deepcopy(certificate)))

        target=copy.deepcopy(vulnerable);target["label"]="patched";target["program_id"]=patched["program_id"]
        cases.append(("repair-omitted","root-repair-mismatch",vulnerable,target,copy.deepcopy(certificate)))

        target=copy.deepcopy(patched)
        guard=next((instruction for instruction in target["instructions"] if instruction["op"]=="guard" and instruction["role"]=="root"),None)
        if guard is not None:
            guard["pred"]={"op":"and","left":guard["pred"],"right":{"const":False}};over_reason="safe-observation-mismatch"
        else:
            site=next(i for i,x in enumerate(target["instructions"]) if x.get("role","context")=="root")
            target["instructions"].insert(site,{"op":"guard","pred":{"const":False},"role":"root"})
            over_reason="root-repair-mismatch"
        cases.append(("over-restrictive-patch",over_reason,vulnerable,target,copy.deepcopy(certificate)))

        target=copy.deepcopy(patched);target["label"]="vulnerable"
        cases.append(("contradictory-label","contradictory-label",vulnerable,target,copy.deepcopy(certificate)))

        cert=copy.deepcopy(certificate);cert["declared_family"]=next(name for name in MAKERS if name!=family)
        cases.append(("wrong-certificate-family","certificate-family-mismatch",vulnerable,patched,cert))

        cert=copy.deepcopy(certificate);cert["declared_repair"]="not-the-declared-repair"
        cases.append(("wrong-certificate-repair","certificate-repair-mismatch",vulnerable,patched,cert))

        cert=copy.deepcopy(certificate);cert["witness_input"]=_safe_input(vulnerable)
        cases.append(("contradictory-witness","contradictory-witness",vulnerable,patched,cert))

        target=copy.deepcopy(patched);key=sorted(target["input_domains"])[0]
        target["input_domains"][key]=target["input_domains"][key]+["domain-extra"]
        cases.append(("domain-mismatch","input-domain-mismatch",vulnerable,target,copy.deepcopy(certificate)))

        cert=copy.deepcopy(other["certificate"])
        cases.append(("certificate-endpoint-substitution","certificate-pair-mismatch",vulnerable,patched,cert))

        # Keep the relation intact while violating only the production pair-id
        # naming convention.  The certificate-free audit must accept this pair;
        # the submitted certificate must not.
        left=copy.deepcopy(vulnerable);right=copy.deepcopy(patched);cert=copy.deepcopy(certificate)
        left["program_id"]=family+"-left";right["program_id"]=family+"-right"
        cert["vulnerable_id"]=left["program_id"];cert["patched_id"]=right["program_id"]
        cases.append(("endpoint-id-convention","certificate-pair-mismatch",left,right,cert))

        cert=copy.deepcopy(certificate);cert["witness_input"]["undeclared"]=0
        cases.append(("certificate-witness-out-of-domain","certificate-witness-out-of-domain",vulnerable,patched,cert))

        left=copy.deepcopy(vulnerable);right=copy.deepcopy(patched)
        for endpoint in (left,right):
            endpoint["instructions"].insert(0,{"op":"nop","role":"root","tag":endpoint["label"]})
        cases.append(("root-label-channel","root-repair-mismatch",left,right,copy.deepcopy(certificate)))

        sets[family]=cases
        for name,expected,left,right,cert in cases:
            rep=check_pair(left,right,cert)
            rows.append({"family":family,"control":name,"expected_reason":expected,
                         "accepted":rep.accepted,"actual_reason":rep.reason,
                         "detected":(not rep.accepted and rep.reason==expected)})
    return rows,sets

def mutation_analysis(pairs,sets):
    rows=[]
    mutants=[("bounds_inclusive","bounds_write"),("zero_over_zero_safe","divide_zero"),("wrap_without_event","fixed_overflow"),("friend_is_owner","access_control"),("ignore_callback","reentrancy"),("force_call_success","unchecked_call")]
    for mutant,family in mutants:
        chosen=[p for p in pairs if p["family"]==family]
        reports=[_check_pair_for_testing(p["vulnerable"],p["patched"],p["certificate"],mutant=mutant) for p in chosen]
        rejected=sum(not r.accepted for r in reports)
        rows.append({"mutant":mutant,"scope":family,"tests":len(reports),"rejected":rejected,
                     "killed":rejected>0,"reason_counts":json.dumps(dict(Counter(r.reason for r in reports)),sort_keys=True)})
    context_cases=[case for family in sets.values() for case in family if case[0]=="context-leakage"]
    accepted=sum(_check_pair_for_testing(l,r,c,skip_context=True).accepted for _,_,l,r,c in context_cases)
    rows.append({"mutant":"skip-context-obligation","scope":"pair-checker","tests":len(context_cases),"rejected":0,
                 "killed":accepted>0,"reason_counts":json.dumps({"wrongly_accepted":accepted})})
    obs_cases=[case for family in sets.values() for case in family if case[0]=="over-restrictive-patch" and case[1]=="safe-observation-mismatch"]
    accepted=sum(_check_pair_for_testing(l,r,c,skip_observations=True).accepted for _,_,l,r,c in obs_cases)
    rows.append({"mutant":"skip-safe-observation-obligation","scope":"pair-checker","tests":len(obs_cases),"rejected":0,
                 "killed":accepted>0,"reason_counts":json.dumps({"wrongly_accepted":accepted})})
    repair_cases=[case for family in sets.values() for case in family if case[0]=="root-label-channel"]
    accepted=sum(_check_pair_for_testing(l,r,c,require_repair=False).accepted for _,_,l,r,c in repair_cases)
    rows.append({"mutant":"skip-exact-repair-obligation","scope":"pair-checker","tests":len(repair_cases),"rejected":0,
                 "killed":accepted>0,"reason_counts":json.dumps({"wrongly_accepted":accepted})})
    v,p,c=make_bounds("empty-safe-ablation",0)
    for endpoint in (v,p): endpoint["input_domains"]={"idx":[-1,2],"value":[1]}
    c["witness_input"]={"idx":-1,"value":1}
    accepted=_check_pair_for_testing(v,p,c,require_safe=False).accepted
    rows.append({"mutant":"skip-safe-nonvacuity-obligation","scope":"pair-checker","tests":1,"rejected":0,
                 "killed":accepted,"reason_counts":json.dumps({"wrongly_accepted":int(accepted)})})
    v,p,c=make_pre_root_abort_safe_pair("productive-safe-ablation")
    accepted=_check_pair_for_testing(v,p,c,require_productive_safe=False).accepted
    rows.append({"mutant":"skip-productive-safe-obligation","scope":"pair-checker","tests":1,"rejected":0,
                 "killed":accepted,"reason_counts":json.dumps({"wrongly_accepted":int(accepted)})})
    return rows,{"mutants":len(rows),"killed":sum(r["killed"] for r in rows),"mutation_score":sum(r["killed"] for r in rows)/len(rows)}

def leakage_analysis(pairs):
    rows=[];attacked_rejected=0
    names=all_context_feature_names()
    for scenario in ("none","label-token","context-length","partition-skew","mixed-two-feature"):
        altered=contaminate(pairs,scenario);table=rows_from_pairs(altered)
        witness,subsets_examined,search_limit=perfect_witness_search(table,None)
        singles=[(grouped_lookup_accuracy(table,[n])["accuracy"],n) for n in names]
        pairscores=[(grouped_lookup_accuracy(table,list(ns))["accuracy"],"+".join(ns)) for ns in __import__('itertools').combinations(names,2)]
        best_single=max(singles,key=lambda x:(x[0],x[1]));best_pair=max(pairscores,key=lambda x:(x[0],x[1]));rejections=0
        if scenario!="none":
            for pair in altered:
                if not check_pair(pair["vulnerable"],pair["patched"],pair["certificate"]).accepted:rejections+=1
            attacked_rejected+=rejections
        rows.append({"scenario":scenario,"pairs":len(pairs),
                     "minimal_witness_size":witness["size"] if witness else 0,
                     "minimal_witness_features":"+".join(witness["features"]) if witness else "none",
                     "subsets_examined":subsets_examined,"feature_universe_size":len(names),
                     "search_limit":search_limit,"search_complete":witness is None or witness["size"]<=search_limit,
                     "best_single_accuracy":best_single[0],"best_single_feature":best_single[1],
                     "best_pair_accuracy":best_pair[0],"best_pair_features":best_pair[1],
                     "certificate_rejections":rejections})
    return rows,{"attacks":4,
                 "attacks_with_witness":sum(r["scenario"]!="none" and r["minimal_witness_size"]>0 for r in rows),
                 "attacked_pair_obligations":4*len(pairs),"attacked_pairs_rejected":attacked_rejected,
                 "clean_minimal_witness":rows[0]["minimal_witness_features"],
                 "clean_best_single_accuracy":rows[0]["best_single_accuracy"],
                 "feature_universe_size":len(names),
                 "clean_subsets_exhausted":rows[0]["subsets_examined"]}

def tiny_exhaustive_analysis():
    rows=[];runs=0;mismatches=0
    for family,maker in MAKERS.items():
        for seed in range(16):
            v,p,c=maker(f"tiny-{family}-{seed:02d}",seed)
            for program in (v,p):
                for inputs in enumerate_inputs(program):
                    runs+=1
                    if run(program,inputs).semantic()!=execute(program,inputs).semantic():mismatches+=1
            cases=[("valid",v,p,c,True),
                   ("context-divergence",v,copy.deepcopy(p),copy.deepcopy(c),False),
                   ("unclosed-root",v,copy.deepcopy(v),copy.deepcopy(c),False),
                   ("over-restrictive",v,copy.deepcopy(p),copy.deepcopy(c),False)]
            cases[1][2]["context"]["shape"]="different"
            cases[2][2]["label"]="patched";cases[2][2]["program_id"]=p["program_id"]
            site=next(i for i,x in enumerate(cases[3][2]["instructions"]) if x.get("role","context")=="root");cases[3][2]["instructions"].insert(site,{"op":"guard","pred":{"const":False},"role":"root"})
            for name,left,right,cert,expected in cases:
                rep=check_pair(left,right,cert);rows.append({"family":family,"seed":seed,"case":name,"accepted":rep.accepted,"reason":rep.reason,"expected_accept":expected,"matched_expectation":rep.accepted==expected})
    return rows,{"constructor_pairs":96,"certificate_cases":len(rows),"matched_expectation":sum(r["matched_expectation"] for r in rows),"producer_checker_runs":runs,"producer_checker_mismatches":mismatches}

def scaling_analysis():
    rows=[]
    for n in (4,8,16,32,64,128,256):
        v,p,c=make_bounds(f"scale-{n}",0);domain=[-1]+list(range(n))+[n];v["parameters"]["length"]=p["parameters"]["length"]=n;v["initial_public_state"]["buffer"]=p["initial_public_state"]["buffer"]=[0]*n;v["input_domains"]["idx"]=p["input_domains"]["idx"]=domain
        # rewrite bound constants in patched guard
        guard=next(i for i in p["instructions"] if i["op"]=="guard");guard["pred"]["right"]["right"]={"const":n}
        c["witness_input"]={"idx":-1,"value":0}
        reports=[check_pair(v,p,c) for _ in range(5)];times=[r.elapsed_ms for r in reports];rep=reports[-1]
        rows.append({"buffer_length":n,"input_valuations":2*(n+2),"accepted":rep.accepted,"obligations":rep.obligations,"median_replay_ms":round(statistics.median(times),6),"p95_replay_ms":round(percentile(times,.95),6),"certificate_bytes":rep.certificate_bytes})
    return rows

def run_all(output:Path,per_family:int=40)->JSON:
    output.mkdir(parents=True,exist_ok=True);started=time.perf_counter();cpu_started=time.process_time();pairs=generate_corpus(per_family,True)
    pair_rows,pair_summary=evaluate_pairs(pairs);agreement=producer_checker_agreement(pairs);transform_rows,transform_summary,transform_targets=evaluate_transforms(pairs);negative_rows,sets=negative_controls(pairs);mutation_rows,mutation_summary=mutation_analysis(pairs,sets);leakage_rows,leakage_summary=leakage_analysis(pairs);tiny_rows,tiny_summary=tiny_exhaustive_analysis();scaling_rows=scaling_analysis()
    corpus={"pairs":len(pairs),"programs":2*len(pairs),"unreferenced_synthetic_pairs":sum(p["source_kind"]=="generated" for p in pairs),"reference_tagged_pairs":sum(p["source_kind"]=="synthetic-reference-tagged" for p in pairs),"families":sorted({p["family"] for p in pairs}),"profiles":sorted({p["profile"] for p in pairs})}
    write_json(output/"corpus.json",pairs);write_csv(output/"pair_results.csv",pair_rows);write_csv(output/"transform_results.csv",transform_rows);write_csv(output/"negative_controls.csv",negative_rows);write_csv(output/"mutation_results.csv",mutation_rows);write_csv(output/"leakage_results.csv",leakage_rows);write_csv(output/"tiny_exhaustive_results.csv",tiny_rows);write_csv(output/"scaling_results.csv",scaling_rows);write_json(output/"producer_checker_agreement.json",agreement)
    from .observation_oracle import run_observation_campaign
    from .membership_experiment import run_membership_campaign
    observation_summary = run_observation_campaign(output)
    membership_summary = run_membership_campaign(output)
    from .descriptions import run_description_campaign
    description_summary, description_pairs = run_description_campaign(output)
    from .surface_experiment import run_surface_campaign
    surface_summary = run_surface_campaign(output, pairs + description_pairs)
    from .reference_experiment import run_reference_campaign
    reference_summary = run_reference_campaign(output, pairs, description_pairs, transform_targets)
    from .direct_experiment import run_direct_campaign
    direct_summary = run_direct_campaign(output, pairs + description_pairs, sets)
    from .boundary_experiment import run_boundary_campaign
    boundary_summary = run_boundary_campaign(output)
    from .provenance import audit_references
    provenance_summary = audit_references(output)
    from .source_experiment import run_source_campaign
    source_summary = run_source_campaign(output)
    from .semantic_boundary import run_semantic_boundary_campaign
    semantic_boundary_summary = run_semantic_boundary_campaign(output)
    summary={"corpus":corpus,"pair_certificates":pair_summary,"producer_checker_agreement":agreement,"transformation_certificates":transform_summary,"negative_controls":{"controls":len(negative_rows),"detected":sum(r["detected"] for r in negative_rows)},"mutation_analysis":mutation_summary,"leakage_diagnostics":leakage_summary,"tiny_exhaustive":tiny_summary,"scaling":{"points":len(scaling_rows),"largest_input_valuations":scaling_rows[-1]["input_valuations"],"largest_median_replay_ms":scaling_rows[-1]["median_replay_ms"]},"observation_oracle":observation_summary,"membership_controls":membership_summary,"direct_audit":direct_summary,"provenance_audit":provenance_summary,"description_abstractions":description_summary,"surface_balance":surface_summary,"reference_semantics":reference_summary,"semantic_boundary_matrix":semantic_boundary_summary,"source_bridge":source_summary,"boundary_controls":boundary_summary,"execution":{"cpu_seconds":round(time.process_time()-cpu_started,6),"workers":1,"wall_seconds":round(time.perf_counter()-started,6),"max_rss_kib":resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}}
    write_json(output/"summary.json",summary);return summary
