"""Owned synthetic program pairs, with an optional reference-annotation stratum."""
from __future__ import annotations
from typing import Any, Dict, List, Mapping, Tuple
import copy
import csv
from pathlib import Path
from .model import JSON, enumerate_inputs
from .producer import run
from .repair import expected_repair

def C(value: Any) -> JSON: return {"const": value}
def V(name: str) -> JSON: return {"var": name}
def P(name: str) -> JSON: return {"public": name}
def B(op: str, left: Any, right: Any) -> JSON: return {"op": op, "left": left, "right": right}
def N(arg: Any) -> JSON: return {"op": "not", "arg": arg}

def _base(pair_id: str, profile: str, family: str, label: str, parameters: JSON,
          domains: JSON, context: JSON, state: JSON, projection: List[str], instructions: List[JSON]) -> JSON:
    return {"schema": "rcsc-program", "program_id": f"{pair_id}-{label}", "profile": profile,
            "family": family, "label": label, "parameters": copy.deepcopy(parameters),
            "input_domains": copy.deepcopy(domains), "context": copy.deepcopy(context),
            "initial_public_state": copy.deepcopy(state), "public_projection": list(projection),
            "instructions": copy.deepcopy(instructions)}

def _certificate(vulnerable: Mapping[str, Any], patched: Mapping[str, Any]) -> JSON:
    witness = None
    for inputs in enumerate_inputs(vulnerable):
        if run(vulnerable, inputs).violation:
            witness = inputs; break
    return {"schema": "rcsc-pair-certificate",
            "pair_id": vulnerable["program_id"].rsplit("-vulnerable", 1)[0],
            "vulnerable_id": vulnerable["program_id"],
            "patched_id": patched["program_id"],
            "declared_family": vulnerable["family"],
            "declared_repair": expected_repair(vulnerable["family"]),
            "witness_input": witness}

def _nuisance(seed: int) -> List[JSON]:
    return [{"op": "assign", "dst": "aux", "expr": B("add", C(seed % 5), C((seed*3+1)%7)), "role": "context"},
            {"op": "nop", "tag": f"shape-{seed%4}", "role": "context"}]

def _finish(value: Any = None, event: str | None = None) -> List[JSON]:
    out: List[JSON] = []
    if event is not None: out.append({"op": "emit", "name": event, "value": value, "role": "context"})
    out.append({"op": "return", "value": value, "role": "context"}); return out

def make_bounds(pair_id: str, seed: int, provenance: JSON | None = None) -> Tuple[JSON, JSON, JSON]:
    n = 2 + seed % 4; values = [0, 1 + seed % 3]
    domains = {"idx": [-1, 0, n-1, n], "value": values}; params = {"length": n, "element_domain": [0, max(values)]}
    context = {"scenario": "indexed buffer update", "shape": seed%5, "provenance": provenance}; state = {"buffer": [seed%3 for _ in range(n)], "audit": seed%2}
    write = {"op": "buf_write", "buffer": "buffer", "index": V("idx"), "value": V("value"), "role": "root"}
    prefix = _nuisance(seed); suffix = _finish(P("buffer"), "write")
    vi = prefix + [write] + suffix; pred = B("and", B("ge", V("idx"), C(0)), B("lt", V("idx"), C(n)))
    pi = prefix + [{"op": "guard", "pred": pred, "role": "root"}, write] + suffix
    common = dict(pair_id=pair_id, profile="c", family="bounds_write", parameters=params, domains=domains, context=context, state=state, projection=["buffer","audit"])
    v = _base(label="vulnerable", instructions=vi, **common); p = _base(label="patched", instructions=pi, **common); return v,p,_certificate(v,p)

def make_divide(pair_id: str, seed: int, provenance: JSON | None = None) -> Tuple[JSON, JSON, JSON]:
    domains = {"denominator": [-1,0,1,2+seed%2], "numerator": [-2-seed%2,0,3+seed%3]}
    params={"rounding":"toward-zero","result_name":"quotient"}; context={"scenario":"bounded quotient","shape":seed%5,"provenance":provenance}; state={"audit":seed%3}
    div={"op":"divide","dst":"quotient","numerator":V("numerator"),"denominator":V("denominator"),"role":"root"}; prefix=_nuisance(seed); suffix=_finish(V("quotient"),"quotient")
    vi=prefix+[div]+suffix; pi=prefix+[{"op":"guard","pred":B("ne",V("denominator"),C(0)),"role":"root"},div]+suffix
    common=dict(pair_id=pair_id,profile="c",family="divide_zero",parameters=params,domains=domains,context=context,state=state,projection=["audit"])
    v=_base(label="vulnerable",instructions=vi,**common); p=_base(label="patched",instructions=pi,**common); return v,p,_certificate(v,p)

def make_overflow(pair_id: str, seed: int, provenance: JSON | None = None) -> Tuple[JSON, JSON, JSON]:
    width=3+seed%4; hi=2**width-1; domains={"delta":[0,1,2+seed%2],"x":[0,max(0,hi-1),hi]}
    params={"width":width,"signed":False}; context={"scenario":"fixed-width accumulation","shape":seed%5,"provenance":provenance}; state={"audit":seed%4}
    add={"op":"add_fixed","dst":"sum","left":V("x"),"right":V("delta"),"width":width,"signed":False,"role":"root"}; prefix=_nuisance(seed); suffix=_finish(V("sum"),"sum")
    vi=prefix+[add]+suffix; pi=prefix+[{"op":"guard","pred":B("le",V("x"),B("sub",C(hi),V("delta"))),"role":"root"},add]+suffix
    common=dict(pair_id=pair_id,profile="c",family="fixed_overflow",parameters=params,domains=domains,context=context,state=state,projection=["audit"])
    v=_base(label="vulnerable",instructions=vi,**common); p=_base(label="patched",instructions=pi,**common); return v,p,_certificate(v,p)

def make_access(pair_id: str, seed: int, provenance: JSON | None = None) -> Tuple[JSON, JSON, JSON]:
    owner=f"owner{seed%3}"; domains={"sender":[owner,"user","attacker"],"value":[0,1+seed%3]}; params={"owner_key":"owner","protected_key":"setting"}
    context={"scenario":"privileged state update","shape":seed%5,"provenance":provenance}; state={"owner":owner,"setting":seed%2,"audit":seed%3}
    store={"op":"protected_store","owner_key":"owner","key":"setting","value":V("value"),"role":"root"}; prefix=_nuisance(seed); suffix=_finish(P("setting"),"setting")
    vi=prefix+[store]+suffix; pi=prefix+[{"op":"guard","pred":B("eq",V("sender"),P("owner")),"role":"root"},store]+suffix
    common=dict(pair_id=pair_id,profile="solidity",family="access_control",parameters=params,domains=domains,context=context,state=state,projection=["owner","setting","audit"])
    v=_base(label="vulnerable",instructions=vi,**common); p=_base(label="patched",instructions=pi,**common); return v,p,_certificate(v,p)

def make_reentrancy(pair_id: str, seed: int, provenance: JSON | None = None) -> Tuple[JSON, JSON, JSON]:
    balance=2+seed%3; domains={"amount":[1,balance],"reenter":[False,True],"sender":["user"]}; params={"repair":"checks-effects-interactions","balances_key":"balances"}
    context={"scenario":"withdrawal with callback","shape":seed%5,"provenance":provenance}; state={"balances":{"user":balance},"audit":seed%2}
    call={"op":"external_call","account_var":"sender","balances_key":"balances","amount":V("amount"),"role":"root"}; clear={"op":"update_balance","account_var":"sender","balances_key":"balances","set":C(0),"role":"root"}
    prefix=_nuisance(seed); suffix=_finish(P("balances"),"withdraw"); vi=prefix+[call,clear]+suffix; pi=prefix+[clear,call]+suffix
    common=dict(pair_id=pair_id,profile="solidity",family="reentrancy",parameters=params,domains=domains,context=context,state=state,projection=["balances","audit"])
    v=_base(label="vulnerable",instructions=vi,**common); p=_base(label="patched",instructions=pi,**common); return v,p,_certificate(v,p)

def make_unchecked(pair_id: str, seed: int, provenance: JSON | None = None) -> Tuple[JSON, JSON, JSON]:
    domains={"call_ok":[False,True],"value":[0,1+seed%4]}; params={"status_key":"committed"}; context={"scenario":"low-level call followed by commit","shape":seed%5,"provenance":provenance}; state={"committed":0,"audit":seed%2}
    call={"op":"low_call","success_var":"call_ok","role":"root"}; check={"op":"check_call","role":"root"}; commit={"op":"commit_after_call","key":"committed","value":V("value"),"role":"root"}; prefix=_nuisance(seed); suffix=_finish(P("committed"),"commit")
    vi=prefix+[call,commit]+suffix; pi=prefix+[call,check,commit]+suffix
    common=dict(pair_id=pair_id,profile="solidity",family="unchecked_call",parameters=params,domains=domains,context=context,state=state,projection=["committed","audit"])
    v=_base(label="vulnerable",instructions=vi,**common); p=_base(label="patched",instructions=pi,**common); return v,p,_certificate(v,p)

MAKERS={"bounds_write":make_bounds,"divide_zero":make_divide,"fixed_overflow":make_overflow,"access_control":make_access,"reentrancy":make_reentrancy,"unchecked_call":make_unchecked}
def reference_annotations() -> dict:
    path = Path(__file__).resolve().parents[1] / 'external_inputs' / 'reference_annotations.csv'
    groups = {family: [] for family in MAKERS}
    with path.open(newline='') as stream:
        for row in csv.DictReader(stream):
            groups[row['family']].append((row['record'], row['url'], row['basis']))
    if any(len(rows) != 3 for rows in groups.values()):
        raise ValueError('reference annotation selection must contain three records per family')
    return groups


def generate_corpus(per_family: int = 40, include_public: bool = True, seed: int = 2027) -> List[JSON]:
    pairs: List[JSON] = []
    for family, maker in MAKERS.items():
        for index in range(per_family):
            pair_id=f"gen-{family}-{index:03d}"; v,p,c=maker(pair_id, seed+index)
            pairs.append({"pair_id":pair_id,"family":family,"profile":v["profile"],"source_kind":"generated","vulnerable":v,"patched":p,"certificate":c})
        if include_public:
            for index,(record,url,basis) in enumerate(reference_annotations()[family]):
                pair_id=f"pub-{family}-{index:02d}"; provenance={"record":record,"url":url,"basis":basis,"boundary":"synthetic constructor with a reference tag; not an extracted program or a source-equivalent port"}
                v,p,c=maker(pair_id, seed+100+index, provenance)
                pairs.append({"pair_id":pair_id,"family":family,"profile":v["profile"],"source_kind":"synthetic-reference-tagged","vulnerable":v,"patched":p,"certificate":c})
    return pairs
