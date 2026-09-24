"""Frozen owned-program evaluation of context transport and conservative exclusions."""
from __future__ import annotations
import copy, csv, json, resource, statistics, time
from pathlib import Path
from .transport import check_transport, audit_transport, valuations, json_value, footprint, split_root
from .transport_producer import make_transport_certificate
from .transport_cases import make_case, instantiated_pair
from .generate import MAKERS, B, C, V
from .checker import execute, check_pair
from .model import validate_program, value_key, stable_json, is_productive_root_safe
from .reference_semantics import execute as reference_execute


def dump(path, obj):
    path.write_text(json.dumps(obj, indent=2, sort_keys=True)+'\n', encoding='utf-8')


def csv_dump(path, rows):
    with path.open('w', newline='', encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)


def direct_oracle(packet, *, reference=False, retain=False):
    """Concrete Cartesian replay. No footprint, abstract interpreter, or core table."""
    start=time.perf_counter()
    roots={k:v for k,v in packet['vulnerable']['input_domains'].items() if k not in packet['context_domains']}
    seen_security, seen_observation={},{}
    relation=invariant=defined=True
    references=disagreement=executions=0
    rows=[];first_failure=varied=None
    for nuisance in valuations(packet['context_domains']):
        vp,pp,_=instantiated_pair(packet,nuisance)
        validate_program(vp);validate_program(pp)
        productive=vulnerable=0
        for root_input in valuations(roots):
            inputs=dict(root_input,**nuisance)
            row={'root_input':stable_json(root_input),'context_input':stable_json(nuisance),
                 'defined':True,'v_violation':'','p_violation':'','safe_observations_equal':True,
                 'root_invariant':True,'reference_comparisons':0,'reference_mismatches':0}
            try:
                a=execute(vp,inputs,_validated=True);b=execute(pp,inputs,_validated=True);executions+=2
                if reference:
                    for program,result in ((vp,a),(pp,b)):
                        ref=reference_execute(program,inputs);references+=1;row['reference_comparisons']+=1
                        match=value_key(json_value(result.to_json()))==value_key(ref.to_json())
                        disagreement+=int(not match);row['reference_mismatches']+=int(not match)
                productive+=int(is_productive_root_safe(vp,a));vulnerable+=int(a.violation is not None)
                key=stable_json(root_input);security=(a.violation,b.violation,a.aborted,b.aborted)
                equal_security=security==seen_security.setdefault(key,security)
                invariant &= equal_security
                same=a.violation is not None or a.observation()==b.observation()
                relation &= b.violation is None and same
                row.update(v_violation=a.violation or '',p_violation=b.violation or '',
                           safe_observations_equal=same,root_invariant=equal_security)
                if a.violation is None and not a.aborted:
                    old=seen_observation.setdefault(key,(nuisance,json_value(a.to_json())))
                    if varied is None and value_key(old[1]['events'])!=value_key(json_value(a.to_json()['events'])):
                        varied={'root_input':root_input,'first_context':old[0],'second_context':nuisance,
                                'first_result':old[1],'second_result':a.to_json()}
                if first_failure is None and (not same or not equal_security or b.violation):
                    first_failure={'input':inputs,'vulnerable':a.to_json(),'patched':b.to_json()}
            except (ValueError,TypeError,KeyError,OverflowError) as exc:
                defined=relation=False;row['defined']=False
                if first_failure is None:first_failure={'input':inputs,'error':type(exc).__name__}
            if retain:rows.append(row)
        relation &= productive>0 and vulnerable>0
    return {'relation':bool(relation),'security_invariant':bool(invariant),'defined':defined,
            'endpoint_executions':executions,'reference_comparisons':references,'reference_mismatches':disagreement,
            'elapsed_ms':(time.perf_counter()-start)*1000,'first_failure':first_failure,
            'functional_variation':varied,'rows':rows}


def controls(packet):
    out=[]
    def add(name,kind,p):out.append((name,kind,p))
    p=copy.deepcopy(packet)
    for side in ('vulnerable','patched'):
        p[side]['instructions'].insert(0,{'op':'branch_abort','role':'context','pred':B('eq',V('noise_0'),C(1))})
    add('pre-root-abort','semantic-failure',p)
    p=copy.deepcopy(packet);root_read,_=footprint(split_root(p['vulnerable'])[1])
    target=sorted(root_read.intersection(p['vulnerable']['input_domains']))[0]
    for side in ('vulnerable','patched'):
        p[side]['instructions'].insert(0,{'op':'assign','role':'context','dst':target,'expr':V('noise_0')})
    add('root-input-overwrite','frame-failure',p)
    p=copy.deepcopy(packet);p['context_domains']['noise_0']=[0,True]
    for side in ('vulnerable','patched'):p[side]['instructions'][0]['expr']=B('add',V('noise_0'),C(1))
    add('unseen-context-type','semantic-failure',p)
    p=copy.deepcopy(packet)
    growth=[{'op':'assign','role':'context','dst':'growth','expr':B('add',V('noise_0'),C(1))}]
    growth += [{'op':'assign','role':'context','dst':'growth','expr':B('mul',V('growth'),V('growth'))} for _ in range(13)]
    for side in ('vulnerable','patched'):p[side]['instructions']=growth+p[side]['instructions']
    add('unseen-integer-growth','semantic-failure',p)
    p=copy.deepcopy(packet);p['transport_certificate']['rows'].pop();add('missing-row','claim-failure',p)
    p=copy.deepcopy(packet);p['transport_certificate']['rows'][1]=copy.deepcopy(p['transport_certificate']['rows'][0]);add('duplicate-row','claim-failure',p)
    p=copy.deepcopy(packet);p['transport_certificate']['rows'][0]['patched']['aborted']=0;add('bool-int-row','claim-failure',p)
    p=copy.deepcopy(packet);p['transport_certificate']['core_binding']['read_variables']=[];add('false-footprint','claim-failure',p)
    p=copy.deepcopy(packet);p['certificate']['pair_id']='unrelated';add('pair-binding','claim-failure',p)
    p=copy.deepcopy(packet);p['context_domains']['noise_0']=[1];add('missing-anchor','claim-failure',p)
    p=copy.deepcopy(packet)
    for side in ('vulnerable','patched'):
        p[side]['instructions'].insert(0,{'op':'assign','role':'context','dst':target,'expr':V(target)})
    add('identity-prefix-write','valid-outside-fragment',p)
    p=copy.deepcopy(packet)
    for side in ('vulnerable','patched'):p[side]['instructions'].insert(0,{'op':'guard','role':'context','pred':C(True)})
    add('true-prefix-guard','valid-outside-fragment',p)
    if packet['vulnerable']['family'] in ('bounds_write','divide_zero','fixed_overflow','access_control'):
        p=copy.deepcopy(packet);guard=next(i for i in p['patched']['instructions'] if i['op']=='guard')
        guard['pred']=B('and',guard['pred'],B('eq',V('noise_0'),C(0)))
        add('nuisance-guard-conjunct','semantic-failure',p)
    return out


def run_transport(output, base_results=None):
    output.mkdir(parents=True,exist_ok=True);cpu=time.process_time();wall=time.perf_counter()
    primary=[];raw=[];packets=[];variation=[];proofs=[]
    for family in MAKERS:
        for wrapper in range(6):
            generation=time.perf_counter();packet=make_case(family,dimensions=4,wrapper=wrapper)
            gen_ms=(time.perf_counter()-generation)*1000;r=check_transport(packet)
            assert r.accepted,(family,wrapper,r)
            factored=audit_transport(packet['vulnerable'],packet['patched'],packet['context_domains'])
            assert factored.accepted and factored.core_executions==r.core_executions
            oracle=direct_oracle(packet,reference=True,retain=True)
            assert oracle['relation'] and oracle['security_invariant'] and oracle['reference_mismatches']==0
            assert oracle['functional_variation'] is not None
            name=f'{family}-wrapper-{wrapper}'
            primary.append({'case':name,'family':family,'wrapper':wrapper,'core_valuations':r.core_valuations,
                'context_valuations':r.context_valuations,'core_executions':r.core_executions,
                'full_endpoint_executions':oracle['endpoint_executions'],'accepted':r.accepted,
                'oracle_relation':oracle['relation'],'oracle_security_invariant':oracle['security_invariant'],
                'functional_variation':True,'reference_comparisons':oracle['reference_comparisons'],
                'reference_mismatches':oracle['reference_mismatches'],'certificate_bytes':r.certificate_bytes,
                'allocation_upper_bound':r.allocation_upper_bound,'generation_ms':round(gen_ms,6),
                'verification_ms':round(r.elapsed_ms,6),'factored_audit_accepted':factored.accepted,
                'factored_audit_core_executions':factored.core_executions,'factored_audit_ms':round(factored.elapsed_ms,6)})
            raw.extend(dict(case=name,**row) for row in oracle['rows']);packets.append(dict(case=name,packet=packet))
            proofs.append(packet['transport_certificate']);variation.append(dict(case=name,**oracle['functional_variation']))
    scales=[]
    for family in MAKERS:
        for dimensions in (0,2,4,6,8,10,20):
            packet=make_case(family,dimensions=dimensions);trials=[check_transport(packet) for _ in range(3)]
            assert all(r.accepted for r in trials);r=trials[0]
            oracle=direct_oracle(packet) if dimensions<=10 else None
            if oracle:assert oracle['relation'] and oracle['security_invariant']
            scales.append({'family':family,'nuisance_dimensions':dimensions,'core_valuations':r.core_valuations,
                'context_valuations':r.context_valuations,'core_executions':r.core_executions,
                'represented_endpoint_executions':r.represented_endpoint_executions,
                'verification_ms':round(statistics.median(x.elapsed_ms for x in trials),6),
                'certificate_bytes':r.certificate_bytes,'direct_endpoint_executions':oracle['endpoint_executions'] if oracle else 0,
                'direct_oracle_ms':round(oracle['elapsed_ms'],6) if oracle else '',
                'direct_oracle_pass':oracle['relation'] and oracle['security_invariant'] if oracle else '',
                'direct_oracle_status':'exhaustive' if oracle else 'not-run-symbolic-only'})
    control_rows=[];control_packets=[];failures=[]
    for family in MAKERS:
        for name,kind,packet in controls(make_case(family,dimensions=2)):
            r=check_transport(packet);anchor=check_pair(packet['vulnerable'],packet['patched'],packet['certificate'])
            factored=audit_transport(packet['vulnerable'],packet['patched'],packet['context_domains'])
            oracle=direct_oracle(packet) if kind!='claim-failure' else None
            if kind=='valid-outside-fragment':assert oracle['relation'] and oracle['security_invariant']
            assert not r.accepted,(family,name,r)
            control_rows.append({'family':family,'control':name,'kind':kind,'transport_accepted':r.accepted,
                'transport_reason':r.reason,'anchor_pair_accepted':anchor.accepted,
                'full_relation':oracle['relation'] if oracle else '',
                'full_security_invariant':oracle['security_invariant'] if oracle else '',
                'full_defined':oracle['defined'] if oracle else '',
                'direct_endpoint_executions':oracle['endpoint_executions'] if oracle else 0,
                'factored_audit_accepted':factored.accepted,
                'oracle_class':('valid-outside-fragment' if oracle and oracle['relation'] and oracle['security_invariant'] else
                    'invalid-contextual-relation' if oracle else 'claim-not-semantically-replayed')})
            control_packets.append({'family':family,'control':name,'kind':kind,'packet':packet})
            if oracle and oracle['first_failure']:failures.append({'family':family,'control':name,**oracle['first_failure']})
    applicability=[]
    if base_results is not None:
        for source in ('corpus.json','description_corpus.json','observation_corpus.json'):
            for record in json.loads((base_results/source).read_text()):
                v,p,c=record['vulnerable'],record['patched'],record['certificate']
                existing=check_pair(v,p,c)
                result=audit_transport(v,p,{})
                assert not result.accepted or existing.accepted, (record['pair_id'],result)
                applicability.append({'pair_id':record['pair_id'],'source_file':source,
                    'family':v['family'],'existing_pair_accepted':existing.accepted,
                    'framed_relation_accepted':result.accepted,'framed_reason':result.reason,
                    'nuisance_dimensions':0})
    unique_proofs=[]
    for proof in proofs:
        if proof not in unique_proofs:unique_proofs.append(proof)
    summary={'primary_pairs':len(primary),'core_certificates':len(unique_proofs),'families':len(MAKERS),'wrapper_templates':6,
        'primary_core_executions':sum(r['core_executions'] for r in primary),
        'primary_full_endpoint_executions':sum(r['full_endpoint_executions'] for r in primary),
        'reference_comparisons':sum(r['reference_comparisons'] for r in primary),
        'reference_mismatches':sum(r['reference_mismatches'] for r in primary),'functionally_varying_cases':len(variation),
        'factored_audit_agreements':sum(r['factored_audit_accepted']==r['accepted'] for r in primary),
        'certificate_claims_rejected_on_valid_factored_relation':sum(not r['transport_accepted'] and r['factored_audit_accepted'] for r in control_rows),
        'applicability_cases':len(applicability),
        'applicability_existing_accepts':sum(r['existing_pair_accepted'] for r in applicability),
        'applicability_framed_accepts':sum(r['framed_relation_accepted'] for r in applicability),
        'applicability_new_false_accepts':sum(r['framed_relation_accepted'] and not r['existing_pair_accepted'] for r in applicability),
        'scaling_points':len(scales),'exhaustively_checked_scaling_points':sum(r['direct_oracle_status']=='exhaustive' for r in scales),
        'scaling_direct_endpoint_executions':sum(r['direct_endpoint_executions'] for r in scales),
        'max_symbolic_context_valuations':2**20,
        'max_symbolic_endpoint_obligations':max(r['represented_endpoint_executions'] for r in scales),
        'controls':len(control_rows),'rejected_controls':sum(not r['transport_accepted'] for r in control_rows),
        'designed_valid_outside_fragment':sum(r['kind']=='valid-outside-fragment' for r in control_rows),
        'valid_outside_fragment':sum(r['oracle_class']=='valid-outside-fragment' for r in control_rows),
        'invalid_contextual_relations':sum(r['oracle_class']=='invalid-contextual-relation' for r in control_rows),
        'invalid_claim_controls':sum(r['kind']=='claim-failure' for r in control_rows),
        'semantic_or_frame_controls':sum(r['kind'] in ('semantic-failure','frame-failure') for r in control_rows),
        'observed_only_extrapolation_counterexamples':sum(r['anchor_pair_accepted'] and r['kind']!='claim-failure' and (not r['full_relation'] or not r['full_security_invariant']) for r in control_rows),
        'control_endpoint_executions':sum(r['direct_endpoint_executions'] for r in control_rows),
        'median_certificate_bytes':statistics.median(r['certificate_bytes'] for r in primary),
        'max_certificate_bytes':max(r['certificate_bytes'] for r in primary),
        'runtime':{'cpu_seconds':time.process_time()-cpu,'wall_seconds':time.perf_counter()-wall,
                   'max_rss_mib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024,'workers':1},
        'scope':'Owned abstract programs; no native-language or detector evaluation.',
        'large_product_status':'Dimensions 0 through 10 measured exhaustively; 20 checked symbolically only.',
        'completeness':'Sufficient framed fragment only; semantically valid excluded controls retained.'}
    for name,rows in [('transport_primary',primary),('transport_oracle',raw),('transport_scaling',scales),('transport_controls',control_rows),('transport_applicability',applicability)]:csv_dump(output/(name+'.csv'),rows)
    for name,rows in [('transport_packets',packets),('transport_control_packets',control_packets),('transport_counterexamples',failures),('transport_functional_variation',variation),('transport_summary',summary)]:dump(output/(name+'.json'),rows)
    return summary
