"""Bounded, owned context-domain and held-out syntax-channel assessment.

This supplements, never relabels, the historical 36-pair campaign. The split is
declared before feature fitting. All predictors see endpoint instruction syntax
only: no label/id/certificate, peer endpoint, execution result, or split metadata.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from itertools import product
from pathlib import Path
import copy
import csv
import json

from .baselines import canonical_rule
from .checker import execute, check_pair
from .generate import B, C, V, P, MAKERS, _certificate
from .model import stable_json, value_key, validate_program, is_productive_root_safe
from .syntax_normalization import normalize_program
from .transport import audit_transport, check_transport, valuations
from .transport_cases import make_case
from .transport_contract_gate import relation_preconditions
from .transport_oracle import direct_oracle
from .transport_producer import make_transport_certificate
from .assessment_io import open_record

TRAIN_ROOTS = (0, 1)
TEST_ROOTS = (2, 3)
TRAIN_CONTEXTS = (0, 1, 2, 3)
TEST_CONTEXTS = (4, 5)
CONTEXT_DOMAINS = {'ctx_x': [-1, 0, 1], 'ctx_y': [-1, 0, 1],
                   'ctx_mode': [False, True], 'ctx_token': ['', 'a', 'b']}


def split_name(root, wrapper):
    if root in TRAIN_ROOTS and wrapper in TRAIN_CONTEXTS:
        return 'train'
    if root in TEST_ROOTS and wrapper in TRAIN_CONTEXTS:
        return 'held-out-root'
    if root in TRAIN_ROOTS and wrapper in TEST_CONTEXTS:
        return 'held-out-context'
    if root in TEST_ROOTS and wrapper in TEST_CONTEXTS:
        return 'held-out-both'
    raise ValueError('undeclared split member')


def make_assessment_case(family, variant, wrapper):
    """Four finite root configurations/monitor, not four newly discovered causes."""
    if variant not in TRAIN_ROOTS + TEST_ROOTS or wrapper not in TRAIN_CONTEXTS + TEST_CONTEXTS:
        raise ValueError('assessment outside declared grid')
    pair_id = f'assessment-{family}-r{variant}-c{wrapper}'
    v, p, _ = MAKERS[family](pair_id, variant)
    for program in (v, p):
        code = program['instructions']
        if family == 'bounds_write':
            next(i for i in code if i['op'] == 'buf_write')['value'] = B('add', V('value'), C(variant))
        elif family == 'divide_zero':
            next(i for i in code if i['op'] == 'divide')['numerator'] = B('add', V('numerator'), C(variant))
        elif family == 'fixed_overflow':
            width = 3 + variant
            hi = 2**width - 1
            program['input_domains']['x'] = [0, hi - 1, hi]
            program['input_domains']['delta'] = [0, 1, 2 + variant]
            program['parameters']['width'] = width
            next(i for i in code if i['op'] == 'add_fixed')['width'] = width
            for inst in code:
                if inst['op'] == 'guard':
                    inst['pred'] = B('le', V('x'), B('sub', C(hi), V('delta')))
        elif family == 'access_control':
            next(i for i in code if i['op'] == 'protected_store')['value'] = B('add', V('value'), C(variant))
        elif family == 'reentrancy':
            balance = 4 + variant
            program['initial_public_state']['balances'] = {'user': balance}
            program['input_domains']['amount'] = [1, balance - variant]
            next(i for i in code if i['op'] == 'external_call')['amount'] = B('add', V('amount'), C(variant))
        else:
            next(i for i in code if i['op'] == 'commit_after_call')['value'] = B('add', V('value'), C(variant))

    # Keep the original root-derived return and event. Context suffixes can
    # consume that result, requiring boundary-store preservation in the proof.
    root_value = copy.deepcopy(v['instructions'][-1]['value'])
    before, after = [], []
    names = list(CONTEXT_DOMAINS)
    for name in names:
        expr = V(name)
        if wrapper == 1 and name in ('ctx_x', 'ctx_y'):
            expr = B('add', B('mul', V(name), C(2)), C(1))
        elif wrapper == 1 and name == 'ctx_mode':
            expr = {'op': 'not', 'arg': expr}
        emit = {'op': 'emit', 'role': 'context', 'name': name, 'value': expr}
        (before if wrapper == 0 else after).append(emit)
    if wrapper >= 2:
        exprs = {
            2: B('add', V('ctx_x'), B('mul', C(2), V('ctx_y'))),
            3: B('mul', V('ctx_x'), V('ctx_y')),
            4: B('lt', V('ctx_x'), V('ctx_y')),
            5: B('and', B('eq', V('ctx_token'), C('a')), V('ctx_mode')),
        }
        after.append({'op': 'emit', 'role': 'context', 'name': 'combination', 'value': exprs[wrapper]})
        # For scalar outputs the comparison is with zero. Structured root
        # outputs are compared with their declared initial value, not discarded.
        sentinel = (v['initial_public_state'][root_value['public']]
                    if set(root_value) == {'public'} else 0)
        after.append({'op': 'emit', 'role': 'context', 'name': 'root-context',
                      'value': B('eq', B('eq', root_value, C(sentinel)), V('ctx_mode'))})
    for program in (v, p):
        roots = [i for i in program['instructions'] if i['role'] == 'root']
        suffix = [i for i in program['instructions'] if i['op'] in ('emit', 'return')]
        program['input_domains'].update({n: [values[0]] for n, values in CONTEXT_DOMAINS.items()})
        program['instructions'] = [
            {'op': 'nop', 'role': 'context', 'tag': f'format-{variant % 2}'}
        ] + before + roots + after + suffix
        program['context'] = {'scenario': 'owned mixed scalar context assessment'}
    cert = _certificate(v, p)
    domains = copy.deepcopy(CONTEXT_DOMAINS)
    return {'vulnerable': v, 'patched': p, 'certificate': cert,
            'context_domains': domains,
            'transport_certificate': make_transport_certificate(v, p, domains)}


def normalized_packet(packet):
    out = copy.deepcopy(packet)
    for side in ('vulnerable', 'patched'):
        out[side] = normalize_program(packet[side])
    out['transport_certificate'] = make_transport_certificate(
        out['vulnerable'], out['patched'], out['context_domains'])
    return out


def syntax_features(program):
    """Only code syntax; no endpoint identity, label, certificate or execution."""
    roots = [i['op'] for i in program['instructions'] if i['role'] == 'root']
    effects_first = ('external_call' in roots and 'update_balance' in roots
                     and roots.index('update_balance') < roots.index('external_call'))
    return {
        'constant': 'one-cell',
        'context-only': stable_json([i for i in program['instructions'] if i['role'] == 'context']),
        'repair-syntax': stable_json(['guard' in roots, 'check_call' in roots, effects_first]),
    }


def fit_lookup(rows, feature):
    """Fit once on training rows; unseen cells use training majority, lexical tie."""
    if not rows or any(r['split'] != 'train' for r in rows):
        raise ValueError('fit must receive nonempty training rows only')
    counts = defaultdict(Counter)
    total = Counter()
    for row in rows:
        counts[row['features'][feature]][row['label']] += 1
        total[row['label']] += 1
    winner = lambda c: sorted(c, key=lambda label: (-c[label], label))[0]
    return {'feature': feature, 'cells': {key: winner(c) for key, c in sorted(counts.items())},
            'fallback': winner(total), 'training_endpoints': len(rows)}


def predict(model, row):
    return model['cells'].get(row['features'][model['feature']], model['fallback'])


def functional_domain(packet):
    """Enumerate a productive root's typed observations and one-coordinate edges."""
    roots = {n: d for n, d in packet['vulnerable']['input_domains'].items()
             if n not in packet['context_domains']}
    anchor = {n: d[0] for n, d in packet['context_domains'].items()}
    program = packet['vulnerable']
    root = next(r for r in valuations(roots)
                if is_productive_root_safe(program, execute(program, dict(r, **anchor))))
    records = []
    for context in valuations(packet['context_domains']):
        point = copy.deepcopy(program)
        point['input_domains'].update({n: [x] for n, x in context.items()})
        result = execute(point, dict(root, **context))
        records.append({'context': context, 'observation': result.observation(),
                        'security': (result.violation, result.aborted)})
    edges = []
    for name in sorted(packet['context_domains']):
        edge = next(((a, b) for a, b in product(records, repeat=2)
                     if value_key(a['context'][name]) != value_key(b['context'][name])
                     and all(value_key(a['context'][n]) == value_key(b['context'][n])
                             for n in packet['context_domains'] if n != name)
                     and a['observation'] != b['observation']), None)
        if edge:
            a, b = edge
            edges.append({'coordinate': name, 'first_context': a['context'],
                          'second_context': b['context'], 'security_equal': a['security'] == b['security']})
    return {'root_input': root, 'reachable_contexts': len(records),
            'distinct_typed_observations': len({r['observation'] for r in records}),
            'effective_coordinates': len(edges), 'coordinate_witnesses': edges,
            'security_profiles': len({r['security'] for r in records})}


def normalization_comparisons(original, normalized):
    """Full-domain semantic comparison for both true labels; no trace equality."""
    count = 0
    roots = {n: d for n, d in original['vulnerable']['input_domains'].items()
             if n not in original['context_domains']}
    for context in valuations(original['context_domains']):
        points = {}
        for version, packet in (('raw', original), ('normalized', normalized)):
            for side in ('vulnerable', 'patched'):
                point = copy.deepcopy(packet[side])
                point['input_domains'].update({n: [x] for n, x in context.items()})
                validate_program(point)
                points[version, side] = point
        for root in valuations(roots):
            inputs = dict(root, **context)
            for side in ('vulnerable', 'patched'):
                a = execute(points['raw', side], inputs, _validated=True)
                b = execute(points['normalized', side], inputs, _validated=True)
                if a.semantic() != b.semantic():
                    raise AssertionError(('normalization changed semantics', side, inputs))
                count += 1
    return count


def relevance_controls(repair_models):
    """Correct endpoint labels still cannot authorize a new context family."""
    base = make_case('divide_zero', dimensions=1)
    guard_case, abort_case = copy.deepcopy(base), copy.deepcopy(base)
    guard = next(i for i in guard_case['patched']['instructions'] if i['op'] == 'guard')
    guard['pred'] = B('and', guard['pred'], B('eq', V('noise_0'), C(0)))
    for side in ('vulnerable', 'patched'):
        abort_case[side]['instructions'].insert(0, {
            'op': 'branch_abort', 'role': 'context', 'pred': B('eq', V('noise_0'), C(1))})
    rows = []
    for name, raw in (('context-dependent-repair', guard_case), ('common-pre-root-abort', abort_case)):
        for representation in ('raw', 'normalized'):
            packet = copy.deepcopy(raw)
            if representation == 'normalized':
                for side in ('vulnerable', 'patched'):
                    packet[side] = normalize_program(packet[side])
                # Invalid families have no admissible new table. The frame/control
                # gate rejects before the old table could be used as evidence.
            anchor = check_pair(packet['vulnerable'], packet['patched'], packet['certificate'])
            gate = relation_preconditions(packet)
            oracle = direct_oracle(packet)
            transport = check_transport(packet)
            correct = sum(predict(repair_models[representation], {
                'features': syntax_features(packet[side])}) == packet[side]['label']
                          for side in ('vulnerable', 'patched'))
            if not (anchor.accepted and gate['preconditions_ok'] and correct == 2
                    and not oracle['semantic_contract_holds'] and not transport.accepted):
                raise AssertionError(('relevance control', name, representation))
            rows.append({'control': name, 'representation': representation,
                         'anchor_pair_accepted': anchor.accepted, 'correct_endpoint_labels': correct,
                         'structural_premises': gate['preconditions_ok'],
                         'expanded_semantic_contract': oracle['semantic_contract_holds'],
                         'transport_accepted': transport.accepted, 'transport_reason': transport.reason,
                         'full_endpoint_executions': oracle['endpoint_executions'],
                         'first_failure': stable_json(oracle['first_failure'])})
    return rows


def write_csv(path, rows):
    with open_record(path, 'w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def run_assessment(output: Path):
    packets, feature_rows, case_rows, oracle_rows, domains, manifest = [], [], [], [], [], []
    root_keys, context_keys = defaultdict(set), defaultdict(set)
    comparisons = 0
    for family in MAKERS:
        for variant in TRAIN_ROOTS + TEST_ROOTS:
            for wrapper in TRAIN_CONTEXTS + TEST_CONTEXTS:
                case = f'{family}-r{variant}-c{wrapper}'
                split = split_name(variant, wrapper)
                packet = make_assessment_case(family, variant, wrapper)
                normalized = normalized_packet(packet)
                comparisons += normalization_comparisons(packet, normalized)
                domain = functional_domain(packet)
                if domain['effective_coordinates'] != 4 or domain['distinct_typed_observations'] != 54:
                    raise AssertionError((case, 'ineffective context', domain))
                domains.append(dict(case=case, **domain))
                root_key = stable_json(normalized['transport_certificate']['core_binding'])
                context_key = syntax_features(normalized['vulnerable'])['context-only']
                root_keys['train' if variant in TRAIN_ROOTS else 'test'].add(root_key)
                context_keys['train' if wrapper in TRAIN_CONTEXTS else 'test'].add(context_key)
                manifest.append({'case': case, 'family': family, 'root_variant': variant,
                                 'wrapper': wrapper, 'split': split,
                                 'root_binding': root_key, 'context_syntax': context_key})
                for representation, value in (('raw', packet), ('normalized', normalized)):
                    gate = relation_preconditions(value)
                    checked = check_transport(value)
                    audit = audit_transport(value['vulnerable'], value['patched'], value['context_domains'])
                    oracle = direct_oracle(value, reference=True, retain=True)
                    if not (gate['preconditions_ok'] and checked.accepted and audit.accepted
                            and oracle['semantic_contract_holds'] and not oracle['reference_mismatches']):
                        raise AssertionError((case, representation, gate, checked, oracle['first_failure']))
                    if checked.core_executions != audit.core_executions:
                        raise AssertionError('factored baseline work mismatch')
                    case_rows.append({'case': case, 'split': split, 'representation': representation,
                                      'transport_accepted': checked.accepted, 'audit_accepted': audit.accepted,
                                      'root_executions': checked.core_executions,
                                      'audit_root_executions': audit.core_executions,
                                      'full_endpoint_executions': oracle['endpoint_executions'],
                                      'reference_comparisons': oracle['reference_comparisons'],
                                      'reference_mismatches': oracle['reference_mismatches'],
                                      'semantic_contract': oracle['semantic_contract_holds'],
                                      'structural_premises': gate['preconditions_ok']})
                    oracle_rows.extend(dict(case=case, representation=representation, **r) for r in oracle['rows'])
                    for side in ('vulnerable', 'patched'):
                        feature_rows.append({'case': case, 'split': split, 'representation': representation,
                                             'label': value[side]['label'], 'features': syntax_features(value[side])})
                packets.append({'case': case, 'packet': packet})
        print(f'completed {family}', flush=True)
    if root_keys['train'] & root_keys['test'] or context_keys['train'] & context_keys['test']:
        raise AssertionError('actual normalized root/context split overlaps')

    scores, predictions, models = [], [], []
    historical, historical_domains = [], []
    for representation in ('raw', 'normalized'):
        rows = [r for r in feature_rows if r['representation'] == representation]
        train = [r for r in rows if r['split'] == 'train']
        for feature in ('constant', 'context-only', 'repair-syntax'):
            model = fit_lookup(train, feature)
            models.append(dict(representation=representation, **model))
            for split in ('held-out-root', 'held-out-context', 'held-out-both'):
                test = [r for r in rows if r['split'] == split]
                correct = 0
                for row in test:
                    prediction = predict(model, row)
                    correct += prediction == row['label']
                    predictions.append({k: row[k] for k in ('case', 'split', 'representation', 'label')}
                                       | {'baseline': feature, 'prediction': prediction,
                                          'seen_training_cell': row['features'][feature] in model['cells']})
                scores.append({'representation': representation, 'split': split, 'baseline': feature,
                               'training_endpoints': len(train), 'test_endpoints': len(test),
                               'correct': correct, 'accuracy': correct / len(test)})
        # Fixed, prespecified rule on the historical 72 labels: descriptive
        # channel assessment, not a held-out performance estimate.
        for family in MAKERS:
            for wrapper in range(6):
                old = make_case(family, dimensions=4, wrapper=wrapper)
                if representation == 'raw':
                    historical_domains.append({'family': family, 'wrapper': wrapper, **functional_domain(old)})
                for side in ('vulnerable', 'patched'):
                    q = old[side] if representation == 'raw' else normalize_program(old[side])
                    historical.append({'family': family, 'wrapper': wrapper, 'representation': representation,
                                       'label': q['label'], 'prediction': canonical_rule(q)})

    summary = {'pairs': len(packets), 'root_configurations': len(root_keys['train'] | root_keys['test']),
               'train_root_configurations': len(root_keys['train']), 'test_root_configurations': len(root_keys['test']),
               'split_pairs': dict(Counter(r['split'] for r in manifest)),
               'root_binding_overlap': 0, 'normalized_context_overlap': 0,
               'context_valuations_per_pair': 54, 'effective_coordinates_per_pair': 4,
               'distinct_observations_min': min(d['distinct_typed_observations'] for d in domains),
               'distinct_observations_max': max(d['distinct_typed_observations'] for d in domains),
               'raw_and_normalized_full_endpoint_executions': sum(r['full_endpoint_executions'] for r in case_rows),
               'reference_comparisons': sum(r['reference_comparisons'] for r in case_rows),
               'reference_mismatches': sum(r['reference_mismatches'] for r in case_rows),
               'normalization_semantic_comparisons': comparisons,
               'normalization_mismatches': 0,
               'transport_audit_agreements': len(case_rows),
               'historical_fixed_rule_correct': dict(Counter(r['representation'] for r in historical if r['label'] == r['prediction'])),
               'historical_domain_cases': len(historical_domains),
               'historical_distinct_observations_min': min(d['distinct_typed_observations'] for d in historical_domains),
               'historical_effective_coordinates_min': min(d['effective_coordinates'] for d in historical_domains),
               'scores': scores,
               'scope': 'owned finite configurations within six existing monitors; not unseen monitor families or native faults',
               'split_protocol': 'roots 0/1 and contexts 0..3 train; roots 2/3 and contexts 4/5 held out; both labels and representations remain in their pair split',
               'predictor_information': 'endpoint instruction syntax only; ids, labels, pair sides, certificates, runtime results and split metadata excluded',
               'fit_protocol': 'prespecified feature maps; lookup cells, majority fallback and tie break fitted only to training labels; no test tuning',
               'normalization_scope': 'endpoint-local nop removal and equivalent comparison spellings; no repair erasure; labels unchanged',
               'represented_but_unexecuted_cases': 0}
    relevance = relevance_controls({m['representation']: m for m in models if m['feature'] == 'repair-syntax'})
    summary['separate_relevance_control_rows'] = len(relevance)
    summary['separate_relevance_control_endpoint_executions'] = sum(r['full_endpoint_executions'] for r in relevance)
    output.mkdir(parents=True, exist_ok=True)
    for name, rows in (('cases', case_rows), ('oracle', oracle_rows), ('scores', scores),
                       ('predictions', predictions), ('split_manifest', manifest), ('historical_channel', historical),
                       ('relevance_controls', relevance)):
        write_csv(output / f'{name}.csv', rows)
    for name, obj in (('packets', packets), ('functional_domain', domains),
                      ('historical_functional_domain', historical_domains), ('models', models),
                      ('features', feature_rows), ('summary', summary)):
        with open_record(output / f'{name}.json', 'w') as stream:
            stream.write(json.dumps(obj, indent=2, sort_keys=True) + '\n')
    return summary
