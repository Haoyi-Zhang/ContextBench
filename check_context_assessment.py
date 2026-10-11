"""Reconcile held-out assessment predictions, actual domains and recorded replay."""
from collections import Counter
from pathlib import Path
import argparse
import csv
import json

from rcsc.context_assessment import (fit_lookup, predict, syntax_features, split_name,
                                     functional_domain, normalized_packet, relevance_controls)
from rcsc.model import stable_json
from rcsc.transport import valuations, cardinality
from rcsc.syntax_normalization import normalize_program
from rcsc.transport_cases import make_case
from rcsc.baselines import canonical_rule
from rcsc.generate import MAKERS
from rcsc.assessment_io import open_record


def check(output):
    def read(name):
        with open_record(output / f'{name}.json') as stream:
            return json.load(stream)
    def table(name):
        with open_record(output / f'{name}.csv', newline='') as stream:
            return list(csv.DictReader(stream))
    def require(ok, message):
        if not ok:
            raise ValueError(message)
    packets = {r['case']: r['packet'] for r in read('packets')}
    features, models, summary = read('features'), read('models'), read('summary')
    cases, predictions, scores, manifest = (table(n) for n in ('cases', 'predictions', 'scores', 'split_manifest'))
    require(len(packets) == len(manifest) == summary['pairs'] == 144, 'pair coverage')
    require(len(cases) == 288 and len(features) == 576, 'representation coverage')
    actual = {r['case']: r for r in manifest}
    require(len(actual) == 144, 'duplicate split entry')
    root_groups, context_groups = {'train': set(), 'test': set()}, {'train': set(), 'test': set()}
    domains = {r['case']: r for r in read('functional_domain')}
    require(set(domains) == set(packets), 'functional coverage')
    expected_oracle, expected_runs = set(), 0
    feature_index = {}
    for case, packet in packets.items():
        row = actual[case]
        root, wrapper = int(row['root_variant']), int(row['wrapper'])
        require(row['split'] == split_name(root, wrapper), 'split assignment')
        require(row['family'] == packet['vulnerable']['family'], 'manifest family')
        binding = stable_json(normalized_packet(packet)['transport_certificate']['core_binding'])
        require(binding == row['root_binding'], 'actual root binding')
        root_groups['train' if root < 2 else 'test'].add(binding)
        context = syntax_features(normalize_program(packet['vulnerable']))['context-only']
        require(context == row['context_syntax'], 'actual normalized context')
        context_groups['train' if wrapper < 4 else 'test'].add(context)
        require(domains[case] == dict(case=case, **functional_domain(packet)), 'functional witness replay')
        root_domains = {n: d for n, d in packet['vulnerable']['input_domains'].items()
                        if n not in packet['context_domains']}
        for representation in ('raw', 'normalized'):
            for r in valuations(root_domains):
                for n in valuations(packet['context_domains']):
                    expected_oracle.add((case, representation, stable_json(r), stable_json(n)))
            expected_runs += 2 * cardinality(root_domains) * cardinality(packet['context_domains'])
            for side in ('vulnerable', 'patched'):
                program = packet[side] if representation == 'raw' else normalize_program(packet[side])
                feature_index[case, representation, side] = {
                    'case': case, 'split': row['split'], 'representation': representation,
                    'label': side, 'features': syntax_features(program)}
    require(not root_groups['train'] & root_groups['test'], 'root overlap')
    require(not context_groups['train'] & context_groups['test'], 'context overlap')
    require(summary['root_binding_overlap'] == summary['normalized_context_overlap'] == 0,
            'reported split overlap')
    require(summary['root_configurations'] == len(root_groups['train'] | root_groups['test']) == 24,
            'root configuration count')
    require(summary['split_pairs'] == dict(Counter(r['split'] for r in manifest)), 'split count')
    require(summary['context_valuations_per_pair'] == summary['distinct_observations_min']
            == summary['distinct_observations_max'] == 54 and summary['effective_coordinates_per_pair'] == 4,
            'reported effective domain')
    require(Counter(stable_json(r) for r in features) == Counter(stable_json(r) for r in feature_index.values()),
            'feature input/label binding')
    seen = set()
    reference_count = 0
    for row in table('oracle'):
        key = tuple(row[n] for n in ('case', 'representation', 'root_input', 'context_input'))
        require(key in expected_oracle and key not in seen, 'oracle domain/duplicate')
        seen.add(key)
        require(all(row[n] == 'True' for n in ('defined', 'monitor_consistent', 'patched_closed',
                                             'safe_observations_equal', 'root_invariant')), 'oracle failed row')
        require(row['reference_comparisons'] == '2' and row['reference_mismatches'] == '0', 'reference row')
        reference_count += 2
    require(seen == expected_oracle, 'incomplete actual oracle domain')
    require(reference_count == expected_runs == summary['reference_comparisons']
            == summary['raw_and_normalized_full_endpoint_executions'], 'execution total')
    require(summary['normalization_semantic_comparisons'] == expected_runs // 2
            and summary['normalization_mismatches'] == summary['reference_mismatches'] == 0,
            'normalization total')
    require(summary['represented_but_unexecuted_cases'] == 0, 'symbolic promotion')
    case_index = {(r['case'], r['representation']): r for r in cases}
    require(len(case_index) == 288, 'duplicate case row')
    for (case, representation), row in case_index.items():
        require(case in packets and row['split'] == actual[case]['split'], 'case binding')
        require(all(row[n] == 'True' for n in ('transport_accepted', 'audit_accepted',
                                             'semantic_contract', 'structural_premises')), 'case failed')
        packet = packets[case]
        roots = {n: d for n, d in packet['vulnerable']['input_domains'].items() if n not in packet['context_domains']}
        require(int(row['root_executions']) == int(row['audit_root_executions']) == 2 * cardinality(roots),
                'same-information factored work')
        require(int(row['full_endpoint_executions']) == int(row['reference_comparisons'])
                == 2 * cardinality(roots) * cardinality(packet['context_domains']), 'case full work')
    model_index = {}
    for model in models:
        representation, feature = model['representation'], model['feature']
        train = [r for r in features if r['representation'] == representation and r['split'] == 'train']
        require(model == dict(representation=representation, **fit_lookup(train, feature)), 'training-only model')
        require((representation, feature) not in model_index, 'duplicate model')
        model_index[representation, feature] = model
    require(len(model_index) == 6 and len(scores) == 18, 'model/score coverage')
    expected_predictions = []
    for row in features:
        if row['split'] == 'train':
            continue
        for feature in ('constant', 'context-only', 'repair-syntax'):
            model = model_index[row['representation'], feature]
            expected_predictions.append({k: str(row[k]) for k in ('case', 'split', 'representation', 'label')}
                                        | {'baseline': feature, 'prediction': predict(model, row),
                                           'seen_training_cell': str(row['features'][feature] in model['cells'])})
    require(Counter(stable_json(r) for r in predictions) == Counter(stable_json(r) for r in expected_predictions),
            'test prediction coverage/model binding')
    for row in scores:
        selected = [r for r in predictions if all(r[n] == row[n] for n in ('representation', 'split'))
                    and r['baseline'] == row['baseline']]
        correct = sum(r['label'] == r['prediction'] for r in selected)
        require(int(row['correct']) == correct and int(row['test_endpoints']) == len(selected)
                and float(row['accuracy']) == correct / len(selected) and int(row['training_endpoints']) == 96,
                'held-out score')
    require(Counter(stable_json({k: str(v) for k, v in r.items()}) for r in summary['scores'])
            == Counter(stable_json(r) for r in scores), 'summary score binding')
    relevance = relevance_controls({m['representation']: m for m in models if m['feature'] == 'repair-syntax'})
    require(table('relevance_controls') == [{k: str(v) for k, v in r.items()} for r in relevance],
            'relevance control replay')
    require(summary['separate_relevance_control_rows'] == len(relevance)
            and summary['separate_relevance_control_endpoint_executions']
            == sum(r['full_endpoint_executions'] for r in relevance), 'relevance control total')
    historical, historical_domains = [], []
    for family in MAKERS:
        for wrapper in range(6):
            old = make_case(family, dimensions=4, wrapper=wrapper)
            historical_domains.append({'family': family, 'wrapper': wrapper, **functional_domain(old)})
            for representation in ('raw', 'normalized'):
                for side in ('vulnerable', 'patched'):
                    q = old[side] if representation == 'raw' else normalize_program(old[side])
                    historical.append({'family': family, 'wrapper': str(wrapper), 'representation': representation,
                                       'label': side, 'prediction': canonical_rule(q)})
    require(read('historical_functional_domain') == historical_domains, 'historical functional replay')
    require(Counter(stable_json(r) for r in table('historical_channel'))
            == Counter(stable_json(r) for r in historical), 'historical syntax channel')
    require(summary['historical_fixed_rule_correct'] == dict(Counter(r['representation'] for r in historical
                                                                     if r['label'] == r['prediction']))
            and summary['historical_domain_cases'] == 36
            and summary['historical_distinct_observations_min'] == 16
            and summary['historical_effective_coordinates_min'] == 4, 'historical diagnostic totals')
    return {'status': 'consistent', 'pairs': len(packets), 'oracle_rows': len(seen),
            'full_endpoint_executions': expected_runs, 'reference_comparisons': reference_count,
            'held_out_predictions': len(predictions), 'functional_witnesses_replayed': len(domains)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', nargs='?', type=Path, default=Path('results/context_assessment'))
    args = parser.parse_args()
    print(json.dumps(check(args.output), indent=2, sort_keys=True))
