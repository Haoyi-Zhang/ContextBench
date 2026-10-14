"""Fixed, training-only ordinary syntax comparator on retained owned endpoints.

No evaluator, peer endpoint or metadata is consulted by the token/model functions.
The split is the pre-existing root/context split, checked against actual objects.
"""
from collections import Counter
from pathlib import Path
import csv
import hashlib
import json
import math
import platform
import re

from .assessment_io import open_record
from .context_assessment import split_name, syntax_features, fit_lookup, predict
from .generate import MAKERS
from .model import stable_json, validate_program
from .syntax_normalization import normalize_program
from .transport import prepare

SPLITS = ('held-out-root', 'held-out-context', 'held-out-both')
LABELS = ('patched', 'vulnerable')
PROTOCOL = {
    'split': 'roots 0/1 and contexts 0..3 train; roots 2/3 and contexts 4/5 held out',
    'input': 'endpoint instructions only; all keys, typed scalar values and container delimiters',
    'tokenization': 'unordered unigram bag; whole strings; no repair feature engineering',
    'model': 'multinomial naive Bayes, alpha=1, empirical training priors, training vocabulary only',
    'decision': 'ignore unknown tokens; sum log scores; lexical label tie break',
    'tuning': 'none; no split, feature, alpha or threshold search',
    'scope': 'within-six-monitor configuration holdouts; not independent fault populations or native execution',
}


def token_bag(program):
    """Generic typed JSON tokens of instruction syntax, not the whole packet."""
    tokens = Counter()
    def walk(value):
        if type(value) is dict:
            tokens['object:{'] += 1
            tokens['object:}'] += 1
            for key, item in sorted(value.items()):
                tokens['key:' + key] += 1
                walk(item)
        elif type(value) is list:
            tokens['list:['] += 1
            tokens['list:]'] += 1
            for item in value:
                walk(item)
        elif type(value) in (int, bool, str, type(None)):
            tokens[type(value).__name__ + ':' + stable_json(value)] += 1
        else:
            raise ValueError('instruction token outside typed JSON syntax')
    walk(program['instructions'])
    return dict(sorted(tokens.items()))


def fit(rows):
    if not rows or any(row['split'] != 'train' for row in rows):
        raise ValueError('fit requires training endpoints only')
    labels = Counter(row['label'] for row in rows)
    if set(labels) != set(LABELS):
        raise ValueError('both declared labels required in training')
    counts = {label: Counter() for label in LABELS}
    for row in rows:
        counts[row['label']].update(row['tokens'])
    vocabulary = sorted(set().union(*(set(counts[label]) for label in LABELS)))
    if not vocabulary:
        raise ValueError('empty instruction vocabulary')
    return {'alpha': 1, 'training_endpoints': len(rows), 'label_counts': dict(labels),
            'vocabulary': vocabulary, 'token_counts': {k: dict(sorted(v.items())) for k, v in counts.items()},
            'token_totals': {k: sum(v.values()) for k, v in counts.items()}}


def classify(model, bag):
    vocabulary = set(model['vocabulary'])
    scores = {}
    for label in LABELS:
        score = math.log(model['label_counts'][label] / model['training_endpoints'])
        denominator = model['token_totals'][label] + len(vocabulary)
        for token, count in sorted(bag.items()):
            if token in vocabulary:
                score += count * math.log((model['token_counts'][label].get(token, 0) + 1) / denominator)
        scores[label] = score
    return min(LABELS, key=lambda label: (-scores[label], label)), scores


def compute(source):
    with open_record(source/'packets.json') as stream:
        packets = json.load(stream)
    with open_record(source/'split_manifest.csv', newline='') as stream:
        manifest = list(csv.DictReader(stream))
    index = {r['case']: r for r in manifest}
    expected = {f'{family}-r{root}-c{context}' for family in MAKERS
                for root in range(4) for context in range(6)}
    if len(packets) != 144 or len(index) != len(manifest) or set(index) != expected:
        raise ValueError('fixed 144-pair manifest coverage')
    if len({r['case'] for r in packets}) != 144 or {r['case'] for r in packets} != expected:
        raise ValueError('fixed packet coverage')
    features, bindings = [], []
    root_keys, context_keys = {'train': set(), 'test': set()}, {'train': set(), 'test': set()}
    for record in packets:
        case, packet = record['case'], record['packet']
        family, root, context = re.fullmatch(r'(.+)-r([0-3])-c([0-5])', case).groups()
        root, context = int(root), int(context)
        split = split_name(root, context)
        raw = {side: packet[side] for side in ('vulnerable', 'patched')}
        for side, program in raw.items():
            validate_program(program)
            if program['family'] != family or program['label'] != side:
                raise ValueError('endpoint declaration mismatch')
        normalized = {side: normalize_program(program) for side, program in raw.items()}
        binding = stable_json(prepare(normalized['vulnerable'], normalized['patched'],
                                      packet['context_domains'])['binding'])
        context_syntax = syntax_features(normalized['vulnerable'])['context-only']
        entry = {'case': case, 'family': family, 'root_variant': str(root), 'wrapper': str(context),
                 'split': split, 'root_binding': binding, 'context_syntax': context_syntax}
        if entry != index[case]:
            raise ValueError('actual normalized root/context manifest mismatch')
        bindings.append(entry)
        root_keys['train' if root < 2 else 'test'].add(binding)
        context_keys['train' if context < 4 else 'test'].add(context_syntax)
        for representation, programs in (('raw', raw), ('normalized', normalized)):
            for program in programs.values():
                features.append({'case': case, 'family': family, 'split': split,
                                 'representation': representation, 'label': program['label'],
                                 'tokens': token_bag(program), 'features': syntax_features(program)})
    if root_keys['train'] & root_keys['test'] or context_keys['train'] & context_keys['test']:
        raise ValueError('root/context overlap')
    models, predictions, scores, family_scores = [], [], [], []
    for representation in ('raw', 'normalized'):
        rows = [r for r in features if r['representation'] == representation]
        train = [r for r in rows if r['split'] == 'train']
        nb = fit(train)
        lookups = {feature: fit_lookup(train, feature)
                   for feature in ('constant', 'context-only', 'repair-syntax')}
        models.append({'representation': representation, 'ordinary-unigram-nb': nb, 'lookups': lookups})
        for split in SPLITS:
            test = [r for r in rows if r['split'] == split]
            for baseline in ('ordinary-unigram-nb', *lookups):
                batch = []
                for row in test:
                    if baseline == 'ordinary-unigram-nb':
                        prediction, log_scores = classify(nb, row['tokens'])
                    else:
                        prediction, log_scores = predict(lookups[baseline], row), {}
                    item = {k: row[k] for k in ('case', 'family', 'split', 'representation', 'label')}
                    item.update(baseline=baseline, prediction=prediction, log_scores=log_scores)
                    predictions.append(item)
                    batch.append(item)
                scores.append({'representation': representation, 'split': split, 'baseline': baseline,
                               'training_endpoints': len(train), 'test_endpoints': len(test),
                               'correct': sum(r['label'] == r['prediction'] for r in batch),
                               'accuracy': sum(r['label'] == r['prediction'] for r in batch)/len(batch)})
                for family in MAKERS:
                    subset = [r for r in batch if r['family'] == family]
                    family_scores.append({'representation': representation, 'split': split,
                                          'baseline': baseline, 'family': family,
                                          'test_endpoints': len(subset),
                                          'correct': sum(r['label'] == r['prediction'] for r in subset),
                                          'confusion': dict(Counter(r['label']+'->'+r['prediction'] for r in subset))})
    sources = {name: hashlib.sha256((source/name).read_bytes()).hexdigest()
               for name in ('packets.json.gz', 'split_manifest.csv.gz')}
    summary = {'protocol': PROTOCOL, 'source_sha256': sources, 'pairs': len(packets),
               'split_pairs': dict(Counter(r['split'] for r in bindings)),
               'train_root_bindings': len(root_keys['train']), 'test_root_bindings': len(root_keys['test']),
               'root_binding_overlap': 0, 'context_syntax_overlap': 0,
               'feature_rows': len(features), 'prediction_rows': len(predictions), 'scores': scores,
               'classifier_endpoint_executions': 0, 'native_executions': 0}
    return {'summary': summary, 'models': models, 'features': features,
            'predictions': predictions, 'family_scores': family_scores, 'split_manifest': bindings}


def run(source, output):
    result = compute(source)
    # Fresh output prevents replacing historical evidence or a previous run.
    output.mkdir(parents=True, exist_ok=False)
    for name, value in result.items():
        (output/(name+'.json')).write_text(json.dumps(value, indent=2, sort_keys=True)+'\n', encoding='utf-8')
    environment = {'python': platform.python_version(), 'implementation': platform.python_implementation(),
                   'os': platform.platform(), 'scope': 'syntax extraction/fitting/prediction; no semantic replay'}
    (output/'environment.json').write_text(json.dumps(environment, indent=2)+'\n', encoding='utf-8')
    return result['summary']


def check(source, output):
    expected = compute(source)
    for name, value in expected.items():
        stored = json.loads((output/(name+'.json')).read_text(encoding='utf-8'))
        if stored != value:
            raise ValueError('ordinary syntax evidence mismatch: '+name)
    return {'status': 'consistent', 'pairs': 144, 'prediction_rows': len(expected['predictions']),
            'native_executions': 0, 'semantic_replay': False}
