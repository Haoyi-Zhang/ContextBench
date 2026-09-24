"""Closed order/type grammar with an immutable reference transition system.

The oracle and fixture constructor use no project semantic, schema, or generator
helpers. The evaluation harness imports the implementations only at comparison
sites. All instructions denote owned finite-state examples, not native programs.
"""
from __future__ import annotations

import copy
import csv
from itertools import permutations, product
import json
from pathlib import Path
import time
from typing import Any

INPUTS = tuple({'idx': i, 'value': v} for i, v in product((-1, 0, 1, 2), (0, 1)))


def cases():
    number = 0
    for mode in ('same-type', 'distinct-types'):
        for vulnerable_order in permutations('WST'):
            for patched_order in permutations('GWST'):
                number += 1
                yield {'case_id': f'observation-{number:03d}', 'mode': mode,
                       'vulnerable_order': ''.join(vulnerable_order),
                       'patched_order': ''.join(patched_order)}


def pair_from_case(case: dict[str, Any]) -> dict[str, Any]:
    """Translate the complete tiny grammar into the declared input format."""
    instructions = {
        'W': {'op': 'buf_write', 'role': 'root', 'buffer': 'buffer',
              'index': {'var': 'idx'}, 'value': {'var': 'value'}},
        'G': {'op': 'guard', 'role': 'root', 'pred': {
            'op': 'and', 'left': {'op': 'le', 'left': {'const': 0}, 'right': {'var': 'idx'}},
            'right': {'op': 'lt', 'left': {'var': 'idx'}, 'right': {'const': 2}}}},
        'S': {'op': 'emit', 'role': 'context', 'name': 'snapshot', 'value': {'public': 'buffer'}},
        'T': {'op': 'emit', 'role': 'root', 'name': 'tag', 'value': {'const': 1}},
    }
    out = {'pair_id': case['case_id'], 'family': 'bounds_write', 'grammar': case}
    for side in ('vulnerable', 'patched'):
        sequence = [copy.deepcopy(instructions[x]) for x in case[side + '_order']]
        if side == 'patched' and case['mode'] == 'distinct-types':
            next(i for i in sequence if i['op'] == 'emit' and i['name'] == 'tag')['value'] = {'const': True}
        sequence.append({'op': 'return', 'role': 'context', 'value': {'const': 0}})
        out[side] = {'schema': 'rcsc-program', 'program_id': case['case_id'] + '-' + side,
                     'profile': 'c', 'family': 'bounds_write', 'label': side,
                     'parameters': {'length': 2},
                     'input_domains': {'idx': [-1, 0, 1, 2], 'value': [0, 1]},
                     'context': {'grammar': 'write-snapshot-tag'},
                     'initial_public_state': {'buffer': [0, 0]},
                     'public_projection': ['buffer'], 'instructions': sequence}
    out['certificate'] = {'schema': 'rcsc-pair-certificate', 'pair_id': case['case_id'],
                          'vulnerable_id': out['vulnerable']['program_id'],
                          'patched_id': out['patched']['program_id'],
                          'declared_family': 'bounds_write', 'declared_repair': 'insert-root-guard', 'witness_input': {'idx': -1, 'value': 0}}
    return out


def reference(order: str, inputs: dict[str, int], tag: int | bool) -> dict[str, Any]:
    """An immutable-state transition relation over four tokens, not an AST evaluator."""
    state = (0, 0)
    events = ()
    violation = None
    aborted = False
    returned = None
    for token in order:
        if token == 'G':
            if inputs['idx'] not in (0, 1):
                aborted = True
                break
        elif token == 'W':
            if inputs['idx'] not in (0, 1):
                violation = 'OOB_WRITE'
                break
            state = tuple(inputs['value'] if i == inputs['idx'] else state[i] for i in (0, 1))
        elif token == 'S':
            events = events + (('snapshot', state),)
        elif token == 'T':
            events = events + (('tag', tag),)
        else:
            raise ValueError('token outside the frozen grammar')
    else:
        returned = 0
    return {'violation': violation, 'aborted': aborted, 'returned': returned,
            'events': [[name, list(value) if type(value) is tuple else value] for name, value in events],
            'public_state': [['buffer', list(state)]]}


def canonical(result: Any) -> str:
    # JSON independently distinguishes integer, boolean, object and array types.
    return json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False)


def observation(result: dict[str, Any], alias: bool = False) -> dict[str, Any]:
    out = {key: copy.deepcopy(value) for key, value in result.items() if key != 'violation'}
    if alias:
        for event in out['events']:
            if event[0] == 'snapshot':
                event[1] = copy.deepcopy(result['public_state'][0][1])
    return out


def relation(case: dict[str, Any], *, alias: bool = False, untyped: bool = False):
    found = False
    first = None
    for inputs in INPUTS:
        a = reference(case['vulnerable_order'], inputs, 1)
        b = reference(case['patched_order'], inputs, True if case['mode'] == 'distinct-types' else 1)
        if a['violation']:
            found = True
        if b['violation']:
            return False, {'input': inputs, 'clause': 'patched-root', 'vulnerable': a, 'patched': b}
        if not a['violation']:
            x, y = observation(a, alias), observation(b, alias)
            equal = (x == y) if untyped else (canonical(x) == canonical(y))
            if not equal and first is None:
                first = {'input': inputs, 'clause': 'safe-observation', 'vulnerable': a, 'patched': b}
    return found and first is None, first


def run_observation_campaign(output: Path, *, limit: int | None = None) -> dict[str, Any]:
    from .checker import _check_pair_for_testing, execute
    from .producer import run
    started = time.perf_counter()
    cpu = time.process_time()
    output.mkdir(parents=True, exist_ok=True)
    rows, corpus, counterexamples = [], [], {}
    endpoint_comparisons = 0
    semantic_mismatches = []
    for index, case in enumerate(cases()):
        if limit is not None and index >= limit:
            break
        pair = pair_from_case(case)
        expected, witness = relation(case)
        report = _check_pair_for_testing(pair['vulnerable'], pair['patched'], pair['certificate'], require_repair=False, require_safe=False)
        faults = {}
        for name, alias, untyped in (
            ('alias-only', True, False), ('untyped-only', False, True), ('combined', True, True)):
            faults[name] = relation(case, alias=alias, untyped=untyped)[0]
            if faults[name] and not expected and name not in counterexamples:
                counterexamples[name] = {'case_id': case['case_id'], 'witness': witness,
                                          'faulty_accepted': True, 'expected_accepted': False}
        for side in ('vulnerable', 'patched'):
            tag = True if side == 'patched' and case['mode'] == 'distinct-types' else 1
            for inputs in INPUTS:
                oracle = reference(case[side + '_order'], inputs, tag)
                for name, evaluator in (('direct', run), ('postfix', execute)):
                    actual = evaluator(pair[side], inputs).to_json()
                    projected = {key: actual[key] for key in oracle}
                    endpoint_comparisons += 1
                    if canonical(oracle) != canonical(projected):
                        semantic_mismatches.append({'case_id': case['case_id'], 'side': side,
                                                    'interpreter': name, 'input': inputs,
                                                    'expected': oracle, 'actual': projected})
        rows.append({'case_id': case['case_id'], 'mode': case['mode'],
                     'vulnerable_order': case['vulnerable_order'], 'patched_order': case['patched_order'],
                     'oracle_accepted': expected, 'checker_accepted': report.accepted,
                     'checker_reason': report.reason, 'obligations': report.obligations,
                     'alias_accepted': faults['alias-only'], 'untyped_accepted': faults['untyped-only'],
                     'combined_accepted': faults['combined']})
        corpus.append(pair)
    with (output / 'observation_results.csv').open('w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]) if rows else [])
        writer.writeheader()
        writer.writerows(rows)
    (output / 'observation_corpus.json').write_text(json.dumps(corpus, indent=2) + '\n')
    (output / 'observation_counterexamples.json').write_text(json.dumps(counterexamples, indent=2) + '\n')
    summary = {'pairs': len(rows), 'oracle_accepted': sum(row['oracle_accepted'] for row in rows),
               'oracle_rejected': sum(not row['oracle_accepted'] for row in rows),
               'checker_disagreements': sum(row['oracle_accepted'] != row['checker_accepted'] for row in rows),
               'endpoint_valuations': len(rows) * 16, 'interpreter_comparisons': endpoint_comparisons,
               'interpreter_mismatches': len(semantic_mismatches),
               'pair_check_obligations': sum(row['obligations'] for row in rows),
               'false_acceptances': {name: sum(row[name + '_accepted'] and not row['oracle_accepted'] for row in rows)
                                     for name in ('alias', 'untyped', 'combined')},
               'cpu_seconds': time.process_time() - cpu, 'wall_seconds': time.perf_counter() - started}
    (output / 'observation_mismatches.json').write_text(json.dumps(semantic_mismatches, indent=2) + '\n')
    (output / 'observation_summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    return summary
