"""Public-description predicate abstractions, not C/Solidity source translations.

Only the supplied selected facts are consumed. All concrete widths, states and
input domains below are declared abstraction choices. No native source is read.
"""
from __future__ import annotations
import copy
import csv
import json
from pathlib import Path
from typing import Any

from .checker import check_pair, execute
from .producer import run
from .model import enumerate_inputs
from .repair import expected_repair


def _var(name):
    return {'var': name}


def _literal(value):
    return {'const': value}


def _binary(op, left, right):
    return {'op': op, 'left': left, 'right': right}


def select(record: dict) -> tuple[str | None, str]:
    if record['kind'] == 'suite-description':
        return None, 'suite-not-instance'
    if record['kind'] not in {'individual-case-description', 'category-description'}:
        return None, 'unsupported-description-kind'
    operation = record['operation']
    families = {'indexed-write': 'bounds_write', 'division': 'divide_zero',
                'increment': 'fixed_overflow', 'add-one': 'fixed_overflow',
                'authorization': 'access_control', 'callback-order': 'reentrancy',
                'call-status': 'unchecked_call'}
    if operation not in families:
        return None, 'unsupported-operator'
    family = families[operation]
    if record['family'] != family:
        return None, 'inconsistent-description'
    return family, 'selected-predicate-abstraction'


def map_description(record: dict) -> tuple[dict | None, str]:
    family, status = select(record)
    if family is None:
        return None, status
    pid = 'description-' + record['record'].lower()
    params = {'abstraction': record['operation'], 'source_record': record['record']}
    if family == 'bounds_write':
        domains = {'idx': [0, 9, 10, 11], 'value': [0, 1]}
        state = {'buffer': [0] * 10}
        root = [{'op': 'buf_write', 'role': 'root', 'buffer': 'buffer',
                 'index': _var('idx'), 'value': _var('value')}]
        guard = _binary('lt', _var('idx'), _literal(10))
        repair = [{'op': 'guard', 'role': 'root', 'pred': guard}] + root
        witness = {'idx': 10, 'value': 0}
        params['length'] = 10
    elif family == 'divide_zero':
        domains = {'denominator': [-1, 0, 1, 2]}
        state = {'audit': 0}
        root = [{'op': 'divide', 'role': 'root', 'dst': 'result',
                 'numerator': _literal(12), 'denominator': _var('denominator')}]
        repair = [{'op': 'guard', 'role': 'root', 'pred':
                   _binary('ne', _var('denominator'), _literal(0))}] + root
        witness = {'denominator': 0}
        params['numerator'] = 12
    elif family == 'fixed_overflow':
        domains = {'x': [-8, 0, 6, 7]}
        state = {'audit': 0}
        root = [{'op': 'add_fixed', 'role': 'root', 'dst': 'result',
                 'left': _var('x'), 'right': _literal(1), 'width': 4, 'signed': True}]
        repair = [{'op': 'guard', 'role': 'root', 'pred':
                   _binary('le', _var('x'), _literal(6))}] + root
        witness = {'x': 7}
        params.update(width=4, signed=True, increment=1)
    elif family == 'access_control':
        domains = {'sender': ['owner', 'other']}
        state = {'owner': 'owner', 'effect': 0}
        root = [{'op': 'protected_store', 'role': 'root', 'owner_key': 'owner',
                 'key': 'effect', 'value': _literal(1)}]
        repair = [{'op': 'guard', 'role': 'root', 'pred':
                   _binary('eq', _var('sender'), {'public': 'owner'})}] + root
        witness = {'sender': 'other'}
    elif family == 'reentrancy':
        domains = {'sender': ['member'], 'reenter': [False, True]}
        state = {'balances': {'member': 4}}
        call = {'op': 'external_call', 'role': 'root', 'account_var': 'sender',
                'balances_key': 'balances', 'amount': _literal(4)}
        clear = {'op': 'update_balance', 'role': 'root', 'account_var': 'sender',
                 'balances_key': 'balances', 'set': _literal(0)}
        root, repair = [call, clear], [clear, call]
        witness = {'sender': 'member', 'reenter': True}
        params['full_withdrawal_amount'] = 4
    else:
        domains = {'call_ok': [False, True]}
        state = {'effect': 0}
        call = {'op': 'low_call', 'role': 'root', 'success_var': 'call_ok'}
        commit = {'op': 'commit_after_call', 'role': 'root', 'key': 'effect', 'value': _literal(1)}
        root = [call, commit]
        repair = [call, {'op': 'check_call', 'role': 'root'}, commit]
        witness = {'call_ok': False}
    result = _var('result') if family in {'divide_zero', 'fixed_overflow'} else _literal(0)
    finish = [{'op': 'emit', 'role': 'context', 'name': 'effect', 'value': result},
              {'op': 'return', 'role': 'context', 'value': result}]
    common = {'schema': 'rcsc-program', 'profile': 'c' if family in {
               'bounds_write', 'divide_zero', 'fixed_overflow'} else 'solidity',
              'family': family, 'parameters': params, 'input_domains': domains,
              'context': {'source_record': record['record'], 'source_kind': record['kind'],
                          'scope': 'declared description predicate; not native source semantics'},
              'initial_public_state': state, 'public_projection': sorted(state)}
    vulnerable = copy.deepcopy(common)
    vulnerable.update(program_id=pid+'-vulnerable', label='vulnerable', instructions=copy.deepcopy(root+finish))
    patched = copy.deepcopy(common)
    patched.update(program_id=pid+'-patched', label='patched', instructions=copy.deepcopy(repair+finish))
    certificate = {'schema': 'rcsc-pair-certificate', 'pair_id': pid,
                   'vulnerable_id': vulnerable['program_id'], 'patched_id': patched['program_id'],
                   'declared_family': family, 'declared_repair': expected_repair(family), 'witness_input': witness}
    return {'pair_id': pid, 'family': family, 'profile': common['profile'],
            'source_kind': 'public-description-abstraction', 'record': record['record'],
            'vulnerable': vulnerable, 'patched': patched, 'certificate': certificate}, status


def description_oracle(record: dict, patched: bool, inputs: dict) -> dict[str, Any]:
    """Closed-form predicate oracle: no instruction evaluation or shared observers."""
    op = record['operation']
    violation = None
    aborted = False
    value = 0
    if op == 'indexed-write':
        buffer = (0,) * 10
        bad = inputs['idx'] >= 10
        if not bad:
            index = inputs['idx']
            buffer = buffer[:index] + (inputs['value'],) + buffer[index+1:]
        state = [('buffer', list(buffer))]
        symbol = 'OOB_WRITE'
    elif op == 'division':
        bad = inputs['denominator'] == 0
        if not bad:
            # Declared denominators are -1, 1 and 2: exact signed integer quotients.
            value = {-1: -12, 1: 12, 2: 6}[inputs['denominator']]
        state = [('audit', 0)]
        symbol = 'DIVIDE_BY_ZERO'
    elif op in {'increment', 'add-one'}:
        bad = inputs['x'] == 7
        if not bad:
            value = inputs['x'] + 1
        state = [('audit', 0)]
        symbol = 'INTEGER_OVERFLOW'
    elif op == 'authorization':
        bad = inputs['sender'] != 'owner'
        state = [('effect', 0 if bad else 1), ('owner', 'owner')]
        symbol = 'UNAUTHORIZED_WRITE'
    elif op == 'callback-order':
        bad = inputs['reenter']
        state = [('balances', {'member': 0 if patched or not bad else 4})]
        symbol = 'REENTRANT_WITHDRAWAL'
    elif op == 'call-status':
        bad = not inputs['call_ok']
        state = [('effect', 0 if bad else 1)]
        symbol = 'UNCHECKED_CALL_FAILURE'
    else:
        raise ValueError('no oracle outside selected description predicates')
    if bad and not patched:
        violation = symbol
    elif bad and patched and op != 'callback-order':
        aborted = True
    complete = violation is None and not aborted
    return {'violation': violation, 'aborted': aborted,
            'returned': value if complete else None,
            'events': [('effect', value)] if complete else [], 'public_state': state}


def _actual(result):
    return {'violation': result.violation, 'aborted': result.aborted,
            'returned': result.returned, 'events': result.events, 'public_state': result.public_state}


def run_description_campaign(output: Path, pilot: bool = False) -> tuple[dict, list[dict]]:
    facts_path = Path(__file__).resolve().parents[1]/'external_inputs/reference_facts.json'
    records = json.loads(facts_path.read_text())
    if pilot:
        names = {'NIST-SARD-62684', 'NIST-SARD-95487', 'SWC-107', 'NIST-SARD-95045'}
        records = [r for r in records if r['record'] in names]
    selections, decisions, semantics, controls, corpus = [], [], [], [], []
    for record in records:
        pair, reason = map_description(record)
        selections.append({'record': record['record'], 'mapped': pair is not None, 'reason': reason})
        if pair is None:
            continue
        corpus.append(pair)
        report = check_pair(pair['vulnerable'], pair['patched'], pair['certificate'])
        decisions.append({'record': record['record'], 'accepted': report.accepted,
                          'reason': report.reason, 'obligations': report.obligations})
        for endpoint in ('vulnerable', 'patched'):
            program = pair[endpoint]
            for inputs in enumerate_inputs(program):
                expected = description_oracle(record, endpoint == 'patched', inputs)
                for name, evaluator in [('producer', run), ('checker', execute)]:
                    actual = _actual(evaluator(program, inputs))
                    semantics.append({'record': record['record'], 'endpoint': endpoint,
                        'input': json.dumps(inputs, sort_keys=True), 'evaluator': name,
                        'expected': json.dumps(expected, sort_keys=True),
                        'actual': json.dumps(actual, sort_keys=True),
                        'matched': json.dumps(expected, sort_keys=True) == json.dumps(actual, sort_keys=True)})
        unclosed = copy.deepcopy(pair['vulnerable'])
        unclosed['program_id'] = pair['patched']['program_id']; unclosed['label'] = 'patched'
        negative = check_pair(pair['vulnerable'], unclosed, pair['certificate'])
        controls.append({'record': record['record'], 'accepted': negative.accepted,
                         'reason': negative.reason,
                         'detected': not negative.accepted and negative.reason == 'root-repair-mismatch'})
    output.mkdir(parents=True, exist_ok=True)
    for filename, rows in [('description_selection.csv', selections), ('description_pair_results.csv', decisions),
                           ('description_semantics.csv', semantics), ('description_controls.csv', controls)]:
        with (output/filename).open('w', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
    summary = {'descriptions': len(records), 'mapped_pairs': len(corpus), 'excluded_descriptions': len(records)-len(corpus),
               'accepted_pairs': sum(r['accepted'] for r in decisions), 'semantic_comparisons': len(semantics),
               'semantic_mismatches': sum(not r['matched'] for r in semantics),
               'repair_removal_controls': len(controls), 'detected_controls': sum(r['detected'] for r in controls),
               'source_equivalent_programs': 0, 'scope': 'declared predicate abstraction of public descriptions'}
    (output/'description_summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    (output/'description_corpus.json').write_text(json.dumps(corpus,indent=2)+'\n')
    return summary, corpus
