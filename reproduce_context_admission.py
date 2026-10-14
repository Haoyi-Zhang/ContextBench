"""Retain owned finite admission/call-accounting inputs and observed calls.

The injected core error is explicitly a unit instrument, not a semantic workload.
Natural arithmetic-error cases are inadmissible relations, not accepted benchmarks.
"""
import argparse
import copy
import json
import platform
from pathlib import Path
from unittest.mock import patch

from rcsc import transport as tr
from rcsc import transport_oracle as oracle
from rcsc.generate import B, C
from rcsc.transport_cases import make_case
from rcsc.transport_contract_gate import relation_preconditions


def run(output):
    base = make_case('divide_zero', dimensions=1)
    inputs, results = [], []
    for name, value in [('int-at-bound', 2**255), ('int-over-bound', 2**256),
                        ('text-at-bound', 'a'*4096), ('text-over-bound', 'a'*4097)]:
        packet = copy.deepcopy(base)
        packet['context_domains']['noise_0'] = [0, value]
        gate, production = relation_preconditions(packet), tr.check_transport(packet)
        expected = name.endswith('at-bound')
        assert gate['preconditions_ok'] == production.accepted == expected
        inputs.append({'case': name, 'packet': packet})
        results.append({'case': name, 'gate': gate, 'production': production.to_json(),
                        'expected_admitted': expected})
    for kind in ('natural-first-error', 'natural-second-error'):
        packet = copy.deepcopy(base)
        if kind == 'natural-first-error':
            for side in ('vulnerable', 'patched'):
                packet[side]['input_domains']['numerator'] = [True]
        else:
            packet['patched']['instructions'].insert(0, {
                'op': 'assign', 'role': 'root', 'dst': 'test_local',
                'expr': B('add', C(True), C(1))})
        calls = []
        actual = oracle.execute
        def counted(program, values, **kw):
            row = {'label': program['label'], 'inputs': copy.deepcopy(values), 'completed': False}
            calls.append(row)
            result = actual(program, values, **kw)
            row['completed'] = True
            return result
        with patch.object(oracle, 'execute', counted):
            result = oracle.direct_oracle(packet, retain=True)
        assert not result['defined'] and not result['semantic_contract_holds']
        assert result['endpoint_execution_attempts'] == len(calls)
        assert result['endpoint_executions'] == sum(c['completed'] for c in calls)
        inputs.append({'case': kind, 'packet': packet})
        results.append({'case': kind, 'gate': relation_preconditions(packet),
                        'observed_calls': calls, 'oracle': result})
    calls = []
    actual = tr.execute
    def injected(program, values):
        calls.append({'label': program['label'], 'inputs': copy.deepcopy(values), 'completed': False})
        if len(calls) == 2:
            raise ValueError('test-only second-call failure')
        result = actual(program, values)
        calls[-1]['completed'] = True
        return result
    with patch.object(tr, 'execute', injected):
        core = tr.audit_transport(base['vulnerable'], base['patched'], base['context_domains'])
    assert not core.accepted and core.core_execution_attempts == 2 and core.core_executions == 1
    inputs.append({'case': 'test-only-core-second-call-injection', 'packet': base,
                   'instrument': 'raise ValueError before the second evaluator call; unit accounting only'})
    results.append({'case': 'test-only-core-second-call-injection', 'observed_calls': calls,
                    'production': core.to_json(), 'scope': 'unit fault injection, not scientific workload'})
    summary = {'domain_cases': 4, 'natural_error_cases': 2, 'unit_injection_cases': 1,
               'native_executions': 0,
               'natural_endpoint_attempts': sum(r['oracle']['endpoint_execution_attempts']
                                               for r in results if 'oracle' in r),
               'natural_endpoint_completions': sum(r['oracle']['endpoint_executions']
                                                  for r in results if 'oracle' in r),
               'scope': 'owned finite scalar admission and undefined-arithmetic accounting; no valid-pair gain'}
    environment = {'python': platform.python_version(), 'os': platform.platform(),
                   'implementation': platform.python_implementation()}
    output.mkdir(parents=True, exist_ok=False)
    for name, value in [('inputs', inputs), ('results', results), ('summary', summary),
                        ('environment', environment)]:
        (output/(name+'.json')).write_text(json.dumps(value, indent=2, sort_keys=True)+'\n', encoding='utf-8')
    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    print(json.dumps(run(parser.parse_args().output), indent=2, sort_keys=True))
