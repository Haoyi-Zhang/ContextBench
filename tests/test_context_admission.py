"""Owned finite schema boundaries and actual attempted/completed call accounting."""
import copy
import unittest
from unittest.mock import patch

from rcsc import transport as tr
from rcsc import transport_oracle as oracle
from rcsc.generate import B, C
from rcsc.transport_cases import make_case
from rcsc.transport_contract_gate import relation_preconditions


class ContextAdmissionTests(unittest.TestCase):
    def packet(self):
        return make_case('divide_zero', dimensions=1)

    def test_expanded_literals_use_existing_source_json_limits(self):
        for value, admitted in [(2**255, True), (2**256, False),
                                ('a'*4096, True), ('a'*4097, False)]:
            packet = self.packet()
            packet['context_domains']['noise_0'] = [0, value]
            with self.subTest(kind=type(value).__name__, admitted=admitted):
                gate = relation_preconditions(packet)
                self.assertEqual(gate['context_domains_ok'], admitted)
                self.assertEqual(gate['preconditions_ok'], admitted)
                self.assertEqual(tr.check_transport(packet).accepted, admitted)

    def test_context_keys_and_nonfinite_values_fail_structurally(self):
        for domains in [{0: [0]}, {'noise_0': [0, float('nan')]},
                        {'noise_0': [0, object()]}]:
            packet = self.packet()
            packet['context_domains'] = domains
            gate = relation_preconditions(packet)
            self.assertFalse(gate['context_domains_ok'])
            self.assertFalse(gate['preconditions_ok'])
            self.assertTrue(gate['diagnostics'])

    def test_boolean_integer_domains_are_distinct_not_duplicates(self):
        packet = self.packet()
        packet['context_domains']['noise_0'] = [0, False]
        self.assertTrue(relation_preconditions(packet)['preconditions_ok'])
        packet['context_domains']['noise_0'] = [False, 1]
        self.assertFalse(relation_preconditions(packet)['context_domains_ok'])

    def test_natural_undefined_execution_counts_each_attempt(self):
        packet = self.packet()
        for side in ('vulnerable', 'patched'):
            packet[side]['input_domains']['numerator'] = [True]
        with patch.object(oracle, 'execute', wraps=oracle.execute) as calls:
            result = oracle.direct_oracle(packet, retain=True)
        self.assertFalse(result['defined'])
        self.assertEqual(result['endpoint_execution_attempts'], calls.call_count)
        self.assertEqual(result['endpoint_executions'], 0)
        self.assertEqual(result['completed_pair_rows'], 0)
        self.assertGreater(calls.call_count, 0)
        self.assertEqual(sum(r['endpoint_execution_attempts'] for r in result['rows']), calls.call_count)

    def test_partial_pair_retains_successful_first_call(self):
        packet = self.packet()
        packet['patched']['instructions'].insert(0, {
            'op': 'assign', 'role': 'root', 'dst': 'test_local',
            'expr': B('add', C(True), C(1))})
        with patch.object(oracle, 'execute', wraps=oracle.execute) as calls:
            result = oracle.direct_oracle(packet, retain=True)
        self.assertFalse(result['defined'])
        self.assertEqual(result['endpoint_execution_attempts'], calls.call_count)
        self.assertEqual(result['endpoint_executions'], len(result['rows']))
        self.assertEqual(calls.call_count, 2*len(result['rows']))
        self.assertEqual(result['completed_pair_rows'], 0)

    def test_reference_attempts_not_fabricated_comparisons(self):
        packet = self.packet()
        with patch.object(oracle, 'reference_execute', side_effect=ValueError('test-only error')) as calls:
            result = oracle.direct_oracle(packet, reference=True, retain=True)
        self.assertFalse(result['defined'])
        self.assertEqual(result['reference_execution_attempts'], calls.call_count)
        self.assertEqual(result['reference_executions'], 0)
        self.assertEqual(result['reference_comparisons'], 0)
        self.assertEqual(result['endpoint_execution_attempts'], result['endpoint_executions'])
        self.assertEqual(result['completed_pair_rows'], len(result['rows']))

    def test_core_accounting_on_test_only_second_call_failure(self):
        packet = self.packet()
        actual = tr.execute
        calls = []
        def failing(program, inputs):
            calls.append(program['label'])
            if len(calls) == 2:
                raise ValueError('test-only second-call error')
            return actual(program, inputs)
        # Production resolves its executor at call time and accounts per call.
        with patch.object(tr, 'execute', failing):
            result = tr.audit_transport(packet['vulnerable'], packet['patched'], packet['context_domains'])
        self.assertFalse(result.accepted)
        self.assertEqual(result.core_execution_attempts, len(calls))
        self.assertEqual(result.core_execution_attempts, 2)
        self.assertEqual(result.core_executions, 1)
        self.assertEqual(result.completed_core_rows, 0)

    def test_accepted_execution_counts_do_not_change(self):
        packet = self.packet()
        result = tr.check_transport(packet)
        direct = oracle.direct_oracle(packet, reference=True, retain=True)
        self.assertTrue(result.accepted)
        self.assertTrue(direct['semantic_contract_holds'])
        self.assertEqual(result.core_execution_attempts, result.core_executions)
        self.assertEqual(result.completed_core_rows, result.core_valuations)
        self.assertEqual(direct['endpoint_execution_attempts'], direct['endpoint_executions'])
        self.assertEqual(direct['reference_execution_attempts'], direct['reference_comparisons'])
        self.assertEqual(direct['reference_executions'], direct['reference_comparisons'])
        self.assertEqual(direct['completed_pair_rows'], len(direct['rows']))
        self.assertEqual(direct['endpoint_executions'], result.represented_endpoint_executions)

    def test_admission_and_execution_leave_packet_unchanged(self):
        packet = self.packet()
        original = copy.deepcopy(packet)
        relation_preconditions(packet)
        tr.check_transport(packet)
        oracle.direct_oracle(packet)
        self.assertEqual(packet, original)
