"""Observer, grammar-admission, serialized-input and checker-isolation regressions."""
import ast
import copy
import inspect
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from rcsc.checker import check_pair, execute, _check_pair_for_testing
from rcsc.boundary_cases import make_pre_root_abort_safe_pair
from rcsc.direct_audit import audit_pair
from rcsc.generate import make_bounds, make_overflow
from rcsc.membership import check_preserving_membership
from rcsc.model import (EvaluationLimit, SchemaError, RunResult, ValueBudget,
                        validate_json_tree, validate_program, value_key)
from rcsc.observation_oracle import cases, pair_from_case, reference, canonical
from rcsc.producer import run
from rcsc.transform import check_transform, preserving_variants
from verify import load_packet, verify_packet


class BoundaryTests(unittest.TestCase):
    def test_transform_kind_has_closed_type(self):
        v, p, _ = make_bounds('closed-transform', 0)
        certificate = {'schema': 'rcsc-transform-certificate', 'class': 'root-flipping',
                       'source_id': v['program_id'], 'target_id': p['program_id'],
                       'transform': []}
        report = check_transform(v, p, certificate)
        self.assertFalse(report.accepted)
        self.assertEqual(report.reason, 'unknown-class')

    def test_packet_kind_has_closed_enum(self):
        with self.assertRaises(ValueError):
            verify_packet('unknown', {})

    def test_past_event_is_not_changed_by_later_write(self):
        case = {'case_id': 'snapshot', 'mode': 'same-type',
                'vulnerable_order': 'WST', 'patched_order': 'GSWT'}
        pair = pair_from_case(case)
        for evaluator in (run, execute):
            result = evaluator(pair['patched'], {'idx': 0, 'value': 1})
            self.assertEqual(result.events[0], ('snapshot', [0, 0]))
            self.assertEqual(result.public_state, (('buffer', [1, 0]),))
        self.assertEqual(_check_pair_for_testing(pair['vulnerable'], pair['patched'], pair['certificate'], require_repair=False, require_safe=False).reason,
                         'safe-observation-mismatch')

    def test_type_distinct_event_is_rejected(self):
        case = {'case_id': 'type', 'mode': 'distinct-types',
                'vulnerable_order': 'WST', 'patched_order': 'GWST'}
        pair = pair_from_case(case)
        self.assertEqual(_check_pair_for_testing(pair['vulnerable'], pair['patched'], pair['certificate'], require_repair=False, require_safe=False).reason,
                         'safe-observation-mismatch')

    def test_array_and_object_observations_are_distinct(self):
        a = RunResult(None, False, None, (), (('x', {'a': 1}),), 0, ())
        b = RunResult(None, False, None, (), (('x', [['a', 1]]),), 0, ())
        self.assertNotEqual(a.observation(), b.observation())
        self.assertNotEqual(value_key(1), value_key(True))
        self.assertNotEqual(value_key(0), value_key(False))

    def test_assignment_is_a_value_snapshot(self):
        v, _, _ = make_bounds('assign-copy', 0)
        v['instructions'] = [
            {'op': 'assign', 'role': 'context', 'dst': 'saved', 'expr': {'public': 'buffer'}},
            {'op': 'buf_write', 'role': 'root', 'buffer': 'buffer',
             'index': {'var': 'idx'}, 'value': {'var': 'value'}},
            {'op': 'return', 'role': 'context', 'value': {'var': 'saved'}}]
        for evaluator in (run, execute):
            self.assertEqual(evaluator(v, {'idx': 0, 'value': 1}).returned, [0, 0])

    def test_shared_acyclic_ast_is_admitted(self):
        node = {'const': 1}
        self.assertGreater(validate_json_tree([node, node]), 0)

    def test_shared_initial_state_matches_serialized_tree(self):
        v, _, _ = make_bounds('initial-tree', 0)
        shared = [0, 0]
        v['initial_public_state'] = {'buffer': shared, 'other': shared}
        v['public_projection'] = ['buffer', 'other']
        v['instructions'] = [
            {'op': 'buf_write', 'role': 'root', 'buffer': 'buffer',
             'index': {'var': 'idx'}, 'value': {'var': 'value'}},
            {'op': 'return', 'role': 'context', 'value': {'public': 'other'}}]
        decoded = json.loads(json.dumps(v))
        for evaluator in (run, execute):
            direct = evaluator(v, {'idx': 0, 'value': 1})
            serialized = evaluator(decoded, {'idx': 0, 'value': 1})
            self.assertEqual(direct.returned, [0, 0])
            self.assertEqual(direct.semantic(), serialized.semantic())

    def test_empty_benign_domain_is_rejected_by_nonvacuity_gate(self):
        v, p, c = make_bounds('empty-benign', 0)
        for endpoint in (v, p):
            endpoint['input_domains'] = {'idx': [-1, 2], 'value': [1]}
        c['witness_input'] = {'idx': -1, 'value': 1}
        weak = _check_pair_for_testing(v, p, c, require_repair=False, require_safe=False)
        strong = check_pair(v, p, c)
        self.assertTrue(weak.accepted)
        self.assertFalse(strong.accepted)
        self.assertEqual(strong.reason, 'missing-safe-input')
        self.assertEqual(strong.safe_inputs_compared, 0)

    def test_safe_partition_must_reach_and_complete_the_root(self):
        vulnerable, patched, certificate = make_pre_root_abort_safe_pair(
            "productive-safe"
        )
        weak = _check_pair_for_testing(
            vulnerable,
            patched,
            certificate,
            require_productive_safe=False,
        )
        strong = check_pair(vulnerable, patched, certificate)
        direct = audit_pair(vulnerable, patched)

        self.assertTrue(weak.accepted)
        self.assertEqual(weak.safe_inputs_compared, 1)
        self.assertEqual(weak.productive_safe_inputs, 0)
        self.assertFalse(strong.accepted)
        self.assertEqual(strong.reason, "missing-productive-safe-input")
        self.assertEqual(strong.safe_inputs_compared, 1)
        self.assertEqual(strong.productive_safe_inputs, 0)
        self.assertFalse(direct["accepted"])
        self.assertEqual(direct["reason"], "missing-productive-safe-input")
        self.assertEqual(direct["safe_inputs"], 1)
        self.assertEqual(direct["productive_safe_inputs"], 0)

    def test_root_label_tokens_are_rejected_by_exact_repair_gate(self):
        v, p, c = make_bounds('root-label', 0)
        for endpoint in (v, p):
            endpoint['instructions'].insert(0, {'op': 'nop', 'role': 'root',
                                                'tag': endpoint['label']})
        weak = _check_pair_for_testing(v, p, c, require_repair=False, require_safe=False)
        strong = check_pair(v, p, c)
        self.assertTrue(weak.accepted)
        self.assertFalse(strong.accepted)
        self.assertEqual(strong.reason, 'root-repair-mismatch')
        self.assertNotEqual(v['instructions'][0]['tag'], p['instructions'][0]['tag'])

    def test_account_key_and_balance_types_are_checked(self):
        from rcsc.generate import make_reentrancy
        v, _, _ = make_reentrancy('account-type', 0)
        v['input_domains'] = {'sender': [1], 'reenter': [False]}
        v['instructions'] = [{'op':'update_balance','role':'root','account_var':'sender',
                              'balances_key':'balances','set':{'const':0}}]
        for evaluator in (run, execute):
            with self.assertRaises(TypeError):
                evaluator(v, {'sender':1, 'reenter':False})
        v['input_domains']['sender'] = ['user']
        v['instructions'][0]['set'] = {'const': True}
        for evaluator in (run, execute):
            with self.assertRaises(TypeError):
                evaluator(v, {'sender':'user', 'reenter':False})

    def test_cyclic_json_is_rejected(self):
        cyclic = []
        cyclic.append(cyclic)
        with self.assertRaises(SchemaError):
            validate_json_tree(cyclic)

    def test_deep_json_is_rejected(self):
        value = 0
        for _ in range(42):
            value = [value]
        with self.assertRaises(SchemaError):
            validate_json_tree(value)

    def test_non_json_literals_are_rejected(self):
        for value in (1.0, float('nan'), float('inf'), (1, 2), {1: 2}):
            with self.subTest(value=repr(value)), self.assertRaises(SchemaError):
                validate_json_tree(value)

    def test_literal_and_width_limits_are_enforced(self):
        with self.assertRaises(SchemaError):
            validate_json_tree(2 ** 256)
        v, _, _ = make_overflow('width', 0)
        next(i for i in v['instructions'] if i['op'] == 'add_fixed')['width'] = 257
        with self.assertRaises(SchemaError):
            validate_program(v)

    def test_cartesian_product_is_admitted_before_enumeration(self):
        v, p, c = make_bounds('domain-size', 0)
        for x in (v, p):
            x['input_domains']['idx'] = list(range(4097))
        self.assertEqual(check_pair(v, p, c).reason, 'schema-error')

    def test_value_budget_fails_before_another_copy(self):
        budget = ValueBudget()
        budget.nodes = 500000
        with self.assertRaises(EvaluationLimit):
            budget.charge([0])

    def test_integer_sinks_do_not_coerce_boolean(self):
        v, p, c = make_bounds('sink-type', 0)
        for x in (v, p):
            x['input_domains']['idx'] = [-1, True]
        self.assertEqual(check_pair(v, p, c).reason, 'execution-error')

    def test_profile_specific_operations_are_rejected(self):
        v, p, c = make_bounds('profile', 0)
        for x in (v, p):
            x['profile'] = 'solidity'; x['family'] = 'access_control'
        self.assertEqual(check_pair(v, p, c).reason, 'schema-error')

    def test_production_pair_checker_has_no_bypass_switch(self):
        self.assertEqual(set(inspect.signature(check_pair).parameters),
                         {'vulnerable', 'patched', 'certificate'})
        v, p, c = make_bounds('no-switch', 0)
        with self.assertRaises(TypeError):
            check_pair(v, p, c, skip_observations=True)

    def test_membership_does_not_import_constructors(self):
        path = Path(__file__).resolve().parents[1] / 'rcsc' / 'membership.py'
        tree = ast.parse(path.read_text())
        modules = [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
        self.assertNotIn('transform', modules)
        self.assertNotIn('generate', modules)

    def test_generator_corruption_cannot_authorize_identity(self):
        source, _, _ = make_bounds('bad-generator', 0)
        for target, certificate in preserving_variants(source):
            unchanged = copy.deepcopy(source)
            unchanged['program_id'] = target['program_id']
            self.assertIsNotNone(check_preserving_membership(source, unchanged, certificate))
            self.assertFalse(check_transform(source, unchanged, certificate).accepted)
        target, certificate = preserving_variants(source)[0]
        with patch('rcsc.transform.preserve_root_nop', side_effect=AssertionError('constructor invoked')):
            self.assertTrue(check_transform(source, target, certificate).accepted)

    def test_duplicate_serialized_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'packet.json'
            p.write_text('{"certificate": 1, "certificate": 2}')
            with self.assertRaises(ValueError):
                load_packet(p)

    def test_serialized_float_and_nonfinite_values_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'packet.json'
            for literal in ('1.0', 'NaN', 'Infinity'):
                p.write_text('{"x": ' + literal + '}')
                with self.assertRaises(ValueError):
                    load_packet(p)

    def test_serialized_pair_round_trip(self):
        v, p, c = make_bounds('round-trip', 0)
        packet = {'vulnerable': v, 'patched': p, 'certificate': c}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'packet.json'
            path.write_text(json.dumps(packet))
            self.assertTrue(verify_packet('pair', load_packet(path)).accepted)

    def test_serialized_extra_fields_are_rejected(self):
        v, p, c = make_bounds('extra', 0)
        with self.assertRaises(ValueError):
            verify_packet('pair', {'vulnerable': v, 'patched': p, 'certificate': c, 'skip_context': True})


if __name__ == '__main__':
    unittest.main()
