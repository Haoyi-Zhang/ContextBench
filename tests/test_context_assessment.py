import copy
import unittest
from pathlib import Path
from unittest.mock import patch

from rcsc.context_assessment import (
    CONTEXT_DOMAINS, TRAIN_ROOTS, TEST_ROOTS, TRAIN_CONTEXTS, TEST_CONTEXTS,
    fit_lookup, functional_domain, make_assessment_case, normalization_comparisons,
    normalized_packet, predict, split_name, syntax_features,
)
from rcsc.generate import MAKERS, B, C
from rcsc.model import stable_json
from rcsc.syntax_normalization import normalize_expression, normalize_program
from rcsc.transport import audit_transport, check_transport
from rcsc.transport_cases import make_case
from rcsc.transport_oracle import direct_oracle
from rcsc.transport_contract_gate import relation_preconditions


class SyntaxNormalizationTests(unittest.TestCase):
    def test_endpoint_local_and_idempotent_with_true_labels(self):
        for family in MAKERS:
            packet = make_case(family, dimensions=2)
            for side in ('vulnerable', 'patched'):
                original = copy.deepcopy(packet[side])
                normalized = normalize_program(original)
                self.assertEqual(normalized, normalize_program(normalized))
                self.assertEqual(normalized['label'], side)
                self.assertEqual(original, packet[side])
                self.assertFalse(any(i['op'] == 'nop' for i in normalized['instructions']))
            self.assertGreater(normalization_comparisons(packet, normalized_packet(packet)), 0)

    def test_normalization_preserves_repair_polarity_and_status_order(self):
        for family in MAKERS:
            packet = normalized_packet(make_case(family, dimensions=1))
            self.assertTrue(check_transport(packet).accepted)
            self.assertNotEqual(syntax_features(packet['vulnerable'])['repair-syntax'],
                                syntax_features(packet['patched'])['repair-syntax'])

    def test_equivalent_comparison_spelling_not_type_collapse(self):
        self.assertEqual(normalize_expression(B('ge', C(2), C(1))),
                         normalize_expression(B('le', C(1), C(2))))
        self.assertEqual(normalize_expression(B('eq', C('a'), C(True))),
                         normalize_expression(B('eq', C(True), C('a'))))
        self.assertNotEqual(stable_json(normalize_expression(B('eq', C(1), C(True)))),
                            stable_json(normalize_expression(B('eq', C(1), C(1)))))


class HeldOutAssessmentTests(unittest.TestCase):
    def test_split_is_declared_and_pair_grouped(self):
        self.assertEqual(split_name(0, 0), 'train')
        self.assertEqual(split_name(2, 0), 'held-out-root')
        self.assertEqual(split_name(0, 4), 'held-out-context')
        self.assertEqual(split_name(2, 4), 'held-out-both')
        with self.assertRaises(ValueError):
            split_name(9, 0)

    def test_actual_normalized_roots_and_contexts_are_disjoint(self):
        roots = {'train': set(), 'test': set()}
        contexts = {'train': set(), 'test': set()}
        for family in MAKERS:
            for variant in TRAIN_ROOTS + TEST_ROOTS:
                for wrapper in TRAIN_CONTEXTS + TEST_CONTEXTS:
                    packet = normalized_packet(make_assessment_case(family, variant, wrapper))
                    roots['train' if variant in TRAIN_ROOTS else 'test'].add(
                        stable_json(packet['transport_certificate']['core_binding']))
                    contexts['train' if wrapper in TRAIN_CONTEXTS else 'test'].add(
                        syntax_features(packet['vulnerable'])['context-only'])
        self.assertEqual(len(roots['train']), 12)
        self.assertEqual(len(roots['test']), 12)
        self.assertFalse(roots['train'] & roots['test'])
        self.assertFalse(contexts['train'] & contexts['test'])

    def test_lookup_fits_only_train_and_does_not_refit_for_test_labels(self):
        train = [{'split': 'train', 'label': 'vulnerable', 'features': {'f': 'x'}},
                 {'split': 'train', 'label': 'patched', 'features': {'f': 'y'}}]
        model = fit_lookup(train, 'f')
        test = {'split': 'held-out-both', 'label': 'patched', 'features': {'f': 'x'}}
        self.assertEqual(predict(model, test), 'vulnerable')
        test['label'] = 'vulnerable'
        self.assertEqual(predict(model, test), 'vulnerable')
        with self.assertRaises(ValueError):
            fit_lookup(train + [test], 'f')
        with self.assertRaises(ValueError):
            fit_lookup([], 'f')

    def test_feature_information_excludes_label_id_metadata_and_certificate(self):
        packet = make_assessment_case('divide_zero', 0, 0)
        q = copy.deepcopy(packet['vulnerable'])
        expected = syntax_features(q)
        q['label'] = 'patched'
        q['program_id'] = 'label-bearing-id'
        q['context']['label_hint'] = 'patched'
        self.assertEqual(expected, syntax_features(q))

    def test_mixed_domains_have_54_distinct_observations_and_four_effective_coordinates(self):
        for wrapper in TRAIN_CONTEXTS + TEST_CONTEXTS:
            evidence = functional_domain(make_assessment_case('divide_zero', 0, wrapper))
            self.assertEqual(evidence['reachable_contexts'], 54)
            self.assertEqual(evidence['distinct_typed_observations'], 54)
            self.assertEqual(evidence['effective_coordinates'], 4)
            self.assertEqual(evidence['security_profiles'], 1)
            self.assertTrue(all(w['security_equal'] for w in evidence['coordinate_witnesses']))

    def test_unused_declared_coordinate_does_not_count_as_effective(self):
        packet = make_assessment_case('divide_zero', 0, 0)
        for side in ('vulnerable', 'patched'):
            packet[side]['instructions'] = [i for i in packet[side]['instructions']
                                           if not (i['op'] == 'emit' and i['name'] == 'ctx_token')]
        evidence = functional_domain(packet)
        self.assertEqual(evidence['reachable_contexts'], 54)
        self.assertEqual(evidence['distinct_typed_observations'], 18)
        self.assertEqual(evidence['effective_coordinates'], 3)

    def test_all_six_monitors_match_same_information_factored_baseline_and_reference(self):
        for family in MAKERS:
            raw = make_assessment_case(family, 3, 5)
            normalized = normalized_packet(raw)
            self.assertGreater(normalization_comparisons(raw, normalized), 0)
            for packet in (raw, normalized):
                self.assertTrue(relation_preconditions(packet)['preconditions_ok'])
                check = check_transport(packet)
                audit = audit_transport(packet['vulnerable'], packet['patched'], CONTEXT_DOMAINS)
                oracle = direct_oracle(packet, reference=True)
                self.assertTrue(check.accepted, check)
                self.assertTrue(audit.accepted, audit)
                self.assertEqual(check.core_executions, audit.core_executions)
                self.assertTrue(oracle['semantic_contract_holds'])
                self.assertEqual(oracle['reference_mismatches'], 0)


class AssessmentResultTests(unittest.TestCase):
    def test_retained_result_closes_against_domains_models_and_predictions(self):
        from check_context_assessment import check
        result = check(Path(__file__).resolve().parents[1] / 'results' / 'context_assessment')
        self.assertEqual(result['pairs'], 144)
        self.assertEqual(result['full_endpoint_executions'], 222912)
        self.assertEqual(result['held_out_predictions'], 1152)

    def test_reported_test_scores_cannot_replace_training_only_fit(self):
        from check_context_assessment import check
        with patch('check_context_assessment.fit_lookup', return_value={'cells': {}}):
            with self.assertRaisesRegex(ValueError, 'training-only model'):
                check(Path(__file__).resolve().parents[1] / 'results' / 'context_assessment')


if __name__ == '__main__':
    unittest.main()
