"""Training-only and metadata-isolation regressions, not accuracy targets."""
import copy
import json
import math
from pathlib import Path
import tempfile
import unittest

from rcsc.ordinary_syntax import token_bag, fit, classify, run, check
from rcsc.transport_cases import make_case

ROOT = Path(__file__).resolve().parents[1]


class OrdinarySyntaxTests(unittest.TestCase):
    def training(self):
        return [{'split': 'train', 'label': 'patched', 'tokens': {'a': 2}},
                {'split': 'train', 'label': 'vulnerable', 'tokens': {'b': 2}}]

    def test_model_uses_training_rows_only(self):
        rows = self.training()
        rows[0]['split'] = 'held-out-root'
        with self.assertRaisesRegex(ValueError, 'training'):
            fit(rows)

    def test_laplace_scores_and_lexical_tie(self):
        model = fit(self.training())
        label, scores = classify(model, {'a': 1})
        self.assertEqual(label, 'patched')
        self.assertAlmostEqual(scores['patched'], math.log(.5)+math.log(3/4))
        self.assertAlmostEqual(scores['vulnerable'], math.log(.5)+math.log(1/4))
        self.assertEqual(classify(model, {'unseen-test-token': 100})[0], 'patched')
        self.assertNotIn('unseen-test-token', model['vocabulary'])

    def test_only_instructions_enter_features(self):
        program = make_case('divide_zero', dimensions=1)['vulnerable']
        changed = copy.deepcopy(program)
        for name in ('label', 'program_id', 'family', 'profile', 'parameters', 'context',
                     'input_domains', 'initial_public_state', 'public_projection'):
            changed[name] = {'arbitrary': 'outside-instruction-metadata'}
        self.assertEqual(token_bag(changed), token_bag(program))

    def test_boolean_integer_literals_are_distinct(self):
        self.assertNotEqual(token_bag({'instructions': [{'const': True}]}),
                            token_bag({'instructions': [{'const': 1}]}))

    def test_unigram_order_blindness_is_preserved(self):
        program = make_case('reentrancy', dimensions=1)['vulnerable']
        changed = copy.deepcopy(program)
        changed['instructions'].reverse()
        self.assertEqual(token_bag(program), token_bag(changed))

    def test_complete_evidence_and_mutated_prediction_rejection(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)/'fresh'
            run(ROOT/'results/context_assessment', output)
            self.assertEqual(check(ROOT/'results/context_assessment', output)['prediction_rows'], 1536)
            path = output/'predictions.json'
            rows = json.loads(path.read_text(encoding='utf-8'))
            rows[0]['prediction'] = 'vulnerable' if rows[0]['prediction'] == 'patched' else 'patched'
            path.write_text(json.dumps(rows), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'predictions'):
                check(ROOT/'results/context_assessment', output)

    def test_runner_never_overwrites_an_existing_output(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(FileExistsError):
                run(ROOT/'results/context_assessment', Path(temp))
