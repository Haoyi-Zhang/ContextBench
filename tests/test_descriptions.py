"""Selection and closed-form description checks; no native programs."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from rcsc.descriptions import map_description, run_description_campaign, select

class DescriptionTests(unittest.TestCase):
    def test_full_frozen_selection_and_predicates(self):
        with tempfile.TemporaryDirectory() as directory:
            summary, corpus = run_description_campaign(Path(directory))
            self.assertEqual(summary['descriptions'], 12)
            self.assertEqual(summary['mapped_pairs'], 10)
            self.assertEqual(summary['excluded_descriptions'], 2)
            self.assertEqual(summary['accepted_pairs'], 10)
            self.assertEqual(summary['semantic_comparisons'], 184)
            self.assertEqual(summary['semantic_mismatches'], 0)
            self.assertEqual(summary['detected_controls'], 10)
            self.assertEqual(summary['source_equivalent_programs'], 0)
            self.assertEqual(len(corpus), 10)
    def test_inconsistent_and_unsupported_descriptions_reject(self):
        self.assertEqual(select({'kind':'individual-case-description', 'operation':'division', 'family':'bounds_write'}), (None,'inconsistent-description'))
        self.assertEqual(select({'kind':'individual-case-description', 'operation':'modulo', 'family':'divide_zero'}), (None,'unsupported-operator'))
        self.assertEqual(select({'kind':'suite-description'}), (None,'suite-not-instance'))
        self.assertEqual(select({'kind':'unknown'}), (None,'unsupported-description-kind'))
