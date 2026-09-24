import copy
import inspect
import unittest

from rcsc.checker import _check_pair_for_testing, check_pair
from rcsc.generate import MAKERS, generate_corpus, make_bounds, make_divide
from rcsc.leakage import perfect_witness_search, rows_from_pairs
from rcsc.model import stable_json
from rcsc.repair import check_repair_membership, nuisance_surface
from rcsc.surface_experiment import run_surface_campaign


class RepairRelationTests(unittest.TestCase):
    def test_each_declared_repair_family_is_checked_directly(self):
        for index, (family, maker) in enumerate(MAKERS.items()):
            vulnerable, patched, certificate = maker(f"repair-{family}", 900 + index)
            reason, derivation = check_repair_membership(
                vulnerable, patched, certificate["declared_repair"]
            )
            self.assertIsNone(reason, (family, derivation))
            self.assertEqual(derivation["repair"], certificate["declared_repair"])

        # Each guard relation accepts only direction-reversed spellings of the
        # same protected-operand predicate, not an unrelated but well-typed
        # comparison.  These checks make the operand binding explicit for all
        # four guard families rather than relying on corpus-level acceptance.
        guard_cases = {
            "bounds_write": (
                {
                    "op": "and",
                    "left": {"op": "le", "left": {"const": 0}, "right": {"var": "idx"}},
                    "right": {"op": "gt", "left": {"const": 4}, "right": {"var": "idx"}},
                },
                {
                    "op": "and",
                    "left": {"op": "ge", "left": {"var": "value"}, "right": {"const": 0}},
                    "right": {"op": "lt", "left": {"var": "value"}, "right": {"const": 4}},
                },
            ),
            "divide_zero": (
                {"op": "ne", "left": {"const": 0}, "right": {"var": "denominator"}},
                {"op": "ne", "left": {"var": "numerator"}, "right": {"const": 0}},
            ),
            "fixed_overflow": (
                {
                    "op": "ge",
                    "left": {"op": "sub", "left": {"const": 63}, "right": {"var": "delta"}},
                    "right": {"var": "x"},
                },
                {
                    "op": "le",
                    "left": {"var": "x"},
                    "right": {"op": "sub", "left": {"const": 63}, "right": {"var": "x"}},
                },
            ),
            "access_control": (
                {"op": "eq", "left": {"public": "owner"}, "right": {"var": "sender"}},
                {"op": "eq", "left": {"var": "sender"}, "right": {"public": "setting"}},
            ),
        }
        # Seeds fix the bounds length at four and the unsigned overflow width
        # at six (high endpoint 63), matching the concrete predicates above.
        guard_seeds = {"bounds_write": 902, "divide_zero": 900, "fixed_overflow": 903, "access_control": 900}
        for family, (reversed_predicate, unrelated_predicate) in guard_cases.items():
            maker = MAKERS[family]
            vulnerable, patched, certificate = maker(f"guard-binding-{family}", guard_seeds[family])
            guard = next(inst for inst in patched["instructions"] if inst["op"] == "guard")

            guard["pred"] = reversed_predicate
            reason, derivation = check_repair_membership(
                vulnerable, patched, certificate["declared_repair"]
            )
            self.assertIsNone(reason, (family, derivation))
            self.assertTrue(check_pair(vulnerable, patched, certificate).accepted, family)

            guard["pred"] = unrelated_predicate
            reason, derivation = check_repair_membership(
                vulnerable, patched, certificate["declared_repair"]
            )
            self.assertEqual(reason, "root-repair-mismatch", family)
            self.assertEqual(derivation["kind"], "guard-predicate-binding", family)


    def test_domain_discharged_bound_requires_unchanged_input(self):
        vulnerable, patched, certificate = make_bounds("domain-discharge", 0)
        for endpoint in (vulnerable, patched):
            endpoint["input_domains"]["idx"] = [0, 1]
            endpoint["instructions"].insert(
                2,
                {"op": "assign", "role": "root", "dst": "idx", "expr": {"const": -1}},
            )
        guard = next(inst for inst in patched["instructions"] if inst["op"] == "guard")
        guard["pred"] = {
            "op": "lt", "left": {"var": "idx"}, "right": {"const": 2}
        }
        reason, details = check_repair_membership(
            vulnerable, patched, certificate["declared_repair"]
        )
        self.assertEqual(reason, "root-repair-mismatch")
        self.assertEqual(details["kind"], "guard-predicate-binding")

    def test_repair_declaration_and_edit_are_both_bound(self):
        vulnerable, patched, certificate = make_bounds("repair-binding", 901)
        wrong = copy.deepcopy(certificate)
        wrong["declared_repair"] = "effects-before-interaction"
        self.assertEqual(
            check_pair(vulnerable, patched, wrong).reason,
            "certificate-repair-mismatch",
        )

        patched = copy.deepcopy(patched)
        patched["context"]["shape"] = 999
        self.assertEqual(
            check_pair(vulnerable, patched, certificate).reason,
            "context-leakage",
        )

    def test_nuisance_surface_is_the_same_for_both_endpoints_by_construction(self):
        for pair in generate_corpus(per_family=2, include_public=False):
            surface = nuisance_surface(
                pair["vulnerable"], pair["patched"], pair["certificate"]["declared_repair"]
            )
            self.assertEqual(surface["normalized_instructions"], pair["vulnerable"]["instructions"])
            self.assertNotIn("label", surface)
            self.assertNotIn("program_id", surface)

    def test_surface_normalization_is_explicitly_pair_conditioned(self):
        import tempfile
        from pathlib import Path

        pairs = generate_corpus(per_family=1, include_public=False)
        with tempfile.TemporaryDirectory() as directory:
            summary = run_surface_campaign(Path(directory), pairs)
        self.assertFalse(summary["normalization_is_endpoint_local"])
        self.assertEqual(
            summary["normalization_scope"],
            "pair-conditioned quotient after validated repair erasure",
        )
        self.assertEqual(summary["optimal_deterministic_surface_only_accuracy"], 0.5)
        self.assertEqual(summary["declared_root_polarity_accuracy"], 1.0)

    def test_production_checker_has_no_ablation_switches(self):
        self.assertEqual(
            list(inspect.signature(check_pair).parameters),
            ["vulnerable", "patched", "certificate"],
        )

    def test_semantic_diagnostic_is_independent_of_domain_order(self):
        vulnerable, patched, certificate = make_bounds("diagnostic-order", 902)
        patched = copy.deepcopy(vulnerable)
        patched["program_id"] = "diagnostic-order-patched"
        patched["label"] = "patched"
        reports = []
        for reverse in (False, True):
            left = copy.deepcopy(vulnerable)
            right = copy.deepcopy(patched)
            if reverse:
                for program in (left, right):
                    program["input_domains"]["idx"].reverse()
                    program["input_domains"]["value"].reverse()
            reports.append(
                _check_pair_for_testing(
                    left, right, certificate, require_repair=False, require_safe=False
                )
            )
        self.assertEqual([report.reason for report in reports], ["patched-still-vulnerable"] * 2)
        self.assertEqual(
            stable_json(reports[0].witness["input"]),
            stable_json(reports[1].witness["input"]),
        )


    def test_semantically_equivalent_but_undeclared_guard_is_rejected(self):
        vulnerable, patched, certificate = make_divide("undeclared-equivalent", 0)
        guard = next(inst for inst in patched["instructions"] if inst["op"] == "guard")
        guard["pred"] = {
            "op": "not",
            "arg": {"op": "eq", "left": {"var": "denominator"}, "right": {"const": 0}},
        }
        weak = _check_pair_for_testing(
            vulnerable, patched, certificate, require_repair=False, require_safe=False
        )
        strong = check_pair(vulnerable, patched, certificate)
        self.assertTrue(weak.accepted)
        self.assertFalse(strong.accepted)
        self.assertEqual(strong.reason, "root-repair-mismatch")
        self.assertEqual(strong.witness["kind"], "guard-predicate-binding")

    def test_full_feature_universe_is_exhausted_for_clean_pairs(self):
        rows = rows_from_pairs(generate_corpus(per_family=1, include_public=False))
        witness, examined, limit = perfect_witness_search(rows)
        self.assertIsNone(witness)
        self.assertEqual(limit, 14)
        self.assertEqual(examined, 2**14 - 1)


if __name__ == "__main__":
    unittest.main()
