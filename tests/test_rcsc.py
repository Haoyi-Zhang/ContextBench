import copy
import unittest

from rcsc.checker import check_pair, execute
from rcsc.boundary_cases import make_pre_root_abort_safe_pair
from rcsc.direct_audit import audit_pair
from rcsc.generate import generate_corpus
from rcsc.leakage import contaminate, minimal_perfect_witness, rows_from_pairs
from rcsc.model import SchemaError, enumerate_inputs
from rcsc.producer import run
from rcsc.transform import (
    check_transform,
    flip_certificate,
    preserve_alpha_unused,
    preserve_swap_independent,
    preserving_variants,
)


class RCSCTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pairs = generate_corpus(per_family=2, include_public=True)

    def _pair(self, family, offset=0):
        return [pair for pair in self.pairs if pair["family"] == family][offset]

    def test_all_clean_pairs_accept(self):
        for pair in self.pairs:
            report = check_pair(pair["vulnerable"], pair["patched"], pair["certificate"])
            self.assertTrue(report.accepted, (pair["pair_id"], report.reason))
            self.assertGreater(report.productive_safe_inputs, 0, pair["pair_id"])

    def test_producer_checker_agree(self):
        for pair in self.pairs:
            for side in ("vulnerable", "patched"):
                for inputs in enumerate_inputs(pair[side]):
                    self.assertEqual(run(pair[side], inputs).semantic(), execute(pair[side], inputs).semantic())

    def test_preserving_transforms(self):
        for target, certificate in preserving_variants(self.pairs[0]["patched"]):
            self.assertTrue(check_transform(self.pairs[0]["patched"], target, certificate).accepted)

    def test_flipping_transforms(self):
        for pair in self.pairs:
            for source, target, kind in (
                (pair["vulnerable"], pair["patched"], "close-root"),
                (pair["patched"], pair["vulnerable"], "open-root"),
            ):
                report = check_transform(source, target, flip_certificate(source, target, kind))
                self.assertTrue(report.accepted, (pair["pair_id"], kind, report.reason))

    def test_flipping_transform_rejects_extra_root_edit_in_both_directions(self):
        pair = self._pair("bounds_write")
        cases = []

        bad_patched = copy.deepcopy(pair["patched"])
        bad_patched["instructions"].append({"op": "nop", "role": "root"})
        cases.append((pair["vulnerable"], bad_patched, "close-root"))

        bad_vulnerable = copy.deepcopy(pair["vulnerable"])
        bad_vulnerable["instructions"].append({"op": "nop", "role": "root"})
        cases.append((pair["patched"], bad_vulnerable, "open-root"))

        for source, target, kind in cases:
            report = check_transform(source, target, flip_certificate(source, target, kind))
            self.assertFalse(report.accepted, kind)
            self.assertEqual(report.reason, "root-repair-mismatch", kind)

    def test_flipping_transform_rejects_undeclared_equivalent_guard_in_both_directions(self):
        pair = self._pair("divide_zero")
        patched = copy.deepcopy(pair["patched"])
        guard = next(
            instruction
            for instruction in patched["instructions"]
            if instruction["op"] == "guard" and instruction["role"] == "root"
        )
        guard["pred"] = {
            "op": "not",
            "arg": {
                "op": "eq",
                "left": {"var": "denominator"},
                "right": {"const": 0},
            },
        }
        for source, target, kind in (
            (pair["vulnerable"], patched, "close-root"),
            (patched, pair["vulnerable"], "open-root"),
        ):
            report = check_transform(source, target, flip_certificate(source, target, kind))
            self.assertFalse(report.accepted, kind)
            self.assertEqual(report.reason, "root-repair-mismatch", kind)

    def test_flipping_transform_requires_a_nonempty_safe_partition_in_both_directions(self):
        pair = self._pair("bounds_write")
        vulnerable = copy.deepcopy(pair["vulnerable"])
        patched = copy.deepcopy(pair["patched"])
        upper = len(vulnerable["initial_public_state"]["buffer"])
        for endpoint in (vulnerable, patched):
            endpoint["input_domains"]["idx"] = [-1, upper]

        for source, target, kind in (
            (vulnerable, patched, "close-root"),
            (patched, vulnerable, "open-root"),
        ):
            report = check_transform(source, target, flip_certificate(source, target, kind))
            self.assertFalse(report.accepted, kind)
            self.assertEqual(report.reason, "missing-safe-input", kind)

    def test_flipping_transform_requires_productive_safe_root_execution(self):
        vulnerable, patched, _ = make_pre_root_abort_safe_pair(
            "flip-productive-safe"
        )
        for source, target, kind in (
            (vulnerable, patched, "close-root"),
            (patched, vulnerable, "open-root"),
        ):
            report = check_transform(
                source, target, flip_certificate(source, target, kind)
            )
            self.assertFalse(report.accepted, kind)
            self.assertEqual(report.reason, "missing-productive-safe-input", kind)
            self.assertEqual(report.details["safe_inputs"], 1)
            self.assertEqual(report.details["productive_safe_inputs"], 0)


    def test_flipping_transform_diagnostic_is_independent_of_domain_order(self):
        pair = self._pair("bounds_write")
        patched = copy.deepcopy(pair["patched"])
        guard = next(inst for inst in patched["instructions"] if inst["op"] == "guard")
        guard["pred"] = {
            "op": "and",
            "left": guard["pred"],
            "right": {"op": "eq", "left": {"var": "idx"}, "right": {"const": 0}},
        }
        reports = []
        for reverse in (False, True):
            vulnerable_case = copy.deepcopy(pair["vulnerable"])
            patched_case = copy.deepcopy(patched)
            if reverse:
                for endpoint in (vulnerable_case, patched_case):
                    endpoint["input_domains"]["idx"].reverse()
                    endpoint["input_domains"]["value"].reverse()
            reports.append(
                check_transform(
                    vulnerable_case,
                    patched_case,
                    flip_certificate(vulnerable_case, patched_case, "close-root"),
                )
            )
        self.assertEqual(
            [report.reason for report in reports], ["flip-changes-safe-observation"] * 2
        )
        self.assertEqual(reports[0].witness["input"], reports[1].witness["input"])

    def test_preserving_transform_diagnostic_is_independent_of_domain_order(self):
        reports = []
        for reverse in (False, True):
            source = copy.deepcopy(self._pair("bounds_write")["patched"])
            source["input_domains"]["value"] = [True, 0]
            if reverse:
                source["input_domains"]["value"].reverse()
                source["input_domains"]["idx"].reverse()
            source["instructions"][0]["expr"] = {
                "op": "add",
                "left": {"var": "value"},
                "right": {"const": 0},
            }
            target, certificate = next(
                (target, certificate)
                for target, certificate in preserving_variants(source)
                if certificate["transform"] == "root-stutter"
            )
            reports.append(check_transform(source, target, certificate))
        self.assertEqual([report.reason for report in reports], ["execution-error"] * 2)
        self.assertEqual(reports[0].witness["input"], reports[1].witness["input"])

    def test_context_leak_rejected(self):
        pair = contaminate([self.pairs[0]], "label-token")[0]
        report = check_pair(pair["vulnerable"], pair["patched"], pair["certificate"])
        self.assertFalse(report.accepted)
        self.assertEqual(report.reason, "context-leakage")

    def test_exact_two_feature_witness(self):
        rows = rows_from_pairs(contaminate(self.pairs, "mixed-two-feature"))
        witness = minimal_perfect_witness(rows, 3)
        self.assertEqual(witness["size"], 2)
        self.assertEqual(witness["features"], ["label_hint", "source_partition"])

    def test_bad_witness_rejected(self):
        pair = self.pairs[1]
        certificate = copy.deepcopy(pair["certificate"])
        certificate["witness_input"] = next(
            inputs
            for inputs in enumerate_inputs(pair["vulnerable"])
            if run(pair["vulnerable"], inputs).violation is None
        )
        self.assertEqual(
            check_pair(pair["vulnerable"], pair["patched"], certificate).reason,
            "contradictory-witness",
        )

    def test_witness_must_belong_to_declared_domain(self):
        pair = self.pairs[0]
        certificate = copy.deepcopy(pair["certificate"])
        certificate["witness_input"]["undeclared"] = 0
        self.assertEqual(
            check_pair(pair["vulnerable"], pair["patched"], certificate).reason,
            "certificate-witness-out-of-domain",
        )

    def test_pair_certificate_binds_both_endpoints(self):
        pair = self._pair("bounds_write", 0)
        other = self._pair("bounds_write", 1)
        self.assertEqual(
            check_pair(pair["vulnerable"], pair["patched"], other["certificate"]).reason,
            "certificate-pair-mismatch",
        )

    def test_relation_audit_ignores_identifiers_but_certificate_binding_does_not(self):
        pair = self._pair("bounds_write")
        vulnerable = copy.deepcopy(pair["vulnerable"])
        patched = copy.deepcopy(pair["patched"])
        certificate = copy.deepcopy(pair["certificate"])
        vulnerable["program_id"] = "renamed-left"
        patched["program_id"] = "renamed-right"
        certificate["vulnerable_id"] = vulnerable["program_id"]
        certificate["patched_id"] = patched["program_id"]

        self.assertTrue(audit_pair(vulnerable, patched)["accepted"])
        self.assertEqual(
            check_pair(vulnerable, patched, certificate).reason,
            "certificate-pair-mismatch",
        )

    def test_pair_certificate_schema_is_exact(self):
        pair = self.pairs[0]
        certificate = copy.deepcopy(pair["certificate"])
        certificate["schema"] = "unknown"
        self.assertEqual(
            check_pair(pair["vulnerable"], pair["patched"], certificate).reason,
            "certificate-schema-error",
        )

    def test_malformed_program_is_rejected_not_executed(self):
        pair = self.pairs[0]
        patched = copy.deepcopy(pair["patched"])
        guard = next(instruction for instruction in patched["instructions"] if instruction["op"] == "guard")
        del guard["pred"]
        self.assertEqual(
            check_pair(pair["vulnerable"], patched, pair["certificate"]).reason,
            "schema-error",
        )

    def test_malformed_transform_target_rejected(self):
        source = self.pairs[0]["vulnerable"]
        target, certificate = preserving_variants(source)[0]
        target["instructions"].append({"op": "nop", "role": "root"})
        self.assertEqual(check_transform(source, target, certificate).reason, "invalid-transformation")

    def test_transform_certificate_metadata_is_checked(self):
        source = self.pairs[0]["vulnerable"]
        target, certificate = preserving_variants(source)[0]
        certificate["site"] += 1
        self.assertEqual(
            check_transform(source, target, certificate).reason,
            "certificate-derivation-mismatch",
        )

    def test_transform_membership_preconditions_are_enforced(self):
        source = copy.deepcopy(self.pairs[0]["vulnerable"])
        source["instructions"][0], source["instructions"][1] = (
            source["instructions"][1],
            source["instructions"][0],
        )
        with self.assertRaises(ValueError):
            preserve_swap_independent(source)

        source = copy.deepcopy(self.pairs[0]["vulnerable"])
        source["instructions"].insert(
            2,
            {"op": "emit", "name": "aux", "value": {"var": "aux"}, "role": "context"},
        )
        with self.assertRaises(ValueError):
            preserve_alpha_unused(source)

    def test_transform_certificate_schema_is_checked(self):
        source = self.pairs[0]["vulnerable"]
        target, certificate = preserving_variants(source)[0]
        certificate["schema"] = "unknown"
        self.assertEqual(
            check_transform(source, target, certificate).reason,
            "certificate-schema-error",
        )

    def test_void_return_terminates_execution(self):
        program = copy.deepcopy(self.pairs[0]["vulnerable"])
        program["instructions"] = [
            {"op": "return", "role": "context"},
            {"op": "emit", "name": "late", "value": {"const": 1}, "role": "context"},
            {"op": "nop", "role": "root"},
        ]
        inputs = next(enumerate_inputs(program))
        for result in (run(program, inputs), execute(program, inputs)):
            self.assertEqual(result.steps, 1)
            self.assertEqual(result.events, ())
            self.assertIsNone(result.returned)

    def test_integer_division_is_exact_for_large_values(self):
        program = copy.deepcopy(self._pair("divide_zero")["vulnerable"])
        numerator = 10**30 + 1
        program["input_domains"]["numerator"] = [numerator]
        program["input_domains"]["denominator"] = [-3]
        inputs = {"numerator": numerator, "denominator": -3}
        expected = -(numerator // 3)
        self.assertEqual(run(program, inputs).returned, expected)
        self.assertEqual(execute(program, inputs).returned, expected)

    def test_execution_rejects_partial_input(self):
        program = self.pairs[0]["vulnerable"]
        inputs = next(enumerate_inputs(program))
        inputs.pop(next(iter(inputs)))
        with self.assertRaises(SchemaError):
            run(program, inputs)
        with self.assertRaises(SchemaError):
            execute(program, inputs)


if __name__ == "__main__":
    unittest.main()
