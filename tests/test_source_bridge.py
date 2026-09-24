from __future__ import annotations

import ast
import copy
from pathlib import Path
import unittest

from rcsc.checker import execute as checker_execute
from rcsc.producer import run as producer_execute
from rcsc.reference_semantics import execute as immutable_execute
from rcsc.source_bridge import check_source_pair, compare_source_to_ir
from rcsc.source_cases import SOURCE_MAKERS, generate_source_corpus, make_source_pair
from rcsc.source_compile import parse_and_compile
from rcsc.source_reference import decode, encode, enumerate_inputs, execute
from rcsc.source_syntax import Expr, SourceSyntaxError, parse_source


class SourceBridgeTests(unittest.TestCase):
    def test_all_six_source_families_accept(self):
        for family in SOURCE_MAKERS:
            pair = make_source_pair(family, 0)
            report = check_source_pair(
                pair["vulnerable_source"],
                pair["patched_source"],
                pair["vulnerable"],
                pair["patched"],
                pair["source_certificate"],
                pair["certificate"],
            )
            self.assertTrue(report.accepted, (family, report.to_json()))
            self.assertEqual(report.semantic_mismatches, 0)
            self.assertEqual(report.operational_mismatches, 0)
            self.assertEqual(
                report.source_ir_comparisons,
                3 * report.endpoint_valuations,
            )

    def test_complete_source_selection_accepts(self):
        corpus = generate_source_corpus()
        self.assertEqual(len(corpus), 60)
        for pair in corpus:
            report = check_source_pair(
                pair["vulnerable_source"], pair["patched_source"],
                pair["vulnerable"], pair["patched"],
                pair["source_certificate"], pair["certificate"],
            )
            self.assertTrue(report.accepted, (pair["pair_id"], report.to_json()))

    def test_source_certificate_binds_family_profile_language_and_endpoints(self):
        pair = make_source_pair("bounds_write", 0)
        cases = [
            ("declared_family", "divide_zero", "source-certificate-family-mismatch"),
            ("declared_profile", "solidity", "source-certificate-profile-mismatch"),
            ("source_language", "other", "source-certificate-language-mismatch"),
            ("patched_program_id", "other-patched", "source-certificate-pair-mismatch"),
        ]
        for field, value, expected in cases:
            certificate = copy.deepcopy(pair["source_certificate"])
            certificate[field] = value
            report = check_source_pair(
                pair["vulnerable_source"], pair["patched_source"],
                pair["vulnerable"], pair["patched"], certificate, pair["certificate"],
            )
            self.assertEqual(report.reason, expected)

    def test_source_certificate_schema_is_exact(self):
        pair = make_source_pair("divide_zero", 0)
        certificate = copy.deepcopy(pair["source_certificate"])
        certificate["extra"] = True
        report = check_source_pair(
            pair["vulnerable_source"], pair["patched_source"],
            pair["vulnerable"], pair["patched"], certificate, pair["certificate"],
        )
        self.assertEqual(report.reason, "source-certificate-schema-error")

    def test_supplied_ir_must_equal_fresh_translation(self):
        pair = make_source_pair("fixed_overflow", 0)
        patched = copy.deepcopy(pair["patched"])
        patched["context"]["shape"] = 99
        report = check_source_pair(
            pair["vulnerable_source"], pair["patched_source"],
            pair["vulnerable"], patched,
            pair["source_certificate"], pair["certificate"],
        )
        self.assertEqual(report.reason, "source-ir-mismatch")

    def test_supplied_ir_admission_rejects_malformed_cycle_and_excess_depth(self):
        pair = make_source_pair("bounds_write", 0)

        malformed = {"schema": "rcsc-program"}
        cycle = copy.deepcopy(pair["vulnerable"])
        cycle["context"]["cycle"] = cycle
        overdeep = copy.deepcopy(pair["patched"])
        nested = 0
        for _ in range(48):
            nested = [nested]
        overdeep["context"]["shape"] = nested

        cases = (
            ("vulnerable", malformed, pair["patched"]),
            ("vulnerable", cycle, pair["patched"]),
            ("patched", pair["vulnerable"], overdeep),
        )
        for expected_side, vulnerable, patched in cases:
            report = check_source_pair(
                pair["vulnerable_source"], pair["patched_source"],
                vulnerable, patched,
                pair["source_certificate"], pair["certificate"],
            )
            self.assertFalse(report.accepted)
            self.assertEqual(report.reason, "source-ir-admission-error")
            self.assertEqual(report.details["side"], expected_side)
            self.assertIn(report.details["error_type"], {"SchemaError", "ValueError"})
            self.assertTrue(report.details["error"])

    def test_relation_failure_is_not_hidden_by_source_binding(self):
        pair = make_source_pair("unchecked_call", 0)
        text = pair["patched_source"].replace(
            "root: check_call();\n", "root: check_call();\nroot: nop \"extra-root\";\n"
        )
        _, patched = parse_and_compile(text)
        report = check_source_pair(
            pair["vulnerable_source"], text,
            pair["vulnerable"], patched,
            pair["source_certificate"], pair["certificate"],
        )
        self.assertEqual(report.reason, "source-pair-rejected")
        self.assertEqual(report.pair_reason, "root-repair-mismatch")

    def test_pair_certificate_remains_a_separate_claim_layer(self):
        pair = make_source_pair("access_control", 0)
        certificate = copy.deepcopy(pair["certificate"])
        source, _ = parse_and_compile(pair["vulnerable_source"])
        safe = next(inputs for inputs in enumerate_inputs(source) if execute(source, inputs).violation is None)
        certificate["witness_input"] = safe
        report = check_source_pair(
            pair["vulnerable_source"], pair["patched_source"],
            pair["vulnerable"], pair["patched"],
            pair["source_certificate"], certificate,
        )
        self.assertEqual(report.reason, "source-pair-rejected")
        self.assertEqual(report.pair_reason, "contradictory-witness")

    def test_source_parser_rejects_duplicate_and_late_declarations(self):
        pair = make_source_pair("bounds_write", 0)
        duplicate = pair["vulnerable_source"].replace("label vulnerable;", "label vulnerable;\nlabel vulnerable;")
        with self.assertRaises(SourceSyntaxError):
            parse_source(duplicate)
        late = pair["vulnerable_source"].replace(
            "context: return state.buffer;",
            "context: return state.buffer;\ncontext extra = 1;",
        )
        with self.assertRaises(SourceSyntaxError):
            parse_source(late)

    def test_source_parser_rejects_floats_unknown_statements_and_bad_widths(self):
        pair = make_source_pair("bounds_write", 0)
        with self.assertRaises(SourceSyntaxError):
            parse_source(pair["vulnerable_source"].replace("context shape = 1;", "context shape = 1.5;"))
        with self.assertRaises(SourceSyntaxError):
            parse_source(pair["vulnerable_source"].replace("root: buffer[idx] = value;", "root: launch(value);"))
        overflow = make_source_pair("fixed_overflow", 0)["vulnerable_source"]
        with self.assertRaises(SourceSyntaxError):
            parse_source(overflow.replace("add_fixed(x, delta, 6, signed)", "add_fixed(x, delta, zero, signed)"))
        tagged_nop = next(line for line in pair["vulnerable_source"].splitlines() if line.startswith("context: nop \"shape-"))
        overlong_utf8 = pair["vulnerable_source"].replace(
            tagged_nop, 'context: nop "' + ("é" * 5000) + '";'
        )
        with self.assertRaises(SourceSyntaxError):
            parse_source(overlong_utf8)

    def test_source_checker_returns_structured_dynamic_execution_error(self):
        pair = make_source_pair("divide_zero", 0)

        def insert_error(text):
            lines = text.splitlines()
            index = next(i for i, line in enumerate(lines) if line.startswith(("context:", "root:")))
            lines.insert(index, 'context: let source_type_error = "text" + 1;')
            return "\n".join(lines) + "\n"

        vulnerable_source = insert_error(pair["vulnerable_source"])
        patched_source = insert_error(pair["patched_source"])
        _, vulnerable = parse_and_compile(vulnerable_source)
        _, patched = parse_and_compile(patched_source)
        report = check_source_pair(
            vulnerable_source, patched_source, vulnerable, patched,
            pair["source_certificate"], pair["certificate"],
        )
        self.assertFalse(report.accepted)
        self.assertEqual(report.reason, "source-execution-error")
        self.assertEqual(report.details["side"], "vulnerable")
        self.assertEqual(report.details["error"]["layer"], "source")

    def test_source_parser_rejects_reserved_literal_identifiers(self):
        pair = make_source_pair("bounds_write", 0)
        for reserved in ("true", "false", "null"):
            malformed = pair["vulnerable_source"].replace(
                "input idx = [-1,0,4,5];", f"input {reserved} = [-1,0,4,5];"
            )
            with self.assertRaises(SourceSyntaxError):
                parse_source(malformed)

    def test_source_observations_are_typed_snapshots(self):
        text = """rcsc-source 1;
program snapshot-vulnerable;
profile c;
family bounds_write;
label vulnerable;
input idx = [0];
input value = [9];
state buffer = [0];
project buffer;
context: emit("before", state.buffer);
root: buffer[idx] = value;
context: return true == 1;
"""
        source, _ = parse_and_compile(text)
        result = execute(source, {"idx": 0, "value": 9})
        self.assertEqual(decode(result.events[0][1]), [0])
        self.assertEqual(decode(result.public_state[0][1]), [9])
        self.assertIs(decode(result.returned), False)

    def test_expression_and_optional_statement_forms_match_all_ir_interpreters(self):
        expressions = [
            "-5", "!0", "1 + 2", "5 - 8", "3 * 4", "true == 1",
            "true != 1", "1 < 2", "2 <= 2", "3 > 2", "3 >= 3",
            "0 || 4", "1 && 0", "state.value", '"capsule"', "null",
            "-(-3)", "!(1 == 2) && (4 >= 4)",
        ]

        def production_key(result):
            return (
                result.violation,
                result.aborted,
                encode(result.returned),
                tuple((name, encode(value)) for name, value in result.events),
                tuple((name, encode(value)) for name, value in result.public_state),
                result.steps,
                result.trace,
            )

        programs = []
        for index, expression in enumerate(expressions):
            programs.append(
                f"""rcsc-source 1;
program expression-{index}-vulnerable;
profile c;
family divide_zero;
label vulnerable;
input dummy = [0];
state value = 7;
project value;
root: nop;
context: let out = {expression};
context: emit(\"out\", out);
context: return out;
"""
            )
        programs.append(
            """rcsc-source 1;
program optional-forms-vulnerable;
profile c;
family divide_zero;
label vulnerable;
input dummy = [0];
state value = 7;
project value;
root: nop;
context: emit(\"empty\");
context: return;
"""
        )

        for text in programs:
            source, compiled = parse_and_compile(text)
            source_result = execute(source, {"dummy": 0})
            expected = source_result.operational_key()
            self.assertEqual(production_key(producer_execute(compiled, {"dummy": 0})), expected)
            self.assertEqual(production_key(checker_execute(compiled, {"dummy": 0})), expected)
            self.assertEqual(immutable_execute(compiled, {"dummy": 0}).operational_key(), expected)

    def test_semantic_comparator_detects_behavioral_translation_drift(self):
        pair = make_source_pair("divide_zero", 0)
        source, compiled = parse_and_compile(pair["vulnerable_source"])
        mutated = copy.deepcopy(compiled)
        instruction = next(item for item in mutated["instructions"] if item["op"] == "divide")
        instruction["denominator"] = {"const": 1}
        comparison = compare_source_to_ir(source, mutated)
        self.assertGreater(len(comparison["semantic_mismatches"]), 0)

    def test_source_reference_does_not_import_ir_or_checker_modules(self):
        path = Path(__file__).resolve().parents[1] / "rcsc" / "source_reference.py"
        tree = ast.parse(path.read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
        forbidden = {"rcsc.model", "rcsc.checker", "rcsc.producer", "rcsc.source_compile", "rcsc.repair", "rcsc.generate"}
        self.assertTrue(forbidden.isdisjoint(imported), imported)

    def test_source_statement_and_expression_coverage(self):
        corpus = generate_source_corpus()
        instructions = set()
        expressions = set()
        forms = set()
        source_expressions = set()
        source_forms = set()
        source_literals = set()
        signed_modes = set()

        def visit(expr):
            if isinstance(expr, dict):
                if set(expr) == {"const"}:
                    forms.add("const")
                elif set(expr) == {"var"}:
                    forms.add("var")
                elif set(expr) == {"public"}:
                    forms.add("public")
                elif expr.get("op") == "not":
                    expressions.add("not")
                    visit(expr["arg"])
                elif "op" in expr:
                    expressions.add(expr["op"])
                    visit(expr["left"])
                    visit(expr["right"])

        def visit_source(expr):
            source_forms.add(expr.kind)
            if expr.kind == "literal":
                source_literals.add("null" if expr.value is None else type(expr.value).__name__)
            elif expr.kind in {"unary", "binary"}:
                source_expressions.add(expr.value)
            if expr.left is not None:
                visit_source(expr.left)
            if expr.right is not None:
                visit_source(expr.right)

        for pair in corpus:
            for side in ("vulnerable", "patched"):
                for instruction in pair[side]["instructions"]:
                    instructions.add(instruction["op"])
                    if instruction["op"] == "add_fixed":
                        signed_modes.add(instruction["signed"])
                    for key in ("expr", "pred", "index", "value", "numerator", "denominator", "left", "right", "amount", "set"):
                        if key in instruction:
                            visit(instruction[key])
                source = parse_source(pair[side + "_source"])
                for statement in source.statements:
                    for argument in statement.args:
                        if isinstance(argument, Expr):
                            visit_source(argument)
        self.assertEqual(
            instructions,
            {"nop", "assign", "guard", "branch_abort", "buf_write", "divide", "add_fixed", "protected_store", "external_call", "update_balance", "low_call", "check_call", "commit_after_call", "emit", "return"},
        )
        self.assertEqual(expressions, {"add", "sub", "mul", "eq", "ne", "lt", "le", "gt", "ge", "and", "or", "not"})
        self.assertEqual(forms, {"const", "var", "public"})
        self.assertEqual(
            source_expressions,
            {"add", "sub", "mul", "eq", "ne", "lt", "le", "gt", "ge", "and", "or", "not", "neg"},
        )
        self.assertEqual(source_forms, {"literal", "variable", "state", "unary", "binary"})
        self.assertEqual(source_literals, {"null", "bool", "int", "str"})
        self.assertEqual(signed_modes, {False, True})


if __name__ == "__main__":
    unittest.main()
