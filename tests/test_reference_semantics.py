import ast
from pathlib import Path
import unittest

from rcsc.checker import execute
from rcsc.generate import MAKERS
from rcsc.model import enumerate_inputs
from rcsc.producer import run
from rcsc.reference_semantics import encode, execute as reference_execute
from rcsc.transform import preserving_variants


def implementation_key(result):
    return (
        result.violation,
        result.aborted,
        encode(result.returned),
        tuple((name, encode(value)) for name, value in result.events),
        tuple((name, encode(value)) for name, value in result.public_state),
        result.steps,
        result.trace,
    )


class ReferenceSemanticsTests(unittest.TestCase):
    def test_reference_module_has_no_project_imports(self):
        path = Path(__file__).resolve().parents[1] / "rcsc" / "reference_semantics.py"
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                self.assertEqual(node.level, 0, node.module)
                self.assertIn(node.module, {"__future__", "dataclasses", "typing"})
            elif isinstance(node, ast.Import):
                self.fail(f"unexpected import in reference semantics: {node.names}")

    def test_reference_semantics_matches_all_families_and_preserving_edits(self):
        for index, (family, maker) in enumerate(MAKERS.items()):
            vulnerable, patched, _ = maker(f"reference-{family}", 1200 + index)
            programs = [vulnerable, patched]
            programs.extend(target for target, _ in preserving_variants(vulnerable))
            programs.extend(target for target, _ in preserving_variants(patched))
            for program in programs:
                for inputs in enumerate_inputs(program):
                    expected = reference_execute(program, inputs).operational_key()
                    for evaluator in (run, execute):
                        self.assertEqual(
                            implementation_key(evaluator(program, inputs)),
                            expected,
                            (program["program_id"], inputs, evaluator.__module__),
                        )

    def test_reference_values_distinguish_types_and_snapshot_state(self):
        self.assertNotEqual(encode(1), encode(True))
        self.assertNotEqual(encode([1]), encode({"0": 1}))
        vulnerable, _, _ = MAKERS["bounds_write"]("reference-snapshot", 0)
        vulnerable["instructions"] = [
            {"op": "emit", "role": "context", "name": "before", "value": {"public": "buffer"}},
            {"op": "buf_write", "role": "root", "buffer": "buffer", "index": {"var": "idx"}, "value": {"var": "value"}},
            {"op": "return", "role": "context", "value": {"public": "buffer"}},
        ]
        result = reference_execute(vulnerable, {"idx": 0, "value": 1})
        self.assertEqual(result.to_json()["events"][0][1], [0, 0])
        self.assertEqual(result.to_json()["public_state"][0][1], [1, 0])


if __name__ == "__main__":
    unittest.main()
