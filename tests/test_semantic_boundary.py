from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from rcsc.semantic_boundary import run_semantic_boundary_campaign


class SemanticBoundaryMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._temporary = tempfile.TemporaryDirectory()
        cls.summary = run_semantic_boundary_campaign(Path(cls._temporary.name))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temporary.cleanup()

    def test_expression_matrix_is_complete_and_agrees(self) -> None:
        summary = self.summary["expression_matrix"]
        self.assertEqual(summary["cases"], 1596)
        self.assertEqual(summary["typed_values"], 12)
        self.assertEqual(summary["defined_cases"], 651)
        self.assertEqual(summary["error_cases"], 945)
        self.assertEqual(summary["mixed_definedness_cases"], 0)
        self.assertEqual(summary["mismatches"], 0)
        self.assertEqual(
            summary["operators"],
            ["add", "sub", "mul", "eq", "ne", "lt", "le", "gt", "ge", "and", "or", "not"],
        )

    def test_instruction_matrix_is_complete_and_agrees(self) -> None:
        summary = self.summary["instruction_matrix"]
        self.assertEqual(summary["programs"], 20)
        self.assertEqual(summary["valuations"], 1013)
        self.assertEqual(summary["defined_cases"], 588)
        self.assertEqual(summary["error_cases"], 425)
        self.assertEqual(summary["mixed_definedness_cases"], 0)
        self.assertEqual(summary["mismatches"], 0)
        self.assertEqual(len(summary["instruction_operations"]), 15)

    def test_combined_matrix_records_every_evaluation(self) -> None:
        self.assertEqual(self.summary["total_cases"], 2609)
        self.assertEqual(self.summary["total_interpreter_evaluations"], 7827)
        self.assertEqual(self.summary["mismatches"], 0)

    def test_binary_null_operand_is_not_erased_as_unary_absence(self) -> None:
        paths = (Path(self._temporary.name) / "semantic_expression_matrix.csv",
                 Path(__file__).resolve().parents[1] / "results/semantic_expression_matrix.csv")
        for path in paths:
            with path.open(newline="", encoding="utf-8") as stream:
                rows = list(csv.DictReader(stream))
            binary = [row for row in rows if row["operator"] != "not"]
            self.assertTrue(all(row["right"] != "" for row in binary))
            self.assertEqual(sum(json.loads(row["right"]) is None for row in binary), 132)
            self.assertTrue(all(row["right"] == "" for row in rows if row["operator"] == "not"))


if __name__ == "__main__":
    unittest.main()
