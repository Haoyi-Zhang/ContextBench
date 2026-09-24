from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from audit_literature import LiteratureAuditError, audit


ROOT = Path(__file__).resolve().parents[1]


class LiteratureAuditTests(unittest.TestCase):
    def test_inventory_and_calibration_close(self) -> None:
        result = audit(ROOT)
        self.assertEqual(result["status"], "consistent")
        self.assertEqual(result["manuscript_reference_records"], 62)
        self.assertEqual(result["calibration_works"], 72)
        self.assertEqual(result["scholarly_reference_records"], 62)
        self.assertEqual(result["peer_reviewed_reference_records"], 61)
        self.assertEqual(
            result["reference_type_counts"],
            {
                "peer-reviewed publication": 61,
                                "scholarly preprint": 1,
            },
        )
        self.assertEqual(
            result["verification_mode"],
            "offline closure against the recorded bibliographic inventory",
        )
        self.assertEqual(result["live_registry_queries_during_reproduction"], 0)
        self.assertIn("not a live publisher", result["offline_scope"])

    def test_all_inventory_keys_are_calibrated(self) -> None:
        with (ROOT / "bibliography-inventory.csv").open(newline="", encoding="utf-8") as handle:
            inventory = {row["citation_key"] for row in csv.DictReader(handle)}
        with (ROOT / "literature-comparison.csv").open(newline="", encoding="utf-8") as handle:
            matrix = {row["citation_key"] for row in csv.DictReader(handle)}
        self.assertEqual(len(inventory), 62)
        self.assertTrue(inventory <= matrix)

    def test_reference_status_and_current_metadata_are_explicit(self) -> None:
        with (ROOT / "bibliography-inventory.csv").open(newline="", encoding="utf-8") as handle:
            rows = {row["citation_key"]: row for row in csv.DictReader(handle)}
        semantic_trap = rows["huang2026semantictrap"]
        self.assertEqual(
            semantic_trap["title"],
            "Do Fine-Tuned LLMs Understand Vulnerabilities? An Investigation into the Semantic Trap",
        )
        self.assertEqual(semantic_trap["record_type"], "scholarly preprint")
        self.assertEqual(semantic_trap["peer_review_status"], "not peer-reviewed")
        self.assertNotIn("eip1470", rows)
        self.assertEqual(rows["banerjee2016framing"]["verification_date"], "2026-09-21")

    def test_publisher_volume_and_unsupported_pagination_are_guarded(self) -> None:
        bib = ROOT / "manuscript-records" / "references.bib"
        tex = ROOT / "manuscript-records" / "citations.tex"
        source = bib.read_text(encoding="utf-8")
        start = source.index("@inproceedings{lu2021codexglue,")
        end = source.index("\n}", start) + 2
        entry = source[start:end]
        self.assertIn("volume = {1}", entry)
        self.assertNotIn("pages =", entry)
        mutations = [
            (entry.replace("volume = {1}", "volume = {34}"), "volume must be 1"),
            (entry.replace("year = {2021}", "pages = {28958--28972},\n  year = {2021}"), "no verified global page range"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            altered = Path(directory) / "references.bib"
            for replacement, message in mutations:
                altered.write_text(source[:start] + replacement + source[end:], encoding="utf-8")
                with self.subTest(message=message), self.assertRaisesRegex(LiteratureAuditError, message):
                    audit(ROOT, tex_path=tex, bib_path=altered)

    def test_calibration_minima_are_retained(self) -> None:
        result = audit(ROOT)
        roles = result["calibration_role_counts"]
        self.assertGreaterEqual(roles["same-track"], 12)
        self.assertGreaterEqual(roles["distinguished"], 5)
        self.assertGreaterEqual(roles["adjacent"], 5)

    def test_manuscript_bibtex_metadata_matches_verified_inventory(self) -> None:
        tex = ROOT / "manuscript-records" / "citations.tex"
        bib = ROOT / "manuscript-records" / "references.bib"
        result = audit(ROOT)
        cross = result["manuscript_cross_check"]
        self.assertEqual(cross["source"], "bundled manuscript-records snapshot")
        self.assertEqual(cross["unique_citations"], 62)
        self.assertEqual(cross["bib_entries"], 62)
        self.assertEqual(cross["metadata_records_checked"], 62)

        with tempfile.TemporaryDirectory() as directory:
            altered = Path(directory) / "references.bib"
            altered.write_text(
                bib.read_text(encoding="utf-8").replace(
                    "year = {2026}", "year = {2025}", 1
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(LiteratureAuditError, "BibTeX year differs"):
                audit(ROOT, tex_path=tex, bib_path=altered)


if __name__ == "__main__":
    unittest.main()
