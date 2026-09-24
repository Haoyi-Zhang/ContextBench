"""Retained evidence must fail closed on miscounted scientific claims."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from check_transport_results import check

ROOT = Path(__file__).resolve().parents[1]

class ResultClosureTests(unittest.TestCase):
    def test_retained_transport_evidence(self):
        self.assertEqual(check(ROOT/"results")["valid_exclusions"],13)

    def test_valid_exclusion_count_cannot_be_relabelled_attack(self):
        with tempfile.TemporaryDirectory() as temp:
            dest=Path(temp)
            for path in (ROOT/"results").glob("transport_*"):
                shutil.copyfile(path,dest/path.name)
            path=dest/"transport_summary.json"
            data=json.loads(path.read_text());data["valid_outside_fragment"]=12
            path.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError,"valid exclusions"):
                check(dest)

    def test_large_product_cannot_be_counted_as_executed(self):
        with tempfile.TemporaryDirectory() as temp:
            dest=Path(temp)
            for path in (ROOT/"results").glob("transport_*"):
                shutil.copyfile(path,dest/path.name)
            path=dest/"transport_summary.json"
            data=json.loads(path.read_text());data["scaling_direct_endpoint_executions"]+=2**20
            path.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError,"scaling execution summary"):
                check(dest)
