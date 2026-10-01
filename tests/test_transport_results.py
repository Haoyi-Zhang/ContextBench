"""Retained evidence must fail closed on miscounted scientific claims."""
import csv
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


    def test_retained_median_must_come_from_three_raw_trials(self):
        with tempfile.TemporaryDirectory() as temp:
            dest=Path(temp)
            for path in (ROOT/"results").glob("transport_*"):
                shutil.copyfile(path,dest/path.name)
            path=dest/"transport_scaling.csv"
            with path.open(newline="") as stream:
                rows=list(csv.DictReader(stream))
            rows[0]["verification_ms"]=str(float(rows[0]["verification_ms"])+1.0)
            with path.open("w",newline="") as stream:
                writer=csv.DictWriter(stream,fieldnames=list(rows[0]))
                writer.writeheader();writer.writerows(rows)
            with self.assertRaisesRegex(ValueError,"transport median"):
                check(dest)

    def test_scope_control_cannot_be_promoted_to_independent_contract_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            dest=Path(temp)
            for path in (ROOT/"results").glob("transport_*"):
                shutil.copyfile(path,dest/path.name)
            path=dest/"transport_oracle_scope_controls.csv"
            with path.open(newline="") as stream:
                rows=list(csv.DictReader(stream))
            rows[0]["repair_check_independent"]="True"
            with path.open("w",newline="") as stream:
                writer=csv.DictWriter(stream,fieldnames=list(rows[0]))
                writer.writeheader();writer.writerows(rows)
            with self.assertRaisesRegex(ValueError,"scope classification"):
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
