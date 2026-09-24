"""Audit reference annotations; never treat an annotated constructor as a source port."""
from pathlib import Path
import csv
import json


def audit_references(output: Path) -> dict:
    inputs = Path(__file__).resolve().parents[1] / 'external_inputs'
    facts = json.loads((inputs / 'reference_facts.json').read_text())
    by_url = {fact['url']: fact for fact in facts}
    rows = []
    for annotation in csv.DictReader((inputs/'reference_annotations.csv').open()):
        fact = by_url[annotation['url']]
        status = ('suite-not-instance' if fact['kind'] == 'suite-description'
                  else 'unsupported-operator' if fact['operation'] == 'modulo'
                  else 'pattern-reference-only')
        rows.append({'examined_annotation': annotation['examined_annotation'],
                     'record': fact['record'], 'family': annotation['family'],
                     'reference_kind': fact['kind'], 'source_language': fact['source_language'],
                     'operation': fact['operation'], 'status': status,
                     'source_equivalence_established': False})
    output.mkdir(parents=True, exist_ok=True)
    with (output/'provenance_audit.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader(); writer.writerows(rows)
    result = {'reference_tagged_pairs': len(rows), 'distinct_reference_anchors': len(facts),
              'individual_case_descriptions': sum(f['kind'] == 'individual-case-description' for f in facts),
              'category_descriptions': sum(f['kind'] == 'category-description' for f in facts),
              'suite_descriptions': sum(f['kind'] == 'suite-description' for f in facts),
              'pattern_reference_rows': sum(r['status'] == 'pattern-reference-only' for r in rows),
              'unsupported_operator_rows': sum(r['status'] == 'unsupported-operator' for r in rows),
              'suite_not_instance_rows': sum(r['status'] == 'suite-not-instance' for r in rows),
              'source_equivalent_pairs': 0,
              'limitation': 'Descriptions support pattern attribution only; generated programs remain synthetic.'}
    (output/'provenance_summary.json').write_text(json.dumps(result, indent=2)+'\n')
    return result
