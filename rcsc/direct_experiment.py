"""Deterministic semantic-baseline and certificate-only distinction evidence."""
from __future__ import annotations
import csv
import json
import time
from pathlib import Path
from .direct_audit import audit_pair
from .checker import check_pair
from .observation_oracle import cases, pair_from_case


def run_direct_campaign(output: Path, corpus: list[dict], negative_sets: dict,
                        pilot: bool = False) -> dict:
    start = time.process_time()
    rows = []
    grammar = [pair_from_case(c) for c in cases()]
    selected = corpus[:12] if pilot else corpus + grammar
    for pair in selected:
        v, p, c = pair['vulnerable'], pair['patched'], pair['certificate']
        direct = audit_pair(v, p)
        checked = check_pair(v, p, c)
        rows.append({'pair_id': c['pair_id'], 'direct_accept': direct['accepted'],
                     'certificate_accept': checked.accepted,
                     'matched': direct['accepted'] == checked.accepted,
                     'direct_executions': direct['executions'],
                     'direct_safe_inputs': direct.get('safe_inputs', 0),
                     'direct_productive_safe_inputs': direct.get('productive_safe_inputs', 0),
                     'checked_safe_inputs': checked.safe_inputs_compared,
                     'checked_productive_safe_inputs': checked.productive_safe_inputs})
    controls = []
    certificate_only = {'wrong-certificate-family', 'contradictory-witness',
                        'certificate-endpoint-substitution', 'certificate-witness-out-of-domain',
                        'wrong-certificate-repair', 'endpoint-id-convention'}
    if not pilot:
        for family, family_cases in negative_sets.items():
            for name, _, v, p, c in family_cases:
                if name not in certificate_only:
                    continue
                direct, checked = audit_pair(v, p), check_pair(v, p, c)
                controls.append({'family': family, 'case': name,
                                 'direct_accept': direct['accepted'],
                                 'certificate_accept': checked.accepted,
                                 'certificate_reason': checked.reason})
    summary = {'pairs': len(rows), 'direct_accepted': sum(r['direct_accept'] for r in rows),
               'certificate_accepted': sum(r['certificate_accept'] for r in rows),
               'decision_disagreements': sum(not r['matched'] for r in rows),
               'certificate_only_controls': len(controls),
               'valid_pairs_with_rejected_claims': sum(r['direct_accept'] and not r['certificate_accept'] for r in controls),
               'cpu_seconds': time.process_time() - start,
               'independent_semantic_oracle': False}
    output.mkdir(parents=True, exist_ok=True)
    for filename, data in [('direct_audit_results.csv', rows), ('certificate_only_controls.csv', controls)]:
        if data:
            with (output / filename).open('w', newline='') as stream:
                writer = csv.DictWriter(stream, fieldnames=list(data[0]))
                writer.writeheader(); writer.writerows(data)
    (output/'direct_audit_summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    return summary
