"""Syntactic transformation membership, independent of transformation constructors.

This module never imports the constructor module. It checks an edit relation
between two supplied instruction sequences and the exact derivation fields.
Semantic preservation remains a separate exhaustive obligation.
"""
from __future__ import annotations

from typing import Any, Mapping
from .model import stable_json


def _equal(a: Any, b: Any) -> bool:
    return stable_json(a) == stable_json(b)


def _reads(instruction: Mapping[str, Any], name: str) -> bool:
    """Iterative expression scan, including the language's implicit variable reads."""
    work = [instruction[field] for field in (
        'expr', 'pred', 'index', 'value', 'numerator', 'denominator',
        'left', 'right', 'amount', 'set') if field in instruction]
    while work:
        node = work.pop()
        if type(node) is not dict:
            continue
        if set(node) == {'var'}:
            if node['var'] == name:
                return True
        elif set(node) not in ({'const'}, {'public'}):
            work.extend(node[key] for key in ('left', 'right', 'arg') if key in node)
    return (instruction.get('account_var') == name
            or instruction.get('success_var') == name
            or (instruction['op'] == 'protected_store' and name == 'sender')
            or (instruction['op'] == 'external_call' and name == 'reenter'))


def check_preserving_membership(source: Mapping[str, Any], target: Mapping[str, Any],
                                certificate: Mapping[str, Any]) -> str | None:
    """Return None exactly on the specified catalogue relation; otherwise a reason.

    The caller first validates both programs and the certificate's JSON shape.
    This function does not execute code or reconstruct a target via a generator.
    """
    kind = certificate.get('transform')
    a, b = source['instructions'], target['instructions']
    common = {'schema': 'rcsc-transform-certificate', 'class': 'root-preserving',
              'transform': kind, 'source_id': source['program_id'],
              'target_id': target['program_id']}
    site = None
    if kind == 'root-stutter':
        site = next((i for i, inst in enumerate(a) if inst['role'] == 'root'), None)
        if site is None:
            return 'invalid-transformation'
        derivation = dict(common, site=site)
        edit_ok = (len(b) == len(a) + 1 and _equal(a[:site], b[:site])
                   and _equal(a[site:], b[site + 1:])
                   and _equal(b[site], {'op': 'nop', 'tag': 'certified-root-stutter', 'role': 'root'}))
    elif kind == 'guard-dual':
        site = next((i for i, inst in enumerate(a)
                     if inst['role'] == 'root' and inst['op'] == 'guard'), None)
        if site is None:
            return 'invalid-transformation'
        derivation = dict(common, site=site)
        edit_ok = (len(b) == len(a) and _equal(a[:site], b[:site])
                   and _equal(a[site + 1:], b[site + 1:])
                   and _equal(b[site], {'op': 'branch_abort', 'role': 'root',
                          'pred': {'op': 'not', 'arg': a[site]['pred']}}))
    elif kind == 'alpha-unused':
        site = next((i for i, inst in enumerate(a)
                     if inst['op'] == 'assign' and inst['role'] == 'context'), None)
        if site is None:
            return 'invalid-transformation'
        old = a[site]['dst']
        new = old + '_fresh'
        declared = set(source['input_domains']) | {inst['dst'] for inst in a if 'dst' in inst}
        if old in source['input_domains'] or new in declared or any(_reads(inst, old) for inst in a[site + 1:]):
            return 'invalid-transformation'
        derivation = dict(common, site=site, old=old, new=new)
        edited_fields = {key: value for key, value in a[site].items() if key != 'dst'}
        edit_ok = (len(b) == len(a) and _equal(a[:site], b[:site])
                   and _equal(a[site + 1:], b[site + 1:])
                   and b[site].get('dst') == new
                   and _equal(edited_fields, {key: value for key, value in b[site].items() if key != 'dst'}))
    elif kind == 'swap-independent':
        if not (len(a) >= 2 and a[0]['op'] == 'assign' and a[0]['role'] == 'context'
                and a[1]['op'] == 'nop' and a[1]['role'] == 'context'):
            return 'invalid-transformation'
        derivation = dict(common, sites=[0, 1])
        edit_ok = (len(a) == len(b) and _equal(a[0], b[1]) and _equal(a[1], b[0])
                   and _equal(a[2:], b[2:]))
    else:
        return 'invalid-transformation'
    if not _equal(derivation, certificate):
        return 'certificate-derivation-mismatch'
    if target['program_id'] != source['program_id'] + '-' + str(kind):
        return 'invalid-transformation'
    if not _equal({k: v for k, v in source.items() if k not in {'program_id', 'instructions'}},
                  {k: v for k, v in target.items() if k not in {'program_id', 'instructions'}}):
        return 'invalid-transformation'
    return None if edit_ok else 'invalid-transformation'
