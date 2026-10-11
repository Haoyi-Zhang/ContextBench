"""Endpoint-local syntax normalization without erasing a repair or a true label.

Only no-ops and equivalent comparison spellings are normalized. Identifiers,
literal types, event names, domains, stores, instruction roles and repair order
are retained. Semantic observations are preserved; steps/traces intentionally
are not. This is not the pair-conditioned repair quotient.
"""
from __future__ import annotations

import copy
from .model import stable_json, validate_program

EXPR_FIELDS = frozenset({'expr', 'pred', 'index', 'value', 'numerator',
                        'denominator', 'left', 'right', 'amount', 'set'})


def normalize_expression(expr):
    if type(expr) is not dict or set(expr) in ({'const'}, {'var'}, {'public'}):
        return copy.deepcopy(expr)
    if expr['op'] == 'not':
        return {'op': 'not', 'arg': normalize_expression(expr['arg'])}
    op = expr['op']
    left = normalize_expression(expr['left'])
    right = normalize_expression(expr['right'])
    if op in ('gt', 'ge'):
        op = {'gt': 'lt', 'ge': 'le'}[op]
        left, right = right, left
    elif op in ('eq', 'ne') and stable_json(right) < stable_json(left):
        left, right = right, left
    return {'op': op, 'left': left, 'right': right}


def normalize_program(program):
    """Same transformation for either label; no peer endpoint/certificate used."""
    validate_program(program)
    out = copy.deepcopy(program)
    code = []
    for instruction in out['instructions']:
        if instruction['op'] == 'nop':
            continue
        for field in EXPR_FIELDS.intersection(instruction):
            instruction[field] = normalize_expression(instruction[field])
        code.append(instruction)
    out['instructions'] = code
    # In a program whose only root is a nop, deletion would violate admission.
    # This normalizer is intentionally partial rather than inventing a root.
    validate_program(out)
    return out
