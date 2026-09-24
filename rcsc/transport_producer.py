"""Untrusted producer for context-transport tables, using immutable reference semantics."""
from __future__ import annotations
from .transport import prepare, valuations, replay_row
from .reference_semantics import execute as reference_execute


def make_transport_certificate(vulnerable, patched, context_domains):
    plan = prepare(vulnerable, patched, context_domains)
    return {'schema': 'rcsc-context-transport', 'core_binding': plan['binding'],
            'rows': [replay_row(plan, inputs, reference_execute)
                     for inputs in valuations(plan['root_domains'])]}
