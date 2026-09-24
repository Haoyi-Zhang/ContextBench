"""Owned benign context-transport cases. No third-party executable programs."""
from __future__ import annotations
import copy
from .generate import MAKERS, B, C, V
from .transport_producer import make_transport_certificate


def make_case(family: str, seed: int = 0, dimensions: int = 4, wrapper: int = 0):
    v, p, cert = MAKERS[family](f'transport-{family}-{seed}-{dimensions}-{wrapper}', seed)
    names = [f'noise_{i}' for i in range(dimensions)]
    domains = {name: [0, 1] for name in names}
    before, after = [], []
    for i, name in enumerate(names):
        # Nuisance is deliberately used, publicly observable, and never erased.
        expr = V(name)
        if wrapper % 3 == 1:
            expr = B('mul', B('add', V(name), C(i + 1)), C(2))
        elif wrapper % 3 == 2:
            expr = B('eq', V(name), C(0))
        before.append({'op': 'assign', 'role': 'context', 'dst': f'context_{i}', 'expr': expr})
        if wrapper % 2 == 0:
            before.append({'op': 'emit', 'role': 'context', 'name': f'pre-{i}', 'value': V(f'context_{i}')})
        else:
            after.append({'op': 'emit', 'role': 'context', 'name': f'post-{i}', 'value': V(f'context_{i}')})
    for q in (v, p):
        q['input_domains'].update({name: [0] for name in names})
        q['instructions'] = before + q['instructions'][:-1] + after + q['instructions'][-1:]
    cert['witness_input'].update({name: 0 for name in names})
    packet = {'vulnerable': v, 'patched': p, 'certificate': cert, 'context_domains': domains}
    packet['transport_certificate'] = make_transport_certificate(v, p, domains)
    return packet


def instantiated_pair(packet, nuisance):
    v, p, cert = (copy.deepcopy(packet[k]) for k in ('vulnerable', 'patched', 'certificate'))
    for q in (v, p):
        q['input_domains'].update({name: [value] for name, value in nuisance.items()})
    cert['witness_input'].update(nuisance)
    return v, p, cert
