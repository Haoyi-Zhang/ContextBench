"""Consumer-side finite-core certificates for quantified context transport.

The consumer reconstructs footprints and instrumented core programs from the
supplied endpoints. It neither imports a generator nor enumerates the nuisance
Cartesian product. The certificate is evidence to check, never an authorization.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from itertools import product
from typing import Any, Mapping
import copy
import json
import time

from .checker import execute, _validate_pair_certificate
from .model import (validate_program, validate_json_tree, value_key, stable_json,
                    context_skeleton, VIOLATION_FOR_FAMILY, MAX_VALUE_BITS,
                    MAX_VALUE_NODES, MAX_ALLOCATION_NODES)
from .repair import check_repair_membership

CONTEXT_OPS = frozenset({'nop', 'assign', 'emit', 'return'})
ROOT_OPS = frozenset({'nop', 'assign', 'guard', 'branch_abort', 'buf_write',
    'divide', 'add_fixed', 'protected_store', 'external_call', 'update_balance',
    'low_call', 'check_call', 'commit_after_call'})
EXPR_FIELDS = frozenset({'expr', 'pred', 'index', 'value', 'numerator',
                        'denominator', 'left', 'right', 'amount', 'set'})
MAX_CORE_INSTRUCTIONS = 24
MAX_CONTEXT_INSTRUCTIONS = 128
MAX_CORE_ROWS = 128
MAX_NUISANCE_INPUTS = 32
MAX_DOMAIN_VALUES = 32


class TransportError(ValueError):
    def __init__(self, reason: str, detail: Any = None):
        super().__init__(reason)
        self.reason, self.detail = reason, detail


def require(test: bool, reason: str, detail: Any = None) -> None:
    if not test:
        raise TransportError(reason, detail)


def json_value(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=True, allow_nan=False))


def valuations(domains: Mapping[str, list[Any]]):
    names = sorted(domains)
    for values in product(*(sorted(domains[name], key=stable_json) for name in names)):
        yield dict(zip(names, values))


def cardinality(domains: Mapping[str, list[Any]]) -> int:
    answer = 1
    for values in domains.values():
        answer *= len(values)
    return answer


def expr_variables(expr: Any) -> set[str]:
    if type(expr) is not dict:
        return set()
    if set(expr) == {'var'}:
        return {expr['var']}
    if set(expr) in ({'const'}, {'public'}):
        return set()
    if expr['op'] == 'not':
        return expr_variables(expr['arg'])
    return expr_variables(expr['left']) | expr_variables(expr['right'])


def expression_nodes(expr: Any) -> int:
    if type(expr) is not dict or set(expr) in ({'var'}, {'const'}, {'public'}):
        return 1
    if expr['op'] == 'not':
        return 1 + expression_nodes(expr['arg'])
    return 1 + expression_nodes(expr['left']) + expression_nodes(expr['right'])


def footprint(core: list[dict]) -> tuple[set[str], set[str]]:
    reads, writes = set(), set()
    for inst in core:
        for name in EXPR_FIELDS.intersection(inst):
            reads |= expr_variables(inst[name])
        if inst['op'] in {'assign', 'divide', 'add_fixed'}:
            writes.add(inst['dst'])
        if inst['op'] == 'protected_store':
            reads.add('sender')
        if inst['op'] in {'external_call', 'update_balance'}:
            reads.add(inst['account_var'])
        if inst['op'] == 'external_call':
            # An implicit monitor input: absence means the evaluator's false default.
            reads.add('reenter')
        if inst['op'] == 'low_call':
            reads.add(inst['success_var'])
    return reads, writes


def split_root(program: Mapping[str, Any]) -> tuple[list, list, list]:
    code = program['instructions']
    indices = [i for i, inst in enumerate(code) if inst['role'] == 'root']
    require(bool(indices), 'transport-missing-root')
    first, last = min(indices), max(indices)
    require(indices == list(range(first, last + 1)), 'transport-noncontiguous-root')
    prefix, core, suffix = code[:first], code[first:last + 1], code[last + 1:]
    require(len(core) <= MAX_CORE_INSTRUCTIONS, 'transport-core-budget')
    require(len(prefix) + len(suffix) <= MAX_CONTEXT_INSTRUCTIONS, 'transport-context-budget')
    require(all(inst['op'] in ROOT_OPS for inst in core), 'transport-root-operation')
    for inst in prefix + suffix:
        require(inst['op'] in CONTEXT_OPS, 'transport-context-control-or-monitor', inst['op'])
    require(all(inst['op'] != 'return' for inst in prefix), 'transport-prefix-return')
    require(all(inst['op'] != 'return' for inst in suffix[:-1]), 'transport-early-return')
    return prefix, core, suffix


@dataclass(frozen=True)
class Bound:
    kinds: frozenset[str]
    low: int = 0
    high: int = 0
    nodes: int = 1


def exact_bound(value: Any) -> Bound:
    nodes = validate_json_tree(value, runtime=True)
    kind = type(value).__name__
    return Bound(frozenset({kind}), value if type(value) is int else 0,
                 value if type(value) is int else 0, nodes)


def domain_bound(values: list[Any]) -> Bound:
    bounds = [exact_bound(value) for value in values]
    kinds = frozenset().union(*(b.kinds for b in bounds))
    integers = [value for value in values if type(value) is int]
    return Bound(kinds, min(integers, default=0), max(integers, default=0),
                 max(b.nodes for b in bounds))


def abstract_expr(expr: Any, env: Mapping[str, Bound], public: Mapping[str, Bound]) -> tuple[Bound, int]:
    """Sound total-expression interval rules; second component bounds charged nodes."""
    if type(expr) is not dict:
        out = exact_bound(expr)
        return out, out.nodes
    if set(expr) == {'const'}:
        out = exact_bound(expr['const'])
        return out, out.nodes
    if set(expr) == {'var'}:
        require(expr['var'] in env, 'transport-undefined-context-variable', expr['var'])
        out = env[expr['var']]
        return out, out.nodes
    if set(expr) == {'public'}:
        out = public[expr['public']]
        return out, out.nodes
    op = expr['op']
    if op == 'not':
        _, cost = abstract_expr(expr['arg'], env, public)
        return Bound(frozenset({'bool'})), cost + 1
    left, lc = abstract_expr(expr['left'], env, public)
    right, rc = abstract_expr(expr['right'], env, public)
    if op in {'add', 'sub', 'mul', 'lt', 'le', 'gt', 'ge'}:
        require(left.kinds == right.kinds == frozenset({'int'}),
                'transport-context-type-error', op)
    if op == 'add':
        lo, hi = left.low + right.low, left.high + right.high
    elif op == 'sub':
        lo, hi = left.low - right.high, left.high - right.low
    elif op == 'mul':
        corners = [a*b for a in (left.low, left.high) for b in (right.low, right.high)]
        lo, hi = min(corners), max(corners)
    else:
        return Bound(frozenset({'bool'})), lc + rc + 1
    require(max(abs(lo).bit_length(), abs(hi).bit_length()) <= MAX_VALUE_BITS,
            'transport-context-integer-budget')
    return Bound(frozenset({'int'}), lo, hi), lc + rc + 1


def abstract_context(code: list[dict], env: dict[str, Bound],
                     public: dict[str, Bound]) -> tuple[dict[str, Bound], int]:
    env = dict(env)
    cost = 0
    for inst in code:
        op = inst['op']
        if op == 'nop':
            continue
        if op == 'assign':
            out, used = abstract_expr(inst['expr'], env, public)
            env[inst['dst']] = out
        else:
            out, used = abstract_expr(inst.get('value', None), env, public)
        # Extra snapshot allowance is conservative for both production evaluators.
        cost += used + out.nodes
    return env, cost


def core_probe(program: dict, core: list, root_domains: dict, probe_names: set[str]) -> dict:
    """Read all root-accessible locals and all public cells at a normal root exit."""
    out = copy.deepcopy(program)
    out['input_domains'] = copy.deepcopy(root_domains)
    out['instructions'] = copy.deepcopy(core) + [
        {'op': 'emit', 'role': 'context', 'name': 'local:' + name, 'value': {'var': name}}
        for name in sorted(probe_names)]
    out['public_projection'] = sorted(out['initial_public_state'])
    out['context'] = {'purpose': 'complete root exit store'}
    validate_program(out)
    return out


def _suffix_cost(code: list[dict], env: dict[str, Bound],
                 public: dict[str, Bound], costs: dict[tuple, int]) -> int:
    """Reuse only successful costs for the fixed suffix in this invocation."""
    key = (tuple(sorted(env.items())), tuple(sorted(public.items())))
    if key not in costs:
        _, cost = abstract_context(code, env, public)
        costs[key] = cost
    return costs[key]


def prepare(v: dict, p: dict, context_domains: dict) -> dict:
    validate_program(v)
    validate_program(p)
    validate_json_tree(context_domains)
    require(v['label'] == 'vulnerable' and p['label'] == 'patched', 'contradictory-label')
    require(value_key(context_skeleton(v)) == value_key(context_skeleton(p)), 'context-leakage')
    vp, vr, vs = split_root(v)
    pp, pr, ps = split_root(p)
    require(value_key(vp) == value_key(pp) and value_key(vs) == value_key(ps),
            'transport-context-placement')
    require(type(context_domains) is dict and len(context_domains) <= MAX_NUISANCE_INPUTS,
            'transport-domain-schema')
    rread, rwrite = footprint(vr + pr)
    protected = rread | rwrite
    require(not protected.intersection(context_domains), 'transport-nuisance-root-flow',
            sorted(protected.intersection(context_domains)))
    pwrites = {inst['dst'] for inst in vp if inst['op'] == 'assign'}
    require(not protected.intersection(pwrites), 'transport-prefix-root-write',
            sorted(protected.intersection(pwrites)))
    for name, domain in context_domains.items():
        require(name in v['input_domains'] and len(v['input_domains'][name]) == 1,
                'transport-anchor-domain', name)
        require(type(domain) is list and 1 <= len(domain) <= MAX_DOMAIN_VALUES,
                'transport-domain-schema', name)
        require(all(type(x) in (int, bool, str, type(None)) for x in domain),
                'transport-domain-scalar', name)
        require(len({stable_json(x) for x in domain}) == len(domain),
                'transport-domain-duplicate', name)
        require(any(value_key(x) == value_key(v['input_domains'][name][0]) for x in domain),
                'transport-anchor-not-in-domain', name)
    root_domains = {name: values for name, values in v['input_domains'].items()
                    if name not in context_domains}
    require(root_domains and cardinality(root_domains) <= MAX_CORE_ROWS, 'transport-core-domain-budget')
    # Inputs not used by the root may stay on the enumerated side: sound but not minimal.
    probes = (rread | rwrite).intersection(set(root_domains) | rwrite)
    cv = core_probe(v, vr, root_domains, probes)
    cp = core_probe(p, pr, root_domains, probes)
    env = {name: domain_bound(context_domains.get(name, values))
           for name, values in v['input_domains'].items()}
    pub = {name: exact_bound(value) for name, value in v['initial_public_state'].items()}
    prefix_env, prefix_cost = abstract_context(vp, env, pub)
    core_cost = max(sum(expression_nodes(inst[field]) for inst in core
                   for field in EXPR_FIELDS.intersection(inst)) * MAX_VALUE_NODES
                    for core in (vr, pr))
    # Initial env/public charges and final projected-state charges, all conservative.
    fixed_cost = (2 + sum(b.nodes for b in env.values()) +
                  sum(b.nodes for b in pub.values()) + len(pub)*MAX_VALUE_NODES)
    return {'prefix': vp, 'suffix': vs, 'v_core': cv, 'p_core': cp,
            'root_domains': root_domains, 'context_domains': context_domains,
            'prefix_env': prefix_env, 'prefix_cost': prefix_cost,
            'core_cost': core_cost, 'fixed_cost': fixed_cost,
            'binding': {'profile': v['profile'], 'family': v['family'],
                'root_domains': root_domains, 'initial_public_state': v['initial_public_state'],
                'vulnerable_core': vr, 'patched_core': pr,
                'read_variables': sorted(rread), 'write_variables': sorted(rwrite)}}


def replay_row(plan: dict, inputs: dict, executor=execute) -> dict:
    return {'input': copy.deepcopy(inputs),
            'vulnerable': json_value(executor(plan['v_core'], inputs).to_json()),
            'patched': json_value(executor(plan['p_core'], inputs).to_json())}


@dataclass
class TransportReport:
    accepted: bool
    reason: str
    core_valuations: int = 0
    context_valuations: int = 0
    core_executions: int = 0
    represented_endpoint_executions: int = 0
    productive_safe_roots: int = 0
    vulnerable_roots: int = 0
    allocation_upper_bound: int = 0
    certificate_bytes: int = 0
    elapsed_ms: float = 0.0
    detail: Any = None

    def to_json(self):
        return asdict(self)


def _check_transport(packet: Any, *, claim_check: bool) -> TransportReport:
    started = time.perf_counter()
    report = TransportReport(False, 'transport-input-error')
    try:
        validate_json_tree(packet)
        require(type(packet) is dict and set(packet) == {'vulnerable', 'patched',
                'certificate', 'context_domains', 'transport_certificate'}, 'transport-packet-schema')
        v, p = packet['vulnerable'], packet['patched']
        plan = prepare(v, p, packet['context_domains'])
        if claim_check:
            reason, detail = _validate_pair_certificate(v, p, packet['certificate'])
            require(reason is None, reason or 'certificate-error', detail)
        # Relation membership is reconstructed even in the certificate-free audit.
        from .repair import expected_repair
        reason, detail = check_repair_membership(v, p, expected_repair(v['family']))
        require(reason is None, reason or 'root-repair-mismatch', detail)
        cert = packet['transport_certificate']
        if claim_check:
            require(type(cert) is dict and set(cert) == {'schema', 'core_binding', 'rows'}
                    and cert['schema'] == 'rcsc-context-transport', 'transport-certificate-schema')
            report.certificate_bytes = len(stable_json(cert).encode('utf-8'))
            require(value_key(cert['core_binding']) == value_key(plan['binding']), 'transport-core-binding')
        expected_inputs = list(valuations(plan['root_domains']))
        if claim_check:
            require(type(cert['rows']) is list and len(cert['rows']) == len(expected_inputs),
                    'transport-row-coverage')
        report.core_valuations = len(expected_inputs)
        report.context_valuations = cardinality(plan['context_domains'])
        report.represented_endpoint_executions = 2 * report.core_valuations * report.context_valuations
        witness_root = ({key: packet['certificate']['witness_input'][key] for key in plan['root_domains']}
                        if claim_check else None)
        witness_seen = False
        max_suffix_cost = 0
        # Fixed suffix, invocation-local complete abstract stores. Bound is frozen
        # and its hash/equality includes kinds, interval endpoints and node count.
        # At most two normal outcomes per admitted root row can be retained.
        suffix_costs: dict[tuple, int] = {}
        for index, inputs in enumerate(expected_inputs):
            row = replay_row(plan, inputs)
            report.core_executions += 2
            if claim_check:
                require(value_key(cert['rows'][index]) == value_key(row),
                        'transport-row-mismatch', {'input': inputs})
            a, b = row['vulnerable'], row['patched']
            require(a['violation'] in (None, VIOLATION_FOR_FAMILY[v['family']]), 'wrong-root-cause')
            require(b['violation'] is None, 'patched-still-vulnerable', {'input': inputs})
            if a['violation']:
                report.vulnerable_roots += 1
                witness_seen |= not claim_check or value_key(inputs) == value_key(witness_root)
            else:
                for key in ('aborted', 'returned', 'events', 'public_state'):
                    require(value_key(a[key]) == value_key(b[key]), 'transport-safe-store-mismatch',
                            {'input': inputs, 'component': key})
                if not a['aborted']:
                    report.productive_safe_roots += 1
            for result in (a, b):
                if result['violation'] is not None or result['aborted']:
                    continue
                env = dict(plan['prefix_env'])
                # Preserve prefix assignments to enumerated-but-root-unread inputs.
                # Resetting all input bindings here would make totality unsound.
                env.update({name.removeprefix('local:'): exact_bound(value)
                            for name, value in result['events']})
                pub = {name: exact_bound(value) for name, value in result['public_state']}
                cost = _suffix_cost(plan['suffix'], env, pub, suffix_costs)
                max_suffix_cost = max(max_suffix_cost, cost)
        require(witness_seen, 'certificate-witness-not-vulnerable')
        require(report.productive_safe_roots > 0, 'missing-productive-safe-input')
        report.allocation_upper_bound = (plan['fixed_cost'] + plan['prefix_cost'] +
                                         plan['core_cost'] + max_suffix_cost)
        require(report.allocation_upper_bound <= MAX_ALLOCATION_NODES, 'transport-allocation-budget')
        report.accepted, report.reason = True, 'accepted'
    except TransportError as exc:
        report.reason, report.detail = exc.reason, exc.detail
    except (ValueError, TypeError, KeyError, IndexError, RecursionError, OverflowError) as exc:
        report.reason, report.detail = 'transport-admission-or-execution-error', str(exc)
    report.elapsed_ms = (time.perf_counter() - started) * 1000
    return report


def check_transport(packet: Any) -> TransportReport:
    """Validate every submitted identity, edit, frame, table, and semantic claim."""
    return _check_transport(packet, claim_check=True)


def audit_transport(vulnerable: dict, patched: dict, context_domains: dict) -> TransportReport:
    """Derive the framed relation without any incoming certificate claims.

    This is the certificate-elimination baseline, not the production admission API.
    It shares the frame/replay implementation; only the full Cartesian oracle is
    independent of that implementation. The CLI exposes the production checker.
    """
    packet = {'vulnerable': vulnerable, 'patched': patched, 'context_domains': context_domains,
              'certificate': None, 'transport_certificate': None}
    return _check_transport(packet, claim_check=False)
