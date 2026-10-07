"""Portable finite correctness gates; no saved results or private-stage inputs."""
import copy
import itertools
import json
import unittest
from unittest.mock import patch

from rcsc import transport as tr
from rcsc.checker import execute
from rcsc.generate import B, C, V, MAKERS
from rcsc.reference_semantics import execute as literal_execute
from rcsc.transport_cases import make_case
from rcsc.transport_producer import make_transport_certificate


def report_key(report):
    fields = report.to_json()
    fields.pop("elapsed_ms")  # A measured field, not an equality/performance claim.
    return json.dumps(fields, sort_keys=True, separators=(",", ":"))


def scan_context(code, env, public):
    """Test-local nonmemoizing abstract interpreter, independent expression walk."""
    def literal(value):
        def nodes(x):
            if type(x) is dict:
                return 1 + sum(nodes(v) for v in x.values())
            if type(x) is list:
                return 1 + sum(nodes(v) for v in x)
            return 1
        integer = value if type(value) is int else 0
        return tr.Bound(frozenset({type(value).__name__}), integer, integer, nodes(value))

    def expression(e, store):
        if type(e) is not dict or set(e) == {"const"}:
            result = literal(e["const"] if type(e) is dict else e)
            return result, result.nodes
        if set(e) == {"var"}:
            if e["var"] not in store:
                raise tr.TransportError("transport-undefined-context-variable", e["var"])
            return store[e["var"]], store[e["var"]].nodes
        if set(e) == {"public"}:
            return public[e["public"]], public[e["public"]].nodes
        if e["op"] == "not":
            _, cost = expression(e["arg"], store)
            return tr.Bound(frozenset({"bool"})), cost + 1
        a, ca = expression(e["left"], store)
        b, cb = expression(e["right"], store)
        op = e["op"]
        if op in ("add", "sub", "mul", "lt", "le", "gt", "ge"):
            if a.kinds != frozenset({"int"}) or b.kinds != frozenset({"int"}):
                raise tr.TransportError("transport-context-type-error", op)
        if op == "add":
            limits = (a.low + b.low, a.high + b.high)
        elif op == "sub":
            limits = (a.low - b.high, a.high - b.low)
        elif op == "mul":
            values = tuple(x * y for x in (a.low, a.high) for y in (b.low, b.high))
            limits = (min(values), max(values))
        else:
            return tr.Bound(frozenset({"bool"})), ca + cb + 1
        if any(abs(x).bit_length() > tr.MAX_VALUE_BITS for x in limits):
            raise tr.TransportError("transport-context-integer-budget")
        return tr.Bound(frozenset({"int"}), *limits), ca + cb + 1

    store, cost = dict(env), 0
    for inst in code:
        if inst["op"] == "nop":
            continue
        value, used = expression(inst["expr"] if inst["op"] == "assign"
                                 else inst.get("value"), store)
        if inst["op"] == "assign":
            store[inst["dst"]] = value
        cost += used + value.nodes
    return store, cost


def scan_suffix_cost(code, env, public, costs):
    """Matched local comparison reference: always scan, never use the cache."""
    return scan_context(code, env, public)[1]


def fixture_packets():
    for family in MAKERS:
        for wrapper in range(6):
            for dimensions in (0, 1, 2, 4):
                yield f"{family}/{wrapper}/{dimensions}", make_case(
                    family, dimensions=dimensions, wrapper=wrapper)
    for family in ("bounds_write", "access_control", "unchecked_call"):
        packet = make_case(family, dimensions=1, wrapper=2)
        for side in ("vulnerable", "patched"):
            packet[side]["input_domains"]["value"] = [0, True, "a", "bb", None]
        packet["transport_certificate"] = make_transport_certificate(
            packet["vulnerable"], packet["patched"], packet["context_domains"])
        yield f"{family}/typed-values", packet
    packet = make_case("divide_zero", dimensions=1)
    for side in ("vulnerable", "patched"):
        packet[side]["input_domains"]["unread"] = [0]
        packet[side]["instructions"].insert(0, {
            "op": "assign", "role": "context", "dst": "unread", "expr": C("text")})
        packet[side]["instructions"].insert(-1, {
            "op": "emit", "role": "context", "name": "bad", "value": B("add", V("unread"), C(1))})
    packet["certificate"]["witness_input"]["unread"] = 0
    packet["transport_certificate"] = make_transport_certificate(
        packet["vulnerable"], packet["patched"], packet["context_domains"])
    yield "prefix-overwrite/type-failure", packet
    packet = make_case("divide_zero", dimensions=1)
    for side in ("vulnerable", "patched"):
        growth = [{"op": "assign", "role": "context", "dst": "growth", "expr": C(2)}]
        growth += [{"op": "assign", "role": "context", "dst": "growth",
                    "expr": B("mul", V("growth"), V("growth"))} for _ in range(13)]
        packet[side]["instructions"][-1:-1] = growth
    yield "suffix/integer-failure", packet


def finite_oracle(packet):
    """Literal full-product executions; no factorization, bound or table helpers."""
    program = packet["vulnerable"]
    roots = {k: v for k, v in program["input_domains"].items()
             if k not in packet["context_domains"]}
    def points(domains):
        names = sorted(domains)
        for values in itertools.product(*(domains[n] for n in names)):
            yield dict(zip(names, values))
    profiles, runs = {}, 0
    for context in points(packet["context_domains"]):
        vulnerable, productive = 0, 0
        for root in points(roots):
            inputs = dict(root, **context)
            results = []
            for side in ("vulnerable", "patched"):
                point = copy.deepcopy(packet[side])
                point["input_domains"].update({k: [v] for k, v in context.items()})
                actual = json.loads(json.dumps(execute(point, inputs).to_json()))
                expected = literal_execute(point, inputs).to_json()
                assert json.dumps(actual, sort_keys=True) == json.dumps(expected, sort_keys=True)
                results.append(expected)
                runs += 1
            a, b = results
            profile = (a["violation"], b["violation"], a["aborted"], b["aborted"])
            key = json.dumps(root, sort_keys=True)
            assert profiles.setdefault(key, profile) == profile
            assert b["violation"] is None
            if a["violation"] is not None:
                assert a["violation"] == tr.VIOLATION_FOR_FAMILY[program["family"]]
                vulnerable += 1
            else:
                for field in ("aborted", "returned", "events", "public_state"):
                    assert json.dumps(a[field]) == json.dumps(b[field])
                if not a["aborted"]:
                    required = {f"{i}:{x['op']}" for i, x in enumerate(program["instructions"])
                                if x["role"] == "root"}
                    assert required <= set(a["trace"])
                    productive += 1
        assert vulnerable and productive
    return runs


class SuffixReuseTests(unittest.TestCase):
    def test_complete_reports_against_independent_uncached_scan(self):
        for name, packet in fixture_packets():
            with self.subTest(name=name):
                pristine = copy.deepcopy(packet)
                certified = tr.check_transport(packet)
                audited = tr.audit_transport(packet["vulnerable"], packet["patched"], packet["context_domains"])
                with patch.object(tr, "_suffix_cost", scan_suffix_cost):
                    self.assertEqual(report_key(certified), report_key(tr.check_transport(packet)))
                    self.assertEqual(report_key(audited), report_key(tr.audit_transport(
                        packet["vulnerable"], packet["patched"], packet["context_domains"])))
                self.assertEqual(packet, pristine)

    def test_literal_full_cartesian_oracle(self):
        for name, packet in fixture_packets():
            if name.endswith("failure"):
                continue
            with self.subTest(name=name):
                result = tr.check_transport(packet)
                self.assertTrue(result.accepted, result)
                self.assertEqual(finite_oracle(packet), result.represented_endpoint_executions)
                self.assertEqual(result.core_executions, 2 * result.core_valuations)

    def test_every_bound_field_and_store_name_is_keyed(self):
        code = [{"op": "emit", "role": "context", "name": "value", "value": V("x")}]
        base = tr.Bound(frozenset({"int"}), 0, 1, 1)
        variants = [base, tr.Bound(frozenset({"bool"}), 0, 1, 1),
                    tr.Bound(base.kinds, -1, 1, 1), tr.Bound(base.kinds, 0, 2, 1),
                    tr.Bound(base.kinds, 0, 1, 2)]
        costs = {}
        with patch.object(tr, "abstract_context", wraps=tr.abstract_context) as scan:
            for bound in variants:
                env, public = {"x": bound}, {"p": base}
                self.assertEqual(tr._suffix_cost(code, env, public, costs),
                                 scan_context(code, env, public)[1])
                tr._suffix_cost(code, env, public, costs)
            for bound in variants[1:]:
                tr._suffix_cost(code, {"x": base}, {"p": bound}, costs)
            tr._suffix_cost(code, {"x": base, "unused": base}, {"p": base}, costs)
            tr._suffix_cost(code, {"x": base}, {"other": base}, costs)
            self.assertEqual(scan.call_count, 11)
            self.assertEqual(len(costs), 11)
        self.assertEqual(tr.exact_bound("a"), tr.exact_bound("bb"))

    def test_reuse_is_local_and_does_not_skip_root_replay(self):
        packet = make_case("reentrancy", dimensions=2)
        plan = tr.prepare(packet["vulnerable"], packet["patched"], packet["context_domains"])
        expected = 0
        for inputs in tr.valuations(plan["root_domains"]):
            for result in (tr.replay_row(plan, inputs)["vulnerable"], tr.replay_row(plan, inputs)["patched"]):
                expected += result["violation"] is None and not result["aborted"]
        suffix_scans = []
        original = tr.abstract_context
        def counted(code, env, public):
            if code == plan["suffix"]:
                suffix_scans.append(1)
            return original(code, env, public)
        with patch.object(tr, "abstract_context", counted):
            first = tr.check_transport(packet)
            count = len(suffix_scans)
            second = tr.check_transport(packet)
        self.assertGreater(count, 0)
        self.assertLess(count, expected)
        self.assertEqual(len(suffix_scans), 2 * count)
        self.assertEqual(report_key(first), report_key(second))
        self.assertEqual(first.core_executions, 2 * first.core_valuations)
        # A changed wrapper is freshly analyzed, never served by a previous check.
        for side in ("vulnerable", "patched"):
            packet[side]["instructions"].insert(-1, {"op": "emit", "role": "context",
                "name": "bad", "value": B("add", C("text"), C(1))})
        self.assertEqual(tr.check_transport(packet).reason, "transport-context-type-error")

    def test_failures_are_not_cached_or_reordered(self):
        bad = [{"op": "emit", "role": "context", "name": "bad",
                "value": B("add", V("x"), C(1))}]
        costs = {}
        for _ in range(2):
            with self.assertRaises(tr.TransportError) as error:
                tr._suffix_cost(bad, {"x": tr.exact_bound(None)}, {}, costs)
            self.assertEqual((error.exception.reason, error.exception.detail),
                             ("transport-context-type-error", "add"))
            self.assertEqual(costs, {})
        for name, packet in fixture_packets():
            if name.endswith("failure"):
                actual = tr.check_transport(packet)
                with patch.object(tr, "_suffix_cost", scan_suffix_cost):
                    self.assertEqual(report_key(actual), report_key(tr.check_transport(packet)))
                self.assertFalse(actual.accepted)
                self.assertGreater(actual.core_executions, 0)
        packet = make_case("divide_zero", dimensions=2)
        limit = tr.check_transport(packet).allocation_upper_bound
        for maximum in (limit, limit - 1):
            with patch.object(tr, "MAX_ALLOCATION_NODES", maximum):
                result = tr.check_transport(packet)
                with patch.object(tr, "_suffix_cost", scan_suffix_cost):
                    self.assertEqual(report_key(result), report_key(tr.check_transport(packet)))
                self.assertEqual(result.accepted, maximum == limit)
                self.assertEqual(result.allocation_upper_bound, limit)
        for values, reason in ((list(range(32)), "accepted"),
                               (list(range(33)), "transport-domain-schema")):
            packet["context_domains"]["noise_0"] = values
            self.assertEqual(tr.check_transport(packet).reason, reason)

    def test_ordered_claim_controls_and_shared_audit_scope(self):
        for mutation in ("missing", "duplicate", "reorder", "type", "binding", "witness"):
            packet = make_case("divide_zero", dimensions=2)
            rows = packet["transport_certificate"]["rows"]
            if mutation == "missing":
                rows.pop()
            elif mutation == "duplicate":
                rows[1] = copy.deepcopy(rows[0])
            elif mutation == "reorder":
                rows.reverse()
            elif mutation == "type":
                rows[0]["patched"]["aborted"] = 0
            elif mutation == "binding":
                packet["transport_certificate"]["core_binding"]["read_variables"] = []
            else:
                packet["certificate"]["witness_input"]["denominator"] = 1
            result = tr.check_transport(packet)
            with patch.object(tr, "_suffix_cost", scan_suffix_cost):
                self.assertEqual(report_key(result), report_key(tr.check_transport(packet)))
            self.assertFalse(result.accepted)
            self.assertTrue(tr.audit_transport(packet["vulnerable"], packet["patched"],
                                               packet["context_domains"]).accepted)


if __name__ == "__main__":
    unittest.main()
