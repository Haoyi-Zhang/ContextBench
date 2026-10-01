import ast
import copy
import unittest
from pathlib import Path

from rcsc.transport import check_transport, valuations, TransportError, prepare
from rcsc.transport_producer import make_transport_certificate
from rcsc.transport_cases import make_case, instantiated_pair
from rcsc.generate import MAKERS, B, C, V
from rcsc.checker import check_pair
from verify import verify_packet


class ContextTransportTests(unittest.TestCase):
    def test_all_families_match_full_small_product(self):
        for family in MAKERS:
            packet = make_case(family, dimensions=2)
            report = check_transport(packet)
            self.assertTrue(report.accepted, report)
            self.assertEqual(report.context_valuations, 4)
            self.assertEqual(report.represented_endpoint_executions, report.core_executions * 4)
            for nuisance in valuations(packet['context_domains']):
                self.assertTrue(check_pair(*instantiated_pair(packet, nuisance)).accepted)

    def test_core_proof_reused_across_six_observable_contexts(self):
        for family in MAKERS:
            packets = [make_case(family, dimensions=4, wrapper=i) for i in range(6)]
            for packet in packets:
                self.assertEqual(packet['transport_certificate'], packets[0]['transport_certificate'])
                self.assertTrue(check_transport(packet).accepted)

    def test_twenty_context_dimensions_are_not_enumerated(self):
        packet = make_case('divide_zero', dimensions=20)
        result = check_transport(packet)
        self.assertTrue(result.accepted, result)
        self.assertEqual(result.context_valuations, 2**20)
        self.assertEqual(result.core_executions, 24)

    def test_extra_guard_passes_anchor_but_fails_transport(self):
        packet = make_case('divide_zero', dimensions=1)
        guard = next(inst for inst in packet['patched']['instructions'] if inst['op'] == 'guard')
        guard['pred'] = B('and', guard['pred'], B('eq', V('noise_0'), C(0)))
        self.assertTrue(check_pair(packet['vulnerable'], packet['patched'], packet['certificate']).accepted)
        self.assertFalse(check_pair(*instantiated_pair(packet, {'noise_0': 1})).accepted)
        self.assertEqual(check_transport(packet).reason, 'transport-nuisance-root-flow')

    def test_prefix_data_flow_to_root_is_rejected(self):
        packet = make_case('divide_zero', dimensions=1)
        for side in ('vulnerable', 'patched'):
            packet[side]['instructions'].insert(0, {'op': 'assign', 'role': 'context',
                'dst': 'denominator', 'expr': V('noise_0')})
        self.assertEqual(check_transport(packet).reason, 'transport-prefix-root-write')

    def test_implicit_reentrancy_input_is_protected(self):
        packet = make_case('reentrancy', dimensions=1)
        for side in ('vulnerable', 'patched'):
            packet[side]['input_domains']['reenter'] = [False]
        packet['context_domains']['reenter'] = [False, True]
        self.assertEqual(check_transport(packet).reason, 'transport-nuisance-root-flow')

    def test_control_flow_in_context_is_not_silently_ignored(self):
        packet = make_case('divide_zero', dimensions=1)
        for side in ('vulnerable', 'patched'):
            packet[side]['instructions'].insert(0, {'op': 'branch_abort', 'role': 'context',
                                                  'pred': B('eq', V('noise_0'), C(1))})
        self.assertEqual(check_transport(packet).reason, 'transport-context-control-or-monitor')

    def test_totality_checks_unseen_dynamic_type_error(self):
        packet = make_case('bounds_write', dimensions=1)
        packet['context_domains']['noise_0'] = [0, True]
        for side in ('vulnerable', 'patched'):
            packet[side]['instructions'][0]['expr'] = B('add', V('noise_0'), C(1))
        self.assertEqual(check_transport(packet).reason, 'transport-context-type-error')

    def test_totality_checks_unseen_integer_growth(self):
        packet = make_case('divide_zero', dimensions=1)
        pre = [{'op':'assign','role':'context','dst':'growth','expr':B('add',V('noise_0'),C(1))}]
        pre += [{'op':'assign','role':'context','dst':'growth','expr':B('mul',V('growth'),V('growth'))} for _ in range(13)]
        for side in ('vulnerable', 'patched'):
            packet[side]['instructions'] = pre + packet[side]['instructions']
        self.assertTrue(check_pair(packet['vulnerable'],packet['patched'],packet['certificate']).accepted)
        self.assertEqual(check_transport(packet).reason, 'transport-context-integer-budget')

    def test_suffix_type_check_uses_root_exit_state(self):
        packet = make_case('divide_zero', dimensions=1)
        for side in ('vulnerable', 'patched'):
            packet[side]['instructions'].insert(-1, {'op':'emit','role':'context','name':'combined',
                'value':B('add',V('quotient'),V('noise_0'))})
        self.assertTrue(check_transport(packet).accepted)
        packet['context_domains']['noise_0'] = [0, 'wrong']
        self.assertEqual(check_transport(packet).reason, 'transport-context-type-error')

    def test_suffix_does_not_reset_a_prefix_assignment_to_an_unread_input(self):
        packet = make_case('divide_zero', dimensions=1)
        for side in ('vulnerable','patched'):
            packet[side]['input_domains']['unread'] = [0]
            packet[side]['instructions'].insert(0, {'op':'assign','role':'context','dst':'unread','expr':C('text')})
            packet[side]['instructions'].insert(-1, {'op':'emit','role':'context','name':'bad','value':B('add',V('unread'),C(1))})
        packet['certificate']['witness_input']['unread'] = 0
        packet['transport_certificate'] = make_transport_certificate(packet['vulnerable'],packet['patched'],packet['context_domains'])
        self.assertEqual(check_transport(packet).reason, 'transport-context-type-error')

    def test_certificate_row_coverage(self):
        packet = make_case('divide_zero')
        packet['transport_certificate']['rows'].pop()
        self.assertEqual(check_transport(packet).reason, 'transport-row-coverage')

    def test_duplicate_row_rejected(self):
        packet = make_case('divide_zero')
        packet['transport_certificate']['rows'][1] = copy.deepcopy(packet['transport_certificate']['rows'][0])
        self.assertEqual(check_transport(packet).reason, 'transport-row-mismatch')

    def test_type_distinct_certificate_values(self):
        packet = make_case('divide_zero')
        packet['transport_certificate']['rows'][0]['patched']['aborted'] = 0
        self.assertEqual(check_transport(packet).reason, 'transport-row-mismatch')

    def test_footprint_is_reconstructed_not_trusted(self):
        packet = make_case('divide_zero')
        packet['transport_certificate']['core_binding']['read_variables'] = []
        self.assertEqual(check_transport(packet).reason, 'transport-core-binding')

    def test_core_program_change_invalidates_certificate(self):
        packet = make_case('divide_zero')
        for side in ('vulnerable','patched'):
            div=next(inst for inst in packet[side]['instructions'] if inst['op']=='divide')
            div['numerator']=C(7)
        self.assertEqual(check_transport(packet).reason, 'transport-core-binding')

    def test_context_domain_must_include_anchor(self):
        packet = make_case('divide_zero')
        packet['context_domains']['noise_0'] = [1,2]
        self.assertEqual(check_transport(packet).reason, 'transport-anchor-not-in-domain')

    def test_context_domains_are_type_exact(self):
        packet = make_case('divide_zero', dimensions=1, wrapper=2)
        packet['context_domains']['noise_0'] = [0, True]
        self.assertTrue(check_transport(packet).accepted)
        packet['context_domains']['noise_0'] = [False, True]
        self.assertEqual(check_transport(packet).reason, 'transport-anchor-not-in-domain')

    def test_domain_order_does_not_affect_root_certificate(self):
        packet = make_case('divide_zero', dimensions=2)
        for side in ('vulnerable','patched'):
            for values in packet[side]['input_domains'].values(): values.reverse()
        # Exact binding intentionally records the declared root domain ordering.
        packet['transport_certificate'] = make_transport_certificate(packet['vulnerable'],packet['patched'],packet['context_domains'])
        self.assertTrue(check_transport(packet).accepted)

    def test_zero_nuisance_baseline(self):
        packet=make_case('divide_zero', dimensions=0)
        self.assertTrue(check_transport(packet).accepted)
        self.assertEqual(check_transport(packet).context_valuations,1)

    def test_harmless_prefix_rewrite_is_a_documented_false_negative(self):
        packet=make_case('divide_zero', dimensions=1)
        for side in ('vulnerable','patched'):
            packet[side]['instructions'].insert(0,{'op':'assign','role':'context','dst':'denominator','expr':V('denominator')})
        self.assertTrue(all(check_pair(*instantiated_pair(packet,n)).accepted for n in valuations(packet['context_domains'])))
        self.assertEqual(check_transport(packet).reason,'transport-prefix-root-write')

    def test_constant_true_context_guard_is_outside_fragment(self):
        packet=make_case('divide_zero', dimensions=1)
        for side in ('vulnerable','patched'):
            packet[side]['instructions'].insert(0,{'op':'guard','role':'context','pred':C(True)})
        self.assertTrue(all(check_pair(*instantiated_pair(packet,n)).accepted for n in valuations(packet['context_domains'])))
        self.assertEqual(check_transport(packet).reason,'transport-context-control-or-monitor')

    def test_library_fails_closed_on_cycles_and_unexpected_shapes(self):
        for value in (None, [], {'vulnerable':None}):
            self.assertFalse(check_transport(value).accepted)
        packet=make_case('divide_zero'); packet['vulnerable']['context']['cycle']=packet
        self.assertFalse(check_transport(packet).accepted)

    def test_consumer_does_not_import_generator_or_reference_producer(self):
        module=Path(__file__).resolve().parents[1]/'rcsc'/'transport.py'
        for node in ast.walk(ast.parse(module.read_text())):
            if isinstance(node,ast.ImportFrom):
                self.assertNotIn(node.module,('generate','transport_cases','transport_producer','reference_semantics'))

    def test_cartesian_semantic_oracle_does_not_import_factorization_or_repair(self):
        module=Path(__file__).resolve().parents[1]/'rcsc'/'transport_oracle.py'
        forbidden=('transport','transport_cases','transport_producer','transport_contract_gate','repair')
        for node in ast.walk(ast.parse(module.read_text())):
            if isinstance(node,ast.ImportFrom):
                imported=(node.module or '').split('.')[-1]
                self.assertNotIn(imported,forbidden)

    def test_cli_dispatch(self):
        self.assertTrue(verify_packet('transport', make_case('divide_zero')).accepted)


if __name__=='__main__': unittest.main()

class TransportAuditTests(unittest.TestCase):
    def test_factored_relation_does_not_need_incoming_proof(self):
        from rcsc.transport import audit_transport
        for family in MAKERS:
            packet=make_case(family,dimensions=4)
            direct=audit_transport(packet['vulnerable'],packet['patched'],packet['context_domains'])
            certified=check_transport(packet)
            self.assertTrue(direct.accepted,direct)
            self.assertEqual(direct.core_executions,certified.core_executions)
            packet['transport_certificate']['rows'][0]['patched']['aborted']=0
            self.assertFalse(check_transport(packet).accepted)
            self.assertTrue(audit_transport(packet['vulnerable'],packet['patched'],packet['context_domains']).accepted)

    def test_audit_still_checks_frame_and_closure(self):
        from rcsc.transport import audit_transport
        packet=make_case('divide_zero',dimensions=1)
        inst=next(x for x in packet['patched']['instructions'] if x['op']=='guard')
        inst['pred']=B('and',inst['pred'],B('eq',V('noise_0'),C(0)))
        self.assertFalse(audit_transport(packet['vulnerable'],packet['patched'],packet['context_domains']).accepted)

class ConservativeCoverageTests(unittest.TestCase):
    def test_overwrite_can_be_semantically_harmless(self):
        from rcsc.transport_experiment import controls, direct_oracle
        packet=next(p for name,kind,p in controls(make_case('reentrancy',dimensions=2))
                    if name=='root-input-overwrite')
        oracle=direct_oracle(packet)
        self.assertTrue(oracle['semantic_relation'])
        self.assertTrue(oracle['monitor_consistent'])
        self.assertTrue(oracle['security_invariant'])
        self.assertEqual(check_transport(packet).reason,'transport-prefix-root-write')


class MovingWitnessTest(unittest.TestCase):
    def test_all_point_pairs_valid_but_root_security_partition_moves(self):
        from rcsc.transport_experiment import direct_oracle
        from rcsc.transport_cases import instantiated_pair
        packet = make_case('divide_zero', dimensions=1)
        denominator = B('sub', V('denominator'), V('noise_0'))
        for side in ('vulnerable', 'patched'):
            program = packet[side]
            program['input_domains']['denominator'] = [0, 1]
            program['input_domains']['numerator'] = [1]
            for inst in program['instructions']:
                if inst['op'] == 'divide':
                    inst['denominator'] = copy.deepcopy(denominator)
                if inst['op'] == 'guard':
                    inst['pred'] = B('ne', copy.deepcopy(denominator), C(0))
        packet['certificate']['witness_input']['denominator'] = 0
        packet['certificate']['witness_input']['numerator'] = 1
        for n in (0, 1):
            v, p, cert = instantiated_pair(packet, {'noise_0': n})
            cert['witness_input']['denominator'] = n
            self.assertTrue(check_pair(v, p, cert).accepted)
        result = direct_oracle(packet)
        self.assertTrue(result['semantic_relation'])
        self.assertTrue(result['monitor_consistent'])
        self.assertFalse(result['security_invariant'])
        self.assertEqual(check_transport(packet).reason, 'transport-nuisance-root-flow')


class CartesianOracleScopeTests(unittest.TestCase):
    def test_trailing_root_nop_is_semantically_inert_but_not_the_named_repair(self):
        from rcsc.transport_experiment import oracle_scope_controls
        row=next(item for item in oracle_scope_controls()
                 if item['control']=='patched-root-trailing-nop')
        self.assertTrue(row['semantic_relation'])
        self.assertTrue(row['security_invariant'])
        self.assertTrue(row['monitor_consistent'])
        self.assertFalse(row['repair_membership_precondition'])
        self.assertFalse(row['contract_classification'])
        self.assertFalse(row['production_accepted'])
        self.assertEqual(row['production_reason'],'root-repair-mismatch')

    def test_wrong_family_declaration_fails_monitor_and_repair_components(self):
        from rcsc.transport_experiment import oracle_scope_controls
        row=next(item for item in oracle_scope_controls()
                 if item['control']=='divide-pair-declared-fixed-overflow')
        self.assertFalse(row['semantic_relation'])
        self.assertTrue(row['security_invariant'])
        self.assertFalse(row['monitor_consistent'])
        self.assertFalse(row['repair_membership_precondition'])
        self.assertFalse(row['contract_classification'])
        self.assertFalse(row['production_accepted'])
        self.assertEqual(row['production_reason'],'root-repair-mismatch')
