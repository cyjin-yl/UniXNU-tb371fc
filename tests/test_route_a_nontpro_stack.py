"""Synthetic leaf-composition negatives; no target program is executed."""
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from audit_route_a_nontpro_state import Analyzer, Pointer, Program, SOURCE_SHA256, SOURCE_SIZE, State
from audit_route_a_nontpro_stack import (CONFIG, MM, RUNTIME, OPEN_GATES, STACK_PINS, STACK_PREMISES,
                                        ReturnStates, compose_stack_contract, pinned_stack_program)

RET = 0xd65f03c0
ALL_PREMISES = dict.fromkeys(STACK_PREMISES, True)


def movw(register, value):
    return 0x52800000 | (value << 5) | register


def loadx(register, base, offset=0):
    return 0xf9400000 | ((offset // 8) << 10) | (base << 5) | register


def storex(register, base, offset=0):
    return 0xf9000000 | ((offset // 8) << 10) | (base << 5) | register


def cbnz(register, source, target):
    return 0xb5000000 | ((((target - source) // 4) & 0x7ffff) << 5) | register


def bl(source, target):
    return 0x94000000 | (((target - source) // 4) & 0x3ffffff)


def synthetic_program(**replace):
    # Independent tiny fixtures at the composition interface's fixed entries.
    # They do not reproduce any complete private-input function body.
    query = STACK_PINS['stack_query'][0]
    process = STACK_PINS['process_constructor'][0]
    process_words = [0xd503201f] * ((0x1ffdc - process) // 4)
    process_words += [0xaa1303e0, 0x940004a1, 0x39040660]
    constructor = STACK_PINS['stack_constructor'][0]
    constructor_words = [0x35000000 | (10 << 5) | 1]  # CBNZ W1 to the opaque enable call.
    constructor_words += [storex(31, 0, offset) for offset in range(0, 64, 8)]
    constructor_words += [RET, bl(constructor + 40, 0x70000), RET]
    runtime = STACK_PINS['runtime_constructor'][0]
    runtime_words = [0xa9be4ff4, 0xa9017bfd, 0xaa0003f3, storex(1, 0, 8),
                     0x39444421, 0x9113e000, 0xdac10a30, 0xdac10e11]
    runtime_words += [0xd503201f] * (((0x3c7d4 - runtime) // 4) - len(runtime_words))
    runtime_words += [bl(0x3c7d4, constructor), 0xaa1303e0, 0xa9417bfd, 0xa8c24ff4, RET]
    definitions = {
        'process_constructor': process_words,
        'default_stack_policy': [movw(0, 0), RET],
        'runtime_constructor': runtime_words,
        'stack_constructor': constructor_words,
        'install_stack': [storex(1, 0, 0x30), RET],
        'stack_query': [loadx(8, 0), cbnz(8, query + 4, query + 24),
                        loadx(8, 0, 0x18), cbnz(8, query + 12, query + 24),
                        movw(0, 0), RET, movw(0, 1), RET],
    }
    definitions.update(replace)
    return Program([(name, STACK_PINS[name][0], struct.pack('<' + 'I' * len(words), *words))
                    for name, words in definitions.items()])


class DisabledStackCompositionTests(unittest.TestCase):
    def test_complete_synthetic_sequence_retains_exact_nonnull_object_identity(self):
        result = compose_stack_contract(synthetic_program(), ALL_PREMISES)
        self.assertEqual(result['status'], 'conditional_disabled_stack_binding')
        self.assertEqual(len(result['phases']), 5)
        self.assertTrue(result['postconditions']['published_mm_protected_stack_nonnull'])
        self.assertTrue(result['postconditions']['query_returns_false'])
        final = result['phases'][-1]['post_states'][0]
        self.assertEqual(final['installed_pointer']['value'], {'object': 'runtime_state', 'offset': 0x4f8})
        self.assertEqual(final['hardware']['value'], '0x0')
        self.assertTrue(final['all_64_stack_bytes_zero'])
        self.assertEqual(final['process_policy_byte']['value'], '0x0')
        self.assertEqual(final['process_policy_byte']['writes'], ['0x1ffe4'])
        self.assertTrue(all(result[gate] is False for gate in OPEN_GATES))

    def test_each_missing_premise_prevents_composition(self):
        for missing in STACK_PREMISES:
            with self.subTest(missing=missing):
                assumptions = dict(ALL_PREMISES)
                assumptions[missing] = False
                result = compose_stack_contract(synthetic_program(), assumptions)
                self.assertEqual(result['status'], 'unresolved')
                self.assertEqual(result['phases'], [])
                self.assertIn(missing, result['unresolved'][0]['premises'])

    def test_unknown_or_nonboolean_premise_is_rejected(self):
        for assumptions in ({**ALL_PREMISES, 'runtime_is_ready': True},
                            {**ALL_PREMISES, 'apple_hw_absent': 1}):
            with self.subTest(assumptions=assumptions), self.assertRaises(ValueError):
                compose_stack_contract(synthetic_program(), assumptions)

    def test_enabled_policy_return_cannot_be_used_as_disabled_constructor_input(self):
        result = compose_stack_contract(synthetic_program(default_stack_policy=[movw(0, 1), RET]), ALL_PREMISES)
        self.assertEqual(result['status'], 'unresolved')
        self.assertEqual(result['unresolved'][0]['phase'], 'default_stack_policy')
        self.assertEqual(len(result['phases']), 1)

    def test_unknown_policy_result_is_not_boolean_false(self):
        result = compose_stack_contract(synthetic_program(default_stack_policy=[loadx(0, 0, 8), RET]), ALL_PREMISES)
        self.assertEqual(result['status'], 'unresolved')
        self.assertEqual(result['unresolved'][0]['phase'], 'default_stack_policy')

    def test_partial_constructor_zeroing_cannot_claim_complete_object(self):
        constructor = [storex(31, 0, offset) for offset in range(0, 56, 8)] + [RET]
        result = compose_stack_contract(synthetic_program(stack_constructor=constructor), ALL_PREMISES)
        self.assertEqual(result['status'], 'unresolved')
        self.assertEqual(result['unresolved'][0]['phase'], 'runtime_constructor')
        self.assertFalse(result['phases'][-1]['post_states'][0]['all_64_stack_bytes_zero'])

    def test_unknown_callee_blocks_even_if_later_stores_restore_zero_bytes(self):
        start = STACK_PINS['stack_constructor'][0]
        # Preserve the object's address in a callee-saved register, perform an
        # opaque call, then restore and zero the object. The unknown call itself
        # remains an open obligation; a final-byte comparison cannot erase it.
        constructor = [0xaa0003f3, bl(start + 4, 0x70000), 0xaa1303e0]
        constructor += [storex(31, 0, offset) for offset in range(0, 64, 8)] + [RET]
        result = compose_stack_contract(synthetic_program(stack_constructor=constructor), ALL_PREMISES)
        self.assertEqual(result['status'], 'unresolved')
        last = result['phases'][-1]
        self.assertTrue(last['post_states'][0]['all_64_stack_bytes_zero'])
        self.assertFalse(last['local_effects_closed_under_premises'])
        self.assertTrue(any(event['kind'] == 'unresolved_callee' for event in last['events']))

    def test_publication_to_adjacent_runtime_subobject_is_rejected(self):
        install = [0x91002021, storex(1, 0, 0x30), RET]  # ADD X1,X1,#8
        result = compose_stack_contract(synthetic_program(install_stack=install), ALL_PREMISES)
        self.assertEqual(result['status'], 'unresolved')
        self.assertEqual(result['unresolved'][0]['phase'], 'install_stack')

    def test_publication_cannot_reenable_hardware_flag(self):
        install = [storex(1, 0, 0x30), movw(2, 1), 0x39008002, RET]  # STRB W2,[X0,#0x20]
        result = compose_stack_contract(synthetic_program(install_stack=install), ALL_PREMISES)
        self.assertEqual(result['status'], 'unresolved')
        self.assertEqual(result['unresolved'][0]['phase'], 'install_stack')
        self.assertEqual(result['phases'][-1]['post_states'][0]['hardware']['value'], '0x1')

    def test_query_must_actually_return_false(self):
        result = compose_stack_contract(synthetic_program(stack_query=[movw(0, 1), RET]), ALL_PREMISES)
        self.assertEqual(result['status'], 'unresolved')
        self.assertEqual(result['unresolved'][0]['phase'], 'stack_query')

    def test_unknown_alias_writer_during_query_kills_the_composed_invariant(self):
        result = compose_stack_contract(synthetic_program(stack_query=[storex(31, 2), movw(0, 0), RET]), ALL_PREMISES)
        self.assertEqual(result['status'], 'unresolved')
        self.assertTrue(any(event['kind'] == 'unknown_alias_write'
                            for event in result['phases'][-1]['events']))

    def test_a_terminal_exception_alternative_is_not_a_total_leaf_contract(self):
        query = STACK_PINS['stack_query'][0]
        body = [cbnz(2, query, query + 12), movw(0, 0), RET, 0xd4200020]
        result = compose_stack_contract(synthetic_program(stack_query=body), ALL_PREMISES)
        self.assertEqual(result['status'], 'unresolved')
        self.assertFalse(result['phases'][-1]['local_effects_closed_under_premises'])

    def test_unsupported_return_target_cannot_be_counted_by_return_observer(self):
        result = compose_stack_contract(synthetic_program(stack_query=[movw(0, 0), 0xd65f00a0]), ALL_PREMISES)
        self.assertEqual(result['status'], 'unresolved')
        self.assertTrue(result['phases'][-1]['unmodeled'])

    def test_outgoing_edge_outside_supplied_bytes_keeps_composition_open(self):
        result = compose_stack_contract(synthetic_program(stack_query=[0x14000002]), ALL_PREMISES)
        self.assertEqual(result['status'], 'unresolved')
        self.assertTrue(result['phases'][-1]['unmodeled'])

    def test_production_entry_rejects_forged_input_identity_with_unmatched_bytes(self):
        class ForgedSource:
            identity = {'sha256': SOURCE_SHA256, 'size': SOURCE_SIZE}

            def read(self, address, length):
                return bytes(length)

        with self.assertRaisesRegex(ValueError, 'bytes differ'):
            pinned_stack_program(ForgedSource())

    def test_policy_store_requires_exact_preserved_process_pointer(self):
        policy = [movw(0, 0), 0xd2800013, RET]  # MOV X19,#0 destroys caller identity.
        result = compose_stack_contract(synthetic_program(default_stack_policy=policy), ALL_PREMISES)
        self.assertEqual(result['status'], 'unresolved')
        self.assertEqual(result['unresolved'][0]['phase'], 'process_policy_publication')

    def test_wrong_process_store_instruction_is_not_accepted_as_an_equivalent_offset(self):
        process = STACK_PINS['process_constructor'][0]
        body = [0xd503201f] * ((0x1ffdc - process) // 4)
        body += [0xaa1303e0, 0x940004a1, 0x39040a60]  # STRB to +0x102, not +0x101.
        with self.assertRaisesRegex(ValueError, 'call/store edge bytes changed'):
            compose_stack_contract(synthetic_program(process_constructor=body), ALL_PREMISES)

    def test_identical_callee_target_at_another_call_site_is_opaque(self):
        start = STACK_PINS['runtime_constructor'][0]
        result = compose_stack_contract(synthetic_program(runtime_constructor=[bl(start, 0x3cb2c), RET]), ALL_PREMISES)
        self.assertEqual(result['status'], 'unresolved')
        self.assertTrue(any(event['kind'] == 'unresolved_callee' for event in result['phases'][-1]['events']))

    def test_data_signing_form_requires_exact_owner_word_and_explicit_premise(self):
        start = STACK_PINS['runtime_constructor'][0]
        for address, word, enabled in ((start, 0xdac10a10, True), (0x1000, 0xdac10a30, True),
                                       (start, 0xdac10a30, False)):
            with self.subTest(address=hex(address), word=hex(word), enabled=enabled):
                program = Program([('synthetic', address, struct.pack('<II', word, RET))])
                state = State(registers={'sp': Pointer('stack', 0), 'x16': 123, 'x17': 456})
                result = ReturnStates(program, {**ALL_PREMISES, 'data_signing_effects': enabled}).run(address, state)
                self.assertTrue(result.unmodeled)
                self.assertEqual(result.returned, 0)

    def test_hardware_zero_does_not_override_an_enabled_config_stack_byte(self):
        state = State(registers={'sp': Pointer('stack', 0), 'x0': RUNTIME, 'x1': CONFIG})
        state.store(MM.add(0x20), 1, 0, None)
        state.store(CONFIG.add(0x111), 1, 1, None)
        result = ReturnStates(synthetic_program(), ALL_PREMISES).run(0x3c4a8, state)
        self.assertTrue(any(branch['pc'] == '0x3cb2c' and branch['taken'] is True
                            for branch in result.branches))
        self.assertTrue(any(event['kind'] == 'unresolved_callee' and event['target'] == '0x70000'
                            for event in result.events))

    def test_constructor_store_past_runtime_allocation_does_not_close(self):
        body = [storex(31, 0, offset) for offset in range(0, 64, 8)]
        body += [storex(31, 0, 64), RET]
        result = compose_stack_contract(synthetic_program(stack_constructor=body), ALL_PREMISES)
        self.assertEqual(result['status'], 'unresolved')
        self.assertTrue(any(event['kind'] == 'unresolved_object_access'
                            for event in result['phases'][-1]['events']))

    def test_unused_query_load_outside_live_object_is_still_unresolved(self):
        result = compose_stack_contract(synthetic_program(stack_query=[loadx(8, 0, 64), movw(0, 0), RET]), ALL_PREMISES)
        self.assertEqual(result['status'], 'unresolved')
        self.assertTrue(any(event['kind'] == 'unresolved_object_access'
                            for event in result['phases'][-1]['events']))

    def test_base_interpreter_does_not_acquire_subclass_data_signing_semantics(self):
        start = STACK_PINS['runtime_constructor'][0]
        program = Program([('synthetic', start, struct.pack('<II', 0xdac10a30, RET))])
        state = State(registers={'sp': Pointer('stack', 0)})
        result = Analyzer(program, ALL_PREMISES).run(start, state)
        self.assertTrue(result.unmodeled)
        self.assertEqual(result.returned, 0)


if __name__ == '__main__':
    unittest.main()
