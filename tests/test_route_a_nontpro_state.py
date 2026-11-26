"""Synthetic abstract-state counterexamples; these do not execute target code."""
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from audit_route_a_nontpro_state import (Analyzer, Pointer, PREMISES, Program, SOURCE_SHA256,
                                        SOURCE_SIZE, State, compare, condition, pinned_program)


BASE = 0x1000
MRS_TPRO = 0xd53b4068
RET = 0xd65f03c0


def words(values):
    return struct.pack('<' + 'I' * len(values), *values)


def branch_link(source, target):
    return 0x94000000 | (((target - source) // 4) & 0x3ffffff)


def cbz(register, source, target):
    return 0x34000000 | ((((target - source) // 4) & 0x7ffff) << 5) | register


def run(values, state=None, assumptions=None, **limits):
    program = Program([('synthetic', BASE, words(values))])
    state = state if state is not None else State(registers={'sp': Pointer('stack', 0)})
    assumptions = assumptions if assumptions is not None else {'ordinary_call_returns': True}
    return Analyzer(program, assumptions, **limits).run(BASE, state)


class ByteStateTests(unittest.TestCase):
    def test_pointer_arithmetic_and_store_interval_overflow_fail_closed(self):
        self.assertIsNone(Pointer('stack', (1 << 63) - 1).add(1))
        self.assertIsNone(Pointer('image', (1 << 64) - 1).add(1))
        self.assertIsNone(Pointer('image', 0).add(-1))
        state = State(registers={'sp': Pointer('stack', 0), 'x8': 0})
        state.store(Pointer('mm', 0x20), 1, 0, BASE)
        self.assertEqual(state.store(Pointer('image', (1 << 64) - 4), 8, 0, BASE + 4),
                         'invalid_store_interval')
        self.assertEqual(state.memory, {})
        with self.assertRaises(ValueError):
            state.store(Pointer('stack', -8), -1, 0, BASE)

    def test_constructor_overlapping_zero_and_byte_stores_preserve_adjacent_hardware(self):
        state, mm = State(), Pointer('stack', -0xd0)
        state.store(mm.add(0x1f), 4, 0, 0x1000)
        state.store(mm.add(0x21), 1, None, 0x1004)
        self.assertEqual(state.load(mm.add(0x20), 1), 0)
        self.assertIsNone(state.load(mm.add(0x21), 1))
        self.assertEqual(state.load(mm.add(0x22), 1), 0)
        self.assertEqual(state.fact(mm.add(0x20), 1)['writes'], ['0x1000'])

    def test_context_pointer_store_does_not_overwrite_protected_stack_zero(self):
        state, mm = State(), Pointer('stack', -0xd0)
        state.store(mm.add(0x28), 16, 0, 0x1000)
        state.store(mm.add(0x28), 8, Pointer('cache_input', 0), 0x1004)
        self.assertEqual(state.load(mm.add(0x28), 8), Pointer('cache_input', 0))
        self.assertEqual(state.load(mm.add(0x30), 8), 0)

    def test_partial_pointer_overwrite_invalidates_pointer_identity(self):
        state, local = State(), Pointer('stack', -8)
        state.store(local, 8, Pointer('mm', 0), 0x1000)
        self.assertEqual(state.load(local, 8), Pointer('mm', 0))
        state.store(local.add(3), 1, 0, 0x1004)
        self.assertIsNone(state.load(local, 8))

    def test_unknown_alias_write_and_external_stack_escape_kill_all_facts(self):
        for target, value, reason in ((None, 0, 'unknown_alias_write'),
                                      (Pointer('image', 0xcc080), Pointer('stack', -0xd0),
                                       'stack_pointer_escape')):
            with self.subTest(reason=reason):
                state = State(registers={'sp': Pointer('stack', 0), 'x8': 0, 'x19': Pointer('stack', -0xd0)})
                state.store(Pointer('stack', -0xb0), 1, 0, 0x1000)
                self.assertEqual(state.store(target, 8, value, 0x1004), reason)
                self.assertEqual(state.memory, {})
                self.assertIsNone(state.get('x8'))
                self.assertIsNone(state.get('x19'))
                self.assertEqual(state.get('sp'), Pointer('stack', 0))

    def test_same_offset_in_different_objects_does_not_alias(self):
        state = State()
        state.store(Pointer('stack', 0x20), 1, 0, 0x1000)
        state.store(Pointer('image', 0x20), 1, 1, 0x1004)
        self.assertEqual(state.load(Pointer('stack', 0x20), 1), 0)
        self.assertEqual(state.load(Pointer('image', 0x20), 1), 1)


class ConditionalFlowTests(unittest.TestCase):
    def test_known_zero_branch_excludes_hazard_in_this_synthetic_frame(self):
        # mov w8,#0; strb/ldrb w8,[x19,#0x20]; cbz; hazard; ret
        state = State(registers={'sp': Pointer('stack', 0), 'x19': Pointer('mm', 0)})
        result = run([0x52800008, 0x39008268, 0x39408268,
                      cbz(8, BASE + 12, BASE + 20), MRS_TPRO, RET], state)
        self.assertEqual(result.reached_hazards, set())
        self.assertEqual(result.returned, 1)
        self.assertEqual(result.branches[0]['taken'], True)

    def test_unknown_call_cannot_preserve_a_known_hardware_flag(self):
        state = State(registers={'sp': Pointer('stack', 0), 'x19': Pointer('mm', 0)})
        result = run([0x52800008, 0x39008268, branch_link(BASE + 8, 0x2000),
                      0x39408268, cbz(8, BASE + 16, BASE + 24), MRS_TPRO, RET], state)
        self.assertEqual(result.reached_hazards, {BASE + 20})
        self.assertIsNone(result.branches[0]['taken'])
        self.assertTrue(any(item['kind'] == 'unresolved_callee' for item in result.events))
        self.assertIsNone(state.load(Pointer('mm', 0x20), 1))

    def test_unknown_call_cannot_preserve_old_comparison_flags(self):
        state = State(registers={'sp': Pointer('stack', 0), 'x0': 0})
        result = run([0x7100001f, branch_link(BASE + 4, 0x2000),
                      0x54000040, MRS_TPRO, RET], state)  # b.eq skips one word
        self.assertEqual(result.reached_hazards, {BASE + 12})
        self.assertIsNone(result.branches[0]['taken'])

    def test_unknown_store_kills_a_previously_loaded_scalar(self):
        state = State(registers={'sp': Pointer('stack', 0), 'x8': 0, 'x0': None})
        result = run([0x39008008, cbz(8, BASE + 4, BASE + 12), MRS_TPRO, RET], state)
        self.assertEqual(result.reached_hazards, {BASE + 8})
        self.assertTrue(any(item['kind'] == 'unknown_alias_write' for item in result.events))

    def test_pointer_escape_kills_previously_loaded_scalar(self):
        state = State(registers={'sp': Pointer('stack', 0), 'x8': 0,
                                 'x19': Pointer('stack', -0xd0), 'x1': Pointer('image', 0xcc080)})
        result = run([0xf9000033, cbz(8, BASE + 4, BASE + 12), MRS_TPRO, RET], state)
        self.assertEqual(result.reached_hazards, {BASE + 8})
        self.assertTrue(any(item['kind'] == 'stack_pointer_escape' for item in result.events))

    def test_unrecognized_instruction_is_not_treated_as_no_effect(self):
        result = run([0xd500401f, RET])  # CFINV, deliberately outside this tiny model.
        self.assertEqual(result.returned, 0)
        self.assertEqual(len(result.unmodeled), 1)

    def test_simd_mov_or_add_alias_cannot_leave_a_stale_q_register_fact(self):
        for word in (0x4ea11c20, 0x4e228420):  # MOV V0.16B,V1.16B; ADD V0.16B,V1.16B,V2.16B
            state = State(registers={'sp': Pointer('stack', 0), 'q0': 0, 'q1': 1, 'q2': 2})
            with self.subTest(word=hex(word)):
                result = run([word, RET], state)
                self.assertEqual(result.returned, 0)
                self.assertTrue(result.unmodeled)
                self.assertIsNone(state.get('q0'))

    def test_shifted_comparison_cannot_be_silently_treated_as_unshifted(self):
        state = State(registers={'sp': Pointer('stack', 0), 'x0': 2, 'x1': 1})
        result = run([0xeb01041f, RET], state)  # CMP X0,X1,LSL #1
        self.assertEqual(result.returned, 0)
        self.assertTrue(result.unmodeled)
        self.assertIsNone(state.flags)

    def test_loop_and_path_budgets_fail_closed(self):
        with self.assertRaisesRegex(ValueError, 'step budget'):
            run([0x14000000], max_steps=8)
        with self.assertRaisesRegex(ValueError, 'state budget'):
            run([cbz(0, BASE, BASE), 0x17ffffff], max_steps=100, max_states=2)

    def test_incomplete_function_bytes_and_branch_outside_program_stay_open(self):
        with self.assertRaises(ValueError):
            Program([('truncated', BASE, b'\0\0\0')])
        result = run([0x14000002])
        self.assertEqual(result.returned, 0)
        self.assertEqual(result.unmodeled[0]['pc'], hex(BASE + 8))

    def test_pauth_or_return_assumptions_are_not_implicit(self):
        result = run([0xd503237f, RET], assumptions={})
        self.assertEqual(result.returned, 0)
        self.assertTrue(result.unmodeled)
        result = run([RET], assumptions={})
        self.assertEqual(result.returned, 0)
        result = run([0xd65f0fff])  # RETAB also requires the PAuth-control premise.
        self.assertEqual(result.returned, 0)
        result = run([0xd65f00a0])  # RET x5 is not an ordinary LR return.
        self.assertEqual(result.returned, 0)

    def test_subtraction_flags_distinguish_unsigned_and_signed_paths(self):
        flags = compare(0xffffffff, 1, 32)
        self.assertTrue(condition(flags, 'hi'))
        self.assertTrue(condition(flags, 'lt'))
        self.assertFalse(condition(flags, 'eq'))


class ConditionalLeafTests(unittest.TestCase):
    def test_lookup_absence_requires_matching_vector_key_and_contract(self):
        target, caller = 0x6e78, BASE
        state = State(registers={'sp': Pointer('stack', 0), 'x0': Pointer('apple', 0),
                                 'x1': 0xa62f7, 'x20': Pointer('mm', 0)})
        state.store(Pointer('mm', 0x20), 1, 0, BASE - 4)
        result = run([branch_link(caller, target), RET], state,
                     {'lookup_readonly': True, 'apple_hw_absent': True, 'ordinary_call_returns': True})
        self.assertEqual(state.get('x0'), 0)
        self.assertEqual(state.load(Pointer('mm', 0x20), 1), 0)
        self.assertTrue(any(item['kind'] == 'conditional_lookup_model' for item in result.events))

    def test_missing_lookup_contract_kills_memory_instead_of_assuming_readonly(self):
        state = State(registers={'sp': Pointer('stack', 0), 'x0': Pointer('apple', 0), 'x1': 0xa62f7})
        state.store(Pointer('mm', 0x20), 1, 0, BASE - 4)
        result = run([branch_link(BASE, 0x6e78), RET], state)
        self.assertIsNone(state.load(Pointer('mm', 0x20), 1))
        self.assertTrue(any(item['kind'] == 'unresolved_callee' for item in result.events))

    def test_syscall_output_aliasing_the_mm_object_cannot_preserve_facts(self):
        program = Program([('synthetic_svc', 0xa9d4, words([0xd4001001, RET]))])
        state = State(registers={'sp': Pointer('stack', -0x150), 'x0': 0, 'x1': 0, 'x2': 0,
                                 'x3': Pointer('stack', -0x148), 'x16': 38})
        state.store(Pointer('stack', -0x148), 8, Pointer('stack', -0xb0), BASE)
        state.store(Pointer('stack', -0xb0), 1, 0, BASE + 4)
        result = Analyzer(program, {'syscall38_bounded': True, 'ordinary_call_returns': True}).run(0xa9d4, state)
        self.assertIsNone(state.load(Pointer('stack', -0xb0), 1))
        self.assertTrue(any(item['kind'] == 'unresolved_syscall' for item in result.events))

    def test_bounded_syscall_only_invalidates_its_distinct_output_byte(self):
        program = Program([('synthetic_svc', 0xa9d4, words([0xd4001001, RET]))])
        output = Pointer('stack', -0x121)
        state = State(registers={'sp': Pointer('stack', -0x150), 'x0': 0, 'x1': 0, 'x2': 0,
                                 'x3': Pointer('stack', -0x148), 'x16': 38})
        state.store(Pointer('stack', -0x148), 8, output, BASE)
        state.store(output, 1, 0, BASE)
        state.store(Pointer('stack', -0xb0), 1, 0, BASE + 4)
        result = Analyzer(program, {'syscall38_bounded': True, 'ordinary_call_returns': True}).run(0xa9d4, state)
        self.assertIsNone(state.load(output, 1))
        self.assertEqual(state.load(Pointer('stack', -0xb0), 1), 0)
        self.assertEqual(state.load(Pointer('stack', -0x148), 8), output)
        self.assertTrue(any(item['kind'] == 'conditional_syscall38_model' for item in result.events))

    def test_real_input_claim_cannot_substitute_unmatched_function_bytes(self):
        class WrongSource:
            identity = {'sha256': SOURCE_SHA256, 'size': SOURCE_SIZE}

            def read(self, address, length):
                return bytes(length)

        with self.assertRaisesRegex(ValueError, 'bytes differ'):
            pinned_program(WrongSource())
        self.assertIn('entry_context', PREMISES)
        self.assertIn('syscall38_bounded', PREMISES)


if __name__ == '__main__':
    unittest.main()
