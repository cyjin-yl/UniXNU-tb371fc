"""Byte-backed entry paths cannot borrow an unexecuted jump-table clamp."""
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from arm64_lowering.proof import _candidate_census, _validate_table_entry_guards
from route_a_zeta import zeta_userland_code as code
from test_route_a_jump_tables import BASE, TABLE, ANCHOR, CMP_ONE, CMP_X9, CSEL, MOV_X9_ONE, fixture


def branch(source, target):
    return 0x14000000 | (((target - source) >> 2) & 0x3FFFFFF)


def adr(register, source, target):
    delta = target - source
    return 0x10000000 | register | ((delta & 3) << 29) | (((delta >> 2) & 0x7FFFF) << 5)


def add_words(insns, data, address, words):
    offset = address - BASE
    struct.pack_into(f'<{len(words)}I', data, offset, *words)
    insns.update(code.decode(data, [dict(addr=address, offset=offset, size=4 * len(words))]))


class JumpTableEntryTests(unittest.TestCase):
    def test_entry_at_the_required_definition_is_allowed(self):
        insns, data, translate, pc = fixture([CMP_ONE, CSEL])
        result = code.walk(insns, data, translate, [BASE], set(), set(), False, set())
        self.assertEqual(result[1][0]['guard_start'], BASE)
        self.assertEqual(result[1][0]['dispatch'], pc)

    def test_direct_dispatch_entry_cannot_borrow_an_earlier_clamp(self):
        insns, data, translate, pc = fixture([CMP_ONE, CSEL])
        with self.assertRaisesRegex(ValueError, 'clamp.*bypassed'):
            code.walk(insns, data, translate, [pc - 20], set(), set(), False, set())

    def test_register_bound_requires_entry_at_its_mov_definition(self):
        insns, data, translate, pc = fixture([MOV_X9_ONE, CMP_X9, CSEL])
        self.assertEqual(code.jump_table(insns, data, translate, pc)['guard_start'], BASE)
        with self.assertRaisesRegex(ValueError, 'clamp.*bypassed'):
            code.walk(insns, data, translate, [BASE + 4], set(), set(), False, set())

    def test_roots_are_not_hidden_by_previously_proven_code(self):
        insns, data, translate, pc = fixture([CMP_ONE, CSEL])
        inside = pc - 20
        alternatives = [dict(weak={inside}), dict(pointers={inside})]
        alternatives += [dict(ordered=[(grade, {inside})]) for grade in ('landing', 'stub', 'call')]
        for changes in alternatives:
            arguments = dict(strong={BASE}, weak=set(), starts={BASE}, pointers=set(), ordered=[])
            arguments.update(changes)
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, 'clamp.*bypassed'):
                code.prove_roots(insns, data, translate, **arguments)

    def test_unadmitted_direct_branch_and_materialized_address_are_potential_entries(self):
        for producer in (branch, lambda source, target: adr(8, source, target)):
            insns, data, translate, pc = fixture([CMP_ONE, CSEL])
            location = BASE + 0x100
            add_words(insns, data, location, [producer(location, pc - 20)])
            with self.subTest(producer=producer.__name__), self.assertRaisesRegex(ValueError, 'clamp.*bypassed'):
                code.walk(insns, data, translate, [BASE], set(), set(), False, set())

    def test_unadmitted_table_targets_are_in_the_initial_entry_superset(self):
        insns, data, translate, pc = fixture([CMP_ONE, CSEL])
        other = BASE + 0x200
        # A second, unvisited table dispatch targets the first dispatch's ADRP.
        words = [CMP_ONE, CSEL, 0xB0000011, 0x91040231, 0xB8B07A30,
                 adr(17, other + 20, ANCHOR), 0x8B100230, 0xD61F0200]
        add_words(insns, data, other, words)
        struct.pack_into('<2i', data, TABLE + 0x100 - BASE, pc - 20 - ANCHOR, 0)
        with self.assertRaisesRegex(ValueError, 'clamp.*bypassed'):
            code.walk(insns, data, translate, [BASE], set(), set(), False, set())

    def test_late_external_root_forces_fresh_proof_to_reject(self):
        insns, data, translate, pc = fixture([CMP_ONE, CSEL])
        result = code.prove_roots(insns, data, translate, {BASE}, set(), {BASE}, set())
        self.assertEqual(len(result[3]), 1)
        with self.assertRaisesRegex(ValueError, 'clamp.*bypassed'):
            code.prove_roots(insns, data, translate, {BASE}, set(), {BASE}, set(),
                             [('call', {pc - 20})])


class CacheTableEntryAdmissionTests(unittest.TestCase):
    """The admission guard scans bytes of both owners; it grants no new roots."""
    def inputs(self, *, target=None, rebased=()):
        _, data, _, pc = fixture([CMP_ONE, CSEL])
        other = BASE + 0x1800
        struct.pack_into('<I', data, other - BASE,
                         branch(other, target) if target is not None else 0xD503201F)

        def locate(address):
            offset = address - BASE
            if offset < 0 or offset >= len(data):
                raise ValueError('outside synthetic cache mapping')
            return 0, offset, len(data) - offset

        cache = SimpleNamespace(images=[], files=[SimpleNamespace(data=data)], locate=locate,
                                slide_targets=lambda: np.array(rebased, dtype=np.uint64))
        bound = [
            (dict(kept={'table': 1}, tables=1, table_dispatches=[pc]),
             dict(address=hex(BASE), file=0, size=0x1100,
                  regions=[dict(address=BASE, offset=0, size=0x1100)])),
            (dict(kept={}, tables=0, table_dispatches=[]),
             dict(address=hex(other), file=0, size=4,
                  regions=[dict(address=other, offset=other - BASE, size=4)])),
        ]
        return cache, bound, {BASE: (BASE,), other: ()}, pc

    def test_cross_owner_unadmitted_branch_disqualifies_a_claimed_table(self):
        cache, bound, roots, _ = self.inputs(target=BASE + 8)
        with self.assertRaisesRegex(ValueError, 'static-entry bypass'):
            _validate_table_entry_guards(cache, bound, roots)

    def test_cross_owner_branch_to_the_definition_is_safe(self):
        cache, bound, roots, _ = self.inputs(target=BASE)
        _validate_table_entry_guards(cache, bound, roots)

    def test_slide_pointer_into_the_guard_disqualifies_a_claim(self):
        cache, bound, roots, _ = self.inputs(rebased=(BASE + 8,))
        with self.assertRaisesRegex(ValueError, 'rebased-pointer bypass'):
            _validate_table_entry_guards(cache, bound, roots)

    def test_final_closure_roots_participate_in_admission(self):
        cache, bound, roots, _ = self.inputs()
        roots[BASE] += (BASE + 8,)
        with self.assertRaisesRegex(ValueError, 'static-entry bypass'):
            _validate_table_entry_guards(cache, bound, roots)

    def test_zero_kept_table_still_requires_cross_owner_guard_admission(self):
        cache, bound, roots, _ = self.inputs(target=BASE + 8)
        bound[0][0]['kept'] = {}
        with self.assertRaisesRegex(ValueError, 'static-entry bypass'):
            _validate_table_entry_guards(cache, bound, roots)

    def test_zero_kept_table_still_requires_rebased_pointer_guard_admission(self):
        cache, bound, roots, _ = self.inputs(rebased=(BASE + 8,))
        bound[0][0]['kept'] = {}
        with self.assertRaisesRegex(ValueError, 'rebased-pointer bypass'):
            _validate_table_entry_guards(cache, bound, roots)

    def test_zero_kept_dispatch_count_must_still_match(self):
        cache, bound, _, _ = self.inputs()
        entry, geometry = bound[0]
        entry['kept'] = {}
        entry['tables'] = 0
        edits = np.zeros((0, 5), dtype=np.uint64)
        kept = np.zeros((0, 3), dtype=np.uint64)
        with self.assertRaisesRegex(ValueError, 'jump-table count differs'):
            _candidate_census(cache, 0, geometry, entry, edits, kept)


if __name__ == '__main__':
    unittest.main()
