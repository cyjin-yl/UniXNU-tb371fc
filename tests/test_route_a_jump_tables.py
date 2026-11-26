"""Real AArch64 words exercise the reaching values used by jump-table discovery.

These fixtures contain no Apple binaries. MOV/ADD/CMP encodings and the
expected index bounds are independent of the recognizer's textual search.
"""
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from route_a_zeta import zeta_userland_code as code

BASE, TABLE, ANCHOR = 0x1000, 0x2000, 0x3000
CMP_ONE, CMP_X9 = 0xF100061F, 0xEB09021F
CSEL, CSNEG = 0x9A9F9210, 0xDA9F9610
MOV_X16_TWO, MOV_W16_TWO = 0xD2800050, 0x52800050
MOV_X9_ONE, MOV_W9_ONE = 0xD2800029, 0x52800029
ADD_X8_ONE, ADD_X9_ONE, ADD_W9_ONE = 0x91000508, 0x91000529, 0x11000529
NOP = 0xD503201F


def fixture(prefix, entries=3):
    """A byte-backed clamp/dispatch and a relative-offset table."""
    dispatch = BASE + 4 * len(prefix)
    adr_at = dispatch + 12
    displacement = ANCHOR - adr_at
    adr = 0x10000011 | ((displacement & 3) << 29) | (((displacement >> 2) & 0x7FFFF) << 5)
    words = list(prefix) + [0xB0000011, 0x91000231, 0xB8B07A30, adr, 0x8B100230, 0xD61F0200]
    data = bytearray(max(0x3000, TABLE - BASE + 4 * entries))
    struct.pack_into(f'<{len(words)}I', data, 0, *words)
    struct.pack_into(f'<{entries}i', data, TABLE - BASE, *range(0, 4 * entries, 4))

    def va_to_off(address, length):
        offset = address - BASE
        if offset < 0 or offset + length > len(data):
            raise ValueError('fixture address outside mapping')
        return offset

    insns = code.decode(data, [dict(offset=0, addr=BASE, size=4 * len(words))])
    return insns, data, va_to_off, dispatch + 20


class JumpTableReachingValueTests(unittest.TestCase):
    def table(self, prefix, entries=3):
        return code.jump_table(*fixture(prefix, entries))

    def test_immediate_clamps(self):
        for selection in (CSEL, CSNEG):
            with self.subTest(selection=hex(selection)):
                table = self.table([CMP_ONE, selection])
                self.assertEqual(table['entries'], 2)
                self.assertEqual(table['targets'], [ANCHOR, ANCHOR + 4])

    def test_scheduled_register_reads_and_unrelated_writes_are_allowed(self):
        # ADD x8 preserves flags; STR reads x16, but does not replace the index.
        table = self.table([MOV_X9_ONE, ADD_X8_ONE, CMP_X9, ADD_X8_ONE,
                            CSEL, 0xF90003F0])  # str x16, [sp]
        self.assertEqual(table['entries'], 2)

    def test_flags_before_cmp_or_after_selection_are_irrelevant(self):
        equal = 0xEB1F03FF  # cmp xzr, xzr
        self.assertEqual(self.table([MOV_X9_ONE, equal, CMP_X9, CSEL, equal])['entries'], 2)

    def test_w_register_constant_zero_extends_into_x_register_bound(self):
        for constant in (MOV_X9_ONE, MOV_W9_ONE):
            with self.subTest(constant=hex(constant)):
                self.assertEqual(self.table([constant, CMP_X9, CSEL])['entries'], 2)

    def test_zero_register_bound_has_one_entry(self):
        # A write to XZR is discarded; it cannot establish a nonzero bound.
        self.assertEqual(self.table([0xD280003F, 0xEB1F021F, CSEL])['entries'], 1)

    def test_shifted_immediate_bound(self):
        self.assertEqual(self.table([0xF140061F, CSEL], entries=4097)['entries'], 4097)

    def test_index_clobber_after_selection_is_rejected(self):
        for write in (MOV_X16_TWO, MOV_W16_TWO, 0xF9400110):  # ldr x16, [x8]
            with self.subTest(write=hex(write)):
                self.assertIsNone(self.table([CMP_ONE, CSEL, write]))

    def test_index_clobber_between_compare_and_selection_is_rejected(self):
        for write in (MOV_X16_TWO, MOV_W16_TWO):
            with self.subTest(write=hex(write)):
                self.assertIsNone(self.table([CMP_ONE, write, CSEL]))

    def test_nzcv_clobber_between_compare_and_selection_is_rejected(self):
        # CMP; ADDS to an unrelated GPR; FCMP; MSR NZCV; CFINV/XAFLAG/AXFLAG.
        # The last three expose missing implicit writes in Capstone 5.0.6.
        # Fixed LLVM llvmorg-19.1.7 vectors: armv8.4a-flag.s / armv8.5a-altnzcv.s.
        for write in (0xEB1F03FF, 0xB1000508, 0x1E602000, 0xD51B4200,
                      0xD500401F, 0xD500403F, 0xD500405F):
            with self.subTest(write=hex(write)):
                self.assertIsNone(self.table([CMP_ONE, write, CSEL]))

    def test_register_bound_clobber_is_rejected_in_both_register_views(self):
        for write in (ADD_X9_ONE, ADD_W9_ONE, 0xF9400109):  # ldr x9, [x8]
            with self.subTest(write=hex(write)):
                self.assertIsNone(self.table([MOV_X9_ONE, write, CMP_X9, CSEL]))

    def test_memory_base_writeback_is_a_register_write(self):
        # str x8, [x16, #8]! and str x8, [x9, #8]!
        self.assertIsNone(self.table([CMP_ONE, CSEL, 0xF8008E08]))
        self.assertIsNone(self.table([MOV_X9_ONE, 0xF8008D28, CMP_X9, CSEL]))

    def test_control_transfer_or_exception_cannot_be_crossed(self):
        for word in (0x14000001, 0x94000001, 0x54000020, 0x35000020,
                     0x36000020, 0xD65F03C0, 0xD4000001, 0xD4200000,
                     0xD5233063, 0xD5233164, 0xD503307F, 0xD4624680):
            for prefix in ([CMP_ONE, CSEL, word], [CMP_ONE, word, CSEL],
                           [MOV_X9_ONE, word, CMP_X9, CSEL]):
                with self.subTest(word=hex(word), prefix=prefix):
                    self.assertIsNone(self.table(prefix))

    def test_unknown_or_missing_effects_fail_closed(self):
        self.assertIsNone(self.table([CMP_ONE, CSEL, 0xFFFFFFFF]))
        insns, data, translate, pc = fixture([CMP_ONE, CSEL, NOP])
        del insns[BASE + 8]
        self.assertIsNone(code.jump_table(insns, data, translate, pc))

    def test_effects_come_from_actual_words(self):
        insns, data, translate, pc = fixture([CMP_ONE, CSEL, MOV_X16_TWO])
        insns[BASE + 8] = ('nop', '')
        self.assertIsNone(code.jump_table(insns, data, translate, pc))

    def test_unmodeled_transaction_control_does_not_fall_through(self):
        # Fixed LLVM llvmorg-19.1.7/llvm/test/MC/AArch64/tme.s encodings.
        for word in (0xD5233063, 0xD5233164, 0xD503307F, 0xD4624680):
            with self.subTest(word=hex(word)):
                data = struct.pack('<3I', word, 0xD65F0FFF, 0xD65F03C0)
                insns = code.decode(data, [dict(offset=0, addr=BASE, size=len(data))])
                self.assertTrue(insns[BASE][0].startswith('.unmodeled-'))
                translate = lambda address, size: address - BASE
                result = code.walk(insns, data, translate, [BASE], set(), set(), False, set())
                self.assertNotIn(BASE + 4, result[0])
                self.assertTrue(result[2])
                self.assertIsNone(code.walk(insns, data, translate, [BASE], set(), set(), True, set()))


if __name__ == '__main__':
    unittest.main()
