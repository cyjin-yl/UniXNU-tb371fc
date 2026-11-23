"""Instruction correctness checks with independent LLVM assembler golden words.

Reference: LLVM D36517's armv8.3a-signed-pointer.s/.txt and encoding definitions,
https://reviews.llvm.org/D36517 . The fixture contains instruction encodings, not
Apple executables. Run with ``python3 -m unittest discover -s tests -p
test_route_a_instructions.py`` from the repository root.
"""

import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from arm64_lowering.instructions import LoweringError, describe, lower


class InstructionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = ROOT / "tests" / "fixtures" / "route_a_instruction_vectors.json"
        cls.vectors = json.loads(fixture.read_text())["vectors"]

    def test_llvm_golden_vectors(self):
        for v in self.vectors:
            with self.subTest(assembly=v["assembly"]):
                word = int(v["word"], 16)
                info = describe(word)
                self.assertIsNotNone(info)
                self.assertEqual(info["mnemonic"], v["assembly"].split()[0].upper())
                self.assertFalse(info["authentication_preserved"])
                if "replacement" in v:
                    self.assertEqual(lower(word, plain_pointers=True),
                                     (info["mnemonic"], int(v["replacement"], 16)))
                else:
                    self.assertFalse(info["supported"])
                    with self.assertRaises(LoweringError) as caught:
                        lower(word, plain_pointers=True)
                    self.assertEqual(caught.exception.reason, v["reject"])

    def test_contract_is_required_even_for_strip_and_hints(self):
        for v in self.vectors:
            word = int(v["word"], 16)
            if describe(word)["supported"]:
                with self.subTest(assembly=v["assembly"]):
                    with self.assertRaises(LoweringError) as caught:
                        lower(word)
                    self.assertEqual(caught.exception.reason, "plain_pointer_abi_not_asserted")

    def test_ordinary_instructions_and_unallocated_neighbors_are_untouched(self):
        words = [
            0xD503201F, 0xD503203F, 0xD65F03C0, 0xD61F0000, 0xD63F03C0,
            0xAA0003E0, 0xF9400020, 0xF8400020, 0xF8400C20,
            0xDAC12000, 0xDAC14000,  # invalid Rn in zero/strip encodings
            0xD61F0800, 0xD63F0C00,  # invalid Rm in zero-modifier branches
            0xD65F0BFE, 0xD69F0FFE,  # not authenticated return encodings
            0xF8000400, 0xF8200000,  # neighboring load class, required bit absent
            0x9AC03400, 0x9AE03000,  # not PACGA
        ]
        for word in words:
            with self.subTest(word=hex(word)):
                self.assertIsNone(describe(word))
                self.assertIsNone(lower(word))

    def test_authenticated_branches_preserve_every_target_and_call_kind(self):
        families = [
            (0xD71F0800, 0xD61F0000, False), (0xD71F0C00, 0xD61F0000, False),
            (0xD73F0800, 0xD63F0000, False), (0xD73F0C00, 0xD63F0000, False),
            (0xD61F081F, 0xD61F0000, True), (0xD61F0C1F, 0xD61F0000, True),
            (0xD63F081F, 0xD63F0000, True), (0xD63F0C1F, 0xD63F0000, True),
        ]
        for opcode, replacement, zero in families:
            for target in range(32):
                for modifier in ([31] if zero else range(32)):
                    word = opcode | (target << 5) | modifier
                    info = describe(word)
                    self.assertEqual(info["operands"]["target"], target)
                    self.assertEqual(lower(word, plain_pointers=True)[1],
                                     replacement | (target << 5))
        # BLRAAZ X30 must become BLR X30. Ordinary BLR reads the old target
        # before writing LR=PC+4; using an ad-hoc MOV-to-LR sequence would fail.
        self.assertEqual(lower(0xD63F0BDF, plain_pointers=True)[1], 0xD63F03C0)

    def test_zero_forms_reject_every_reserved_modifier(self):
        for base in (0xDAC12000, 0xDAC12400, 0xDAC12800, 0xDAC12C00,
                     0xDAC13000, 0xDAC13400, 0xDAC13800, 0xDAC13C00,
                     0xDAC14000, 0xDAC14400):
            for modifier in range(31):
                for destination in (0, 17, 31):
                    self.assertIsNone(describe(base | (modifier << 5) | destination))

    def test_all_scaled_load_offsets_preserve_effective_address(self):
        # Independent decoder for *ordinary* A64 LDR/LDUR output. It checks
        # byte offsets rather than mirroring how input LDRA bits are unpacked.
        for key_b in (False, True):
            for writeback in (False, True):
                for units in range(-512, 512):
                    raw = units & 0x3FF
                    word = (0xF8200420 | (int(key_b) << 23) |
                            ((raw >> 9) << 22) | ((raw & 511) << 12) |
                            (int(writeback) << 11))
                    offset = units * 8
                    info = describe(word)
                    self.assertEqual(info["operands"]["offset"], offset)
                    fits = (-256 <= offset <= 255) if writeback else offset >= -256
                    self.assertEqual(info["supported"], fits)
                    if not fits:
                        with self.assertRaises(LoweringError):
                            lower(word, plain_pointers=True)
                        continue
                    output = lower(word, plain_pointers=True)[1]
                    self.assertEqual(output & 0x3FF, 0x20)
                    if output & 0xFFC00000 == 0xF9400000:
                        self.assertFalse(writeback)
                        decoded_offset = ((output >> 10) & 0xFFF) * 8
                    else:
                        self.assertEqual(output & 0xFFE00C00,
                                         0xF8400C00 if writeback else 0xF8400000)
                        decoded_offset = (output >> 12) & 511
                        if decoded_offset >= 256:
                            decoded_offset -= 512
                    self.assertEqual(decoded_offset, offset)

    def test_writeback_overlap_is_not_silently_given_defined_semantics(self):
        for register in range(31):
            word = 0xF8200C00 | (register << 5) | register
            self.assertEqual(describe(word)["reason"],
                             "constrained_unpredictable_writeback_overlap")
            with self.assertRaises(LoweringError):
                lower(word, plain_pointers=True)
        # Base 31 is SP, destination 31 is XZR: these are different registers.
        self.assertEqual(lower(0xF8200FFF, plain_pointers=True)[1], 0xF8400FFF)

    def test_pacga_never_becomes_a_constant_or_an_implicit_hash(self):
        for destination in (0, 17, 31):
            for source in (0, 17, 31):
                for modifier in (0, 17, 31):
                    word = 0x9AC03000 | (modifier << 16) | (source << 5) | destination
                    info = describe(word)
                    self.assertEqual(info["operands"]["modifier_is_sp"], modifier == 31)
                    self.assertEqual(info["operands"]["source_is_zero"], source == 31)
                    with self.assertRaises(LoweringError):
                        lower(word, plain_pointers=True)
        with self.assertRaises(ValueError):
            lower(0x9AC23020, plain_pointers=True, pacga_policy="zero")

    def test_hints_keep_their_original_encoding(self):
        for v in self.vectors:
            word = int(v["word"], 16)
            if describe(word)["family"] == "hint":
                self.assertEqual(lower(word, plain_pointers=True)[1], word)

    def test_input_validation(self):
        for bad in (-1, 1 << 32):
            with self.assertRaises(ValueError):
                describe(bad)
        for bad in (True, 1.0, "0xd503201f", None):
            with self.assertRaises(TypeError):
                describe(bad)
        with self.assertRaises(TypeError):
            lower(0xD503201F, plain_pointers=1)


if __name__ == "__main__":
    unittest.main()
