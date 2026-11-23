"""Synthetic dyld CFG coverage; no Apple executable is included or executed.

TCHANGE golden words come from LLVM's llvm/test/MC/AArch64/arm-poe2.s,
git blob dbed9ba599067923194b15c63e365c8a4f2d38e6. These tests establish
decoding and unchanged control-flow admission, not POE2 emulation on A77.

https://github.com/llvm/llvm-project/blob/main/llvm/test/MC/AArch64/arm-poe2.s
Fall-through evidence is LLVM's TCHANGERegInst/TCHANGEImmInst -> I -> EncodedI
-> AArch64Inst -> Instruction inheritance, without overrides of Instruction's
false branch/call/return/terminator flags. The production decoder cites the
three TableGen files at commit 8ac298779c251819b6bab7739464547ee014aabd;
scripts/route_a_zeta/README.md records their source hashes.
"""

import hashlib
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from arm64_lowering.macho import parse_macho
from arm64_lowering.pipeline import rewrite_userland, verify_code_pages
from route_a_zeta import zeta_userland_code as proof
from test_route_a_pipeline import signed_fixture


GOLDEN_POE2 = (
    (0xD5800020, "tchangef", "x0, x1"),
    (0xD5820020, "tchangef", "x0, x1, nb"),
    (0xD5900061, "tchangef", "x1, #3"),
    (0xD5920061, "tchangef", "x1, #3, nb"),
    (0xD5840020, "tchangeb", "x0, x1"),
    (0xD5860020, "tchangeb", "x0, x1, nb"),
    (0xD5940121, "tchangeb", "x1, #9"),
    (0xD5960121, "tchangeb", "x1, #9, nb"),
)


def synthetic_dyld(words):
    """Create MH_DYLINKER with an ARM_THREAD_STATE64 LC_UNIXTHREAD entry."""
    data = bytearray(signed_fixture(words))
    commands, at = [], 32
    for _ in range(struct.unpack_from("<I", data, 16)[0]):
        command, size = struct.unpack_from("<II", data, at)
        blob = bytes(data[at:at + size])
        if command == 0x80000028:
            thread = bytearray(288)
            struct.pack_into("<4I", thread, 0, 5, 288, 6, 68)
            struct.pack_into("<Q", thread, 16 + 32 * 8, 0x100000400)
            blob = bytes(thread)
        commands.append(blob)
        at += size
    blob = b"".join(commands)
    assert 32 + len(blob) <= 0x400
    data[32:32 + len(blob)] = blob
    struct.pack_into("<I", data, 12, 7)
    struct.pack_into("<I", data, 20, len(blob))
    signature = parse_macho(data).code_signature
    directory = signature["offset"] + 20
    hash_offset = struct.unpack_from(">I", data, directory + 16)[0]
    data[directory + hash_offset:directory + hash_offset + 32] = hashlib.sha256(
        data[:signature["offset"]]).digest()
    return bytes(data)


def weak_graph(*, unknown=False, roots=True):
    """A weak caller reaches a TCHANGE-containing weak callee by BL."""
    words = (0xD503237F, 0x94000003, 0xD65F0FFF, 0xD4200000,
             0xD5901000 if unknown else 0xD5900040, 0xD5940000, 0xD65F0FFF)
    data = struct.pack("<7I", *words)
    section = {"offset": 0, "size": len(data), "addr": 0x1000}
    insns = proof.decode(data, [section])
    starts = {0x1000, 0x1010} if roots else set()
    return proof.prove_roots(insns, data, lambda address, size: address - 0x1000,
                             set(), starts, starts, set())


class DyldRootsTests(unittest.TestCase):
    def test_official_llvm_poe2_encoding_vectors(self):
        for word, mnemonic, operands in GOLDEN_POE2:
            with self.subTest(word=hex(word)):
                self.assertEqual(proof.poe2_instruction(word), (mnemonic, operands))
        self.assertEqual(proof.poe2_instruction(0xD5900040), ("tchangef", "x0, #2"))
        self.assertEqual(proof.poe2_instruction(0xD5940000), ("tchangeb", "x0, #0"))
        self.assertEqual(proof.poe2_instruction(0xD5960FFF), ("tchangeb", "xzr, #127, nb"))

    def test_fixed_bits_do_not_admit_reserved_neighbors_or_other_instructions(self):
        for word in (0xD5800400, 0xD5840800, 0xD5901000, 0xD5942000,
                     0xD5904000, 0xD65F0FFF, 0xD503201F, 0x03020100):
            with self.subTest(word=hex(word)):
                self.assertIsNone(proof.poe2_instruction(word))

    def test_existing_strict_walk_accepts_weak_caller_and_decoded_callee(self):
        _, code, data_words, tables, anomalies, roots = weak_graph()
        self.assertEqual(set(code), {0x1000, 0x1004, 0x1008, 0x1010, 0x1014, 0x1018})
        self.assertEqual(set(code.values()), {"start"})
        self.assertFalse(data_words or tables or anomalies or roots["rejected"])

    def test_decoding_does_not_grant_an_unrooted_sequence_code_status(self):
        _, code, _, _, _, _ = weak_graph(roots=False)
        self.assertEqual(code, {})

    def test_unknown_word_still_rejects_callee_and_its_weak_caller(self):
        _, code, _, _, _, roots = weak_graph(unknown=True)
        self.assertEqual(code, {})
        self.assertEqual({entry["address"] for entry in roots["rejected"]}, {"0x1000", "0x1010"})

    def test_dyld_thread_entry_rewrite_retains_poe2_and_reports_runtime_requirement(self):
        words = (0xD503237F, 0xD5900040, 0xD5940000, 0xD65F0FFF)
        original = synthetic_dyld(words)
        self.assertEqual(parse_macho(original).file_type, 7)
        output, report = rewrite_userland(original, plain_pointers=True)
        self.assertEqual(struct.unpack_from("<4I", output, 0x400), words[:-1] + (0xD65F03C0,))
        self.assertEqual(report["instruction_edits"], 1)
        self.assertEqual(report["code_proof"]["proven_instructions"], 4)
        requirements = report["retained_isa_requirements"]
        self.assertEqual(len(requirements), 1)
        self.assertEqual(requirements[0]["feature"], "FEAT_S1POE2")
        self.assertEqual(requirements[0]["mnemonic_counts"], {"tchangef": 1, "tchangeb": 1})
        self.assertEqual(requirements[0]["instruction_count"], 2)
        self.assertTrue(requirements[0]["instructions_unchanged"])
        self.assertFalse(requirements[0]["native_on_a77"])
        self.assertFalse(requirements[0]["runtime_dispatch_verified"])
        self.assertFalse(report["target_isa_audited"])
        self.assertFalse(report["hardware_tested"])
        verify_code_pages(output, parse_macho(output).code_signature)


if __name__ == "__main__":
    unittest.main()
