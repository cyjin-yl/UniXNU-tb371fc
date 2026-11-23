"""Independent malformed-image and code/data boundary fixtures."""

from pathlib import Path
import json
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from arm64_lowering.macho import MachOError, UnsupportedMachO, parse_macho


TEXT_BASE = 0x100000000
TEXT_OFFSET = 0x400
CONST_OFFSET = 0x500
TEXT_SIZE = 32
TEXT_COMMAND = 32
TEXT_SECTION = TEXT_COMMAND + 72
CONST_SECTION = TEXT_SECTION + 80


def section(name, address, size, offset, flags, segment="__TEXT"):
    return struct.pack("<16s16s2Q8I", name.encode(), segment.encode(), address, size,
                       offset, 2, 0, 0, flags, 0, 0, 0)


def fixture(*, dice=(), extra_commands=(), subtype=0x80000002,
            code_flags=0x80000400, signature=True, fixups=False):
    # __TEXT deliberately contains PAC-shaped bytes in __const as well as
    # __text.  Scanning the executable segment would corrupt the data copy.
    code = section("__text", TEXT_BASE + TEXT_OFFSET, TEXT_SIZE, TEXT_OFFSET, code_flags)
    constant = section("__const", TEXT_BASE + CONST_OFFSET, TEXT_SIZE, CONST_OFFSET, 0)
    text = struct.pack("<2I16s4Q4I", 0x19, 232, b"__TEXT", TEXT_BASE, 0x1000,
                       0, 0x1000, 5, 5, 2, 0) + code + constant
    linkedit = struct.pack("<2I16s4Q4I", 0x19, 72, b"__LINKEDIT", TEXT_BASE + 0x1000,
                           0x1000, 0x1000, 0x200, 1, 1, 0, 0)
    commands = [text, linkedit]
    commands.append(struct.pack("<4I", 0x29, 16, 0x1000, len(dice) * 8))
    if signature:
        commands.append(struct.pack("<4I", 0x1D, 16, 0x1100, 32))
    if fixups:
        commands.append(struct.pack("<4I", 0x80000034, 16, 0x1080, 28))
    commands.extend(extra_commands)
    header = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, subtype, 2,
                         len(commands), sum(map(len, commands)), 0, 0)
    result = bytearray(0x1200)
    result[:len(header)] = header
    at = 32
    for command in commands:
        result[at:at + len(command)] = command
        at += len(command)
    # PACIASP's encoding is just a recognizable value here, not an oracle for
    # the instruction lowerer tested elsewhere.
    for offset in (TEXT_OFFSET, CONST_OFFSET):
        result[offset:offset + TEXT_SIZE] = struct.pack("<8I", *([0xD503233F] * 8))
    for index, entry in enumerate(dice):
        struct.pack_into("<IHH", result, 0x1000 + 8 * index, *entry)
    return result


class MachOGeometryTests(unittest.TestCase):
    def test_candidates_exclude_constants_in_executable_segment(self):
        original = fixture()
        before = bytes(original)
        image = parse_macho(original)
        self.assertEqual([(r.offset, r.size) for r in image.candidate_ranges], [(TEXT_OFFSET, 32)])
        self.assertTrue(image.is_candidate(TEXT_OFFSET))
        self.assertFalse(image.is_candidate(CONST_OFFSET))
        self.assertEqual(bytes(original), before)

    def test_data_in_code_removes_only_its_code_words(self):
        image = parse_macho(fixture(dice=[(TEXT_OFFSET + 8, 8, 4)]))
        self.assertEqual([(r.offset, r.size) for r in image.candidate_ranges],
                         [(TEXT_OFFSET, 8), (TEXT_OFFSET + 16, 16)])
        self.assertFalse(image.is_candidate(TEXT_OFFSET + 8))
        self.assertFalse(image.is_candidate(TEXT_OFFSET + 4, 8))

    def test_partial_instruction_data_excludes_whole_word(self):
        image = parse_macho(fixture(dice=[(TEXT_OFFSET + 5, 1, 1)]))
        self.assertEqual([(r.offset, r.size) for r in image.candidate_ranges],
                         [(TEXT_OFFSET, 4), (TEXT_OFFSET + 8, 24)])
        self.assertFalse(image.is_candidate(TEXT_OFFSET + 4))
        self.assertEqual(image.to_zeta_info()["dice"], [(TEXT_OFFSET + 5, 1, 1)])

    def test_overlapping_data_entries_merge_for_candidate_exclusion(self):
        image = parse_macho(fixture(dice=[(TEXT_OFFSET + 4, 8, 1), (TEXT_OFFSET + 8, 8, 1)]))
        self.assertEqual([(r.offset, r.size) for r in image.candidate_ranges],
                         [(TEXT_OFFSET, 4), (TEXT_OFFSET + 16, 16)])

    def test_full_subtype_and_metadata_survive_json_and_zeta_adapter(self):
        image = parse_macho(fixture(subtype=0x82000002, fixups=True))
        report = json.loads(json.dumps(image.to_dict()))
        self.assertEqual(report["subtype_raw"], 0x82000002)
        self.assertEqual(report["subtype_base"], 2)
        self.assertEqual(report["subtype_features"], 0x82000000)
        self.assertEqual(report["ptrauth_abi_version"], 2)
        self.assertFalse(report["candidate_ranges_are_code_proof"])
        self.assertEqual(image.code_signature["offset"], 0x1100)
        self.assertEqual(image.chained_fixups["offset"], 0x1080)
        adapter = image.to_zeta_info()
        self.assertEqual(adapter["signature"], (0x1100, 32))
        self.assertEqual(adapter["segments"][0]["sections"][0]["offset"], TEXT_OFFSET)

    def test_unsigned_image_can_be_audited_without_inventing_signature(self):
        image = parse_macho(fixture(signature=False))
        self.assertIsNone(image.code_signature)
        self.assertIsNone(image.to_zeta_info()["signature"])

    def test_some_instructions_is_only_a_candidate_with_warning(self):
        image = parse_macho(fixture(code_flags=0x400))
        self.assertFalse(image.candidate_ranges[0].pure_instructions)
        self.assertIn("mixed_instruction_section:__TEXT,__text", image.warnings)

    def test_encrypted_image_is_metadata_only(self):
        encryption = struct.pack("<6I", 0x2C, 24, TEXT_OFFSET, TEXT_SIZE, 1, 0)
        image = parse_macho(fixture(extra_commands=[encryption]))
        self.assertFalse(image.can_scan_candidates)
        self.assertEqual(image.candidate_ranges, [])
        self.assertIn("encrypted_image:cryptid=1", image.blockers)
        with self.assertRaises(MachOError):
            image.to_zeta_info()

    def test_clear_encryption_command_does_not_block(self):
        encryption = struct.pack("<6I", 0x2C, 24, TEXT_OFFSET, TEXT_SIZE, 0, 0)
        self.assertTrue(parse_macho(fixture(extra_commands=[encryption])).can_scan_candidates)

    def test_protected_segment_without_encryption_command_is_not_scanned(self):
        data = fixture()
        struct.pack_into("<I", data, TEXT_COMMAND + 68, 8)
        image = parse_macho(data)
        self.assertEqual(image.candidate_ranges, [])
        self.assertIn("protected_segment:__TEXT", image.blockers)

    def test_embedded_shared_cache_image_is_not_treated_as_loose_binary(self):
        data = fixture()
        struct.pack_into("<I", data, 24, 0x80000000)
        image = parse_macho(data)
        self.assertIn("shared_cache_image_requires_cache_mapping", image.blockers)
        self.assertFalse(image.can_scan_candidates)

    def test_cfg_symbol_table_references_cannot_leave_file(self):
        command = struct.pack("<6I", 2, 24, 0x1100, 64, 0x1100, 32)
        with self.assertRaisesRegex(MachOError, "symbol table"):
            parse_macho(fixture(extra_commands=[command]))

    def test_unknown_required_command_is_blocked(self):
        image = parse_macho(fixture(extra_commands=[struct.pack("<2I", 0x80001234, 8)]))
        self.assertEqual(image.candidate_ranges, [])
        self.assertIn("unknown_required_load_command:0x80001234", image.blockers)

    def test_truncated_headers_and_load_commands_are_rejected(self):
        data = fixture()
        for end in (0, 3, 4, 31, 39, 120):
            with self.subTest(end=end), self.assertRaises(MachOError):
                parse_macho(data[:end])

    def test_load_command_count_and_size_cannot_disagree(self):
        data = fixture()
        struct.pack_into("<I", data, 16, 3)  # One otherwise valid command left over.
        with self.assertRaisesRegex(MachOError, "count/sizeofcmds"):
            parse_macho(data)

    def test_load_command_alignment_is_checked(self):
        data = fixture()
        struct.pack_into("<I", data, TEXT_COMMAND + 4, 228)
        with self.assertRaisesRegex(MachOError, "alignment"):
            parse_macho(data)

    def test_section_count_must_fit_command(self):
        data = fixture()
        struct.pack_into("<I", data, TEXT_COMMAND + 64, 3)
        with self.assertRaisesRegex(MachOError, "section count"):
            parse_macho(data)

    def test_section_outside_own_segment_rejected_even_when_inside_file(self):
        data = fixture()
        struct.pack_into("<Q", data, TEXT_SECTION + 32, TEXT_BASE + 0x1080)
        struct.pack_into("<I", data, TEXT_SECTION + 48, 0x1080)
        with self.assertRaisesRegex(MachOError, "segment VM range"):
            parse_macho(data)

    def test_section_vm_file_mapping_must_agree(self):
        data = fixture()
        struct.pack_into("<Q", data, TEXT_SECTION + 32, TEXT_BASE + TEXT_OFFSET + 4)
        with self.assertRaisesRegex(MachOError, "file/VM mapping"):
            parse_macho(data)

    def test_overlapping_sections_are_rejected(self):
        data = fixture()
        struct.pack_into("<Q", data, CONST_SECTION + 32, TEXT_BASE + TEXT_OFFSET)
        struct.pack_into("<I", data, CONST_SECTION + 48, TEXT_OFFSET)
        with self.assertRaisesRegex(MachOError, "overlapping section"):
            parse_macho(data)

    def test_instruction_section_cannot_hide_in_header(self):
        data = fixture()
        struct.pack_into("<Q", data, TEXT_SECTION + 32, TEXT_BASE + 64)
        struct.pack_into("<I", data, TEXT_SECTION + 48, 64)
        with self.assertRaisesRegex(MachOError, "overlaps header"):
            parse_macho(data)

    def test_zero_fill_instruction_section_rejected(self):
        data = fixture(code_flags=0x80000401)
        with self.assertRaisesRegex(MachOError, "zero-fill"):
            parse_macho(data)

    def test_vm_overflow_rejected(self):
        data = fixture()
        struct.pack_into("<Q", data, TEXT_COMMAND + 24, (1 << 64) - 16)
        with self.assertRaisesRegex(MachOError, "VM leaves"):
            parse_macho(data)

    def test_signature_blob_cannot_overlap_instructions(self):
        data = fixture()
        signature_command = 32 + 232 + 72 + 16
        struct.pack_into("<2I", data, signature_command + 8, TEXT_OFFSET, 16)
        with self.assertRaisesRegex(MachOError, "overlaps instruction"):
            parse_macho(data)

    def test_data_in_code_cannot_claim_noncode_region(self):
        with self.assertRaisesRegex(MachOError, "not contained"):
            parse_macho(fixture(dice=[(CONST_OFFSET, 8, 1)]))

    def test_duplicate_signature_rejected(self):
        duplicate = struct.pack("<4I", 0x1D, 16, 0x1100, 32)
        with self.assertRaisesRegex(MachOError, "duplicate linkedit"):
            parse_macho(fixture(extra_commands=[duplicate]))

    def test_fat_fileset_and_cache_are_explicitly_unsupported(self):
        fileset = fixture()
        struct.pack_into("<I", fileset, 12, 0xC)
        examples = [(struct.pack(">2I", 0xCAFEBABE, 1), "fat32"),
                    (struct.pack(">2I", 0xCAFEBABF, 1), "fat64"),
                    (fileset, "fileset"), (b"dyld_v1  arm64e\0", "dyld-cache")]
        for blob, expected_format in examples:
            with self.subTest(format=expected_format):
                with self.assertRaises(UnsupportedMachO) as caught:
                    parse_macho(blob)
                self.assertEqual(caught.exception.format, expected_format)


if __name__ == "__main__":
    unittest.main()
