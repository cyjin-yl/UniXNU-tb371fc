"""Host loader contracts; generated Mach-O fixtures never count as XNU boot."""
import ctypes
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("route_a_loader", ROOT / "scripts/probe_route_a_loader.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
CONFIG = json.loads(MODULE.CONFIG.read_text())
BASE = 0xFFFFFFF007004000


def section(name, segment, address, size, offset, flags=0, alignment=0):
    return struct.pack("<16s16sQQ8I", name.encode(), segment.encode(), address, size,
                       offset, alignment, 0, 0, flags, 0, 0, 0)


def segment(name, address, size, offset, amount, protection, sections=()):
    return (struct.pack("<II16sQQQQ4I", 0x19, 72 + 80 * len(sections), name.encode(),
                        address, size, offset, amount, protection, protection, len(sections), 0)
            + b"".join(sections))


def fixture():
    """Four mapped segments, two holes, a BSS tail and a real direct branch."""
    text = segment("__TEXT", BASE, 0x1000, 0, 0x1000, 1)
    code = segment("__TEXT_EXEC", BASE + 0x2000, 0x1000, 0x1000, 0x1000, 5,
                   [section("__text", "__TEXT_EXEC", BASE + 0x2000, 0x1000, 0x1000, 0x80000400, 2)])
    data = segment("__DATA", BASE + 0x4000, 0x2000, 0x2000, 0x100, 3,
                   [section("__data", "__DATA", BASE + 0x4000, 0x100, 0x2000),
                    section("__bss", "__DATA", BASE + 0x4100, 0x1F00, 0, 1)])
    linkedit = segment("__LINKEDIT", BASE + 0x6000, 0x1000, 0x3000, 0x1000, 1)
    strings = b"\0__start\0_start_first_cpu\0"
    symbols = (struct.pack("<IBBHQ", 1, 15, 1, 0, BASE + 0x2000)
               + struct.pack("<IBBHQ", 9, 15, 1, 0, BASE + 0x2010))
    symtab = struct.pack("<6I", 2, 24, 0x3000, 2, 0x3020, len(strings))
    version = struct.pack("<6I", 0x32, 24, 2, 27 << 16, 27 << 16, 0)
    thread = bytearray(288)
    struct.pack_into("<4I", thread, 0, 5, 288, 6, 68)
    struct.pack_into("<Q", thread, 272, BASE + 0x2000)
    commands = text + code + data + linkedit + symtab + version + thread
    image = bytearray(0x4000)
    struct.pack_into("<8I", image, 0, 0xFEEDFACF, 0x0100000C, 0, 2, 7, len(commands), 1, 0)
    image[32:32 + len(commands)] = commands
    image[0x1000:0x2000] = struct.pack("<I", 0xD503201F) * 1024
    struct.pack_into("<I", image, 0x1000, 0x14000004)
    image[0x2000:0x2100] = b"\x6b" * 0x100
    image[0x3000:0x3020] = symbols
    image[0x3020:0x3020 + len(strings)] = strings
    return image


def modified(data, offset, fmt, value):
    result = bytearray(data)
    struct.pack_into(fmt, result, offset, value)
    return result


def relocation_fixture(records=None):
    """Self-authored unsigned64 local records, including packed and empty bounds."""
    data = fixture()
    command_size = struct.unpack_from("<I", data, 20)[0]
    commands = bytearray(data[32:32 + command_size])
    data_at = 72 + 152
    insertion = data_at + 232
    commands[insertion:insertion] = section("__empty", "__DATA", BASE + 0x4080, 0, 0x2080)
    struct.pack_into("<I", commands, data_at + 4, 312)
    struct.pack_into("<I", commands, data_at + 64, 3)
    if records is None:
        records = [(0x4000, 1, BASE + 0x2010), (0x400C, 3, BASE + 0x4100), (0x4020, 4, BASE + 0x4080)]
    fields = [0, 0, 0, 2, 2, 0] + [0] * 10 + [0x3100, len(records)]
    commands += struct.pack("<20I", 0xB, 80, *fields)
    data[32:32 + len(commands)] = commands
    struct.pack_into("<II", data, 16, 8, len(commands))
    for index, (address, ordinal, value) in enumerate(records):
        struct.pack_into("<iI", data, 0x3100 + index * 8, address, ordinal | (3 << 25))
        if 0x4000 <= address and address + 8 <= 0x4100:
            struct.pack_into("<Q", data, 0x2000 + address - 0x4000, value)
    return data


class LocalRelocationTests(unittest.TestCase):
    def test_audits_every_record_packed_storage_bss_and_empty_boundary(self):
        result = MODULE.strict_kernel(relocation_fixture())["local_relocations"]
        self.assertEqual(result["record_count"], result["records_checked"])
        self.assertEqual(result["records_checked"], 3)
        self.assertEqual(result["records_skipped"], 0)
        self.assertEqual(result["location_alignment_mod8"], {"0": 2, "4": 1})
        self.assertEqual(result["target_section_counts"]["3:__DATA,__bss"], 1)
        boundary = result["empty_section_boundary_records"][0]
        self.assertEqual(boundary["target_va"], BASE + 0x4080)
        self.assertFalse(boundary["boundary_implies_dereferenceable_object"])
        self.assertEqual(boundary["storage_symbols"], [])
        self.assertEqual(result["relocation_writes_performed"], 0)
        self.assertFalse(result["physical_placement_is_virtual_slide"])

    def test_rejects_unknown_record_forms_missing_ordinals_and_scattered(self):
        data = relocation_fixture()
        for bits in (1 | (2 << 25), 1 | (3 << 25) | (1 << 24), 1 | (3 << 25) | (1 << 27),
                     1 | (3 << 25) | (1 << 28), 1 | (3 << 25) | (11 << 28), 3 << 25, 0xFFFFFF | (3 << 25)):
            with self.subTest(bits=bits):
                with self.assertRaisesRegex(MODULE.ProbeError, "local relocation 0"):
                    MODULE.strict_kernel(modified(data, 0x3104, "<I", bits))
        with self.assertRaisesRegex(MODULE.ProbeError, "negative/scattered"):
            MODULE.strict_kernel(modified(data, 0x3100, "<I", 0x80000000))

    def test_rejects_duplicate_or_overlapping_storage(self):
        duplicate = relocation_fixture([(0x4000, 1, BASE + 0x2010), (0x4000, 1, BASE + 0x2010)])
        with self.assertRaisesRegex(MODULE.ProbeError, "duplicate or overlap"):
            MODULE.strict_kernel(duplicate)
        overlap = relocation_fixture([(0x4000, 1, BASE + 0x2010), (0x4004, 1, BASE + 0x2010)])
        with self.assertRaises(MODULE.ProbeError):
            MODULE.strict_kernel(overlap)

    def test_requires_complete_file_backed_storage_and_declared_target(self):
        bad = relocation_fixture([(0x40FC, 1, BASE + 0x2010)])
        with self.assertRaisesRegex(MODULE.ProbeError, "complete 8-byte storage"):
            MODULE.strict_kernel(bad)
        for ordinal, target in ((1, BASE + 0x4000), (2, BASE + 0x4100), (4, BASE + 0x4081)):
            bad = relocation_fixture([(0x4000, ordinal, target)])
            with self.assertRaisesRegex(MODULE.ProbeError, "loaded parent segment|outside its declared section"):
                MODULE.strict_kernel(bad)

    def test_empty_boundary_must_still_belong_to_its_loaded_parent(self):
        data = relocation_fixture([(0x4000, 4, BASE + 0x6000)])
        empty_at = 32 + 72 + 152 + 232
        struct.pack_into("<Q", data, empty_at + 32, BASE + 0x6000)
        with self.assertRaisesRegex(MODULE.ProbeError, "loaded parent segment"):
            MODULE.strict_kernel(data)

    def test_rejects_empty_parent_hidden_by_same_named_loaded_segment(self):
        # Without name uniqueness, a lookup could assign this empty parent's
        # section to the later loaded __DATA segment and accept its boundary.
        data = relocation_fixture([(0x4000, 2, BASE + 0x4080)])
        command_size = struct.unpack_from("<I", data, 20)[0]
        commands = bytearray(data[32:32 + command_size])
        extra = segment("__DATA", BASE + 0x4080, 0, 0, 0, 0,
                        [section("__empty_parent", "__DATA", BASE + 0x4080, 0, 0)])
        before_loaded_data = 72 + 152
        commands[before_loaded_data:before_loaded_data] = extra
        data[32:32 + len(commands)] = commands
        struct.pack_into("<II", data, 16, 9, len(commands))
        with self.assertRaisesRegex(MODULE.ProbeError, "duplicate segment names"):
            MODULE.strict_kernel(data)

    def test_table_is_bounded_owned_and_does_not_alias_symbol_metadata(self):
        data = relocation_fixture()
        dysym = 32 + struct.unpack_from("<I", data, 20)[0] - 80
        for offset, reason in ((len(data) - 8, "outside file"), (0x2000, "__LINKEDIT"), (0x3000, "overlaps")):
            with self.assertRaisesRegex(MODULE.ProbeError, reason):
                MODULE.strict_kernel(modified(data, dysym + 8 + 16 * 4, "<I", offset))
        for field in (5, 7, 9, 11, 13, 15):
            with self.assertRaises(MODULE.ProbeError):
                MODULE.strict_kernel(modified(data, dysym + 8 + field * 4, "<I", 1))

    def test_noreloc_annotation_must_match_actual_incoming_and_outgoing_records(self):
        for command in (32 + 72, 32 + 72 + 152):
            data = modified(relocation_fixture(), command + 68, "<I", MODULE.SG_NORELOC)
            with self.assertRaisesRegex(MODULE.ProbeError, "SG_NORELOC contradicts"):
                MODULE.strict_kernel(data)

    def test_split_cache_threaded_and_nonzero_virtual_slide_are_unsupported(self):
        for flags in (0x21, 0x80000001):
            with self.assertRaisesRegex(MODULE.ProbeError, "different relocation/slide semantics"):
                MODULE.strict_kernel(modified(relocation_fixture(), 24, "<I", flags))
        data = relocation_fixture()
        empty_at = 32 + 72 + 152 + 232
        data[empty_at:empty_at + 16] = b"__thread_starts".ljust(16, b"\0")
        struct.pack_into("<Q", data, empty_at + 40, 8)
        with self.assertRaisesRegex(MODULE.ProbeError, "threaded fixup contract"):
            MODULE.strict_kernel(data)
        with self.assertRaisesRegex(MODULE.ProbeError, "zero virtual slide"):
            MODULE.audit_local_relocations(b"", None, None, None, None, virtual_slide=0x200000)

    def test_another_link_base_does_not_get_a_zero_slide_claim(self):
        data = fixture()
        delta = 0x200000
        end = 32 + struct.unpack_from("<I", data, 20)[0]
        cursor = 32
        while cursor < end:
            kind, size = struct.unpack_from("<II", data, cursor)
            if kind == 0x19:
                value = struct.unpack_from("<Q", data, cursor + 24)[0]
                struct.pack_into("<Q", data, cursor + 24, value + delta)
                count = struct.unpack_from("<I", data, cursor + 64)[0]
                for index in range(count):
                    at = cursor + 72 + index * 80 + 32
                    value = struct.unpack_from("<Q", data, at)[0]
                    struct.pack_into("<Q", data, at, value + delta)
            elif kind == 5:
                struct.pack_into("<Q", data, cursor + 272, BASE + 0x2000 + delta)
            cursor += size
        with self.assertRaisesRegex(MODULE.ProbeError, "linked iOS ARM64 base"):
            MODULE.strict_kernel(data)


class LoaderStructureTests(unittest.TestCase):
    def test_complete_geometry_and_direct_entry_trampoline(self):
        data = fixture()
        strict = MODULE.strict_kernel(data)
        self.assertEqual(strict["metadata"]["load_contract"]["memory_span"], 0x7000)
        self.assertEqual(strict["metadata"]["load_contract"]["required_physical_base_low_21_bits"], 0x4000)
        self.assertEqual(len(strict["zero_sections"]), 1)
        entry = MODULE.check_entry_symbols(strict, CONFIG, data)
        self.assertEqual(entry["trampoline"]["decoded_target"], BASE + 0x2010)
        self.assertFalse(entry["entry_executed"])

    def test_rejects_overlapping_file_ranges(self):
        data = fixture()
        # Map __LINKEDIT over __DATA's file bytes; no section metadata can hide it.
        linkedit = 32 + 72 + 152 + 232
        data = modified(data, linkedit + 40, "<Q", 0x2000)
        with self.assertRaisesRegex(MODULE.ProbeError, "overlapping file-backed"):
            MODULE.strict_kernel(data)

    def test_rejects_virtual_overlap_and_address_overflow(self):
        data = fixture()
        code = 32 + 72
        for value in (BASE, (1 << 64) - 0x800):
            bad = modified(data, code + 24, "<Q", value)
            bad = modified(bad, code + 72 + 32, "<Q", value)
            thread = 32 + 72 + 152 + 232 + 72 + 24 + 24
            bad = modified(bad, thread + 272, "<Q", value)
            with self.assertRaises((MODULE.ProbeError, MODULE.platform_link.LinkError)):
                MODULE.strict_kernel(bad)

    def test_rejects_unmapped_header_and_wrong_section_mapping(self):
        data = fixture()
        bad = modified(data, 32 + 48, "<Q", 8)
        with self.assertRaisesRegex(MODULE.ProbeError, "header is not loaded"):
            MODULE.strict_kernel(bad)
        bad = modified(data, 32 + 72 + 72 + 48, "<I", 0x1004)
        with self.assertRaisesRegex(MODULE.ProbeError, "outside their segment|mapping disagrees"):
            MODULE.strict_kernel(bad)

    def test_rejects_section_escape_relocations_and_segment_policy(self):
        data = fixture()
        code = 32 + 72
        cases = [(code + 72 + 40, "<Q", 0x1001), (code + 72 + 60, "<I", 1),
                 (code + 68, "<I", 1), (code + 56, "<I", 1),
                 (code + 32, "<Q", 0)]
        for offset, fmt, value in cases:
            with self.subTest(offset=offset):
                with self.assertRaises((MODULE.ProbeError, MODULE.platform_link.LinkError)):
                    MODULE.strict_kernel(modified(data, offset, fmt, value))

    def test_explicit_noreloc_annotation_preserves_empty_and_nonempty_mapping(self):
        data = fixture()
        linkinfo = 32 + 72 + 152 + 232
        data[linkinfo + 8:linkinfo + 24] = b"__LINKINFO".ljust(16, b"\0")
        struct.pack_into("<I", data, linkinfo + 68, MODULE.SG_NORELOC)
        # The real candidate has empty prelink placeholders below the loaded
        # base. They must remain empty and must not choose a fake physical root.
        empty = bytearray(segment("__PRELINK_TEXT", BASE - 0x3000000, 0, len(data), 0, 5))
        struct.pack_into("<I", empty, 68, MODULE.SG_NORELOC)
        size = struct.unpack_from("<I", data, 20)[0]
        data[32 + size:32 + size + len(empty)] = empty
        struct.pack_into("<I", data, 16, 8)
        struct.pack_into("<I", data, 20, size + len(empty))
        strict = MODULE.strict_kernel(data)
        self.assertEqual(strict["metadata"]["load_contract"]["virtual_base"], BASE)
        self.assertEqual(strict["metadata"]["load_contract"]["memory_span"], 0x7000)
        marked = [s for s in strict["segment_annotations"] if s["flags"] == 4]
        self.assertEqual([(s["name"], s["vmsize"], s["maxprot"], s["initprot"]) for s in marked],
                         [("__LINKINFO", 0x1000, 1, 1), ("__PRELINK_TEXT", 0, 5, 5)])

    def test_other_segment_flags_and_combinations_remain_rejected(self):
        for flags in (1, 2, 8, 16, 0x20, 4 | 1, 4 | 2, 4 | 8, 4 | 16, 0x80000004):
            with self.subTest(flags=flags):
                bad = modified(fixture(), 32 + 68, "<I", flags)
                with self.assertRaisesRegex(MODULE.ProbeError, "__TEXT: unsupported segment flags"):
                    MODULE.strict_kernel(bad)

    def test_noreloc_does_not_override_actual_relocations_or_protections(self):
        code = 32 + 72
        marked = modified(fixture(), code + 68, "<I", MODULE.SG_NORELOC)
        bad = modified(marked, code + 72 + 60, "<I", 1)
        with self.assertRaisesRegex(MODULE.ProbeError, "__TEXT_EXEC,__text: section has unresolved relocations"):
            MODULE.strict_kernel(bad)
        bad = modified(marked, code + 56, "<I", 1)
        with self.assertRaisesRegex(MODULE.ProbeError, "__TEXT_EXEC: unsupported segment protections"):
            MODULE.strict_kernel(bad)

    def test_rejects_arm64e_fileset_and_unknown_fixup_command(self):
        data = fixture()
        for offset, value in ((8, 2), (12, 12)):
            with self.assertRaises(MODULE.platform_link.LinkError):
                MODULE.strict_kernel(modified(data, offset, "<I", value))
        # An otherwise unused metadata command must not silently enable dyld fixups.
        linkedit = 32 + 72 + 152 + 232
        bad = modified(data, linkedit, "<I", 0x80000034)
        with self.assertRaisesRegex(MODULE.ProbeError, "unsupported load command"):
            MODULE.strict_kernel(bad)

    def test_entry_requires_b_not_bl_and_exact_cold_cpu_destination(self):
        for instruction in (0x94000004, 0xD503201F, 0x14000005):
            bad = modified(fixture(), 0x1000, "<I", instruction)
            with self.assertRaisesRegex(MODULE.ProbeError, "trampoline|does not reach"):
                MODULE.check_entry_symbols(MODULE.strict_kernel(bad), CONFIG, bad)
        bad = modified(fixture(), 0x3000 + 8, "<Q", BASE + 0x2004)
        with self.assertRaisesRegex(MODULE.ProbeError, "does not select"):
            MODULE.check_entry_symbols(MODULE.strict_kernel(bad), CONFIG, bad)

    def test_entry_negative_branch_immediate_is_sign_extended(self):
        data = fixture()
        thread = 32 + 72 + 152 + 232 + 72 + 24 + 24
        struct.pack_into("<Q", data, thread + 272, BASE + 0x2010)
        struct.pack_into("<Q", data, 0x3000 + 8, BASE + 0x2010)
        struct.pack_into("<Q", data, 0x3010 + 8, BASE + 0x2000)
        struct.pack_into("<I", data, 0x1010, 0x17FFFFFC)
        result = MODULE.check_entry_symbols(MODULE.strict_kernel(data), CONFIG, data)
        self.assertEqual(result["trampoline"]["decoded_target"], BASE + 0x2000)

    def test_entry_and_early_cpu_must_name_their_actual_instruction_section(self):
        for symbol in (0x3000, 0x3010):
            bad = modified(fixture(), symbol + 5, "<B", 2)
            with self.assertRaisesRegex(MODULE.ProbeError, "symbol section"):
                MODULE.check_entry_symbols(MODULE.strict_kernel(bad), CONFIG, bad)
        bad = modified(fixture(), 0x3010 + 8, "<Q", BASE + 0x2FFE)
        with self.assertRaisesRegex(MODULE.ProbeError, "complete pure instruction"):
            MODULE.check_entry_symbols(MODULE.strict_kernel(bad), CONFIG, bad)

    def test_source_digest_blob_and_extraction_boundaries_fail_closed(self):
        raw = b"example\n"
        record = {"size": len(raw), "sha256": MODULE.sha256(raw), "git_blob": MODULE.blob_sha(raw)}
        MODULE.verify_bytes(raw, record, "self-authored fixture")
        with self.assertRaisesRegex(MODULE.ProbeError, "pinned bytes"):
            MODULE.verify_bytes(raw + b"x", record, "fixture")
        with self.assertRaisesRegex(MODULE.ProbeError, "Git blob"):
            MODULE.verify_bytes(raw, {**record, "git_blob": "0" * 40}, "fixture")
        with self.assertRaisesRegex(MODULE.ProbeError, "ambiguous"):
            MODULE.extract("first\nfirst\nlast\n", "first", "last", "fixture")

    def test_protected_recheck_detects_modified_and_missing_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input"
            path.write_bytes(b"original")
            records = [MODULE.identity(path)]
            self.assertTrue(MODULE.recheck(records)["unchanged"])
            path.write_bytes(b"changed")
            self.assertFalse(MODULE.recheck(records)["unchanged"])
            path.unlink()
            self.assertFalse(MODULE.recheck(records)["unchanged"])

    def test_input_symlink_is_rejected_before_normalization(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "input"
            path.write_bytes(b"fixture")
            alias = root / "alias"
            alias.symlink_to(path)
            with self.assertRaisesRegex(MODULE.ProbeError, "nonsymlink"):
                MODULE.input_path(alias)


class ProductionLoaderHostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source_dir = os.environ.get("ROUTE_A_LOADER_SOURCES")
        if not source_dir:
            raise unittest.SkipTest("ROUTE_A_LOADER_SOURCES is absent; actual production C extraction not exercised")
        cc = shutil.which("cc")
        if not cc:
            raise unittest.SkipTest("host C compiler is unavailable")
        cls.temp = tempfile.TemporaryDirectory(prefix="route-a-loader-test-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.output = Path(cls.temp.name)
        cls.sources = MODULE.public_sources(CONFIG, Path(source_dir))
        cls.report = {}
        cls.lib = MODULE.build_harness(cls.sources, cls.output, Path(cc), cls.report)

    def test_original_parser_and_original_copy_block_materialize_all_bytes(self):
        data = fixture()
        evidence = MODULE.verify_load(self.lib, bytes(data), MODULE.strict_kernel(data), self.output / "synthetic.load.bin")
        self.assertEqual(evidence["image"]["size"], 0x7000)
        self.assertEqual(len(evidence["zeroed_gaps"]), 2)
        self.assertEqual(evidence["zero_fill_tails"], [{"segment": "__DATA", "offset": 0x4100, "size": 0x1F00}])
        self.assertTrue(evidence["destination_guards_unchanged"])
        self.assertFalse(evidence["kernel_bytes_executed"])
        self.assertTrue(all(item["source_bytes_unchanged"] for item in self.report["production_extractions"]))

    def test_original_copy_preserves_all_unsigned64_pointer_bytes_without_slide(self):
        data = bytes(relocation_fixture())
        strict = MODULE.strict_kernel(data)
        result = MODULE.verify_load(self.lib, data, strict, self.output / "relocation-synthetic.load.bin")
        loaded = Path(result["image"]["path"]).read_bytes()
        for source, destination in ((0x2000, 0x4000), (0x200C, 0x400C), (0x2020, 0x4020)):
            self.assertEqual(loaded[destination:destination + 8], data[source:source + 8])
        self.assertEqual(strict["local_relocations"]["records_checked"], 3)
        self.assertFalse(strict["local_relocations"]["runtime_kernel_slide_verified"])

    def test_original_parser_retains_broader_policy_but_outer_route_a_gate_rejects(self):
        data = bytes(modified(fixture(), 8, "<I", 2))
        parsed = MODULE.CKernel()
        buf = ctypes.create_string_buffer(data)
        self.assertEqual(self.lib.probe_parse(buf, len(data), ctypes.byref(parsed)), 0)
        with self.assertRaises(MODULE.platform_link.LinkError):
            MODULE.strict_kernel(data)
        # The original parser does not enforce disjoint file ranges; retain it
        # verbatim and make this distinct outer restriction explicit.
        linkedit = 32 + 72 + 152 + 232
        data = bytes(modified(fixture(), linkedit + 40, "<Q", 0x2000))
        buf = ctypes.create_string_buffer(data)
        self.assertEqual(self.lib.probe_parse(buf, len(data), ctypes.byref(parsed)), 0)
        with self.assertRaisesRegex(MODULE.ProbeError, "overlapping file-backed"):
            MODULE.strict_kernel(data)

    def test_real_abi_declarations_and_generated_target_offset_checks(self):
        result = MODULE.check_abi(self.lib)
        by_name = {row["xnu_field"]: row for row in result["fields"]}
        self.assertEqual(result["size"], 0x480)
        self.assertEqual(by_name["deviceTreeP"]["offset"], 0x60)
        self.assertEqual(by_name["CommandLine"]["offset"], 0x6C)
        self.assertEqual(by_name["memSizeActual"]["offset"], 0x478)
        self.assertEqual([row["offset"] for row in result["video_fields"]], [40, 48, 56, 64, 72, 80])
        assym = "".join(f"#define {name}{suffix} {by_name[field]['offset']}\n"
                        for name, field in MODULE.ASSYM_FIELDS.items() for suffix in ("", "_NUM"))
        self.assertEqual(len(MODULE.check_abi(self.lib, assym)["assym_offsets"]), 10)
        for bad in (assym.replace("BA_BOOT_FLAGS 1136", "BA_BOOT_FLAGS 1137"),
                    assym + "#define BA_VIRT_BASE 8\n", assym.replace("#define BA_PHYS_BASE 16\n", "")):
            with self.assertRaisesRegex(MODULE.ProbeError, "assym offset"):
                MODULE.check_abi(self.lib, bad)

    def test_video_member_mismatch_is_not_hidden_by_equal_struct_size(self):
        original = self.lib.probe_video_abi
        def wrong_member(field, xnu, size):
            return original(field, xnu, size) + (8 if field == 3 and xnu and not size else 0)
        with patch.object(self.lib, "probe_video_abi", side_effect=wrong_member):
            with self.assertRaisesRegex(MODULE.ProbeError, "Boot_Video member"):
                MODULE.check_abi(self.lib)

    def test_c_copy_refuses_short_destination_and_outer_verification_detects_nonzero_bss(self):
        data = bytes(fixture())
        source, destination, parsed = ctypes.create_string_buffer(data), ctypes.create_string_buffer(8), MODULE.CKernel()
        self.assertEqual(self.lib.probe_load(source, len(data), destination, len(destination), ctypes.byref(parsed)), 1)
        # A zero-fill section can lie inside copied segment padding in real
        # Mach-O. Its bytes must still actually be zero after the copy.
        bad = bytearray(data)
        data_segment = 32 + 72 + 152
        struct.pack_into("<Q", bad, data_segment + 72 + 80 + 32, BASE + 0x4080)
        struct.pack_into("<Q", bad, data_segment + 72 + 80 + 40, 0x1F80)
        with self.assertRaisesRegex(MODULE.ProbeError, "zero-fill section contains"):
            MODULE.verify_load(self.lib, bytes(bad), MODULE.strict_kernel(bad), self.output / "rejected.load.bin")

    def test_late_input_mutation_clears_every_success_flag(self):
        # Only this test substitutes self-authored candidate/prepared receipts.
        # The public CLI always reads the fixed real-candidate config.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs, prepared = root / "inputs", root / "prepared"
            inputs.mkdir()
            boot = prepared / CONFIG["xnu"]["files"][0]["path"]
            boot.parent.mkdir(parents=True)
            boot.write_bytes(self.sources["xnu/pexpert/pexpert/arm64/boot.h"]["bytes"])
            start = prepared / CONFIG["prepared_xnu"]["start_source"]["path"]
            start.parent.mkdir(parents=True)
            start.write_bytes(b"self-authored test source; not XNU startup\n")
            abi = MODULE.check_abi(self.lib)
            by_name = {row["xnu_field"]: row for row in abi["fields"]}
            assym = inputs / "assym.s"
            assym.write_text("".join(f"#define {name}{suffix} {by_name[field]['offset']}\n"
                                     for name, field in MODULE.ASSYM_FIELDS.items() for suffix in ("", "_NUM")))
            candidate = inputs / "synthetic.macho"
            candidate.write_bytes(fixture())
            contract = MODULE.strict_kernel(candidate.read_bytes())["metadata"]["load_contract"]
            report = inputs / "synthetic-link.json"
            report.write_text(json.dumps({"status": "platform_link_compatible", "platform_link_compatible": True,
                "baseline_reproduced": True, "kernel_callback_linked": True,
                "protected_inputs_recheck": {"unchanged": True},
                "candidate": {**MODULE.identity(candidate), "load_contract": contract}}))
            config = copy.deepcopy(CONFIG)
            for key, path in (("start_source", start), ("assym", assym)):
                config["prepared_xnu"][key].update({k: v for k, v in MODULE.identity(path).items() if k != "path"})
            config["candidate"].update({k: v for k, v in MODULE.identity(candidate).items() if k != "path"})
            config["candidate"]["link_report_sha256"] = MODULE.sha256(report.read_bytes())
            args = SimpleNamespace(output=root / "output", sources=Path(os.environ["ROUTE_A_LOADER_SOURCES"]),
                                   kernel=candidate, link_report=report, xnu_work=prepared, assym=assym, cc="cc")
            original = MODULE.check_abi
            def mutate_after_checks(*params, **kwargs):
                result = original(*params, **kwargs)
                candidate.write_bytes(candidate.read_bytes() + b"changed after successful byte loading")
                return result
            with patch.object(MODULE, "check_abi", side_effect=mutate_after_checks):
                result = MODULE.run_probe(args, config)
            self.assertEqual(result["status"], "failed")
            self.assertFalse(result["protected_inputs_recheck"]["unchanged"])
            for name in ("host_loader_probe_verified", "kernel_segment_bytes_verified", "boot_args_abi_verified", "os_boot_verified"):
                self.assertFalse(result[name])


if __name__ == "__main__":
    unittest.main()
