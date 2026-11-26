import copy
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import audit_route_a_nontpro as audit
import route_a_nontpro_fixture as fixture
import route_a_nontpro_xnu as xnu
import probe_route_a_nontpro_fragments as probe


def macho(commands, payload=b""):
    raw = b"".join(commands)
    return struct.pack("<8I", 0xfeedfacf, 0x100000c, 2, 7, len(commands), len(raw), 0, 0) + raw + payload


def thread_command(pc=0x5a90, flavor=6, count=68):
    command = bytearray(288)
    struct.pack_into("<4I", command, 0, 5, 288, flavor, count)
    struct.pack_into("<Q", command, 272, pc)
    return bytes(command)


class ExactInputTests(unittest.TestCase):
    def test_unixthread_entry_rejects_wrong_state_and_duplicate_command(self):
        self.assertEqual(audit.unixthread_entry(macho([thread_command()])), 0x5a90)
        for data in (macho([thread_command(flavor=1)]),
                     macho([thread_command(count=67)]),
                     macho([thread_command(), thread_command()])):
            with self.subTest(data=data[:48]), self.assertRaises(audit.AuditError):
                audit.unixthread_entry(data)

    def test_load_commands_refuses_truncation_and_extra_command_geometry(self):
        valid = macho([thread_command()])
        for data in (valid[:-1], valid[:16] + struct.pack("<I", 2) + valid[20:]):
            with self.assertRaises(audit.AuditError):
                audit.load_commands(data)

    def test_function_starts_are_bounded_and_must_point_to_candidates(self):
        def encoded(blob):
            return macho([struct.pack("<4I", 0x26, 16, 48, len(blob))], blob)
        image = SimpleNamespace(segments=[SimpleNamespace(name="__TEXT", vmaddr=0)],
                                candidate_ranges=[SimpleNamespace(vmaddr=0x1000, size=16)])
        self.assertEqual(audit.function_starts(encoded(b"\x80\x20\x04\0\0"), image), [0x1000, 0x1004])
        for blob in (b"\x80\x20", b"\x80\x20\0\x01", b"\x80" * 10 + b"\x02\0",
                     b"\x80\x20\x40\0"):
            with self.subTest(blob=blob), self.assertRaises(audit.AuditError):
                audit.function_starts(encoded(blob), image)

    def test_wrong_standalone_is_rejected_before_any_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "dyld"
            p.write_bytes(macho([thread_command()]))
            with self.assertRaisesRegex(audit.AuditError, "pinned original"):
                audit.Standalone(p)

    def test_section_identity_requires_one_containing_full_range(self):
        sections = [{"segment": "D", "name": "B", "addr": 0x1000, "size": 16}]
        self.assertEqual(audit.section_coordinate(sections, 0x1008, 8), ("D", "B", 8))
        for address, size in ((0x1009, 8), (-1, 1), (audit.MAX_U64, 2), (0x1000, 0)):
            with self.assertRaises(audit.AuditError):
                audit.section_coordinate(sections, address, size)
        with self.assertRaises(audit.AuditError):
            audit.section_coordinate(sections * 2, 0x1000, 1)

    def test_actual_relocated_store_and_negative_adrp(self):
        self.assertEqual(audit.adrp_store_target((0xb0335248, 0xf9041113), 0x180485c64), 0x1e6ece820)
        self.assertEqual(audit.adrp_store_target((0xf0ffffe8, 0xf9011113), 0x4010), 0x3220)
        for words in ((0xb0335249, 0xf9041113), (0xb0335248, 0xf9041112),
                      (0xb0335248, 0xb9041113)):
            with self.assertRaises(audit.AuditError):
                audit.adrp_store_target(words, 0x180485c64)


class SyntheticLedger:
    def __init__(self):
        self.starts = [0x1000, 0x1400]
        self.symbols = [{"address": 0x1000, "name": "caller"}, {"address": 0x1400, "name": "start"}]
        self.text = SimpleNamespace(addr=0x1000, size=0x800)
        self.words = {0x1000: 0x14000100}
        for i in range(236):
            self.words[0x1400 + 4 * i] = 0xd5900040 if i < 116 else 0xd5940000
        self.words[0x17b0] = 0xd53b4068
        self.words[0x17b4] = 0xd51ef1a0

    def read(self, address, size):
        return b"".join(struct.pack("<I", self.words.get(a, 0xd503201f))
                        for a in range(address, address + size, 4))


class LedgerTests(unittest.TestCase):
    def test_complete_census_preserves_entry_and_state_obligations(self):
        result = audit.hazard_ledger(SyntheticLedger(), None)
        self.assertEqual(result["tchange_count"], 236)
        self.assertEqual(result["tracked_register_count"], 2)
        self.assertEqual(result["groups"][0]["direct_incoming_edges"],
                         [{"address": "0x1000", "target": "0x1400", "kind": "b"}])
        self.assertFalse(result["all_sites_dispatch_verified"])
        self.assertFalse(result["groups"][0]["indirect_incoming_edges_complete"])
        self.assertFalse(result["groups"][0]["state_writers_complete"])
        self.assertTrue(all(not item["closed"] for item in result["hazards"]))

    def test_missing_site_and_cached_instruction_change_are_failures(self):
        source = SyntheticLedger()
        del source.words[0x1400]
        with self.assertRaisesRegex(audit.AuditError, "coverage"):
            audit.hazard_ledger(source, None)
        source = SyntheticLedger()
        cached = SimpleNamespace(base=0x180000000, read_relative=lambda a, n: bytes(n))
        with self.assertRaisesRegex(audit.AuditError, "cached tracked hazard"):
            audit.hazard_ledger(source, cached)

    def test_hazard_cannot_be_assigned_before_a_real_function_start(self):
        source = SyntheticLedger()
        source.starts = [0x1800]
        with self.assertRaisesRegex(audit.AuditError, "precedes"):
            audit.hazard_ledger(source, None)


class FixtureInputTests(unittest.TestCase):
    def test_vector_builder_places_apple_after_both_terminators(self):
        arena = fixture.Arena()
        block, apple = arena.block(["a", "b"], ["E=1", "F=2"], ["x=0", "y="])
        at = block - fixture.INPUT_BASE
        values = struct.unpack_from("<11Q", arena.data, at)
        self.assertEqual(values[1], 2)
        self.assertEqual(values[4], 0)
        self.assertEqual(values[7], 0)
        self.assertEqual(values[10], 0)
        self.assertEqual(apple, block + 64)

    def test_fixture_limits_prevent_unterminated_or_oversized_inputs(self):
        arena = fixture.Arena()
        for text in ("a\0b", "a" * 513):
            with self.assertRaises(audit.AuditError):
                arena.string(text)
        with self.assertRaises(audit.AuditError):
            arena.vector(["x"] * 65)
        with self.assertRaises(audit.AuditError):
            arena.allocate(bytes(fixture.INPUT_SIZE))

    def test_commpage_has_separate_readonly_nonexecute_page(self):
        tables = fixture.page_tables()
        l1 = struct.unpack_from("<Q", tables, 63 * 8)[0]
        l2 = struct.unpack_from("<Q", tables, (l1 & ~4095) - fixture.TABLE_BASE + 511 * 8)[0]
        leaf = struct.unpack_from("<Q", tables, (l2 & ~4095) - fixture.TABLE_BASE + 508 * 8)[0]
        self.assertEqual(leaf & 0x0000fffffffff000, fixture.COMMPAGE_PA)
        self.assertEqual((leaf >> 6) & 3, 3)
        self.assertEqual((leaf >> 53) & 3, 3)
        ram = struct.unpack_from("<Q", tables, 8)[0]
        self.assertEqual((ram >> 6) & 3, 1)
        self.assertEqual(ram & 3, 1)

    def test_zero_and_empty_feature_values_have_nonnull_expected_results(self):
        raw, cases = fixture.build_cases()
        selected = {case["name"]: case for case in cases}
        for name in ("lookup-first-value-zero", "lookup-middle-empty-value", "lookup-last-value-one"):
            self.assertNotEqual(selected[name]["expected"]["x0"], "0x0")
        self.assertEqual(selected["lookup-prefixes-and-bare-key"]["expected"]["x0"], "0x0")
        self.assertEqual(len(raw), fixture.INPUT_SIZE)
        self.assertEqual(sum(c["expected_syscall38_model_calls"] for c in cases), 5)

    def test_result_mismatch_and_model_counter_cannot_pass(self):
        case = {"name": "x", "expected": {"x0": "0x1"}, "observation": None,
                "expected_syscall38_model_calls": 1}
        cases = [copy.deepcopy(case)]
        self.assertFalse(fixture.check_results(cases, struct.pack("<2Q", 0, 7), [None], 1))
        self.assertEqual(cases[0]["observed"], {"x0": "0x0", "x1": "0x7"})
        self.assertFalse(fixture.check_results([copy.deepcopy(case)], struct.pack("<2Q", 1, 7), [None], 0))
        with self.assertRaises(audit.AuditError):
            fixture.check_results([case], b"", [None], 1)


class SyscallModelTests(unittest.TestCase):
    def record(self):
        raw = bytearray(320)
        struct.pack_into("<2Q", raw, 0, 1, 1)
        values = [0, 0, 0, 0x4b00ff80, 0, 0, 0, 0, 38, fixture.DYLD_BASE + 0xa9c4,
                  (0x15 << 26) | 0x80, fixture.DYLD_BASE + 0xa9d8, 0x4b00ff60, 0x60000000,
                  0x4b00ffaf, 0, 45, 0, 0x60000000]
        struct.pack_into("<19Q", raw, 64, *values)
        return raw

    def test_exact_positive_service_and_return_model_are_distinct_from_xnu_execution(self):
        report = fixture.decode_model_state(self.record())
        self.assertTrue(report["synthetic_model_verified"])
        self.assertFalse(report["actual_xnu_dispatch_verified"])
        self.assertEqual(report["records"][0]["x16_signed"], 38)

    def test_wrong_selector_signed_service_argument_and_carry_fail_with_raw_values_kept(self):
        for field, value in ((8, (1 << 64) - 38), (10, (0x15 << 26) | 0x81),
                             (0, 1), (11, fixture.DYLD_BASE + 0xa9dc), (18, 0x40000000),
                             (14, 0x4b010000), (13, 0x60000010)):
            raw = self.record()
            struct.pack_into("<Q", raw, 64 + field * 8, value)
            with self.subTest(field=field):
                report = fixture.decode_model_state(raw)
                self.assertFalse(report["synthetic_model_verified"])
                self.assertEqual(len(report["records"]), 1)

    def test_truncated_and_oversized_state_records_are_rejected(self):
        with self.assertRaises(audit.AuditError):
            fixture.decode_model_state(self.record()[:-1])
        raw = self.record()
        struct.pack_into("<Q", raw, 0, 65)
        with self.assertRaises(audit.AuditError):
            fixture.decode_model_state(raw)



def sysent_object():
    names = b"\0_sysent\0_nsysent\0_sys_crossarch_trap\0_munge_w\0"
    name_offsets = [names.index(name) for name in (b"_sysent", b"_nsysent", b"_sys_crossarch_trap", b"_munge_w")]
    data_offset, count, stride = 288, 39, 24
    table = bytearray(count * stride)
    struct.pack_into("<ihH", table, 38 * stride + 16, 1, 1, 4)
    reloc_offset = (data_offset + len(table) + 4 + 7) & ~7
    sym_offset = reloc_offset + 16
    strings_offset = sym_offset + 64
    segment = bytearray(232)
    struct.pack_into("<II16s4Q4I", segment, 0, 0x19, 232, b"", 0, len(table) + 4,
                     data_offset, len(table) + 4, 7, 7, 2, 0)
    struct.pack_into("<16s16sQQ8I", segment, 72, b"__const", b"__DATA", 0, len(table),
                     data_offset, 3, reloc_offset, 2, 0, 0, 0, 0)
    struct.pack_into("<16s16sQQ8I", segment, 152, b"__const", b"__TEXT", len(table), 4,
                     data_offset + len(table), 2, 0, 0, 0, 0, 0, 0)
    symcmd = struct.pack("<6I", 2, 24, sym_offset, 4, strings_offset, len(names))
    result = bytearray(struct.pack("<8I", 0xfeedfacf, 0x100000c, 0, 1, 2, 256, 0, 0) + segment + symcmd)
    result.extend(table + struct.pack("<I", count))
    result.extend(bytes(reloc_offset - len(result)))
    result.extend(struct.pack("<4I", 38 * stride, 0x0e000002, 38 * stride + 8, 0x0e000003))
    for i, (typ, section, value) in enumerate(((15, 1, 0), (15, 2, len(table)), (1, 0, 0), (1, 0, 0))):
        result.extend(struct.pack("<IBBHQ", name_offsets[i], typ, section, 0, value))
    result.extend(names)
    return result, reloc_offset, sym_offset


class XnuBindingTests(unittest.TestCase):
    def open_object(self, raw, directory):
        path = Path(directory) / "init_sysent.o"
        path.write_bytes(raw)
        return xnu.SelectedMachO(path, ("_sysent", "_nsysent"), 1)

    def test_compiled_extent_and_real_relocation_select_the_table_layout(self):
        raw, _, _ = sysent_object()
        with tempfile.TemporaryDirectory() as directory:
            obj = self.open_object(raw, directory)
            self.assertEqual(xnu.compiled_sysent_layout(obj), (39, 24))
            self.assertEqual(obj.relocation_symbol("_sysent", 38 * 24), "_sys_crossarch_trap")
            self.assertEqual(obj.relocation_symbol("_sysent", 38 * 24 + 8), "_munge_w")

    def test_wrong_width_relocation_and_pointer_addend_are_rejected(self):
        original, reloc, _ = sysent_object()
        mutations = []
        raw = bytearray(original)
        struct.pack_into("<I", raw, reloc + 4, 0x0c000002)
        mutations.append(raw)
        raw = bytearray(original)
        struct.pack_into("<Q", raw, 288 + 38 * 24, 4)
        mutations.append(raw)
        for raw in mutations:
            with tempfile.TemporaryDirectory() as directory, self.assertRaises(audit.AuditError):
                self.open_object(raw, directory).relocation_symbol("_sysent", 38 * 24)

    def test_weak_selected_symbol_and_wrong_architecture_are_rejected(self):
        original, _, sym = sysent_object()
        for offset, pattern in ((sym + 6, struct.pack("<H", 0x80)), (8, struct.pack("<I", 2))):
            raw = bytearray(original)
            raw[offset:offset + len(pattern)] = pattern
            with tempfile.TemporaryDirectory() as directory, self.assertRaises(audit.AuditError):
                self.open_object(raw, directory)

    def test_mismatched_compiled_count_cannot_infer_a_24_byte_layout(self):
        raw, _, _ = sysent_object()
        struct.pack_into("<I", raw, 288 + 39 * 24, 40)
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(audit.AuditError):
            xnu.compiled_sysent_layout(self.open_object(raw, directory))

    def test_contradictory_recipe_definitions_and_extra_json_are_rejected(self):
        import json
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.c"
            source.write_text("int x;\n")
            path = Path(directory) / "recipe.json"
            record = {"directory": directory, "file": "source.c",
                      "arguments": ["clang", "-D", "CONFIG_REQUIRES_U32_MUNGING", "-DCONFIG_REQUIRES_U32_MUNGING=0"]}
            path.write_text(json.dumps(record) + ",\n")
            with self.assertRaises(audit.AuditError):
                xnu.compiler_recipe(path)
            record["arguments"] = ["clang", "-D", "CONFIG_REQUIRES_U32_MUNGING"]
            path.write_text(json.dumps(record) + ",\n")
            self.assertEqual(xnu.compiler_recipe(path)["definitions"]["CONFIG_REQUIRES_U32_MUNGING"], "1")
            record["arguments"].append("-UCONFIG_REQUIRES_U32_MUNGING")
            path.write_text(json.dumps(record) + ",\n")
            self.assertNotIn("CONFIG_REQUIRES_U32_MUNGING", xnu.compiler_recipe(path)["definitions"])
            path.write_text(json.dumps(record) + ",{}")
            with self.assertRaises(audit.AuditError):
                xnu.compiler_recipe(path)


class FixtureReadTests(unittest.TestCase):
    def test_partial_memory_error_preserves_completed_chunk_and_error_reply(self):
        remote = SimpleNamespace(deadline=float("inf"), request=mock.Mock(side_effect=["ab" * 4096, "E14"]))
        record = {}
        with self.assertRaises(audit.AuditError):
            probe.memory_read(remote, 0x48001000, 4100, record)
        self.assertFalse(record["complete"])
        self.assertEqual(record["received_bytes"], 4096)
        self.assertEqual(record["chunks"][-1]["invalid_response_prefix"], "E14")

    def test_expired_deadline_and_overflow_do_not_send_a_read(self):
        remote = SimpleNamespace(deadline=0, request=mock.Mock())
        with self.assertRaises(audit.AuditError):
            probe.memory_read(remote, 0x48001000, 8, {})
        with self.assertRaises(audit.AuditError):
            probe.memory_read(remote, (1 << 64) - 4, 8, {})
        remote.request.assert_not_called()



def linked_function():
    address, code_offset = 0x100000000, 208
    code = struct.pack("<6I", *xnu.CROSSARCH_WORDS)
    strings = b"\0_function\0"
    symbol_offset = code_offset + len(code)
    segment = bytearray(152)
    struct.pack_into("<II16s4Q4I", segment, 0, 0x19, 152, b"__TEXT", address, 0x1000,
                     0, symbol_offset, 5, 5, 1, 0)
    struct.pack_into("<16s16sQQ8I", segment, 72, b"__text", b"__TEXT",
                     address + code_offset, len(code), code_offset, 2, 0, 0, 0x80000400, 0, 0, 0)
    symcmd = struct.pack("<6I", 2, 24, symbol_offset, 1, symbol_offset + 16, len(strings))
    symbol = struct.pack("<IBBHQ", 1, 15, 1, 0, address + code_offset)
    return bytearray(struct.pack("<8I", 0xfeedfacf, 0x100000c, 0, 2, 2, 176, 0, 0) +
                     segment + symcmd + code + symbol + strings)


class LinkedMappingTests(unittest.TestCase):
    def test_linked_function_bytes_follow_loaded_segment_mapping(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "kernel.macho"
            path.write_bytes(linked_function())
            image = xnu.SelectedMachO(path, ("_function",), 2)
            self.assertEqual(image.symbol_data("_function", 24, executable=True),
                             struct.pack("<6I", *xnu.CROSSARCH_WORDS))

    def test_in_bounds_section_offset_and_owner_cannot_redirect_final_function(self):
        original = linked_function()
        bad_offset = bytearray(original)
        struct.pack_into("<Q", bad_offset, 32 + 48, len(bad_offset))
        struct.pack_into("<I", bad_offset, 32 + 72 + 48, 212)
        wrong_owner = bytearray(original)
        wrong_owner[32 + 72 + 16:32 + 72 + 32] = b"__OTHER".ljust(16, b"\0")
        for raw in (bad_offset, wrong_owner):
            with self.subTest(raw=raw[120:128]), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "kernel.macho"
                path.write_bytes(raw)
                with self.assertRaises(audit.AuditError):
                    xnu.SelectedMachO(path, ("_function",), 2)


    def test_zero_section_linked_segment_cannot_exceed_its_virtual_extent(self):
        original = linked_function()
        empty = struct.pack("<II16s4Q4I", 0x19, 72, b"__BAD", 0x200000000, 0,
                            0, 1, 1, 1, 0, 0)
        raw = original[:208] + empty + original[208:]
        struct.pack_into("<II", raw, 16, 3, 248)
        struct.pack_into("<Q", raw, 32 + 48, 304)
        struct.pack_into("<Q", raw, 32 + 72 + 32, 0x100000000 + 280)
        struct.pack_into("<I", raw, 32 + 72 + 48, 280)
        struct.pack_into("<I", raw, 184 + 8, 304)
        struct.pack_into("<I", raw, 184 + 16, 320)
        struct.pack_into("<Q", raw, 304 + 8, 0x100000000 + 280)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "kernel.macho"
            path.write_bytes(raw)
            with self.assertRaisesRegex(audit.AuditError, "linked file extent"):
                xnu.SelectedMachO(path, ("_function",), 2)

    def test_pure_instructions_in_nonexecutable_segment_are_not_a_function_target(self):
        raw = linked_function()
        struct.pack_into("<I", raw, 32 + 60, 1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "kernel.macho"
            path.write_bytes(raw)
            image = xnu.SelectedMachO(path, ("_function",), 2)
            with self.assertRaisesRegex(audit.AuditError, "linked function is not executable"):
                image.symbol_data("_function", 24, executable=True)


class ToolIdentityTests(unittest.TestCase):
    def paths(self, directory):
        root = Path(directory)
        for name in ("first", "second"):
            (root / name).mkdir()
            (root / name / "ld.lld").write_bytes(b"same tool bytes\n")
        alias = root / "selected"
        alias.symlink_to(root / "first", target_is_directory=True)
        return root, alias, alias / "ld.lld"

    def test_changed_parent_alias_is_detected_with_identical_binary_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root, alias, invocation = self.paths(directory)
            first = probe.invocation_identity(invocation)
            alias.unlink()
            alias.symlink_to(root / "second", target_is_directory=True)
            second = probe.invocation_identity(invocation)
            self.assertEqual(first["binary"], second["binary"])
            self.assertNotEqual(first, second)
            self.assertIn(str(alias), [item["path"] for item in first["chain"]])

    def test_version_preserves_driver_name_and_rejects_identity_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root, alias, invocation = self.paths(directory)
            def version(argv, **kwargs):
                self.assertEqual(argv[0], str(invocation))
                alias.unlink()
                alias.symlink_to(root / "second", target_is_directory=True)
                return SimpleNamespace(returncode=0, stdout=b"tool version\n", stderr=b"")
            with mock.patch.object(probe.shutil, "which", return_value=str(invocation)), \
                 mock.patch.object(probe.subprocess, "run", side_effect=version), \
                 self.assertRaisesRegex(audit.AuditError, "changed during version"):
                probe.selected_tool("ld.lld")

    def test_post_observation_tool_change_revokes_fragment_result(self):
        import json
        with tempfile.TemporaryDirectory() as directory:
            root, alias, invocation = self.paths(directory)
            identity = probe.invocation_identity(invocation)
            tool = (str(invocation), {"invocation": str(invocation), "identity": identity, "version": "fixture"})
            output = root / "output"
            source = SimpleNamespace(identity={}, code_pages={}, starts=[], flat_image=lambda: b"dyld",
                                     recheck=lambda: True)
            def build(out, selected, report):
                (out / "entry.bin").write_bytes(b"entry")
            def observe(args, out, source, cases, report):
                report["fixture_result_observed"] = True
                alias.unlink()
                alias.symlink_to(root / "second", target_is_directory=True)
            args = SimpleNamespace(timeout=2, output=output, input="dyld", kernel="kernel",
                                   objects="objects", prepared="source", filelist="filelist",
                                   qemu="qemu", clang="clang", lld="lld", objcopy="objcopy")
            with mock.patch.object(probe, "Standalone", return_value=source), \
                 mock.patch.object(probe, "entry_contract", return_value={}), \
                 mock.patch.object(probe, "bind_syscall38", return_value={"inputs": {}}), \
                 mock.patch.object(probe, "selected_tool", return_value=tool), \
                 mock.patch.object(probe, "compile_fixture", side_effect=build), \
                 mock.patch.object(probe, "build_cases", return_value=(b"inputs", [])), \
                 mock.patch.object(probe, "page_tables", return_value=b"tables"), \
                 mock.patch.object(probe, "launch", side_effect=observe), \
                 mock.patch("builtins.print"):
                self.assertEqual(probe.run(args), 2)
            report = json.loads((output / "report.json").read_text())
            self.assertTrue(report["fixture_result_observed"])
            self.assertFalse(report["fragment_execution_verified"])
            self.assertFalse(report["inputs_unchanged"])
            self.assertFalse(report["input_recheck"]["tool:qemu"])
            self.assertEqual(report["status"], "failed")

if __name__ == "__main__":
    unittest.main()
