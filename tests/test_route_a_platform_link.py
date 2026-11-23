"""Fail-closed platform-link contracts, using small synthetic Mach-O inputs."""
import importlib.util
import difflib
import copy
import json
from pathlib import Path
import struct
import tempfile
import unittest
from contextlib import ExitStack
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("route_a_platform_link", ROOT / "scripts/link_route_a_platform.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

# Exact shape of the binary OID literal emitted by ld64 in link-attempt-003.
OID_MAP_ROW = bytes.fromhex(
    "3078464646464646463030373039313141410930783030303030303043095b3238395d20"
    "6c69746572616c20737472696e673a20065c74608648016503040201") + b"\n"


def image(symbols=(), *, filetype=1, subtype=0, entry=None, constructors=(), platform=2, minos=27 << 16,
          data_section=False):
    base = 0xFFFFFFF007004000 if filetype == 2 else 0
    text = struct.pack("<16s16sQQ8I", b"__text", b"__TEXT_EXEC", base, 0x40,
                       0x1000, 2, 0, 0, 0x80000400, 0, 0, 0)
    init = struct.pack("<16s16sQQ8I", b"__mod_init_func", b"__DATA_CONST", base + 0x40, 8 * len(constructors),
                       0x1040, 3, 0, 0, 9, 0, 0, 0)
    sections = text + init
    if data_section:
        sections += struct.pack("<16s16sQQ8I", b"__data", b"__DATA", base + 0x60, 0x20,
                                0x1060, 3, 0, 0, 0, 0, 0, 0)
    segment = struct.pack("<II16sQQQQ4I", 0x19, 72 + len(sections), b"__TEXT_EXEC", base, 0x80,
                          0x1000, 0x80, 7, 5, 3 if data_section else 2, 0) + sections
    strings, nlists = bytearray(b"\0"), bytearray()
    for symbol in symbols:
        name, n_type, desc, value = symbol[:4]
        n_sect = symbol[4] if len(symbol) == 5 else (1 if n_type & 0xE == 0xE else 0)
        at = len(strings)
        strings += name.encode() + b"\0"
        nlists += struct.pack("<IBBHQ", at, n_type, n_sect, desc, value)
    symoff, stroff = 0x1100, 0x1100 + len(nlists)
    commands = (segment + struct.pack("<6I", 2, 24, symoff, len(symbols), stroff, len(strings)) +
                struct.pack("<6I", 0x32, 24, platform, minos, minos, 0))
    if filetype == 2:
        thread = bytearray(288)
        struct.pack_into("<4I", thread, 0, 5, 288, 6, 68)
        struct.pack_into("<Q", thread, 272, base + 0x10 if entry is None else entry)
        commands += thread
    data = bytearray(stroff + len(strings))
    struct.pack_into("<8I", data, 0, 0xFEEDFACF, 0x0100000C, subtype, filetype,
                     4 if filetype == 2 else 3, len(commands), 0, 0)
    data[32:32 + len(commands)] = commands
    for index, value in enumerate(constructors):
        struct.pack_into("<Q", data, 0x1040 + 8 * index, value)
    data[symoff:stroff], data[stroff:] = nlists, strings
    return bytes(data)


def ar_member(name, payload, *, bsd=False):
    if bsd:
        embedded = name.encode()
        rawname, payload = f"#1/{len(embedded)}", embedded + payload
    else:
        rawname = name + "/"
    header = (f"{rawname:<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(payload):<10}`\n").encode()
    return header + payload + (b"\n" if len(payload) % 2 else b"")


def callback_source_fixture():
    """Three separated synthetic hunks; no real kernel source is distributed."""
    before = "".join(f"unchanged_{i};\n" for i in range(30))
    after = before.replace("unchanged_2;", "void (*arm64_platform_sleep_hook)(int);\nunchanged_2;")
    after = after.replace("unchanged_14;", "arm64_platform_sleep_hook(1);\narm_init_cpu(0, 0);\nunchanged_14;")
    after = after.replace("unchanged_25;", "arm64_platform_sleep_hook(0);\nunchanged_25;")
    delta = "# Copyright: synthetic test fixture\n\n" + "".join(difflib.unified_diff(
        before.splitlines(True), after.splitlines(True), fromfile="a/osfmk/arm64/cpu.c",
        tofile="b/osfmk/arm64/cpu.c", n=2))
    return before.encode(), delta.encode(), after.encode()


class PlatformCallbackContractsTests(unittest.TestCase):
    def test_exact_three_hunks_allow_unique_offsets_but_reject_fuzzy_or_ambiguous_context(self):
        before, delta, after = callback_source_fixture()
        self.assertEqual(MODULE.apply_cpu_patch(before, delta), after)
        # Pinned earlier patches can shift upstream line numbers; complete
        # matching context still has to be unique and ordered.
        shifted = b"earlier unchanged line;\n" + before
        self.assertEqual(MODULE.apply_cpu_patch(shifted, delta), b"earlier unchanged line;\n" + after)
        for invalid in (before.replace(b"unchanged_13;", b"different;"), before + before):
            with self.assertRaisesRegex(MODULE.LinkError, "absent or ambiguous"):
                MODULE.apply_cpu_patch(invalid, delta)
        with self.assertRaisesRegex(MODULE.LinkError, "another file"):
            MODULE.apply_cpu_patch(before, delta + b"--- a/other.c\n+++ b/other.c\n")

    def test_replacement_inventory_keeps_real_weak_winner_and_does_not_double_count_old_cpu(self):
        kernel = MODULE.macho(image([("_ml_arm_sleep", 0xF, 0, 4), ("_weak_in_cpu", 0xF, 0, 8)]), 1)
        old = MODULE.macho(image([("_ml_arm_sleep", 0xF, 0, 4), ("_weak_in_cpu", 0xF, 0x80, 8)]), 1)
        new = MODULE.macho(image([("_ml_arm_sleep", 0xF, 0, 4), ("_weak_in_cpu", 0xF, 0x80, 8),
                                  (MODULE.CALLBACK_SYMBOL, 0xF, 0, 0x60, 3)], data_section=True), 1)
        callback = {"name": "replacement cpu", "macho": new, "original_macho": old}
        provider = {"name": "ArmCpu", "macho": MODULE.macho(image([(MODULE.CALLBACK_SYMBOL, 1, 0x40, 0)]), 1)}
        sources = MODULE.callback_kernel_symbols(kernel, callback)
        result = MODULE.symbol_closure(sources, [provider])
        self.assertEqual(result["duplicate_strong_definitions"], {})
        self.assertEqual(result["unresolved_platform_weak"], [])
        self.assertEqual([s["name"] for s in sources[0]["macho"]["symbols"]["defined_external"]], ["_weak_in_cpu"])
        self.assertFalse(result["inventory_is_link_success"])

    def test_hook_must_be_strong_pointer_sized_data_not_a_function_or_weak_stub(self):
        good = image([(MODULE.CALLBACK_SYMBOL, 0xF, 0, 0x60, 3)], data_section=True)
        self.assertEqual(MODULE.hook_definition(MODULE.macho(good, 1))["section"]["name"], "__data")
        for symbols in ([(MODULE.CALLBACK_SYMBOL, 0xF, 0x80, 0x60, 3)],
                        [(MODULE.CALLBACK_SYMBOL, 0xF, 0, 0x10)],
                        [(MODULE.CALLBACK_SYMBOL, 0xF, 0, 0x7C, 3)]):
            with self.assertRaises(MODULE.LinkError):
                MODULE.hook_definition(MODULE.macho(image(symbols, data_section=True), 1))

    def test_replacement_filelist_changes_exactly_one_entry_and_preserves_baseline(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            old, new = root / "kernel/cpu.o", root / "callback/cpu.o"
            callback = {"evidence": {"original_object": {"path": str(old)},
                                      "replacement_object": {"path": str(new)}}}
            baseline, platform = root / "link.filelist", root / "platform.filelist"
            raw = b"before.o\ncpu.o\nafter.o\n"
            baseline.write_bytes(raw)
            recipe = {"cwd": str(old.parent), "linked_object_count": 7}
            with patch.object(MODULE, "FILELIST_SHA256", MODULE.sha256(raw)):
                evidence = MODULE.replace_cpu_filelist(recipe, baseline, platform, callback)
            self.assertEqual(baseline.read_bytes(), raw)
            self.assertEqual(platform.read_text().splitlines(), ["before.o", str(new), "after.o"])
            self.assertEqual(evidence["replacement_count"], 1)
            self.assertEqual(evidence["unchanged_original_linked_object_count"], 6)
            for bad in (b"before.o\nafter.o\n", b"cpu.o\ncpu.o\n"):
                baseline.write_bytes(bad)
                destination = root / ("missing" if bad.count(b"cpu.o") == 0 else "duplicate")
                with patch.object(MODULE, "FILELIST_SHA256", MODULE.sha256(bad)):
                    with self.assertRaisesRegex(MODULE.LinkError, "exactly once"):
                        MODULE.replace_cpu_filelist(recipe, baseline, destination, callback)
                self.assertFalse(destination.exists())

    def test_map_requires_new_cpu_hook_and_sleep_function_and_excludes_original_cpu(self):
        base = 0xFFFFFFF007004000
        data = image([(MODULE.CALLBACK_SYMBOL, 0xF, 0, base + 0x60, 3),
                      ("_ml_arm_sleep", 0xF, 0, base + 0x10)], filetype=2, data_section=True)
        parsed = MODULE.macho(data, 2)
        callback = {"evidence": {"original_object": {"path": "/old/cpu.o"},
                                  "replacement_object": {"path": "/new/cpu.o"}}}
        text = (f"[ 9] /new/cpu.o\n0x{base + 0x60:X} 0x8 [ 9] {MODULE.CALLBACK_SYMBOL}\n"
                f"0x{base + 0x10:X} 0x8 [ 9] _ml_arm_sleep\n")
        self.assertEqual(MODULE.verify_callback_link_map(text, callback, parsed)["object_index"], 9)
        for wrong, error in ((text + "[ 10] /old/cpu.o\n", "original cpu.o"),
                             (text.replace("/new/cpu.o", "/different/cpu.o"), "actual replacement"),
                             (text.replace("_ml_arm_sleep", "_unrelated"), "not retained"),
                             (text.replace(f"0x{base + 0x60:X}", f"0x{base + 0x68:X}"), "map address")):
            with self.assertRaisesRegex(MODULE.LinkError, error):
                MODULE.verify_callback_link_map(wrong, callback, parsed)
        for original, changed in ((b"/new/cpu.o", b"/new/cpu\x86.o"),
                                  (b"_ml_arm_sleep", b"_ml_arm_\x86sleep"),
                                  (MODULE.CALLBACK_SYMBOL.encode(), b"_arm64_platform_sleep_\x86hook")):
            altered, _ = MODULE.decode_link_map(text.encode().replace(original, changed))
            with self.subTest(changed=changed), self.assertRaises(MODULE.LinkError):
                MODULE.verify_callback_link_map(altered, callback, parsed)

    def test_codegen_consumes_real_decoder_evidence_and_rejects_changed_blr_bytes(self):
        from test_route_a_kernel_callback import object_fixture
        producer = MODULE.callback_producer()
        raw = object_fixture()
        _, symbols, sections, relocations = producer.object_layout(raw)
        decoder, decoder_id = producer.decoder_identity()
        proof = producer.callback_evidence(raw, symbols, sections, relocations, decoder)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = {"sha256": MODULE.sha256(b"synthetic callback source")}
            disassembly = root / "disassembly.txt"
            disassembly.write_text("synthetic fixture: actual code bytes decoded independently\n")
            observed = {**proof, "object_sha256": MODULE.sha256(raw), "source_sha256": source["sha256"],
                        "disassembly": MODULE.identity(disassembly)}
            evidence = root / "evidence.json"
            evidence.write_text(json.dumps(observed))
            report = {"callback_evidence": MODULE.identity(evidence), "decoder": decoder_id,
                      "disassembly": MODULE.identity(disassembly)}
            result, inputs = MODULE.callback_codegen(producer, report, raw, source)
            self.assertTrue(result["recomputed_from_replacement_object"])
            self.assertTrue(MODULE.check_unchanged(inputs)["unchanged"])
            # Updating only the reported object digest must not preserve a
            # stale passing proof after one actual indirect call is removed.
            changed = bytearray(raw)
            struct.pack_into("<I", changed, proof["dispatch_calls"][0]["file_offset"], 0xD503201F)
            observed["object_sha256"] = MODULE.sha256(changed)
            evidence.write_text(json.dumps(observed))
            report["callback_evidence"] = MODULE.identity(evidence)
            with self.assertRaisesRegex(MODULE.LinkError, "generated-code verification failed"):
                MODULE.callback_codegen(producer, report, changed, source)


class PlatformCallbackReportTests(unittest.TestCase):
    """Real recipe replay and metadata checks; the code decoder is a fixture.

    The producer has its own emitted-instruction tests. These tests exercise
    the consuming boundary, including forged reports and changed arguments.
    """
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.kernel, self.prefix = self.root / "kernel", self.root / "tools"
        self.producer = MODULE.callback_producer()
        self.patches = ExitStack()

        def file(path, content):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            return MODULE.identity(path)

        self.file = file
        before, delta, after = callback_source_fixture()
        original = file(self.kernel / MODULE.CPU_OBJECT_RELATIVE, image([("_ml_arm_sleep", 0xF, 0, 0x10)]))
        self.candidate = self.kernel / MODULE.KERNEL_RELATIVE / MODULE.KERNEL_NAME
        candidate = file(self.candidate, image([("_ml_arm_sleep", 0xF, 0, 0xFFFFFFF007004010)], filetype=2))
        old_source = file(self.kernel / MODULE.CPU_SOURCE_RELATIVE, before)
        source = file(self.root / "callback/source/cpu.c", after)
        delta_id = file(self.root / "callback/selection.patch", delta)
        compiler = file(self.prefix / "llvm/bin/clang", b"synthetic compiler identity")
        command = {"directory": str(Path(original["path"]).parent), "file": old_source["path"], "output": "cpu.o",
                   "arguments": [compiler["path"], "-xc", old_source["path"], "-o", "cpu.o",
                                 "--target=arm64-apple-ios27.0", "-mcpu=generic", "-arch", "arm64",
                                 "-mios-version-min=27.0", "-c", "-O2", "-D", "KEEP_ABI=1", "-I", ".",
                                 "-Wno-unused", "-Wno-unused", "-MJ", "cpu.o.json"]}
        original_recipe = file(Path(original["path"]).with_name("cpu.o.json"), (json.dumps(command) + ",\n").encode())
        replacement = file(self.root / "callback/replacement/cpu.o", image([
            ("_ml_arm_sleep", 0xF, 0, 0x10), (MODULE.CALLBACK_SYMBOL, 0xF, 0, 0x60, 3)], data_section=True))
        replacement["symbols"] = file(self.root / "callback/replacement/symbols.json", json.dumps(
            MODULE.macho(Path(replacement["path"]).read_bytes(), 1)["symbols"]).encode())
        argv, changes = self.producer.replay_recipe(command, self.kernel, Path(source["path"]), Path(replacement["path"]).parent)
        self.replay = {"directory": str(Path(replacement["path"]).parent), "file": source["path"],
                       "output": replacement["path"], "arguments": argv}
        replay = file(self.root / "callback/replacement/replay.json", json.dumps(self.replay).encode())
        self.generated = {"passed": True, "scope": "synthetic bounded callback fixture",
            "function": {"name": "_ml_arm_sleep", "address": "0x10", "end": "0x30"},
            "dispatch_calls": [{"instruction": "blr", "argument_value": 1, "address": "0x10"},
                               {"instruction": "blr", "argument_value": 0, "address": "0x20"}],
            "resume_call": {"symbol": "_arm_init_cpu", "instruction": "bl", "second_argument": 0,
                            "after_boot_dispatch": True, "address": "0x18"},
            "runtime_path_execution_verified": False, "sleep_resume_verified": False,
            "full_instruction_set_audited": False, "full_control_flow_proven": False}
        disassembly = file(self.root / "callback/disassembly.txt", b"synthetic disassembly artifact\n")
        self.observed = {**copy.deepcopy(self.generated), "object_sha256": replacement["sha256"],
                         "source_sha256": source["sha256"], "disassembly": disassembly}
        code = file(self.root / "callback/evidence.json", json.dumps(self.observed).encode())
        decoder = {"version": "5.0.6", "core_version": [5, 0, 1280]}
        for key in ("module", "native_library", "python"):
            decoder[key] = file(self.root / "decoder" / key, ("decoder fixture " + key).encode())
        support = [MODULE.identity(ROOT / "scripts/build_route_a_platform.py"),
                   MODULE.identity(ROOT / "scripts/prepare_route_a_toolchain.py")]
        config = {"schema_version": 1, "scope": "arm64-platform-sleep-cpu-replacement",
                  "provenance": MODULE.CALLBACK_PROVENANCE,
                  "patch": {"sha256": delta_id["sha256"], "result_source_sha256": source["sha256"]},
                  "support_files": [{"path": "scripts/" + Path(item["path"]).name,
                                     "sha256": item["sha256"]} for item in support]}
        config_id = file(self.root / "callback/config.json", json.dumps(config).encode())
        stdout = file(self.root / "callback/compile.stdout", b"")
        stderr = file(self.root / "callback/compile.stderr", b"retained compiler warning\n")
        compiled = {"label": "cpu-compile", "status": "completed", "exit_code": 0, "argv": argv,
                    "cwd": self.replay["directory"], "stdout": stdout["path"], "stdout_sha256": stdout["sha256"],
                    "stderr": stderr["path"], "stderr_sha256": stderr["sha256"]}
        self.report = {"schema_version": 1, "status": "kernel_callback_built", "kernel_callback_built": True,
            "scope": config["scope"], "provenance": MODULE.CALLBACK_PROVENANCE, "kernel": candidate,
            "original_object": original, "replacement_object": replacement,
            "source": {"before": old_source, "after": source},
            "compile_record": {"original": original_recipe, "replay": replay},
            "driver": MODULE.identity(Path(self.producer.__file__)), "compiler": compiler, "patch": delta_id,
            "config": config_id, "support_files": support, "callback_evidence": code,
            "recipe_changes": changes, "compile": compiled, "disassembly": disassembly, "decoder": decoder}
        required = [candidate, original, old_source, source, original_recipe, self.report["driver"],
                    config_id, delta_id, compiler, *support]
        self.report["protected_input_rechecks"] = [{"path": item["path"], "expected_sha256": item["sha256"],
            "actual_sha256": item["sha256"], "unchanged": True} for item in required]
        self.report["protected_inputs_unchanged"] = True
        self.report["protected_inputs_recheck"] = {"unchanged": True, "checked_file_count": len(required), "changes": []}
        self.report_path = self.root / "callback/report.json"
        for name, value in (("CPU_OBJECT_SHA256", original["sha256"]), ("CPU_SOURCE_SHA256", old_source["sha256"]),
                            ("CPU_RECIPE_SHA256", original_recipe["sha256"]), ("CALLBACK_PATCH_SHA256", delta_id["sha256"]),
                            ("CALLBACK_SOURCE_SHA256", source["sha256"]), ("CLANG_SHA256", compiler["sha256"])):
            self.patches.enter_context(patch.object(MODULE, name, value))
        self.patches.enter_context(patch.object(self.producer, "decoder_identity", return_value=(None, decoder)))
        self.patches.enter_context(patch.object(self.producer, "callback_evidence", return_value=self.generated))

    def tearDown(self):
        self.patches.close()
        self.temp.cleanup()

    def verify(self):
        self.report_path.write_text(json.dumps(self.report))
        return MODULE.verify_callback(self.report_path, self.candidate, self.kernel, self.prefix)

    def write_replay(self):
        entry = self.report["compile_record"]["replay"]
        self.report["compile_record"]["replay"] = self.file(Path(entry["path"]), json.dumps(self.replay).encode())

    def test_full_report_binds_real_replay_source_symbols_evidence_and_protected_inputs(self):
        callback, inputs = self.verify()
        self.assertTrue(callback["evidence"]["recipe_reconstruction_verified"])
        self.assertTrue(callback["evidence"]["generated_code_verification"]["recomputed_from_replacement_object"])
        self.assertFalse(callback["evidence"]["runtime_path_execution_verified"])
        self.assertTrue(MODULE.check_unchanged(inputs)["unchanged"])
        Path(self.report["compile_record"]["replay"]["path"]).write_text("changed after preflight")
        self.assertFalse(MODULE.check_unchanged(inputs)["unchanged"])

    def test_changed_or_late_target_and_removed_abi_or_warning_arguments_are_rejected(self):
        original = list(self.replay["arguments"])
        for changed in (original + ["--target=arm64e-apple-ios27.0"], original + ["-mcpu=apple-m1"],
                        [arg for arg in original if arg != "KEEP_ABI=1"],
                        [arg for arg in original if arg != "-Wno-unused"]):
            with self.subTest(changed=changed[-3:]):
                self.replay["arguments"] = changed
                self.write_replay()
                with self.assertRaisesRegex(MODULE.LinkError, "CPU contract|exact reconstruction"):
                    self.verify()

    def test_missing_unchanged_receipt_or_omitted_original_source_is_rejected(self):
        self.report["protected_inputs_unchanged"] = False
        with self.assertRaisesRegex(MODULE.LinkError, "unchanged-input receipt"):
            self.verify()
        self.report["protected_inputs_unchanged"] = True
        self.report["protected_input_rechecks"].pop(2)
        self.report["protected_inputs_recheck"]["checked_file_count"] -= 1
        with self.assertRaisesRegex(MODULE.LinkError, "omits a required"):
            self.verify()

    def test_forged_generated_code_calls_and_resume_are_recomputed_from_object(self):
        original = copy.deepcopy(self.observed)
        for key in ("passed", "dispatch_calls", "resume_call"):
            observed = copy.deepcopy(original)
            observed[key] = False if key == "passed" else [] if key == "dispatch_calls" else {}
            path = Path(self.report["callback_evidence"]["path"])
            self.report["callback_evidence"] = self.file(path, json.dumps(observed).encode())
            with self.subTest(key=key), self.assertRaisesRegex(MODULE.LinkError, "generated-code evidence"):
                self.verify()

    def test_wrong_upstream_provenance_and_wrong_original_object_are_rejected(self):
        self.report["provenance"] = {**MODULE.CALLBACK_PROVENANCE, "commit": "0" * 40}
        with self.assertRaisesRegex(MODULE.LinkError, "provenance differs"):
            self.verify()
        self.report["provenance"] = MODULE.CALLBACK_PROVENANCE
        Path(self.report["original_object"]["path"]).write_bytes(image())
        self.report["original_object"].update(MODULE.identity(Path(self.report["original_object"]["path"])))
        with self.assertRaisesRegex(MODULE.LinkError, "pinned kernel cpu.o"):
            self.verify()


class PlatformLinkMetadataTests(unittest.TestCase):
    def test_weak_reference_is_not_a_strong_link_failure(self):
        data = image([("_required", 1, 0, 0), ("_optional_sleep", 1, 0x40, 0),
                      ("_common", 1, 0, 8), ("_weak_definition", 0xF, 0x80, 4)])
        symbols = MODULE.macho(data, 1)["symbols"]
        self.assertEqual([s["name"] for s in symbols["strong_undefined"]], ["_required"])
        self.assertEqual([s["name"] for s in symbols["weak_undefined"]], ["_optional_sleep"])
        self.assertEqual([s["name"] for s in symbols["common_external"]], ["_common"])
        self.assertEqual(symbols["defined_external"][0]["n_desc"], 0x80)

    def test_metadata_rejects_wrong_abi_unbounded_strings_and_unsupported_alias(self):
        with self.assertRaisesRegex(MODULE.LinkError, "ordinary-arm64"):
            MODULE.macho(image(subtype=2), 1)
        corrupted = bytearray(image([("_x", 1, 0, 0)]))
        struct.pack_into("<I", corrupted, 0x1100, 0xFFFFFFF0)
        with self.assertRaisesRegex(MODULE.LinkError, "string index"):
            MODULE.macho(corrupted, 1)
        with self.assertRaisesRegex(MODULE.LinkError, "unsupported external"):
            MODULE.macho(image([("_alias", 0xB, 0, 1)]), 1)

    def test_entry_requires_file_backed_executable_range(self):
        linked = MODULE.macho(image(filetype=2), 2)
        self.assertEqual(linked["load_contract"]["required_physical_base_low_21_bits"], 0x4000)
        self.assertEqual(linked["load_contract"]["entry_offset"], 0x10)
        with self.assertRaisesRegex(MODULE.LinkError, "file-backed executable"):
            MODULE.macho(image(filetype=2, entry=0xFFFFFFF007006000), 2)

    def test_deployment_command_is_exactly_one_complete_ios27_record(self):
        for kwargs in ({"platform": 1}, {"minos": 26 << 16}):
            with self.assertRaisesRegex(MODULE.LinkError, "iOS 27.0"):
                MODULE.macho(image(**kwargs), 1)
        corrupted = bytearray(image())
        version_at = 32 + 232 + 24
        struct.pack_into("<I", corrupted, version_at + 20, 1)
        with self.assertRaisesRegex(MODULE.LinkError, "tool count/size"):
            MODULE.macho(corrupted, 1)
        corrupted = bytearray(image())
        end = 32 + struct.unpack_from("<I", corrupted, 20)[0]
        corrupted[end:end + 24] = struct.pack("<6I", 0x32, 24, 2, 27 << 16, 27 << 16, 0)
        struct.pack_into("<I", corrupted, 16, 4)
        struct.pack_into("<I", corrupted, 20, end - 32 + 24)
        with self.assertRaisesRegex(MODULE.LinkError, "exactly one"):
            MODULE.macho(corrupted, 1)

    def test_regular_archive_binds_actual_payload_and_refuses_thin_or_duplicate(self):
        obj = image()
        for bsd in (False, True):
            members = MODULE.archive_members(b"!<arch>\n" + ar_member("ArmCpu.o", obj, bsd=bsd))
            self.assertEqual(members[0]["data"], obj)
            self.assertEqual(members[0]["sha256"], MODULE.sha256(obj))
        with self.assertRaisesRegex(MODULE.LinkError, "regular archive"):
            MODULE.archive_members(b"!<thin>\n")
        with self.assertRaisesRegex(MODULE.LinkError, "duplicate"):
            MODULE.archive_members(b"!<arch>\n" + ar_member("a.o", obj) * 2)

    def test_closure_respects_weak_definitions_and_checks_cross_component_references(self):
        kernel = {"name": "kernel", "macho": MODULE.macho(image([("_shared", 0xF, 0, 4)]), 1)}
        first = {"name": "ArmDTPlatform", "macho": MODULE.macho(image([
            ("_shared", 0xF, 0x80, 4), ("_provider", 0xF, 0, 8), ("_missing", 1, 0, 0)]), 1)}
        second = {"name": "ArmCpu", "macho": MODULE.macho(image([
            ("_provider", 1, 0, 0), ("_optional", 1, 0x40, 0)]), 1)}
        result = MODULE.symbol_closure([kernel], [first, second])
        self.assertEqual(result["duplicate_strong_definitions"], {})
        self.assertEqual(result["unresolved_platform_strong"], [{"component": "ArmDTPlatform", "symbol": "_missing"}])
        self.assertEqual(result["unresolved_platform_weak"], [{"component": "ArmCpu", "symbol": "_optional"}])
        self.assertFalse(result["inventory_is_link_success"])
        first["macho"] = MODULE.macho(image([("_shared", 0xF, 0, 4)]), 1)
        self.assertIn("_shared", MODULE.symbol_closure([kernel], [first, second])["duplicate_strong_definitions"])

    def test_map_preserves_binary_literals_and_uses_only_ascii_lf_structure(self):
        raw = (b"[289] /kernel/oid.o\n" + OID_MAP_ROW +
               "0x40 0x4 [289] literal string: ─ ∑ \u0085[900] /forged.o\u2028"
               "0x80 0x4 [900] _forged\n".encode() +
               "[\u0661] /unicode-digit.o\n[300]\u00a0/nonbreaking-space.o\n"
               "0xA0\u20030x4 [289] _unicode_whitespace\n".encode())
        text, decoding = MODULE.decode_link_map(raw)
        self.assertEqual(text.encode("utf-8", "surrogateescape"), raw)
        self.assertTrue(decoding["lossless_roundtrip_verified"])
        self.assertEqual(decoding["surrogateescaped_byte_count"], 1)
        self.assertEqual(json.loads(json.dumps(text)).encode("utf-8", "surrogateescape"), raw)
        objects, symbols = MODULE.parse_link_map(text)
        self.assertEqual(objects, {289: "/kernel/oid.o"})
        self.assertEqual(len(symbols), 2)
        self.assertEqual(symbols[0]["name"].encode("utf-8", "surrogateescape"),
                         OID_MAP_ROW.split(b"] ", 1)[1][:-1])
        self.assertIn("\u0085[900]", symbols[1]["name"])
        self.assertIn("\u20280x80", symbols[1]["name"])

    def test_map_requires_member_constructor_metaclass_and_marker(self):
        base = 0xFFFFFFF007004000
        data = image(filetype=2, constructors=(base + 0x10, base + 0x20))
        parsed = MODULE.macho(data, 2)
        components, lines = [], ["# Object files:"]
        for index, name in enumerate(MODULE.COMPONENTS, 1):
            components.append({"name": name, "archive": {"path": "/new/lib" + name + ".a"},
                               "member": {"name": name + ".o"}})
            lines.append(f"[{index:3}] /new/lib{name}.a({name}.o)")
        lines.append("# Symbols:")
        for index, name in enumerate(MODULE.COMPONENTS, 1):
            marker = "_armdt_platform_configured" if index == 1 else "_armcpu_registered"
            for address, symbol in ((base + 16 * index, f"__GLOBAL__sub_I_{name}.cpp"),
                                    (base + 0x50 + index * 8, f"__ZN{name}gMetaClassE"),
                                    (base + 0x60 + index * 4, marker)):
                lines.append(f"0x{address:X} 0x4 [{index:3}] {symbol}")
        text = "\n".join(lines)
        self.assertEqual(len(MODULE.verify_link_map(text, components, parsed, data)["components"]), 2)
        with self.assertRaisesRegex(MODULE.LinkError, "retained constructor"):
            MODULE.verify_link_map(text, components, parsed, image(filetype=2, constructors=(base + 0x10, 0)))
        with self.assertRaisesRegex(MODULE.LinkError, "actual archive member"):
            MODULE.verify_link_map(text.replace("/new/libArmCpu.a", "/stale/libArmCpu.a"), components, parsed, data)
        with self.assertRaisesRegex(MODULE.LinkError, "metaclass"):
            MODULE.verify_link_map(text.replace("gMetaClass", "otherGlobal"), components, parsed, data)
        raw = text.encode() + b"\n[289] /kernel/oid.o\n" + OID_MAP_ROW
        decoded, _ = MODULE.decode_link_map(raw)
        self.assertEqual(len(MODULE.verify_link_map(decoded, components, parsed, data)["components"]), 2)
        for original, changed in (
                (b"/new/libArmCpu.a", b"/new/libArm\x86Cpu.a"),
                (b"_armcpu_registered", b"_armcpu_\x86registered"),
                (b"__ZNArmCpugMetaClassE", b"__ZNArmCpu\x86gMetaClassE"),
                (b"__GLOBAL__sub_I_ArmCpu.cpp", "__GLOBAL__sub_I_ArmCpuλ.cpp".encode()),
                (b"__GLOBAL__sub_I_ArmCpu.cpp", b"__GLOBAL__sub_I_ArmCpu\x06.cpp")):
            altered, _ = MODULE.decode_link_map(raw.replace(original, changed))
            with self.subTest(changed=changed), self.assertRaises(MODULE.LinkError):
                MODULE.verify_link_map(altered, components, parsed, data)

    def test_platform_report_cannot_substitute_archive_bytes_or_stale_object(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            candidate = root / "kernel"
            candidate.write_bytes(image(filetype=2))
            report = {"status": "archives_built", "scope": "public-platform-archives-against-generic-kernel",
                      "kernel": MODULE.identity(candidate), "components": []}
            for name in MODULE.COMPONENTS:
                obj, archive, symbols = root / (name + ".o"), root / ("lib" + name + ".a"), root / (name + ".json")
                obj.write_bytes(image())
                archive.write_bytes(b"!<arch>\n" + ar_member(obj.name, obj.read_bytes(), bsd=True))
                symbols.write_text(json.dumps(MODULE.macho(obj.read_bytes(), 1)["symbols"]))
                report["components"].append({"name": name, "status": "archive_built",
                    "object": {**MODULE.identity(obj), "symbols": MODULE.identity(symbols)},
                    "archive": {**MODULE.identity(archive), "members": [{"name": obj.name, "object_path": str(obj),
                                                                          "sha256": MODULE.identity(obj)["sha256"]}]}})
            path = root / "report.json"
            path.write_text(json.dumps(report))
            self.assertEqual(len(MODULE.verify_platform(path, candidate)[1]), 2)
            archive = Path(report["components"][1]["archive"]["path"])
            archive.write_bytes(b"!<arch>\n" + ar_member("ArmCpu.o", image([("_foreign", 1, 0, 0)]), bsd=True))
            # Even updating the container hash cannot substitute its retained object.
            report["components"][1]["archive"].update(MODULE.identity(archive))
            path.write_text(json.dumps(report))
            with self.assertRaisesRegex(MODULE.LinkError, "exactly the recorded object"):
                MODULE.verify_platform(path, candidate)

    def test_tool_alias_retarget_is_detected_even_with_identical_target_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            original, replacement, alias = root / "original", root / "replacement", root / "ld"
            original.write_bytes(b"same executable bytes")
            replacement.write_bytes(original.read_bytes())
            alias.symlink_to(original.name)
            record = MODULE.tool_identity(alias)
            self.assertEqual(record["path"], str(alias))
            self.assertEqual(record["realpath"], str(original))
            self.assertEqual(record["symlink_target"], original.name)
            self.assertTrue(MODULE.check_unchanged([record])["unchanged"])
            alias.unlink()
            alias.symlink_to(replacement.name)
            changed = MODULE.check_unchanged([record])
            self.assertFalse(changed["unchanged"])
            self.assertEqual(changed["changes"][0]["before"]["sha256"], changed["changes"][0]["after"]["sha256"])
            self.assertNotEqual(changed["changes"][0]["before"]["realpath"], changed["changes"][0]["after"]["realpath"])

    def test_tool_parent_alias_and_broken_alias_are_rechecked(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ("old", "new"):
                (root / name).mkdir()
                (root / name / "clang").write_bytes(b"same compiler bytes")
            alias = root / "bin"
            alias.symlink_to("old", target_is_directory=True)
            record = MODULE.tool_identity(alias / "clang")
            self.assertIsNone(record["symlink_target"])
            alias.unlink()
            alias.symlink_to("new", target_is_directory=True)
            self.assertFalse(MODULE.check_unchanged([record])["unchanged"])
            alias.unlink()
            alias.symlink_to("missing", target_is_directory=True)
            result = MODULE.check_unchanged([record])
            self.assertFalse(result["unchanged"])
            self.assertIn("error", result["changes"][0])


class PlatformLinkReplayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.kernel, self.prefix = self.root / "kernel", self.root / "tools"
        self.cwd = self.kernel / MODULE.KERNEL_RELATIVE
        self.cwd.mkdir(parents=True)
        self.prefix.mkdir()
        self.output = self.root / "isolated"
        (self.output / "inputs").mkdir(parents=True)
        self.sdk = self.kernel / ".cache/fakeroot/usr/local/lib/kernel"
        self.sdk.mkdir(parents=True)
        for name in ("libcc_kext.a", "libfirehose_kernel.a"):
            (self.sdk / name).write_bytes(b"retained archive")
        for name in ("all-kpi.exp", "all-alias.exp", "symbolsets.plist"):
            (self.cwd / name).write_bytes(b"fixed metadata")
        self.flags = self.cwd / ".LDFLAGS"
        self.flags.write_bytes((f"{self.prefix}/CommandLineTools/usr/bin/clang++ -nostdlib -arch arm64 "
                               f"-Wl,-static {self.sdk}/libcc_kext.a\n\0").encode())
        archives = self.cwd / "mach.development.bcm2837.link/mach.development.bcm2837.linkarchives"
        archives.parent.mkdir()
        archives.write_text(f"-L{self.sdk} -L{self.sdk}/platform -lfirehose_kernel\n")
        filelist = self.cwd / "link.filelist"
        filelist.write_text("first.o\nsecond.cpo\n")
        for name in ("first.o", "second.cpo", *MODULE.EXTRA_OBJECTS):
            (self.cwd / name).write_bytes(image())
        make_dir = self.kernel / ".cache/xnu-work/makedefs"
        make_dir.mkdir(parents=True)
        for name in MODULE.MAKE_PINS:
            (make_dir / name).write_bytes(b"fixed make recipe")
        self.patches = ExitStack()
        for constant, path in (("FLAGS_SHA256", self.flags), ("ARCHIVES_SHA256", archives),
                               ("FILELIST_SHA256", filelist)):
            self.patches.enter_context(patch.object(MODULE, constant, MODULE.identity(path)["sha256"]))
        self.patches.enter_context(patch.object(MODULE, "FILELIST_OBJECT_COUNT", 2))
        self.patches.enter_context(patch.object(MODULE, "MAKE_PINS", {
            name: MODULE.identity(make_dir / name)["sha256"] for name in MODULE.MAKE_PINS}))
        self.patches.enter_context(patch.object(MODULE, "EXTRA_OBJECTS", {
            name: MODULE.identity(self.cwd / name)["sha256"] for name in MODULE.EXTRA_OBJECTS}))

    def tearDown(self):
        self.patches.close()
        self.temp.cleanup()

    def test_reconstructed_rule_keeps_order_and_sends_all_outputs_to_new_directory(self):
        recipe, inputs = MODULE.recover_recipe(self.kernel, self.prefix)
        self.assertFalse(recipe["captured_final_argv"])
        self.assertTrue(recipe["byte_identical_baseline_required"])
        self.assertEqual(recipe["linked_object_count"], 6)
        self.assertEqual([Path(path).name for path in recipe["extra_objects"]], list(MODULE.EXTRA_OBJECTS))
        filelist = self.output / "inputs/link.filelist"
        filelist.write_bytes((self.cwd / "link.filelist").read_bytes())
        command = MODULE.link_command(recipe, filelist, self.output / "candidate", self.output / "candidate.map", [
            {"archive": {"path": "/new/libArmCpu.a"}}])
        self.assertEqual(command[command.index("-o") + 1], str(self.output / "candidate"))
        self.assertEqual(command[command.index("-filelist") + 1], str(filelist))
        self.assertEqual(command[-1], "-Wl,-force_load,/new/libArmCpu.a")
        self.assertIn(f"-Wl,-map,{self.output}/candidate.map", command)
        self.assertTrue(MODULE.check_unchanged(inputs)["unchanged"])
        (self.cwd / "first.o").write_bytes(b"changed object")
        self.assertFalse(MODULE.check_unchanged(inputs)["unchanged"])

    def test_modified_retained_flags_and_lto_artifacts_block_reconstruction(self):
        original = self.flags.read_bytes()
        self.flags.write_bytes(original.replace(b"-nostdlib", b"-nostdlib -Wl,-undefined,dynamic_lookup"))
        with self.assertRaisesRegex(MODULE.LinkError, "fixed baseline"):
            MODULE.recover_recipe(self.kernel, self.prefix)
        self.flags.write_bytes(original)
        (self.cwd / "nonltolink.filelist").write_text("first.o\n")
        with self.assertRaisesRegex(MODULE.LinkError, "PRE_LTO"):
            MODULE.recover_recipe(self.kernel, self.prefix)

    def test_outputs_cannot_overwrite_prior_or_protected_locations(self):
        recipe, _ = MODULE.recover_recipe(self.kernel, self.prefix)
        filelist = self.output / "inputs/link.filelist"
        filelist.write_bytes((self.cwd / "link.filelist").read_bytes())
        with self.assertRaisesRegex(MODULE.LinkError, "isolated directory"):
            MODULE.link_command(recipe, filelist, self.cwd / "candidate", self.output / "candidate.map")
        (self.output / "candidate").write_bytes(b"earlier attempt")
        with self.assertRaisesRegex(MODULE.LinkError, "earlier link"):
            MODULE.link_command(recipe, filelist, self.output / "candidate", self.output / "candidate.map")

    def test_output_inside_real_installation_is_rejected_before_mkdir(self):
        from argparse import Namespace
        toolwork = self.root / "toolchain-work"
        toolwork.mkdir()
        (toolwork / "identity.json").write_text(json.dumps({"prefix": str(self.prefix)}))
        platform = self.root / "platform/report.json"
        platform.parent.mkdir()
        platform.write_text("{}")
        alias = self.root / "tools-alias"
        alias.symlink_to(self.prefix, target_is_directory=True)
        before = sorted(self.prefix.rglob("*"))
        for parent in (self.prefix, alias):
            args = Namespace(kernel_dir=self.kernel, toolchain_work=toolwork,
                             platform_report=platform, output=parent / "forbidden-result")
            with self.assertRaisesRegex(MODULE.LinkError, "overlaps protected"):
                MODULE.run(args)
            self.assertFalse(args.output.exists())
            self.assertEqual(sorted(self.prefix.rglob("*")), before)

    def test_invalid_installation_identity_creates_no_output(self):
        from argparse import Namespace
        toolwork = self.root / "toolchain-work"
        toolwork.mkdir()
        (toolwork / "identity.json").write_text(json.dumps({"prefix": "relative-prefix"}))
        platform = self.root / "platform/report.json"
        platform.parent.mkdir()
        platform.write_text("{}")
        args = Namespace(kernel_dir=self.kernel, toolchain_work=toolwork,
                         platform_report=platform, output=self.root / "must-not-exist")
        with self.assertRaisesRegex(MODULE.LinkError, "installation prefix"):
            MODULE.run(args)
        self.assertFalse(args.output.exists())

    def test_output_inside_callback_evidence_tree_is_rejected_before_mkdir(self):
        from argparse import Namespace
        toolwork = self.root / "toolchain-work"
        toolwork.mkdir()
        (toolwork / "identity.json").write_text(json.dumps({"prefix": str(self.prefix)}))
        platform, callback = self.root / "platform/report.json", self.root / "callback/report.json"
        for path in (platform, callback):
            path.parent.mkdir()
            path.write_text("{}")
        args = Namespace(kernel_dir=self.kernel, toolchain_work=toolwork, platform_report=platform,
                         kernel_callback_report=callback, output=callback.parent / "forbidden-result")
        with self.assertRaisesRegex(MODULE.LinkError, "overlaps protected"):
            MODULE.run(args)
        self.assertFalse(args.output.exists())

    def test_tool_environment_restores_recorded_source_version_and_preserves_alias_identity(self):
        toolwork = self.root / "toolchain-work"
        toolwork.mkdir()
        compiler = self.prefix / "llvm/bin/clang"
        compiler.parent.mkdir(parents=True)
        compiler.write_bytes(b"verified compiler fixture")
        compiler_sha = MODULE.identity(compiler)["sha256"]
        ld_target = self.prefix / "ld-real"
        ld_target.write_bytes(b"verified linker fixture")
        ld = self.prefix / "CommandLineTools/usr/bin/ld"
        ld.parent.mkdir(parents=True)
        ld.symlink_to(ld_target)
        (toolwork / "identity.json").write_text(json.dumps({"prefix": str(self.prefix)}))
        (toolwork / "state.json").write_text(json.dumps({"status": "clang_verified",
            "verification": {"compiler": {"sha256": compiler_sha}}}))
        (toolwork / "host-tools-state.json").write_text(json.dumps({"status": "host_tools_built",
            "combined_toolchain_verified": True, "outputs": [{"path": str(ld),
                                                               "sha256": MODULE.identity(ld_target)["sha256"]}]}))
        original_env = MODULE.toolchain.toolchain_environment(self.prefix, self.kernel / ".cache/fakeroot")
        original_env["UNIXNU_XNU_VERSION"] = "12377.121.6"
        report = {"compiler": {"sha256": compiler_sha}, "environment": original_env}
        with patch.object(MODULE, "CLANG_SHA256", compiler_sha):
            prefix, inputs, env = MODULE.tool_inputs(toolwork, report)
            self.assertEqual(prefix, self.prefix)
            self.assertEqual(env["RC_ProjectSourceVersion"], "12377.121.6")
            self.assertTrue(any(item["path"] == str(ld) and item.get("realpath") == str(ld_target)
                                for item in inputs))
            report["environment"]["UNIXNU_XNU_VERSION"] = "0"
            with self.assertRaisesRegex(MODULE.LinkError, "source version"):
                MODULE.tool_inputs(toolwork, report)
            del report["environment"]["UNIXNU_XNU_VERSION"]
            with self.assertRaisesRegex(MODULE.LinkError, "source version"):
                MODULE.tool_inputs(toolwork, report)

    def exercise_run(self, action, *, with_callback=False):
        from argparse import Namespace
        candidate = self.cwd / MODULE.KERNEL_NAME
        baseline_bytes = image([("_ml_arm_sleep", 0xF, 0, 0xFFFFFFF007004030)], filetype=2) if with_callback else image(filetype=2)
        candidate.write_bytes(baseline_bytes)
        candidate.with_name(MODULE.KERNEL_NAME + ".noctf").write_bytes(candidate.read_bytes())
        metadata = self.kernel / ".route-a"
        metadata.mkdir()
        (metadata / "build.lock").touch()
        build_report = metadata / "build-report.json"
        build_report.write_text(json.dumps({"status": "builder_completed", "exit_code": 0}))
        toolwork = self.root / "toolwork"
        toolwork.mkdir()
        (toolwork / "identity.json").write_text(json.dumps({"prefix": str(self.prefix)}))
        (toolwork / "build.lock").touch()
        (toolwork / "host-tools.lock").touch()
        platform = self.root / "platform/report.json"
        platform.parent.mkdir()
        platform.write_text("{}")
        components = []
        for name in MODULE.COMPONENTS:
            obj, archive = platform.parent / (name + ".o"), platform.parent / ("lib" + name + ".a")
            obj.write_bytes(image())
            archive.write_bytes(b"!<arch>\n" + ar_member(obj.name, obj.read_bytes()))
            symbols = platform.parent / (name + ".symbols.json")
            symbols.write_text(json.dumps(MODULE.macho(obj.read_bytes(), 1)["symbols"]))
            components.append({"name": name, "object": MODULE.identity(obj), "archive": MODULE.identity(archive),
                               "symbol_report": MODULE.identity(symbols),
                               "member": {"name": obj.name}, "macho": MODULE.macho(obj.read_bytes(), 1)})
        calls = []

        def simulated_link(argv, **kwargs):
            calls.append(list(argv))
            kwargs["report"]["commands"].append({"label": kwargs["label"], "argv": argv})
            return action(candidate, argv, len(calls))

        args = Namespace(kernel_dir=self.kernel, toolchain_work=toolwork, platform_report=platform,
                         output=self.root / "run-output")
        if with_callback:
            original = self.kernel / MODULE.CPU_OBJECT_RELATIVE
            original.parent.mkdir(parents=True)
            original.write_bytes(image([("_ml_arm_sleep", 0xF, 0, 0x30)]))
            replacement = self.root / "callback/replacement/cpu.o"
            replacement.parent.mkdir(parents=True)
            replacement.write_bytes(image([("_ml_arm_sleep", 0xF, 0, 0x30),
                                            (MODULE.CALLBACK_SYMBOL, 0xF, 0, 0x60, 3)], data_section=True))
            args.kernel_callback_report = self.root / "callback/report.json"
            args.kernel_callback_report.write_text("{}")
            filelist = self.cwd / "link.filelist"
            filelist.write_text(str(original) + "\nsecond.cpo\n")
            self.patches.enter_context(patch.object(MODULE, "FILELIST_SHA256", MODULE.identity(filelist)["sha256"]))
            callback = {"name": "kernel cpu callback", "original_macho": MODULE.macho(original.read_bytes(), 1),
                        "macho": MODULE.macho(replacement.read_bytes(), 1),
                        "evidence": {"original_object": MODULE.identity(original),
                                     "replacement_object": MODULE.identity(replacement)}}
            callback_inputs = [MODULE.identity(path) for path in (original, replacement, args.kernel_callback_report)]
            # Provenance/recipe/code-evidence gates are exercised separately by
            # PlatformCallbackReportTests; this fixture tests link sequencing.
            self.patches.enter_context(patch.object(MODULE, "verify_callback", return_value=(callback, callback_inputs)))
        with patch.object(MODULE, "KERNEL_SHA256", MODULE.identity(candidate)["sha256"]), \
                patch.object(MODULE, "BUILD_REPORT_SHA256", MODULE.identity(build_report)["sha256"]), \
                patch.object(MODULE, "verify_platform", return_value=({}, components)), \
                patch.object(MODULE, "tool_inputs", return_value=(self.prefix, [], {"PATH": "/usr/bin"})), \
                patch.object(MODULE, "execute", side_effect=simulated_link):
            result = MODULE.run(args)
        self.assertTrue((args.output / "report.json").is_file())
        self.assertEqual(candidate.read_bytes(), baseline_bytes)
        return result, calls

    def test_baseline_mismatch_never_attempts_platform_link(self):
        def action(candidate, argv, count):
            Path(argv[argv.index("-o") + 1]).write_bytes(candidate.read_bytes() + b"different")
            return {"exit_code": 0}

        result, calls = self.exercise_run(action)
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["status"], "failed")
        self.assertIn("differs byte-for-byte", result["error"])
        self.assertFalse(result["baseline_reproduced"])
        self.assertFalse(result["platform_link_compatible"])
        self.assertTrue(result["protected_inputs_recheck"]["unchanged"])
        self.assertFalse(any("-force_load" in arg for arg in calls[0]))

    def test_protected_input_mutation_is_recorded_even_when_link_fails(self):
        def action(candidate, argv, count):
            (self.cwd / "first.o").write_bytes(b"unexpected mutation")
            return {"exit_code": 1}

        result, calls = self.exercise_run(action)
        self.assertEqual(len(calls), 1)
        self.assertFalse(result["protected_inputs_recheck"]["unchanged"])
        self.assertEqual(result["protected_inputs_recheck"]["changes"][0]["path"], str(self.cwd / "first.o"))
        self.assertFalse(result["platform_link_compatible"])

    def test_exact_baseline_then_actual_link_failure_preserves_diagnostics_and_scope(self):
        def action(candidate, argv, count):
            if count == 1:
                Path(argv[argv.index("-o") + 1]).write_bytes(candidate.read_bytes())
            return {"exit_code": 0 if count == 1 else 1}

        result, calls = self.exercise_run(action)
        self.assertEqual(len(calls), 2)
        self.assertTrue(result["baseline_reproduced"])
        self.assertEqual(result["failed_stage"], "linking_platform")
        baseline_path = Path(calls[0][calls[0].index("-o") + 1])
        self.assertEqual(baseline_path.name, MODULE.KERNEL_NAME + ".noctf")
        self.assertTrue(baseline_path.is_absolute())
        self.assertNotEqual(baseline_path.parent, self.cwd)
        self.assertEqual(sum("-force_load" in arg for arg in calls[1]), 2)
        self.assertFalse(any("-undefined" in arg for arg in calls[1]))
        self.assertTrue(result["protected_inputs_recheck"]["unchanged"])
        for key in ("platform_link_compatible", "complete_board_archive_closure", "crypto_provider_selected",
                    "pthread_provider_selected", "tb371fc_kernel_qualified", "os_boot_verified"):
            self.assertFalse(result[key])

    def test_callback_is_only_in_platform_filelist_after_exact_baseline_and_actual_map_checks(self):
        base = 0xFFFFFFF007004000
        observed_filelists = []

        def action(candidate, argv, count):
            output = Path(argv[argv.index("-o") + 1])
            filelist = Path(argv[argv.index("-filelist") + 1])
            observed_filelists.append(filelist.read_bytes())
            if count == 1:
                output.write_bytes(candidate.read_bytes())
                self.assertEqual(filelist.read_bytes(), (self.cwd / "link.filelist").read_bytes())
                self.assertFalse((filelist.parent / "platform-link.filelist").exists())
                return {"exit_code": 0}
            replacement = self.root / "callback/replacement/cpu.o"
            self.assertEqual(filelist.read_text().splitlines(), [str(replacement), "second.cpo"])
            output.write_bytes(image([("_ml_arm_sleep", 0xF, 0, base + 0x30),
                                      (MODULE.CALLBACK_SYMBOL, 0xF, 0, base + 0x60, 3)],
                                     filetype=2, constructors=(base + 0x10, base + 0x20), data_section=True))
            map_path = Path(next(arg.split(",", 2)[2] for arg in argv if arg.startswith("-Wl,-map,")))
            archives = [arg.split(",", 2)[2] for arg in argv if arg.startswith("-Wl,-force_load,")]
            lines = [f"[ 9] {replacement}", f"0x{base + 0x60:X} 0x8 [ 9] {MODULE.CALLBACK_SYMBOL}",
                     f"0x{base + 0x30:X} 0x8 [ 9] _ml_arm_sleep"]
            for index, name in enumerate(MODULE.COMPONENTS, 1):
                marker = "_armdt_platform_configured" if index == 1 else "_armcpu_registered"
                lines.extend([f"[{index:3}] {archives[index - 1]}({name}.o)",
                    f"0x{base + index * 16:X} 0x4 [{index:3}] __GLOBAL__sub_I_{name}.cpp",
                    f"0x{base + 0x70 + index * 4:X} 0x4 [{index:3}] __ZN{name}gMetaClassE",
                    f"0x{base + 0x80 + index * 4:X} 0x4 [{index:3}] {marker}"])
            map_path.write_bytes("\n".join(lines).encode() + b"\n[289] /kernel/oid.o\n" + OID_MAP_ROW)
            return {"exit_code": 0}

        result, calls = self.exercise_run(action, with_callback=True)
        self.assertEqual(result["status"], "platform_link_compatible", result.get("error"))
        self.assertEqual(len(calls), 2)
        self.assertTrue(result["baseline_reproduced"])
        self.assertTrue(result["kernel_callback_linked"])
        self.assertTrue(result["link_map_decoding"]["lossless_roundtrip_verified"])
        self.assertEqual(result["link_map_decoding"]["surrogateescaped_byte_count"], 1)
        self.assertEqual(result["link_map"]["sha256"], MODULE.sha256(Path(result["link_map"]["path"]).read_bytes()))
        replacement = result["kernel_callback"]["filelist_replacement"]
        self.assertEqual(replacement["replacement_count"], 1)
        self.assertEqual(replacement["unchanged_original_linked_object_count"], 5)
        self.assertNotEqual(observed_filelists[0], observed_filelists[1])
        self.assertEqual((self.cwd / "link.filelist").read_bytes(), observed_filelists[0])
        inventory = json.loads(Path(result["protected_input_inventory"]["path"]).read_text())
        self.assertIn(str(self.kernel / MODULE.CPU_OBJECT_RELATIVE), [item["path"] for item in inventory])
        self.assertTrue(result["protected_inputs_recheck"]["unchanged"])
        self.assertFalse(result["sleep_runtime_verified"])
        self.assertFalse(result["tb371fc_kernel_qualified"])
        self.assertFalse(result["os_boot_verified"])

    def test_callback_never_replaces_baseline_filelist_when_baseline_digest_mismatches(self):
        def action(candidate, argv, count):
            Path(argv[argv.index("-o") + 1]).write_bytes(candidate.read_bytes() + b"mismatch")
            return {"exit_code": 0}

        result, calls = self.exercise_run(action, with_callback=True)
        self.assertEqual(len(calls), 1)
        self.assertFalse(result["kernel_callback_linked"])
        self.assertFalse((Path(result["output"]) / "inputs/platform-link.filelist").exists())
        self.assertTrue(result["protected_inputs_recheck"]["unchanged"])

    def test_callback_object_is_rechecked_after_a_failing_link(self):
        def action(candidate, argv, count):
            if count == 1:
                Path(argv[argv.index("-o") + 1]).write_bytes(candidate.read_bytes())
                return {"exit_code": 0}
            (self.root / "callback/replacement/cpu.o").write_bytes(b"unexpected external mutation")
            return {"exit_code": 1}

        result, calls = self.exercise_run(action, with_callback=True)
        self.assertEqual(len(calls), 2)
        self.assertFalse(result["platform_link_compatible"])
        self.assertFalse(result["kernel_callback_linked"])
        self.assertFalse(result["protected_inputs_recheck"]["unchanged"])
        self.assertIn(str(self.root / "callback/replacement/cpu.o"),
                      [item["path"] for item in result["protected_inputs_recheck"]["changes"]])


if __name__ == "__main__":
    unittest.main()
