"""Boundary regressions; synthetic Mach-O/compile failures are not kernel builds."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("route_a_kernel_callback", ROOT / "scripts/build_route_a_kernel_callback.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def object_fixture(words=None, references=None, weak=False):
    # ADRP/LDR/CBZ/MOV/BLR for TRUE, then an actual BL relocation to resume;
    # a second ADRP/LDR/CBZ/MOV/BLR for FALSE. This fixture is never executed.
    words = words or [0x90000008, 0xf9400108, 0xb40000a8, 0x52800020, 0xd63f0100,
                      0xd2800001, 0x94000000, 0x90000008, 0xf9400108, 0xb4000088,
                      0x52800000, 0xd63f0100, 0xd503201f, 0xd65f03c0, 0xd65f03c0]
    code = struct.pack("<" + "I" * len(words), *words)
    function_end, hook_address = len(code) - 4, (len(code) + 7) & ~7
    # index, n_type, section, n_desc, value
    entries = [("_ml_arm_sleep", 0xf, 1, 0, 0), ("_next_function", 0xf, 1, 0, function_end),
               ("_arm64_platform_sleep_hook", 0xf, 2, 0x80 if weak else 0, hook_address),
               ("_arm_init_cpu", 1, 0, 0, 0), ("_unrelated", 1, 0, 0, 0)]
    text_offset = 32 + 232 + 24 + 24
    reloc_offset = (text_offset + len(code) + 7) & ~7
    references = references or [(0, 3, 2, True), (4, 4, 2, False), (24, 2, 3, True),
                                (28, 3, 2, True), (32, 4, 2, False)]
    relocations = b"".join(struct.pack("<II", off, symbol | (int(pcrel) << 24) | (2 << 25) | (1 << 27) | (kind << 28))
                            for off, kind, symbol, pcrel in references)
    symoff = reloc_offset + len(relocations)
    strings, symbols = b"\0", b""
    for name, typ, section, desc, value in entries:
        symbols += struct.pack("<IBBHQ", len(strings), typ, section, desc, value)
        strings += name.encode() + b"\0"
    def section(name, segment, address, size, offset, relocs, count, flags):
        return struct.pack("<16s16sQQ8I", name.encode(), segment.encode(), address, size, offset,
                           3 if name == "__bss" else 2, relocs, count, flags, 0, 0, 0)
    segment = struct.pack("<II16sQQQQIIII", 0x19, 232, b"", 0, hook_address + 8, text_offset, len(code), 7, 7, 2, 0)
    segment += section("__text", "__TEXT", 0, len(code), text_offset, reloc_offset, len(references), 0x80000400)
    segment += section("__bss", "__DATA", hook_address, 8, 0, 0, 0, 1)
    commands = segment + struct.pack("<6I", 0x32, 24, 2, 27 << 16, 0, 0)
    commands += struct.pack("<6I", 2, 24, symoff, len(entries), symoff + len(symbols), len(strings))
    header = struct.pack("<8I", 0xfeedfacf, 0x0100000c, 0, 1, 3, len(commands), 0, 0)
    return header + commands + code + b"\0" * (reloc_offset - text_offset - len(code)) + relocations + symbols + strings


def tail_words():
    # The secondary CBNZ at 36 targets 60, bypassing a call and an unrelated
    # block. The B at 56 prevents fallthrough into MOV w0,wzr; BLR x8.
    return [0x90000008, 0xf9400108, 0xb40000a8, 0x52800020, 0xd63f0100,
            0xd2800001, 0x94000000, 0x90000008, 0xf9400108, 0xb50000c8,
            0x52800020, 0x94000000, 0xd503201f, 0xd503201f, 0x17fffff2,
            0x2a1f03e0, 0xd63f0100, 0x52800020, 0x94000000, 0xd65f03c0]


def context_fixture(patch):
    lines = patch.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.startswith("@@ ")]
    source, after, shift = [], [], 0
    for number, (begin, actual_line) in enumerate(zip(starts, (99, 1109, 1151))):
        end = starts[number + 1] if number + 1 < len(starts) else len(lines)
        body = [line for line in lines[begin + 1:end] if line.rstrip("\r\n")]
        old = [line[1:] for line in body if line.startswith(" ")]
        new = [line[1:] for line in body if line.startswith((" ", "+"))]
        padding = ["// synthetic context-only fixture\n"] * (actual_line - 1 - len(source))
        source.extend(padding + old)
        after.extend(padding + new)
        shift += len(new) - len(old)
    return "".join(source), "".join(after)


class CallbackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.kernel = self.root / "kernel"
        self.cwd = self.kernel / "objects"
        self.cwd.mkdir(parents=True)
        self.original = self.kernel / MODULE.SOURCE_RELATIVE
        self.original.parent.mkdir(parents=True)
        self.original.write_text("// synthetic C input\n")
        self.output = self.root / "isolated"
        self.source = self.output / "source/osfmk/arm64/cpu.c"
        self.recipe = {"directory": str(self.cwd), "file": str(self.original), "output": "cpu.o",
                       "arguments": ["/fixture/clang-24", "-xc", str(self.original), "-o", "cpu.o", "-c",
                                     "--target=arm64-apple-ios27.0", "-mcpu=generic", "-arch", "arm64",
                                     "-mios-version-min=27.0", "-I", ".", "-include", "meta_features.h",
                                     "-Weverything", "-Wno-missing-variable-declarations", "-Wno-pre-c11-compat",
                                     "-Wno-missing-variable-declarations", "--target=arm64-apple-ios27.0.0"]}

    def replay(self, record=None):
        return MODULE.replay_recipe(record or self.recipe, self.kernel, self.source, self.output / "replacement")

    def test_c_recipe_preserves_warning_order_and_abi_with_every_output_isolated(self):
        self.recipe["arguments"] += ["-MD", "-MFold.d", "-MJ", "old.json", "-MTold.o", "-MQ", "old2.o"]
        argv, changes = self.replay()
        original_warnings = [v for v in self.recipe["arguments"] if v.startswith("-W")]
        self.assertEqual([v for v in argv if v.startswith("-W")], original_warnings)
        self.assertNotIn("-Werror", argv)
        self.assertEqual(argv[argv.index("-I") + 1], str(self.cwd))
        for flag, target in (("-o", "cpu.o"), ("-MF", "dependencies.d"), ("-MJ", "compiler-record.json"), ("-MT", "cpu.o")):
            self.assertEqual(argv[argv.index(flag) + 1], str(self.output / "replacement" / target))
        self.assertEqual(argv.count("-MD"), 1)
        self.assertIn(str(self.source), argv)
        self.assertNotIn(str(self.original), argv)
        self.assertTrue(changes["warnings_preserved_exactly"])
        self.assertFalse(changes["abi_options_changed"])

    def test_c_recipe_refuses_abi_changes_and_hidden_output_channels(self):
        for extra in (["-xc++"], ["-mcpu=cortex-a77"], ["-march=armv8.3-a"], ["-arch", "arm64e"],
                      ["@flags"], ["-Xclang", "-load", "plugin"], ["--config=hidden"], ["-save-temps"],
                      ["-Wp,-MD,original.d"], ["-fmodules-cache-path=original"], ["-serialize-diagnostics", "original.dia"],
                      ["-I", "/unbound"], ["-D", "__arm64e__=1"], ["--target=arm64-apple-macos27.0"]):
            with self.subTest(extra=extra):
                record = copy.deepcopy(self.recipe)
                record["arguments"] += extra
                with self.assertRaises(MODULE.CallbackError):
                    self.replay(record)

    def test_patch_is_identity_bound_and_requires_unique_complete_context(self):
        config = json.loads(MODULE.CONFIG.read_text())
        path = ROOT / config["patch"]["path"]
        MODULE.verify_patch(path, config["patch"])
        before, _ = context_fixture(path.read_text())
        matches = MODULE.patch_context_matches(before, path.read_text())
        self.assertEqual([item["actual_old_line"] for item in matches], [99, 1109, 1151])
        self.assertEqual([item["line_offset"] for item in matches], [0, -32, -32])
        for bad in (before + before, before.replace("mt_sleep();", "other_sleep();")):
            with self.assertRaises(MODULE.CallbackError):
                MODULE.patch_context_matches(bad, path.read_text())
        altered = self.root / "altered.patch"
        altered.write_text(path.read_text().replace("arm64_platform_sleep_hook(TRUE)", "arm64_platform_sleep_hook(FALSE)"))
        with self.assertRaisesRegex(MODULE.CallbackError, "identity changed"):
            MODULE.verify_patch(altered, config["patch"])

    def evidence(self, raw):
        decoder, _ = MODULE.decoder_identity()
        _, symbols, sections, relocations = MODULE.object_layout(raw)
        return MODULE.callback_evidence(raw, symbols, sections, relocations, decoder)

    def test_actual_a64_sequences_require_two_hook_calls_and_boot_resume(self):
        result = self.evidence(object_fixture())
        self.assertTrue(result["passed"])
        self.assertEqual(sorted(item["argument_value"] for item in result["dispatch_calls"]), [0, 1])
        self.assertEqual(result["resume_call"]["symbol"], "_arm_init_cpu")
        self.assertEqual(result["resume_call"]["second_argument"], 0)
        self.assertFalse(result["runtime_path_execution_verified"])
        self.assertFalse(result["full_control_flow_proven"])

    def test_symbols_or_unrelated_calls_cannot_forge_callback_evidence(self):
        base = [0x90000008, 0xf9400108, 0xb40000a8, 0x52800020, 0xd63f0100,
                0xd2800001, 0x94000000, 0x90000008, 0xf9400108, 0xb4000088,
                0x52800000, 0xd63f0100, 0xd503201f, 0xd65f03c0, 0xd65f03c0]
        for index, replacement in ((4, 0xd503201f), (3, 0x52800040), (2, 0xd503201f), (5, 0xd2800021)):
            words = list(base)
            words[index] = replacement
            with self.subTest(index=index), self.assertRaises(MODULE.CallbackError):
                self.evidence(object_fixture(words=words))
        for references in ([(0, 3, 4, True), (4, 4, 4, False), (24, 2, 3, True), (28, 3, 2, True), (32, 4, 2, False)],
                           [(0, 3, 2, True), (4, 4, 2, False), (24, 2, 4, True), (28, 3, 2, True), (32, 4, 2, False)]):
            with self.subTest(references=references), self.assertRaises(MODULE.CallbackError):
                self.evidence(object_fixture(references=references))
        with self.assertRaisesRegex(MODULE.CallbackError, "strong section definition"):
            self.evidence(object_fixture(weak=True))

    def test_secondary_callback_follows_only_the_explicit_cbnz_taken_tail(self):
        result = self.evidence(object_fixture(words=tail_words()))
        calls = {item["argument_value"]: item for item in result["dispatch_calls"]}
        self.assertEqual(calls[1]["control_flow_shape"], "cbz-fallthrough")
        self.assertEqual(calls[0]["control_flow_shape"], "cbnz-taken-tail-block")
        self.assertEqual(calls[0]["null_guard_address"], "0x24")
        self.assertEqual(calls[0]["guard_taken_target"], "0x3c")
        self.assertEqual(calls[0]["address"], "0x40")
        self.assertEqual(calls[0]["local_direct_incoming"], ["0x24"])
        self.assertEqual(calls[0]["tail_entry_predecessor"], {"address": "0x38", "instruction": "b"})
        self.assertFalse(result["full_control_flow_proven"])
        self.assertFalse(result["runtime_path_execution_verified"])

    def test_tail_rejects_changed_guard_pointer_path_argument_or_incoming_edges(self):
        cases = [("wrong edge", 9, 0xb40000c8), ("wrong guard register", 9, 0xb50000c9),
                 ("narrow guard", 9, 0x350000c8), ("narrow pointer", 8, 0xb9400108),
                 ("skipped argument", 9, 0xb50000e8), ("wrong BLR register", 16, 0xd63f0120),
                 ("missing BLR", 16, 0xd503201f), ("TRUE in secondary", 15, 0x52800020),
                 ("nonboolean argument", 15, 0x52800040), ("physical fallthrough", 14, 0xd503201f),
                 ("extra entry", 12, 0x14000003), ("entry at BLR", 12, 0x14000004),
                 ("branch in tail", 15, 0x14000001)]
        for label, index, word in cases:
            words = tail_words()
            words[index] = word
            with self.subTest(label=label), self.assertRaises(MODULE.CallbackError):
                self.evidence(object_fixture(words=words))
        for word in (0x2a1f03e8, 0xaa1f03e8):  # Both W8 and X8 clobber the hook register.
            words = tail_words()
            words.insert(15, word)
            with self.subTest(clobber=hex(word)), self.assertRaisesRegex(MODULE.CallbackError, "clobber"):
                self.evidence(object_fixture(words=words))
        references = [(0, 3, 2, True), (4, 4, 2, False), (24, 2, 3, True),
                      (28, 3, 4, True), (32, 4, 2, False)]
        with self.assertRaisesRegex(MODULE.CallbackError, "actual ADRP relocation"):
            self.evidence(object_fixture(words=tail_words(), references=references))
        # A bogus external PAGE21 must not hide a second direct B into the tail.
        words = tail_words()
        words[12] = 0x14000003
        references = [(0, 3, 2, True), (4, 4, 2, False), (24, 2, 3, True),
                      (28, 3, 2, True), (32, 4, 2, False), (48, 3, 4, True)]
        with self.assertRaisesRegex(MODULE.CallbackError, "another explicit local incoming edge"):
            self.evidence(object_fixture(words=words, references=references))

    def test_nonplain_object_and_bad_relocation_geometry_are_rejected(self):
        raw = bytearray(object_fixture())
        struct.pack_into("<I", raw, 8, 0x80000000)
        with self.assertRaises(MODULE.CallbackError):
            MODULE.object_layout(bytes(raw))
        raw = bytearray(object_fixture())
        # __text.nreloc is in the first section_64 record.
        struct.pack_into("<I", raw, 32 + 72 + 60, 0x10000000)
        with self.assertRaisesRegex(MODULE.CallbackError, "relocations exceed"):
            MODULE.object_layout(bytes(raw))

    def test_failed_compile_keeps_full_logs_and_original_input_rechecks(self):
        config = json.loads(MODULE.CONFIG.read_text())
        patch = (ROOT / config["patch"]["path"]).read_text()
        before, after = context_fixture(patch)
        self.original.write_text(before)
        (self.cwd / "cpu.o").write_bytes(b"original object sentinel")
        recipe_path = self.cwd / "cpu.o.json"
        recipe_path.write_text(json.dumps(self.recipe))
        original_id, object_id = MODULE.identity(self.original), MODULE.identity(self.cwd / "cpu.o")
        config["baseline"].update(recipe_source_sha256=original_id["sha256"], recipe_source_size=original_id["size"],
                                  original_object_path="objects/cpu.o", original_object_sha256=object_id["sha256"],
                                  original_object_size=object_id["size"])
        import hashlib
        config["patch"].update(result_source_sha256=hashlib.sha256(after.encode()).hexdigest(), result_source_size=len(after.encode()))
        config["support_files"] = []
        config_path = self.root / "fixture-config.json"
        config_path.write_text(json.dumps(config))
        prefix, toolwork = self.root / "prefix", self.root / "toolwork"
        prefix.mkdir(); toolwork.mkdir()
        (self.kernel / ".route-a").mkdir()
        for path in (self.kernel / ".route-a/build.lock", toolwork / "build.lock", toolwork / "host-tools.lock"):
            path.write_bytes(b"")
        (toolwork / "host-tools-state.json").write_text(json.dumps({"environment": {"UNIXNU_TOOLCHAIN": str(prefix)}}))
        (toolwork / "state.json").write_text("{}")
        candidate = self.kernel / "candidate"
        candidate.write_bytes(b"synthetic baseline input")
        build_report = self.kernel / ".route-a/build-report.json"
        build_report.write_text("{}")
        kernel_id = {**MODULE.identity(candidate), "recipe": MODULE.identity(recipe_path),
                     "compiler": MODULE.identity(Path(sys.executable)), "build_report": MODULE.identity(build_report),
                     "original_recipe_object": object_id}
        states = {"clang": MODULE.identity(toolwork / "state.json"), "host_tools": MODULE.identity(toolwork / "host-tools-state.json")}
        real_run = subprocess.run
        def fail_compile(argv, **kwargs):
            if str(argv[0]) == "/fixture/clang-24":
                kwargs["stderr"].write(b"complete synthetic compiler failure diagnostic\n")
                return subprocess.CompletedProcess(argv, 7)
            return real_run(argv, **kwargs)
        args = types.SimpleNamespace(kernel_dir=self.kernel, toolchain_work=toolwork, output=self.output, objdump=None)
        with mock.patch.object(MODULE, "CONFIG", config_path), \
             mock.patch.object(MODULE.platform, "verify_inputs", return_value=(kernel_id, self.recipe, prefix, states, {})), \
             mock.patch.object(MODULE.platform.subprocess, "run", side_effect=fail_compile):
            report = MODULE.build(args)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["failed_stage"], "compiling_callback")
        self.assertEqual(report["compile"]["exit_code"], 7)
        self.assertTrue(report["protected_inputs_unchanged"])
        self.assertEqual(report["protected_inputs_recheck"]["changes"], [])
        self.assertEqual(self.original.read_text(), before)
        self.assertEqual((self.cwd / "cpu.o").read_bytes(), b"original object sentinel")
        self.assertIn("complete synthetic compiler failure", (self.output / "logs/cpu-compile.stderr").read_text())
        self.assertTrue((self.output / "replacement/replay-compile-record.json").is_file())
        with self.assertRaises(MODULE.CallbackError):
            MODULE.platform.new_output(self.output, [self.kernel])


if __name__ == "__main__":
    unittest.main()
