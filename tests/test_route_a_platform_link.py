"""Fail-closed platform-link contracts, using small synthetic Mach-O inputs."""
import importlib.util
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


def image(symbols=(), *, filetype=1, subtype=0, entry=None, constructors=(), platform=2, minos=27 << 16):
    base = 0xFFFFFFF007004000 if filetype == 2 else 0
    text = struct.pack("<16s16sQQ8I", b"__text", b"__TEXT_EXEC", base, 0x40,
                       0x1000, 2, 0, 0, 0x80000400, 0, 0, 0)
    init = struct.pack("<16s16sQQ8I", b"__mod_init_func", b"__DATA_CONST", base + 0x40, 8 * len(constructors),
                       0x1040, 3, 0, 0, 9, 0, 0, 0)
    segment = struct.pack("<II16sQQQQ4I", 0x19, 232, b"__TEXT_EXEC", base, 0x80,
                          0x1000, 0x80, 7, 5, 2, 0) + text + init
    strings, nlists = bytearray(b"\0"), bytearray()
    for name, n_type, desc, value in symbols:
        at = len(strings)
        strings += name.encode() + b"\0"
        nlists += struct.pack("<IBBHQ", at, n_type, 1 if n_type & 0xE == 0xE else 0, desc, value)
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

    def exercise_run(self, action):
        from argparse import Namespace
        candidate = self.cwd / MODULE.KERNEL_NAME
        candidate.write_bytes(image(filetype=2))
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
        with patch.object(MODULE, "KERNEL_SHA256", MODULE.identity(candidate)["sha256"]), \
                patch.object(MODULE, "BUILD_REPORT_SHA256", MODULE.identity(build_report)["sha256"]), \
                patch.object(MODULE, "verify_platform", return_value=({}, components)), \
                patch.object(MODULE, "tool_inputs", return_value=(self.prefix, [], {"PATH": "/usr/bin"})), \
                patch.object(MODULE, "execute", side_effect=simulated_link):
            result = MODULE.run(args)
        self.assertTrue((args.output / "report.json").is_file())
        self.assertEqual(candidate.read_bytes(), image(filetype=2))
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
        self.assertEqual(sum("-force_load" in arg for arg in calls[1]), 2)
        self.assertFalse(any("-undefined" in arg for arg in calls[1]))
        self.assertTrue(result["protected_inputs_recheck"]["unchanged"])
        for key in ("platform_link_compatible", "complete_board_archive_closure", "crypto_provider_selected",
                    "pthread_provider_selected", "tb371fc_kernel_qualified", "os_boot_verified"):
            self.assertFalse(result[key])


if __name__ == "__main__":
    unittest.main()
