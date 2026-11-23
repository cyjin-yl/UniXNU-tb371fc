"""Boundary regressions; synthetic fixtures never count as provider builds."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/build_route_a_platform.py"
SPEC = importlib.util.spec_from_file_location("route_a_platform", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def macho_fixture(kind=1, subtype=0, platform=2, minimum=27 << 16, entries=()):
    strings, symbols = b"\0", b""
    for name, typ, desc, value in entries:
        symbols += struct.pack("<IBBHQ", len(strings), typ, 1 if typ & 0xE else 0, desc, value)
        strings += name.encode() + b"\0"
    commands = (struct.pack("<6I", 0x32, 24, platform, minimum, 0, 0) +
                struct.pack("<6I", 2, 24, 80, len(entries), 80 + len(symbols), len(strings)))
    return struct.pack("<8I", 0xFEEDFACF, 0x0100000C, subtype, kind, 2, 48, 0, 0) + commands + symbols + strings


class PlatformTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.kernel = self.root / "kernel"
        self.cwd = self.kernel / "objects/iokit"
        self.cwd.mkdir(parents=True)
        self.original = self.kernel / ".cache/xnu-work/iokit/Kernel/IOPlatformExpert.cpp"
        self.original.parent.mkdir(parents=True)
        self.original.write_text("// synthetic original input\n")
        (self.cwd / "IOPlatformExpert.cpo").write_bytes(b"original object sentinel")
        self.output = self.root / "new-output"
        self.output.mkdir()
        self.source = self.output / "sources/ArmCpu/ArmCpu.cpp"
        self.source.parent.mkdir(parents=True)
        self.source.write_text("// synthetic provider input\n")
        self.recipe = {
            "directory": str(self.cwd), "file": str(self.original), "output": "IOPlatformExpert.cpo",
            "arguments": ["/fixture/clang-24", "-xc++", str(self.original), "-o", "IOPlatformExpert.cpo",
                          "--target=arm64-apple-ios27.0", "-mcpu=generic", "-arch", "arm64",
                          "-mios-version-min=27.0", "-c", "-std=gnu++2b", "-fapple-kext",
                          "-mllvm", "-disable-atexit-based-global-dtor-lowering", "-I", ".",
                          "-include", "meta_features.h", "-D", "XNU_NATIVE_PAN=0", "-Weverything",
                          "-Xclang", "-Wno-unused-parameter", "--target=arm64-apple-ios27.0.0"],
        }
        self.warnings = ["-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter"]

    def replay(self, record=None):
        return MODULE.replay_recipe(record or self.recipe, self.kernel, self.source,
                                    self.output / "ArmCpu", self.warnings)

    def git(self, repository, *args):
        return subprocess.run(["git", "-C", str(repository), *args], check=True, capture_output=True).stdout

    def source_checkout(self):
        repository = self.root / "checkout"
        repository.mkdir()
        self.git(repository, "init", "--quiet")
        self.git(repository, "config", "user.email", "fixture@example.invalid")
        self.git(repository, "config", "user.name", "Test Fixture")
        for name, data in (("ArmCpu.cpp", '#include "ArmCpuSleep.h"\n'),
                           ("ArmCpuSleep.h", "// retained source header\n"), ("LICENSE", "synthetic test license\n")):
            (repository / name).write_text(data)
        self.git(repository, "add", ".")
        self.git(repository, "commit", "--quiet", "-m", "fixture")
        commit = self.git(repository, "rev-parse", "HEAD").decode().strip()
        spec = {"name": "ArmCpu", "repository": "https://example.invalid/fixture.git", "commit": commit,
                "license": "test fixture only", "translation_unit": "ArmCpu.cpp",
                "files": [{"path": name, "git_blob": self.git(repository, "rev-parse", "HEAD:" + name).decode().strip()}
                          for name in ("ArmCpu.cpp", "ArmCpuSleep.h", "LICENSE")]}
        return repository, spec

    def test_recipe_replaces_every_output_and_retains_target_and_upstream_werror(self):
        original = copy.deepcopy(self.recipe)
        self.recipe["arguments"] += ["-MD", "-MF", "kernel.d", "-MJkernel.json", "-MT", "kernel.cpo", "-MQkernel.cpo"]
        argv, changes = self.replay()
        self.assertEqual(argv[argv.index("-o") + 1], str(self.output / "ArmCpu/ArmCpu.o"))
        self.assertEqual(argv[argv.index("-MF") + 1], str(self.output / "ArmCpu/dependencies.d"))
        self.assertEqual(argv[argv.index("-MJ") + 1], str(self.output / "ArmCpu/compile-record.json"))
        self.assertEqual(argv[argv.index("-MT") + 1], str(self.output / "ArmCpu/ArmCpu.o"))
        self.assertEqual(argv.count("-MD"), 1)
        self.assertNotIn(str(self.original), argv)
        self.assertIn(str(self.source), argv)
        self.assertIn("-mcpu=generic", argv)
        self.assertIn("--target=arm64-apple-ios27.0.0", argv)
        self.assertIn("--no-default-config", argv)
        self.assertNotIn("-Weverything", argv)
        self.assertNotIn("-Xclang", argv)
        self.assertIn("-Werror", argv)
        self.assertEqual(changes["upstream_warning_arguments"], self.warnings)
        self.assertEqual(self.recipe["arguments"][:len(original["arguments"])], original["arguments"])
        self.assertEqual((self.cwd / "IOPlatformExpert.cpo").read_bytes(), b"original object sentinel")

    def test_recipe_rejects_target_escape_plugins_response_files_and_hidden_outputs(self):
        bad = [
            ["@hidden.rsp"], ["-mcpu=apple-a12"], ["-march=armv8.3-a"], ["-arch", "arm64e"],
            ["--target=arm64e-apple-ios27.0"], ["--target=arm64-apple-macos27.0"],
            ["-mios-version-min=26.0"], ["-Xclang", "-load", "plugin.so"],
            ["-mllvm", "-load=plugin.so"], ["-fplugin=plugin.so"], ["-Wp,-MD,original.d"],
            ["-save-temps"], ["-fprofile-generate=original-dir"], ["-fmodules-cache-path=original-dir"],
            ["-serialize-diagnostics", "original.dia"], ["--config=hidden.cfg"], ["second-source.cpp"],
            ["-working-directory", "/tmp"], ["-I", "/unbound/sdk"], ["-D", "__arm64e__=1"],
        ]
        for extra in bad:
            with self.subTest(extra=extra):
                record = copy.deepcopy(self.recipe)
                record["arguments"] += extra
                with self.assertRaises(MODULE.PlatformError):
                    self.replay(record)
        record = copy.deepcopy(self.recipe)
        record["arguments"].remove("-mcpu=generic")
        with self.assertRaisesRegex(MODULE.PlatformError, "incomplete"):
            self.replay(record)

    def test_compiler_compatibility_warnings_must_exist_in_recipe_and_cannot_expand(self):
        retained = list(MODULE.RETAINED_RECIPE_WARNINGS)
        self.recipe["arguments"] += retained + retained[:1]
        argv, changes = MODULE.replay_recipe(self.recipe, self.kernel, self.source,
                                             self.output / "ArmCpu", self.warnings, retained)
        self.assertEqual(changes["retained_recipe_warnings"], retained)
        self.assertEqual(changes["retained_recipe_warning_occurrences"], {retained[0]: 2, retained[1]: 1})
        for value in retained:
            self.assertEqual(argv.count(value), 1)
            self.assertLess(argv.index("-Werror"), argv.index(value))
            self.assertNotIn(value, changes["removed_warning_arguments"])
        self.assertEqual(changes["upstream_warning_arguments"], self.warnings)
        missing = copy.deepcopy(self.recipe)
        missing["arguments"].remove(retained[1])
        with self.assertRaisesRegex(MODULE.PlatformError, "absent from the original recipe"):
            MODULE.replay_recipe(missing, self.kernel, self.source, self.output / "ArmCpu", self.warnings, retained)
        for unreviewed in (retained + ["-Wno-everything"], retained + retained[:1]):
            with self.subTest(unreviewed=unreviewed), self.assertRaisesRegex(MODULE.PlatformError, "only the two fixed"):
                MODULE.replay_recipe(self.recipe, self.kernel, self.source,
                                     self.output / "ArmCpu", self.warnings, unreviewed)

    def test_existing_overlapping_and_symlink_outputs_cannot_modify_inputs(self):
        for output in (self.output, self.kernel / "new", self.kernel.parent):
            with self.subTest(output=output), self.assertRaises(MODULE.PlatformError):
                MODULE.new_output(output, [self.kernel])
        alias = self.root / "alias"
        alias.symlink_to(self.kernel / "absent")
        with self.assertRaises(MODULE.PlatformError):
            MODULE.new_output(alias, [self.kernel])
        self.assertFalse((self.kernel / "new").exists())
        self.assertFalse((self.kernel / "absent").exists())
        created = MODULE.new_output(self.root / "fresh", [self.kernel])
        self.assertTrue(created.is_dir())

    def test_source_snapshot_is_git_bound_and_does_not_use_untracked_headers(self):
        repository, spec = self.source_checkout()
        (repository / "untracked-shadow.h").write_text("not part of provider source\n")
        target = self.root / "snapshot"
        result = MODULE.snapshot_source(repository, spec, target)
        self.assertEqual(sorted(p.name for p in target.iterdir()), ["ArmCpu.cpp", "ArmCpuSleep.h", "LICENSE"])
        self.assertFalse(result["untracked_checkout_files_used"])
        self.assertTrue(result["tracked_checkout_clean"])
        self.assertEqual((target / "LICENSE").read_bytes(), (repository / "LICENSE").read_bytes())
        wrong = {**spec, "commit": "0" * 40}
        with self.assertRaisesRegex(MODULE.PlatformError, "commit changed"):
            MODULE.snapshot_source(repository, wrong, self.root / "wrong-snapshot")

    def test_dirty_source_cannot_be_hidden_with_assume_unchanged(self):
        repository, spec = self.source_checkout()
        (repository / "ArmCpu.cpp").write_text("changed\n")
        with self.assertRaisesRegex(MODULE.PlatformError, "dirty"):
            MODULE.snapshot_source(repository, spec, self.root / "dirty-snapshot")
        self.git(repository, "update-index", "--assume-unchanged", "ArmCpu.cpp")
        self.assertEqual(self.git(repository, "status", "--porcelain", "-uno"), b"")
        with self.assertRaisesRegex(MODULE.PlatformError, "bytes differ"):
            MODULE.snapshot_source(repository, spec, self.root / "masked-snapshot")

    def test_object_target_checks_do_not_mask_subtype_features_or_accept_old_minos(self):
        for subtype, platform, minimum, kind in ((2, 2, 27 << 16, 1), (0x80000000, 2, 27 << 16, 1),
                                               (0, 1, 27 << 16, 1), (0, 2, 26 << 16, 1), (0, 2, 27 << 16, 2)):
            with self.subTest(subtype=subtype, platform=platform, minimum=minimum, kind=kind):
                with self.assertRaises(MODULE.PlatformError):
                    MODULE.macho(macho_fixture(kind, subtype, platform, minimum), 1)
        data = bytearray(macho_fixture())
        struct.pack_into("<I", data, 36, 0x10000000)
        with self.assertRaisesRegex(MODULE.PlatformError, "command size"):
            MODULE.macho(bytes(data), 1)

    def test_weak_imports_and_weak_definitions_keep_raw_link_semantics(self):
        data = macho_fixture(entries=(("_strong", 1, 0, 0), ("_optional_sleep", 1, 0x40, 0),
                                      ("_definition", 0xF, 0, 1), ("_weak_definition", 0xF, 0x80, 2),
                                      ("_common", 1, 0, 4), ("_indirect", 0xB, 0, 1)))
        header, symbols = MODULE.macho(data, 1)
        self.assertEqual(symbols["strong_undefined"], ["_strong"])
        self.assertEqual(symbols["weak_undefined"], ["_optional_sleep"])
        self.assertEqual(symbols["common_external"], ["_common"])
        self.assertEqual(symbols["unsupported_external"], ["_indirect"])
        weak = next(item for item in symbols["records"] if item["name"] == "_weak_definition")
        self.assertEqual(weak["n_desc"], 0x80)
        self.assertFalse(header["full_instruction_set_audited"])
        self.assertFalse(header["relocations_audited"])

    def test_failed_compiler_retains_full_diagnostics_partial_output_and_original_sentinel(self):
        compiler = self.root / "failing-compiler"
        compiler.write_text("#!" + sys.executable + "\nimport pathlib,sys\n"
                            "args=sys.argv[1:]\n"
                            "pathlib.Path(args[args.index('-o')+1]).write_bytes(b'partial object')\n"
                            "pathlib.Path(args[args.index('-MF')+1]).write_text('partial dependencies')\n"
                            "sys.stderr.write('fixture diagnostic\\n' * 2000)\n"
                            "sys.exit(23)\n")
        compiler.chmod(0o755)
        self.recipe["arguments"][0] = str(compiler)
        self.recipe["arguments"] += ["-MD", "-MF", "original.d", "-MJoriginal.json"]
        report = {"commands": [], "components": []}
        runner = MODULE.Execution(self.output, report, {"PATH": os.defpath, "LC_ALL": "C"})
        result = MODULE.compile_component({"name": "ArmCpu", "translation_unit": "ArmCpu.cpp"}, {}, self.recipe,
                                           self.kernel, self.root / "prefix", self.output, Path("/unused/ar"),
                                           self.warnings, runner)
        self.assertEqual(result["status"], "compile_failed")
        self.assertEqual(result["compile"]["exit_code"], 23)
        stderr = Path(result["compile"]["stderr"]).read_text()
        self.assertEqual(stderr, "fixture diagnostic\n" * 2000)
        self.assertLessEqual(len(result["compile"]["stderr_tail"]), 12000)
        self.assertEqual(result["partial_object"]["sha256"], hashlib.sha256(b"partial object").hexdigest())
        self.assertEqual((self.cwd / "IOPlatformExpert.cpo").read_bytes(), b"original object sentinel")
        self.assertFalse((self.cwd / "original.d").exists())
        self.assertFalse((self.cwd / "original.json").exists())
        self.assertFalse((self.output / "ArmCpu/libArmCpu.a").exists())
        saved = json.loads((self.output / "report.json").read_text())
        self.assertEqual(saved["components"][0]["status"], "compile_failed")

    def test_dependency_paths_must_resolve_inside_actual_bound_inputs(self):
        header = self.kernel / "header with space.h"
        header.write_text("// header\n")
        depfile = self.output / "deps.d"
        depfile.write_text("new.o: " + str(self.source) + " \\\n " + str(header).replace(" ", "\\ ") + "\n")
        records = MODULE.dependencies(depfile, self.cwd, [self.kernel, self.output / "sources"])
        self.assertEqual({r["realpath"] for r in records}, {str(header), str(self.source)})
        external = self.root / "foreign.h"
        external.write_text("// foreign\n")
        alias = self.kernel / "header-link.h"
        alias.symlink_to(external)
        depfile.write_text("new.o: " + str(alias) + "\n")
        with self.assertRaisesRegex(MODULE.PlatformError, "outside"):
            MODULE.dependencies(depfile, self.cwd, [self.kernel])

    def test_failure_recheck_records_mutation_without_overwriting_original_error_evidence(self):
        identity = MODULE.file_identity(self.original)
        report = {"status": "failed", "commands": [{"exit_code": 23}], "provider_archives_built": False}
        MODULE.recheck_inputs(report, [identity])
        self.assertTrue(report["protected_inputs_unchanged"])
        self.original.write_text("changed during a failed attempt")
        MODULE.recheck_inputs(report, [identity])
        self.assertFalse(report["protected_inputs_unchanged"])
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["commands"], [{"exit_code": 23}])
        self.assertNotEqual(report["protected_input_rechecks"][0]["actual_sha256"], identity["sha256"])

    def test_modified_raw_recipe_cannot_be_accepted_by_its_old_digest(self):
        path = self.root / "recipe.json"
        path.write_text(json.dumps(self.recipe))
        identity = MODULE.file_identity(path)
        parsed, result = MODULE.verified_json(path, identity["sha256"])
        self.assertEqual(parsed, self.recipe)
        self.assertEqual(result, identity)
        path.write_text(path.read_text() + "\n")
        with self.assertRaisesRegex(MODULE.PlatformError, "digest changed"):
            MODULE.verified_json(path, identity["sha256"])

    def test_actual_kernel_compiler_and_host_tool_bytes_must_match_their_bound_identities(self):
        # The only positive here is acceptance of internally consistent test
        # identities; these tiny fixtures are never executed as a compiler.
        config = json.loads(MODULE.CONFIG.read_text())
        prefix, toolwork = self.root / "prefix", self.root / "toolwork"
        (prefix / "llvm/bin").mkdir(parents=True)
        toolwork.mkdir()
        compiler = prefix / "llvm/bin/clang-24"
        compiler.write_bytes(b"synthetic compiler identity")
        compiler.chmod(0o755)
        compiler_id = {**MODULE.file_identity(compiler), "realpath": str(compiler)}
        host_tool = prefix / "host-tool"
        host_tool.write_bytes(b"synthetic host tool identity")
        verification = {"status": "passed", "static_assertions": 19, "compiler": compiler_id}
        (toolwork / "state.json").write_text(json.dumps({"status": "clang_verified", "verification": verification}))
        (toolwork / "host-tools-state.json").write_text(json.dumps({
            "status": "host_tools_built", "combined_toolchain_verified": True,
            "unixnu_commit": config["unixnu_commit"], "clang_verification": verification,
            "environment": {"UNIXNU_TOOLCHAIN": str(prefix)}, "outputs": [MODULE.file_identity(host_tool)],
        }))
        self.recipe["arguments"][0] = str(compiler)
        recipe_path = self.kernel / "actual-recipe.json"
        recipe_path.write_text(json.dumps(self.recipe) + ",\n")
        candidate = self.kernel / "candidate"
        candidate.write_bytes(macho_fixture(kind=2, entries=(("_kernel_symbol", 0xF, 0, 1),)))
        candidate_id = MODULE.file_identity(candidate)
        report_path = self.kernel / "build-report.json"
        report_path.write_text(json.dumps({
            "status": "builder_completed", "builder_completed": True, "exit_code": 0,
            "ordinary_arm64_candidate_headers_verified": True,
            "unixnu_commit": config["unixnu_commit"], "xnu_commit": config["xnu_commit"],
            "compiler": compiler_id, "artifacts": [{**candidate_id, "path": "candidate"}],
        }))
        config["baseline"].update(build_report_path="build-report.json", build_report_sha256=MODULE.sha256_file(report_path),
                                  kernel_path="candidate", kernel_sha256=candidate_id["sha256"], kernel_size=candidate_id["size"],
                                  recipe_path="actual-recipe.json", recipe_sha256=MODULE.sha256_file(recipe_path),
                                  compiler_sha256=compiler_id["sha256"])
        result = MODULE.verify_inputs(self.kernel, toolwork, config)
        self.assertEqual(result[0]["sha256"], candidate_id["sha256"])
        self.assertEqual(result[0]["original_recipe_object"]["sha256"],
                         hashlib.sha256(b"original object sentinel").hexdigest())
        compiler.write_bytes(b"different compiler")
        with self.assertRaisesRegex(MODULE.PlatformError, "actual compiler differs"):
            MODULE.verify_inputs(self.kernel, toolwork, config)
        compiler.write_bytes(b"synthetic compiler identity")
        host_tool.write_bytes(b"different host tool")
        with self.assertRaisesRegex(MODULE.PlatformError, "host tool changed"):
            MODULE.verify_inputs(self.kernel, toolwork, config)
        host_tool.write_bytes(b"synthetic host tool identity")
        candidate.write_bytes(candidate.read_bytes() + b"changed")
        with self.assertRaisesRegex(MODULE.PlatformError, "actual kernel candidate changed"):
            MODULE.verify_inputs(self.kernel, toolwork, config)


if __name__ == "__main__":
    unittest.main()
