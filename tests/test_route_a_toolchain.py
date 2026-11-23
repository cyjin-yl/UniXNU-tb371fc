"""Protect source identity and compiler-driver semantics without building LLVM."""
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("route_a_toolchain", ROOT / "scripts/prepare_route_a_toolchain.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ToolchainBoundaryTests(unittest.TestCase):
    def test_moving_ref_cannot_select_a_different_source(self):
        pin = MODULE.source_pin("https://github.com/tpoechtrager/cctools-port.git", "1030.6.3-ld64-956.6")
        self.assertEqual(pin["commit"], "3e694ee7393af2a4ce8bd6e7dae28fe37450aa87")
        for url, ref in (("https://github.com/tpoechtrager/cctools-port.git", "master"),
                         ("https://example.invalid/cctools-port", "1030.6.3-ld64-956.6")):
            with self.subTest(url=url, ref=ref), self.assertRaises(MODULE.ToolchainError):
                MODULE.source_pin(url, ref)

    def test_clangplusplus_alias_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            driver = root / "driver"
            driver.write_text('#!/bin/sh\ncase "$0" in *++) printf "cxx-driver\\n";; *) printf "c-driver\\n";; esac\n')
            driver.chmod(0o755)
            alias = root / "clang++"
            alias.symlink_to(driver)
            identity = MODULE.tool_identity(str(alias))
            self.assertEqual(identity["path"], str(alias))
            self.assertEqual(identity["realpath"], str(driver))
            self.assertEqual(identity["version"], "cxx-driver")
            self.assertEqual(identity["sha256"], MODULE.sha256_file(driver))

    def test_existing_verification_directory_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "verification.json").write_text("retained evidence\n")
            with self.assertRaises(FileExistsError):
                MODULE.verify_clang("not-a-compiler", root)
            self.assertEqual((root / "verification.json").read_text(), "retained evidence\n")

    def test_route_a_environment_does_not_inherit_arm64e_defaults(self):
        env = MODULE.toolchain_environment(Path("/owned/toolchain"), Path("/owned/sdk"))
        self.assertEqual(env["DARWIN_TRIPLE"], "arm64-apple-ios27.0")
        self.assertEqual(env["UNIXNU_XNU_ARCH"], "arm64")
        self.assertNotIn("ptrauth", env["CROSS_EXTRA_FLAGS"])
        self.assertEqual(env["CROSS_EXTRA_FLAGS"].split().count("-mcpu=generic"), 1)
        self.assertEqual(env["XNU_BOOT_PROGRESS"], "0")
        self.assertEqual(env["UNIXNU_SDK_BUILD"], "24A446")

    def test_component_cache_rejects_changed_binary_or_source_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory)
            binary = prefix / "CommandLineTools/usr/bin/ld"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"owned build output")
            identity = {"source": "fixed commit", "host": "fixed compiler"}
            record = {"identity": identity, "outputs": MODULE.component_inventory(prefix)}
            MODULE.validate_component_cache(prefix, record, identity)
            with self.assertRaises(MODULE.ToolchainError):
                MODULE.validate_component_cache(prefix, record, {**identity, "source": "different commit"})
            binary.write_bytes(b"different build output")
            with self.assertRaises(MODULE.ToolchainError):
                MODULE.validate_component_cache(prefix, record, identity)

    def test_component_symlinks_must_remain_inside_owned_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory) / "owned"
            bindir = prefix / "bin"
            bindir.mkdir(parents=True)
            (bindir / "tool").symlink_to("../../outside")
            with self.assertRaises(MODULE.ToolchainError):
                MODULE.component_inventory(prefix)

    def test_installer_guard_adapter_refuses_unknown_or_duplicate_shape(self):
        fixture = '''def cctools(clt, dispatch_prefix, src):
    if all((clt / path).exists() for path in ('bin/ld', 'lib/libmacho.a', 'lib/libstuff.a')):
        return
    if not (dispatch_prefix / 'lib/libdispatch.so').exists():
        calls.append("build dispatch")
    tree = src / 'cctools'
    calls.append("build cctools")
def mig(clt):
    if (clt / 'libexec/migcom').exists():
        return
    calls.append("build mig")
def lzfse(prefix):
    if (prefix / 'bin/lzfse').exists():
        return
    calls.append("build lzfse")
'''
        adapted = MODULE.installer_without_existence_shortcuts(fixture)
        scope = {"calls": []}
        exec(compile(adapted, "fixed-recipe-fixture", "exec"), scope)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("bin/ld", "lib/libmacho.a", "lib/libstuff.a", "lib/libdispatch.so", "libexec/migcom", "bin/lzfse"):
                output = root / name
                output.parent.mkdir(parents=True, exist_ok=True)
                output.touch()
            scope["cctools"](root, root, root)
            scope["mig"](root)
            scope["lzfse"](root)
        self.assertEqual(scope["calls"], ["build dispatch", "build cctools", "build mig", "build lzfse"])
        for unknown in (fixture.replace("libexec/migcom", "different-tool"), fixture + fixture):
            with self.assertRaises(MODULE.ToolchainError):
                MODULE.installer_without_existence_shortcuts(unknown)


class ReturnAddressCodegenGateTests(unittest.TestCase):
    """Synthetic outputs test admission decisions, not compiler capability."""

    IR = ('define ptr @route_a_return_address() {\n'
          '  %address = call ptr @llvm.returnaddress.p0(i32 0)\n'
          '  ret ptr %address\n}\n'
          'attributes #0 = { "target-cpu"="generic" "target-features"="+fp-armv8,+neon,+v8a" }\n')
    ASSEMBLY = '_route_a_return_address:\n\thint #7\n\tmov x0, x30\n\tret\n'
    OBJECT = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 1, 0, 0, 0, 0)

    def fake_compiler(self, *, ir=None, assembly=None, obj=None, exit_code=0):
        outputs = {".ll": (self.IR if ir is None else ir).encode(),
                   ".s": (self.ASSEMBLY if assembly is None else assembly).encode(),
                   ".o": self.OBJECT if obj is None else obj}

        def run(args, **kwargs):
            output = Path(args[args.index("-o") + 1])
            if exit_code == 0:
                output.write_bytes(outputs[output.suffix])
            return subprocess.CompletedProcess(args, exit_code, stdout=b"", stderr=b"diagnostic\n" if exit_code else b"")

        return run

    def test_production_probe_does_not_inject_target_or_cpu_flags(self):
        flags = ("-arch", "arm64", "-mkernel", "-mno-implicit-sme",
                 "-momit-leaf-frame-pointer", "-fno-strict-aliasing")
        environment = {"CROSS_CLANG": "/verified/clang", "DARWIN_TRIPLE": "arm64-apple-ios27.0",
                       "CROSS_EXTRA_FLAGS": "-mcpu=generic"}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "check"
            with patch.object(MODULE, "command", side_effect=self.fake_compiler()) as command:
                report = MODULE.verify_return_address_codegen("/verified/CLT/bin/clang", output,
                                                               target_flags=flags, env=environment)
            self.assertTrue(report["passed"])
            self.assertTrue(all(report["checks"].values()))
            self.assertTrue(report["has_compatible_hint_7"])
            self.assertEqual(report["driver_environment"], environment)
            for call in command.call_args_list:
                args = call.args[0]
                self.assertEqual(args[:1 + len(flags)], ["/verified/CLT/bin/clang", *flags])
                self.assertFalse(any(arg.startswith(("-mcpu", "-march", "-target")) for arg in args if isinstance(arg, str)))
                self.assertIs(call.kwargs["env"], environment)
            for entry in report["commands"]:
                self.assertEqual(MODULE.sha256_file(Path(entry["output"])), entry["output_sha256"])
                self.assertEqual(MODULE.sha256_file(Path(entry["stderr"])), entry["stderr_sha256"])
            with self.assertRaises(FileExistsError):
                MODULE.verify_return_address_codegen("/verified/CLT/bin/clang", output)

    def test_legacy_intrinsic_name_and_xpaclri_hint_are_accepted(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
                MODULE, "command", side_effect=self.fake_compiler(
                    ir=self.IR.replace("returnaddress.p0", "returnaddress"),
                    assembly=self.ASSEMBLY.replace("hint #7", "xpaclri"))):
            report = MODULE.verify_return_address_codegen("clang", Path(directory) / "check")
            self.assertTrue(report["passed"])
            self.assertTrue(report["has_compatible_hint_7"])

    def test_cpu_pauth_and_failed_compilation_are_rejected_with_evidence(self):
        cases = (
            ({"ir": self.IR.replace('"generic"', '"apple-a12"')}, "ir_cpu_generic"),
            ({"assembly": self.ASSEMBLY.replace("hint #7", "xpaci x30")}, "no_pauth_instructions"),
            ({"assembly": self.ASSEMBLY.replace("ret\n", "retaa\n")}, "no_pauth_instructions"),
            ({"ir": self.IR + '%stripped = call i64 @llvm.ptrauth.strip(i64 1, i32 0)\n'}, "no_pauth_intrinsics"),
            ({"ir": self.IR.replace("+v8a", "+v8a,+pauth")}, "no_pauth_cpu_feature"),
            ({"ir": self.IR.replace("llvm.returnaddress.p0", "unrelated_function")}, "return_address_intrinsic"),
            ({"obj": struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 2, 1, 0, 0, 0, 0)}, "ordinary_arm64_macho"),
            ({"exit_code": 1}, "all_compiles_succeeded"),
        )
        for values, check in cases:
            with self.subTest(check=check, values=values), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "check"
                with patch.object(MODULE, "command", side_effect=self.fake_compiler(**values)):
                    with self.assertRaises(MODULE.ToolchainError):
                        MODULE.verify_return_address_codegen("clang", output)
                report = json.loads((output / "verification.json").read_text())
                self.assertFalse(report["passed"])
                self.assertFalse(report["checks"][check])
                self.assertEqual(len(report["commands"]), 3)
                self.assertTrue(all(Path(entry["stderr"]).is_file() for entry in report["commands"]))

    def test_direct_clang_qualification_includes_generic_cpu_and_codegen(self):
        compiler = {"path": "/verified/clang", "sha256": "synthetic"}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "check"
            with patch.object(MODULE, "tool_identity", return_value=compiler), patch.object(
                    MODULE, "command", side_effect=self.fake_compiler()) as command:
                report = MODULE.verify_clang("/verified/clang", output)
            self.assertEqual(report["status"], "passed")
            self.assertEqual(report["static_assertions"], 19)
            self.assertTrue(report["return_address_codegen"]["passed"])
            self.assertEqual(command.call_count, 4)
            for call in command.call_args_list:
                self.assertIn("-mcpu=generic", call.args[0])
                self.assertIn("-march=armv8-a", call.args[0])

    def test_trait_success_cannot_hide_a_codegen_failure(self):
        compiler = {"path": "/verified/clang", "sha256": "synthetic"}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "check"
            with patch.object(MODULE, "tool_identity", return_value=compiler), patch.object(
                    MODULE, "command", side_effect=self.fake_compiler(
                        assembly=self.ASSEMBLY.replace("hint #7", "xpaci x30"))):
                with self.assertRaises(MODULE.ToolchainError):
                    MODULE.verify_clang("/verified/clang", output)
            report = json.loads((output / "verification.json").read_text())
            self.assertEqual(report["compiler_exit_code"], 0)
            self.assertEqual(report["status"], "failed")
            self.assertFalse(report["return_address_codegen"]["checks"]["no_pauth_instructions"])


class ToolchainSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.git("init", "--quiet")
        (self.source / "scripts/linux").mkdir(parents=True)
        (self.source / "scripts/linux/setup-toolchain.py").write_text("# fixed installer fixture\n")
        (self.source / "LICENSE").write_text("license fixture\n")
        self.git("add", ".")
        self.git("-c", "user.name=Route A fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "-qm", "fixture")
        self.commit = self.git("rev-parse", "HEAD").stdout.decode().strip()

    def tearDown(self):
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.source), *args], capture_output=True, check=True)

    def test_fixed_objects_override_dirty_checkout_and_protect_export(self):
        (self.source / "scripts/linux/setup-toolchain.py").write_text("# dirty checkout\n")
        target = self.root / "support"
        with patch.object(MODULE, "UNIXNU_COMMIT", self.commit):
            records = MODULE.export_linux_support(self.source, target)
            exported = target / "scripts/linux/setup-toolchain.py"
            self.assertEqual(exported.read_text(), "# fixed installer fixture\n")
            self.assertIn("LICENSE", records)
            exported.write_text("# tampered export\n")
            with self.assertRaises(MODULE.ToolchainError):
                MODULE.export_linux_support(self.source, target)

    def test_new_and_modified_llvm_files_are_both_bound(self):
        (self.source / "LICENSE").write_text("modified fixture\n")
        added = self.source / "new-llvm-source.cpp"
        added.write_text("new fixture\n")
        first = MODULE.source_state(self.source)
        self.assertEqual({entry["path"] for entry in first["changed_files"]},
                         {"LICENSE", "new-llvm-source.cpp"})
        added.write_text("changed new fixture\n")
        self.assertNotEqual(first, MODULE.source_state(self.source))


if __name__ == "__main__":
    unittest.main()
