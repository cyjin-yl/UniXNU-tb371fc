"""Protect source identity and compiler-driver semantics without building LLVM."""
import importlib.util
from pathlib import Path
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
        self.assertEqual(env["XNU_BOOT_PROGRESS"], "0")
        self.assertEqual(env["UNIXNU_SDK_BUILD"], "24A446")


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
