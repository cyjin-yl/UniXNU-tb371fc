"""Reject unrecorded repairs while preserving the qualified source baseline."""
import copy
import difflib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("route_a_build_fixes", ROOT / "scripts/run_route_a_kernel_build.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class BuildFixContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "driver"
        self.tree = self.root / "xnu"
        self.metadata = self.root / "metadata"
        for path in (self.source / "upstream", self.source / "patches", self.tree / "kern", self.metadata):
            path.mkdir(parents=True)
        subprocess.run(["git", "-C", str(self.tree), "init", "--quiet"], check=True)
        self.before = b"int diagnostic(void) { return 1; }\n"
        self.after = b"int diagnostic(void) { return 2; }\n"
        (self.tree / "kern/debug.c").write_bytes(self.before)
        (self.tree / "kern/untouched.c").write_bytes(b"int retained;\n")
        self.patch = self.source / "patches/repair.patch"
        self.patch.write_text(self.diff("kern/debug.c", self.before, self.after))
        self.spec = {"schema_version": 1, "xnu_commit": MODULE.XNU_COMMIT,
                     "base_source_inventory_sha256": MODULE.SOURCE_INVENTORY_SHA256,
                     "fixes": [{"id": "diagnostic", "patch": "patches/repair.patch",
                                "patch_sha256": MODULE.digest(self.patch.read_bytes()),
                                "files": [{"path": "kern/debug.c", "before_sha256": MODULE.digest(self.before),
                                           "after_sha256": MODULE.digest(self.after)}]}]}
        self.save_spec()

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def diff(name, before, after):
        return "".join(difflib.unified_diff(before.decode().splitlines(True), after.decode().splitlines(True),
                                            fromfile="a/" + name, tofile="b/" + name))

    def save_spec(self):
        (self.source / "upstream/route-a-build-fixes.json").write_text(json.dumps(self.spec))

    def apply(self):
        return MODULE.apply_build_fixes(self.tree, self.metadata, self.source)

    def verify(self, receipt):
        MODULE.verify_build_fixes(self.tree, self.metadata, receipt, self.source)

    def test_real_patch_is_bound_to_input_output_and_retained_receipt(self):
        receipt = self.apply()
        self.assertEqual((self.tree / "kern/debug.c").read_bytes(), self.after)
        self.assertEqual((self.tree / "kern/untouched.c").read_bytes(), b"int retained;\n")
        self.assertEqual(len(receipt["applied"]), 1)
        self.verify(receipt)
        changed = copy.deepcopy(receipt)
        changed["applied"][0]["files"][0]["after_sha256"] = "0" * 64
        with self.assertRaisesRegex(MODULE.BuildError, "receipt"):
            self.verify(changed)

    def test_changed_input_is_rejected_before_patch_application(self):
        changed = b"int diagnostic(void) { return 3; }\n"
        (self.tree / "kern/debug.c").write_bytes(changed)
        with self.assertRaisesRegex(MODULE.BuildError, "input changed"):
            self.apply()
        self.assertEqual((self.tree / "kern/debug.c").read_bytes(), changed)

    def test_patch_cannot_change_an_undeclared_second_file(self):
        self.patch.write_text(self.patch.read_text() +
                             self.diff("kern/untouched.c", b"int retained;\n", b"int overwritten;\n"))
        self.spec["fixes"][0]["patch_sha256"] = MODULE.digest(self.patch.read_bytes())
        self.save_spec()
        with self.assertRaisesRegex(MODULE.BuildError, "outside.*declaration"):
            self.apply()
        self.assertEqual((self.tree / "kern/debug.c").read_bytes(), self.before)
        self.assertEqual((self.tree / "kern/untouched.c").read_bytes(), b"int retained;\n")

    def test_unexpected_output_is_retained_but_never_qualified(self):
        self.spec["fixes"][0]["files"][0]["after_sha256"] = "0" * 64
        self.save_spec()
        with self.assertRaisesRegex(MODULE.BuildError, "output.*declaration"):
            self.apply()
        self.assertEqual((self.tree / "kern/debug.c").read_bytes(), self.after)
        self.assertTrue((self.metadata / "build-fixes/manifest.json").exists())

    def test_saved_patch_and_manifest_cannot_be_changed_after_staging(self):
        receipt = self.apply()
        for name in ("build-fixes/manifest.json", receipt["applied"][0]["stored_patch"]):
            with self.subTest(name=name):
                path = self.metadata / name
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                with self.assertRaisesRegex(MODULE.BuildError, "saved build-fix"):
                    self.verify(receipt)
                path.write_bytes(original)

    def test_staged_repair_source_cannot_change_before_build(self):
        receipt = self.apply()
        (self.tree / "kern/debug.c").write_bytes(self.before)
        with self.assertRaisesRegex(MODULE.BuildError, "source changed"):
            self.verify(receipt)

    def test_different_baseline_or_patch_digest_is_not_adopted(self):
        original = copy.deepcopy(self.spec)
        for field in ("baseline", "patch"):
            with self.subTest(field=field):
                self.spec = copy.deepcopy(original)
                if field == "baseline":
                    self.spec["base_source_inventory_sha256"] = "0" * 64
                else:
                    self.spec["fixes"][0]["patch_sha256"] = "0" * 64
                self.save_spec()
                with self.assertRaises(MODULE.BuildError):
                    self.apply()
                self.assertEqual((self.tree / "kern/debug.c").read_bytes(), self.before)


if __name__ == "__main__":
    unittest.main()
