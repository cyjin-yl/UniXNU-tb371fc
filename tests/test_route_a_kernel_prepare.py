"""Source identity and no-PAC recipe regression tests; no kernel boot claims."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("route_a_kernel_prepare",
                                             ROOT / "scripts/prepare_route_a_kernel.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RecipeTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads(MODULE.DEFAULT_CONFIG.read_text())
        names = sorted(MODULE.REQUIRED_PATCHES | MODULE.FORBIDDEN_PATCHES)
        self.arch = "\n".join("../../../../../patches/xnu-12377/" + name for name in names)
        self.exclusions = self.config["exclude_patches"]

    def test_reviewed_configuration_and_selection(self):
        MODULE.validate_config(self.config)
        selected = MODULE.selected_paths(self.arch, "", self.exclusions)
        self.assertEqual(set(Path(path).name for path in selected), MODULE.REQUIRED_PATCHES)
        self.assertFalse(self.config["status"]["kernel_compiled"])

    def test_native_pac_cannot_be_reenabled(self):
        config = deepcopy(self.config)
        config["build_environment"]["UNIXNU_XNU_ARCH"] = "arm64e"
        with self.assertRaises(MODULE.PreparationError):
            MODULE.validate_config(config)
        exclusions = dict(self.exclusions)
        exclusions.pop("patches/xnu-12377/native-pac-keys.patch")
        with self.assertRaises(MODULE.PreparationError):
            MODULE.selected_paths(self.arch, "", exclusions)

    def test_wrong_source_commit_in_build_environment(self):
        config = deepcopy(self.config)
        config["build_environment"]["UNIXNU_XNU_COMMIT"] = "1" * 40
        with self.assertRaises(MODULE.PreparationError):
            MODULE.validate_config(config)

    def test_partial_recipe_and_old_baseline_rejected(self):
        missing = self.arch.replace(
            "../../../../../patches/xnu-12377/native-4k-shared-region-slide.patch", "")
        with self.assertRaises(MODULE.PreparationError):
            MODULE.selected_paths(missing, "", self.exclusions)
        with self.assertRaises(MODULE.PreparationError):
            MODULE.selected_paths(self.arch.replace("xnu-12377/", "xnu/"), "", self.exclusions)

    def test_duplicate_patch_rejected(self):
        with self.assertRaises(MODULE.PreparationError):
            MODULE.selected_paths(self.arch, "arch:../../../patches/xnu-12377/"
                                  "darwin26-kpi.patch", self.exclusions)

    def test_path_escape_and_unreviewed_environment_rejected(self):
        for path in ("../outside", "/absolute", "patches/../escape", "a//b", ""):
            with self.subTest(path=path), self.assertRaises(MODULE.PreparationError):
                MODULE.safe_path(path)
        config = deepcopy(self.config)
        config["build_environment"]["XNU_EXTRA_CFLAGS"] = "-DHAS_NATIVE_PAC=1"
        with self.assertRaises(MODULE.PreparationError):
            MODULE.validate_config(config)

    def test_false_runtime_claim_rejected(self):
        config = deepcopy(self.config)
        config["status"]["kernel_compiled"] = True
        with self.assertRaises(MODULE.PreparationError):
            MODULE.validate_config(config)

    def test_full_commit_required(self):
        config = deepcopy(self.config)
        config["sources"]["unixnu"]["commit"] = "main"
        with self.assertRaises(MODULE.PreparationError):
            MODULE.validate_config(config)


class GitIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.source = self.base / "source"
        self.source.mkdir()
        self.git("init", "-q")
        (self.source / "source.txt").write_text("pinned source\n")
        self.git("add", "source.txt")
        self.git("-c", "user.name=Route A fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "-qm", "fixture")
        self.commit = self.git("rev-parse", "HEAD").stdout.decode().strip()

    def tearDown(self):
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.source), *args],
                              capture_output=True, check=True)

    def test_dirty_checkout_cannot_substitute_for_pinned_content(self):
        (self.source / "source.txt").write_text("untrusted working copy\n")
        self.assertEqual(MODULE.git_blob(self.source, self.commit, "source.txt"),
                         b"pinned source\n")
        target = self.base / "snapshot"
        MODULE.snapshot(self.source, self.commit, target)
        self.assertEqual((target / "source.txt").read_text(), "pinned source\n")

    def test_bare_shallow_fetch_head_only_source(self):
        bare = self.base / "bare.git"
        subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True)
        subprocess.run(["git", "-C", str(bare), "fetch", "--quiet", "--depth", "1",
                        str(self.source), self.commit], check=True)
        refs = subprocess.run(["git", "-C", str(bare), "show-ref"], capture_output=True)
        self.assertEqual(refs.stdout, b"")
        self.assertTrue((bare / "shallow").is_file())
        target = self.base / "from-bare"
        MODULE.snapshot(bare, self.commit, target)
        self.assertEqual((target / "source.txt").read_text(), "pinned source\n")
        self.assertEqual(subprocess.run(
            ["git", "-C", str(target), "rev-parse", "HEAD"],
            capture_output=True, check=True).stdout.decode().strip(), self.commit)
        self.assertEqual(subprocess.run(
            ["git", "-C", str(bare), "show-ref"],
            capture_output=True).stdout, b"")
        # Moving the input must not break the prepared Git object store.
        bare.rename(self.base / "moved-bare")
        self.assertEqual(subprocess.run(
            ["git", "-C", str(target), "show", "HEAD:source.txt"],
            capture_output=True, check=True).stdout, b"pinned source\n")

    def test_failed_patch_never_counts_as_applied(self):
        target = self.base / "snapshot"
        MODULE.snapshot(self.source, self.commit, target)
        patch = b"--- a/source.txt\n+++ b/source.txt\n@@ -1 +1 @@\n-other source\n+new\n"
        report = {"applied_patches": []}
        with self.assertRaises(MODULE.PreparationError):
            MODULE.apply_series(target, [{
                "source": "fixture", "path": "patches/fixture.patch",
                "data": patch, "sha256": MODULE.digest(patch)
            }], self.base / "patches", report)
        self.assertEqual(report["applied_patches"], [])
        self.assertEqual((target / "source.txt").read_text(), "pinned source\n")

    def test_patch_application_records_exact_bytes(self):
        target = self.base / "snapshot"
        MODULE.snapshot(self.source, self.commit, target)
        patch = b"--- a/source.txt\n+++ b/source.txt\n@@ -1 +1 @@\n-pinned source\n+updated source\n"
        report = {"applied_patches": []}
        MODULE.apply_series(target, [{
            "source": "fixture", "path": "patches/fixture.patch",
            "data": patch, "sha256": MODULE.digest(patch)
        }], self.base / "patches", report)
        self.assertEqual((target / "source.txt").read_text(), "updated source\n")
        self.assertEqual(report["applied_patches"][0]["sha256"], MODULE.digest(patch))

    def test_missing_commit_fails_before_snapshot(self):
        with self.assertRaises(MODULE.PreparationError):
            MODULE.snapshot(self.source, "0" * 40, self.base / "missing")


if __name__ == "__main__":
    unittest.main()
