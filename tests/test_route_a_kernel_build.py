"""Exercise staging boundaries with small real Git repositories, without LLVM."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import struct
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("route_a_kernel_build", ROOT / "scripts/run_route_a_kernel_build.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class KernelBuildStagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.git(self.source, "init", "--quiet")
        directory = self.source / "EXTERNAL_HEADERS/TrustCache"
        directory.mkdir(parents=True)
        (directory / "TrustCache.h").write_text("original public header\n")
        (directory / "Types.h").write_text("public types\n")
        (directory / "README").write_text("not a header\n")
        self.git(self.source, "add", ".")
        self.git(self.source, "-c", "user.name=Route A fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "-qm", "fixture")
        self.commit = self.git(self.source, "rev-parse", "HEAD").stdout.decode().strip()
        self.log = self.root / "commands.log"

    def tearDown(self):
        self.temp.cleanup()

    def git(self, directory, *args):
        return subprocess.run(["git", "-C", str(directory), *args], capture_output=True, check=True)

    def test_checkout_from_bare_shallow_fetch_head_only_input(self):
        bare = self.root / "bare.git"
        bare.mkdir()
        self.git(bare, "init", "--bare", "--quiet")
        self.git(bare, "fetch", "--depth", "1", str(self.source), self.commit)
        result = self.git(bare, "for-each-ref", "--format=%(refname)")
        self.assertEqual(result.stdout, b"")
        output = self.root / "output"
        record = MODULE.checkout(output, str(bare), self.commit, self.log)
        bare.rename(self.root / "moved-bare.git")
        self.assertFalse(record["shared_object_store"])
        self.assertEqual(self.git(output, "show", "HEAD:EXTERNAL_HEADERS/TrustCache/TrustCache.h").stdout,
                         b"original public header\n")
        with self.assertRaises(MODULE.BuildError):
            MODULE.checkout(output, str(self.source), self.commit, self.log)

    def test_optional_shared_llvm_copy_uses_commit_not_dirty_files(self):
        (self.source / "EXTERNAL_HEADERS/TrustCache/TrustCache.h").write_text("dirty working header\n")
        output = self.root / "shared"
        result = MODULE.checkout(output, str(self.source), self.commit, self.log,
                                 paths=("/EXTERNAL_HEADERS/TrustCache/",), shared=True)
        self.assertTrue(result["shared_object_store"])
        self.assertTrue((output / ".git/objects/info/alternates").is_file())
        self.assertEqual((output / "EXTERNAL_HEADERS/TrustCache/TrustCache.h").read_text(),
                         "original public header\n")
        with self.assertRaises(MODULE.BuildError):
            MODULE.checkout(self.root / "wrong", str(self.source), "0" * 40, self.log, shared=True)

    def test_header_cache_is_source_bound_and_preserves_selected_patch(self):
        target = self.root / "target"
        target.mkdir()
        (target / "TrustCache.h").write_text("selected Darwin 26 patch\n")
        (self.source / "EXTERNAL_HEADERS/TrustCache/Types.h").write_text("dirty public checkout\n")
        cache = self.root / "cache/headers.json"
        records = MODULE.seed_header_cache(self.source, self.commit, "EXTERNAL_HEADERS/TrustCache", target, cache)
        self.assertEqual((target / "TrustCache.h").read_text(), "selected Darwin 26 patch\n")
        self.assertEqual((target / "Types.h").read_text(), "public types\n")
        self.assertFalse((target / "README").exists())
        by_name = {Path(record["source_path"]).name: record for record in records}
        self.assertTrue(by_name["TrustCache.h"]["preserved_prepared_header"])
        self.assertNotEqual(by_name["TrustCache.h"]["source_sha256"], by_name["TrustCache.h"]["installed_sha256"])
        entries = json.loads(cache.read_text())
        self.assertEqual(len(entries), 2)
        self.assertTrue(all(self.commit in entry["download_url"] for entry in entries))

    def test_prepared_inventory_rejects_modified_and_extra_sources(self):
        prepared = self.root / "prepared"
        prepared.mkdir()
        self.source.rename(prepared / "tree")
        tree = prepared / "tree"
        entries = MODULE.inventory(tree)
        data = (json.dumps(entries, sort_keys=True, indent=2) + "\n").encode()
        (prepared / "source-inventory.json").write_bytes(data)
        report = {"status": "sources_prepared", "preparation_scope": MODULE.PREPARATION_SCOPE,
                  "full_upstream_profile_applied": False,
                  "sources": {"unixnu": {"commit": MODULE.UNIXNU_COMMIT}, "xnu": {"commit": self.commit}},
                  "source_inventory_sha256": MODULE.digest(data)}
        (prepared / "preparation-report.json").write_text(json.dumps(report))
        # Fail before the patch-manifest step when bytes or the source set no
        # longer match their recorded baseline.
        with patch.object(MODULE, "SOURCE_INVENTORY_SHA256", MODULE.digest(data)), \
                patch.object(MODULE, "XNU_COMMIT", self.commit):
            file = tree / "EXTERNAL_HEADERS/TrustCache/TrustCache.h"
            original = file.read_bytes()
            file.write_bytes(b"changed after prepare\n")
            with self.assertRaisesRegex(MODULE.BuildError, "files changed"):
                MODULE.verify_prepared(prepared)
            file.write_bytes(original)
            (tree / "unrecorded-header.h").write_text("extra compile input\n")
            with self.assertRaisesRegex(MODULE.BuildError, "files changed"):
                MODULE.verify_prepared(prepared)

    def test_foreign_board_environment_cannot_select_provider_or_archive(self):
        with patch.dict(os.environ, {"XNU_SOURCE_CORECRYPTO14": "1", "XNU_EXTRA_LD_ARCHIVES": "foreign.a",
                                    "DARWIN_TRIPLE": "arm64e-apple-macos26.0", "CFLAGS": "-march=armv8.5-a",
                                    "UNIXNU_XNU_ARCH": "arm64e", "MAKEFLAGS": "-j99"}):
            env = MODULE.build_environment(Path("/owned/build"), Path("/owned/toolchain"), 2)
        for key in ("XNU_SOURCE_CORECRYPTO14", "XNU_EXTRA_LD_ARCHIVES", "CFLAGS", "MAKEFLAGS"):
            self.assertNotIn(key, env)
        self.assertEqual(env["DARWIN_TRIPLE"], "arm64-apple-ios27.0")
        self.assertEqual(env["UNIXNU_XNU_ARCH"], "arm64")
        self.assertEqual(env["XNU_BOOTSTRAP"], "1")
        self.assertEqual(env["XNU_BOOT_PROGRESS"], "0")
        self.assertEqual(env["JOBS"], "2")
        self.assertEqual(env["UNIXNU_PATCH_LIST"], "/owned/build/.route-a/selected-patches.txt")

    def test_kernel_header_check_distinguishes_arm64e_and_object_from_executable(self):
        candidate = self.root / "kernel-header-fixture"
        for subtype, kind, expected in ((0, 2, True), (2, 2, False), (0, 1, False)):
            with self.subTest(subtype=subtype, kind=kind):
                candidate.write_bytes(struct.pack("<8I", 0xFEEDFACF, 0x0100000C, subtype, kind, 0, 0, 0, 0))
                result = MODULE.kernel_header(candidate)
                self.assertEqual(result["ordinary_arm64_mh_execute"], expected)
                self.assertFalse(result["full_instruction_set_audited"])
        candidate.write_bytes(b"truncated")
        self.assertIsNone(MODULE.kernel_header(candidate)["macho_header_words"])


if __name__ == "__main__":
    unittest.main()
