"""Real temporary repositories exercise frozen-source rejection boundaries."""
from pathlib import Path
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from route_a_checks import frozen_sources as frozen


class FrozenSourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.repo = self.base / "repo"
        self.repo.mkdir()
        (self.repo / "source").mkdir()
        (self.repo / "include").mkdir()
        (self.repo / "source/main.py").write_bytes(b"print('bound source')\n")
        (self.repo / "include/base.h").write_bytes(b"#define VALUE 7\n")
        (self.repo / ".gitignore").write_text(".cache/\n*.tmp\n")
        (self.repo / "source/header.h").symlink_to("../include/base.h")
        self.git("init", "-b", "main")
        self.commit()
        self.manifest = self.base / "manifest.json"
        self.seal()

    def git(self, *args):
        result = subprocess.run(
            ["/usr/bin/git", "-c", "core.hooksPath=/dev/null",
             "-c", "user.name=Frozen Source Test", "-c", "user.email=test@example.invalid",
             "-c", "commit.gpgSign=false", "-C", str(self.repo), *args],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=True, timeout=10,
            env=dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null"))
        return result.stdout

    def commit(self):
        self.git("add", "--all")
        self.git("commit", "-qm", "synthetic source")

    def write_manifest(self, value):
        self.manifest.write_text(json.dumps(value) + "\n")
        self.digest = hashlib.sha256(self.manifest.read_bytes()).hexdigest()

    def seal(self):
        self.head = self.git("rev-parse", "HEAD").decode().strip()
        self.tree = self.git("rev-parse", "HEAD^{tree}").decode().strip()
        self.entries = []
        for entry in self.git("ls-tree", "-rz", "--full-tree", "HEAD").split(b"\0"):
            if not entry:
                continue
            metadata, encoded_name = entry.split(b"\t", 1)
            mode, _, blob = metadata.decode().split()
            name = os.fsdecode(encoded_name)
            path = self.repo / name
            raw = os.fsencode(os.readlink(path)) if mode == "120000" else path.read_bytes()
            self.entries.append(dict(path=name, mode=mode, git_blob=blob,
                                     bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
        self.write_manifest(self.entries)

    def verify(self, **changes):
        args = dict(root=self.repo, manifest=self.manifest, manifest_sha256=self.digest,
                    head=self.head, tree=self.tree)
        args.update(changes)
        return frozen.verify(**args)

    def rejected(self, code, **changes):
        with self.assertRaises(frozen.VerificationError) as caught:
            self.verify(**changes)
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def test_actual_tree_and_internal_link_pass_without_status(self):
        queries = []
        original = frozen._git
        def capture(root, args, budget):
            queries.append(args)
            return original(root, args, budget)
        with mock.patch.object(frozen, "_git", side_effect=capture):
            result = self.verify()
        self.assertTrue(result["complete"])
        self.assertEqual(result["verified_files"], 4)
        self.assertEqual(result["verified_symlinks"], 1)
        self.assertFalse(result["compiler_launched"])
        self.assertFalse(result["kernel_boot_verified"])
        self.assertFalse(any("status" in args for args in queries))
        self.assertTrue(any("ls-files" in args for args in queries))
        self.assertTrue(any("ls-tree" in args for args in queries))

    def test_versioned_envelope_and_legacy_list_both_work(self):
        legacy = self.verify()
        self.write_manifest(dict(schema=frozen.MANIFEST_SCHEMA, files=self.entries))
        self.assertEqual(self.verify()["verified_files"], legacy["verified_files"])

    def test_manifest_hash_is_required_even_for_valid_json(self):
        self.manifest.write_text(self.manifest.read_text() + " ")
        self.rejected("manifest_hash")

    def test_duplicate_json_keys_are_rejected(self):
        raw = b'{"schema":"route-a-frozen-source-manifest-v1","schema":"duplicate","files":[]}'
        self.manifest.write_bytes(raw)
        self.digest = hashlib.sha256(raw).hexdigest()
        self.rejected("manifest_schema")

    def test_duplicate_paths_and_extra_fields_are_rejected(self):
        for value in [self.entries + [self.entries[0]],
                      [{**self.entries[0], "ignored": True}, *self.entries[1:]]]:
            with self.subTest(value=value):
                self.write_manifest(value)
                self.rejected("manifest_schema")

    def test_manifest_rejects_unsafe_paths_and_noninteger_lengths(self):
        for name in ["/abs", "../escape", "source/../escape", ".git/config",
                     "source/.git/config", "source//main.py", "source\\main.py", "source/\nname"]:
            with self.subTest(path=name):
                self.write_manifest([{**self.entries[0], "path": name}, *self.entries[1:]])
                self.rejected("manifest_path")
        for size in [True, -1, 1.5, frozen.MAX_FILE_BYTES + 1]:
            with self.subTest(size=size):
                self.write_manifest([{**self.entries[0], "bytes": size}, *self.entries[1:]])
                self.rejected("manifest_schema")

    def test_tracked_content_changes_with_same_length_fail(self):
        path = self.repo / "source/main.py"
        path.write_bytes(path.read_bytes().replace(b"bound", b"wrong"))
        self.rejected("file_hash")

    def test_executable_bit_changes_fail(self):
        (self.repo / "source/main.py").chmod(0o755)
        self.rejected("file_mode")

    def test_file_to_symlink_and_symlink_to_file_changes_fail(self):
        path = self.repo / "source/main.py"
        raw = path.read_bytes()
        path.unlink()
        path.symlink_to("../include/base.h")
        self.rejected("file_mode")
        path.unlink()
        path.write_bytes(raw)
        link = self.repo / "source/header.h"
        link.unlink()
        link.write_bytes(b"../include/base.h")
        self.rejected("file_type")

    def test_missing_file_extra_file_and_extra_empty_directory_fail(self):
        path = self.repo / "source/main.py"
        raw = path.read_bytes()
        path.unlink()
        self.rejected("missing_path")
        path.write_bytes(raw)
        extra = self.repo / "new.tmp"  # Ignored by Git; still disallowed here.
        extra.write_text("not in the pinned source")
        self.rejected("unexpected_path")
        extra.unlink()
        (self.repo / ".cache").mkdir()  # Also ignored; empty does not make it safe.
        self.rejected("unexpected_path")

    def test_symlink_parent_directory_is_not_followed(self):
        (self.repo / "source").rename(self.base / "outside-source")
        (self.repo / "source").symlink_to(self.base / "outside-source", target_is_directory=True)
        self.rejected("directory_type")

    def test_root_directory_symlink_is_not_followed(self):
        alias = self.base / "alias"
        alias.symlink_to(self.repo, target_is_directory=True)
        with self.assertRaises(OSError):
            self.verify(root=alias)

    def test_link_bytes_are_checked_not_only_resolved_content(self):
        link = self.repo / "source/header.h"
        link.unlink()
        link.symlink_to("../include/./base.h")
        self.rejected("file_size")

    def test_committed_external_absolute_and_git_links_fail(self):
        link = self.repo / "source/header.h"
        for target in ["../../outside", str(self.repo / "include/base.h"), "../.git/config"]:
            with self.subTest(target=target):
                link.unlink()
                link.symlink_to(target)
                self.commit()
                self.seal()
                self.rejected("symlink_escape")

    def test_committed_dangling_and_cyclic_links_fail(self):
        link = self.repo / "source/header.h"
        link.unlink()
        link.symlink_to("absent.h")
        self.commit()
        self.seal()
        self.rejected("symlink_dangling")
        link.unlink()
        link.symlink_to("loop.h")
        (self.repo / "source/loop.h").symlink_to("header.h")
        self.commit()
        self.seal()
        self.rejected("symlink_cycle")

    def test_internal_symlink_chain_and_directory_target_are_bound(self):
        (self.repo / "source/chain.h").symlink_to("header.h")
        (self.repo / "source/includes").symlink_to("../include", target_is_directory=True)
        self.commit()
        self.seal()
        result = self.verify()
        self.assertTrue(result["complete"])
        self.assertEqual(result["verified_symlinks"], 3)

    def test_index_mutation_fails_without_refreshing_worktree_status(self):
        (self.repo / "source/main.py").write_bytes(b"staged different source\n")
        self.git("add", "source/main.py")
        self.rejected("git_index")

    def test_changed_head_and_tree_fail(self):
        self.rejected("git_identity", head="0" * 40)
        self.rejected("git_identity", tree="0" * 40)

    def test_self_consistent_new_manifest_cannot_replace_pinned_tree(self):
        entry = next(item for item in self.entries if item["path"] == "source/main.py")
        raw = b"new source\n"
        (self.repo / entry["path"]).write_bytes(raw)
        entry.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                     git_blob=hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest())
        self.write_manifest(self.entries)
        self.rejected("git_tree")

    def test_generation_change_during_actual_read_is_rejected(self):
        target = self.repo / "source/main.py"
        before = target.stat()
        original = os.read
        changed = False
        def mutate(fd, size):
            nonlocal changed
            raw = original(fd, size)
            info = os.fstat(fd)
            if not changed and info.st_dev == before.st_dev and info.st_ino == before.st_ino:
                changed = True
                os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns + 1))
            return raw
        with mock.patch.object(frozen.os, "read", side_effect=mutate):
            self.rejected("generation")
        self.assertTrue(changed)

    def test_extra_path_during_final_git_check_is_rejected(self):
        original = frozen._git_binding
        calls = 0
        def mutate(*args):
            nonlocal calls
            result = original(*args)
            calls += 1
            if calls == 2:
                (self.repo / "late.py").write_text("changed after read\n")
            return result
        with mock.patch.object(frozen, "_git_binding", side_effect=mutate):
            self.rejected("unexpected_path")

    def test_manifest_changes_during_verification_are_rejected(self):
        original = frozen._git_binding
        calls = 0
        def mutate(*args):
            nonlocal calls
            result = original(*args)
            calls += 1
            if calls == 2:
                self.manifest.write_text(self.manifest.read_text() + " ")
            return result
        with mock.patch.object(frozen, "_git_binding", side_effect=mutate):
            self.rejected("manifest_hash")

    def test_return_from_slow_read_does_not_pass_an_expired_deadline(self):
        budget = frozen.Budget(10)
        parent_fd = os.open(self.repo / "source", os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, parent_fd)
        original = os.read
        def expire(fd, size):
            raw = original(fd, size)
            budget.deadline = float("-inf")
            return raw
        with mock.patch.object(frozen.os, "read", side_effect=expire):
            with self.assertRaises(frozen.VerificationError) as caught:
                frozen._read_regular(parent_fd, "main.py", budget, 1024)
        self.assertEqual(caught.exception.code, "deadline")

    def test_git_output_budget_is_enforced(self):
        with mock.patch.object(frozen, "MAX_GIT_BYTES", 4):
            self.rejected("git_output")

    def test_ambient_git_path_overrides_do_not_select_a_different_index(self):
        with mock.patch.dict(os.environ, GIT_DIR="/absent/gitdir",
                             GIT_WORK_TREE="/absent/worktree", GIT_INDEX_FILE="/absent/index"):
            self.assertTrue(self.verify()["complete"])

    def test_git_executable_mode_uses_owner_not_group_or_other_bits(self):
        path = self.repo / "source/main.py"
        path.chmod(0o654)  # Git 100644, despite group execute.
        self.assertTrue(self.verify()["complete"])
        path.chmod(0o755)
        self.commit()
        self.seal()
        path.chmod(0o654)  # The recorded 100755 owner-execute bit is now absent.
        self.rejected("file_mode")

    def test_ancestor_swap_after_final_git_check_cannot_hide_behind_same_root_inode(self):
        ancestor = self.base / "ancestor"
        ancestor.mkdir()
        self.repo.rename(ancestor / "repo")
        self.repo = ancestor / "repo"
        retained = self.base / "retained-ancestor"
        # Keep the manifest outside the changed ancestor, so its separate
        # no-follow check does not accidentally conceal the root-path bug.
        original = frozen._git_binding
        calls = 0
        def replace_ancestor(*args):
            nonlocal calls
            result = original(*args)
            calls += 1
            if calls == 2:
                ancestor.rename(retained)
                ancestor.symlink_to(retained, target_is_directory=True)
            return result
        try:
            with mock.patch.object(frozen, "_git_binding", side_effect=replace_ancestor):
                self.rejected("root_chain")
        finally:
            if ancestor.is_symlink():
                ancestor.unlink()
                retained.rename(ancestor)

    def test_unresolved_git_child_keeps_identity_in_structured_failure(self):
        identity = dict(pid=12345, start_ticks="987654", pgid=12345, sid=12345, state="D")
        process = mock.Mock(pid=12345)
        process.wait.side_effect = subprocess.TimeoutExpired("git", 2)
        with mock.patch.object(frozen.os, "killpg") as kill, \
                mock.patch.object(frozen, "_child_identity", return_value=identity):
            with self.assertRaises(frozen.VerificationError) as caught:
                frozen._reap_failed_git(process, identity)
        result = caught.exception.record()
        self.assertEqual(result["code"], "git_cleanup_unresolved")
        observation = result["cleanup_observation"]
        for key in ("pid", "start_ticks", "pgid", "sid"):
            self.assertEqual(observation[key], identity[key])
        self.assertFalse(observation["direct_child_reaped"])
        self.assertEqual(observation["last_observed"]["state"], "D")
        kill.assert_called_once_with(12345, frozen.signal.SIGKILL)

    def test_cli_failure_returns_json_and_cannot_launch_compile(self):
        stdout = io.StringIO()
        with mock.patch("sys.stdout", stdout):
            code = frozen.main([
                "--root", str(self.repo), "--manifest", str(self.manifest),
                "--manifest-sha256", "0" * 64, "--head", self.head, "--tree", self.tree])
        result = json.loads(stdout.getvalue())
        self.assertEqual(code, 1)
        self.assertFalse(result["complete"])
        self.assertFalse(result["compiler_launched"])
        self.assertFalse(result["kernel_boot_verified"])
        self.assertEqual(result["error"]["code"], "manifest_hash")


if __name__ == "__main__":
    unittest.main()
