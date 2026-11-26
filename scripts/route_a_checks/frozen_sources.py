"""Bounded, read-only verification of a frozen Git source tree.

This verifies an explicit manifest, not a mutable Git status cache. It does not
start builds, claim a lease, or qualify any kernel/runtime result.
"""
from __future__ import annotations

import argparse
from collections import deque
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time

SCHEMA = "route-a-frozen-source-verification-v1"
MANIFEST_SCHEMA = "route-a-frozen-source-manifest-v1"
MAX_MANIFEST_BYTES = 8 << 20
MAX_FILES = 10_000
MAX_FILE_BYTES = 32 << 20
MAX_TOTAL_BYTES = 256 << 20
MAX_GIT_BYTES = 8 << 20
MAX_PATH_BYTES = 4096
READ_SIZE = 64 << 10


class VerificationError(ValueError):
    """A specific failed condition; never a successful partial verification."""

    def __init__(self, code: str, detail: str, path: str | None = None,
                 cleanup_observation: dict | None = None):
        self.code = code
        self.detail = str(detail)[:1024]
        self.path = path
        self.cleanup_observation = cleanup_observation
        super().__init__(f"{code}: {self.detail}" + (f": {path}" if path else ""))

    def record(self) -> dict:
        result = {"code": self.code, "detail": self.detail, "path": self.path}
        if self.cleanup_observation is not None:
            result["cleanup_observation"] = self.cleanup_observation
        return result


class Budget:
    def __init__(self, seconds: float):
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
            raise VerificationError("budget", "timeout must be a number")
        if not 0 < seconds <= 180:
            raise VerificationError("budget", "timeout must be in (0, 180] seconds")
        self.started = time.monotonic()
        self.deadline = self.started + seconds

    def remaining(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise VerificationError("deadline", "source verification deadline expired")
        return remaining


def generation(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _safe_path(name: str) -> tuple[str, ...]:
    if not isinstance(name, str) or not name or name.startswith("/"):
        raise VerificationError("manifest_path", "expected a relative nonempty path")
    if len(os.fsencode(name)) > MAX_PATH_BYTES:
        raise VerificationError("manifest_path", "path exceeds byte budget")
    parts = name.split("/")
    if (len(parts) > 64 or any(p in ("", ".", "..", ".git") for p in parts)
            or "\\" in name or any(ord(c) < 32 or ord(c) == 127 for c in name)):
        raise VerificationError("manifest_path", "unsafe or noncanonical path", name)
    return tuple(parts)


def _hex(value: str, digits: int, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(rf"[0-9a-f]{{{digits}}}", value) is None:
        raise VerificationError("identity", f"invalid {label}")
    return value


def _open_directory(path: Path, identities: list | None = None) -> int:
    """Open every component without symlinks; optionally retain its identity."""
    if not path.is_absolute() or ".." in path.parts:
        raise VerificationError("root_path", "use an absolute path without '..'")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        if identities is not None:
            info = os.fstat(fd)
            identities.append((info.st_dev, info.st_ino, info.st_mode))
        for part in path.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=fd)
            os.close(fd)
            fd = next_fd
            if identities is not None:
                info = os.fstat(fd)
                identities.append((info.st_dev, info.st_ino, info.st_mode))
        return fd
    except BaseException:
        os.close(fd)
        raise


def _parent_fd(root_fd: int, name: str) -> tuple[int, str]:
    parts = _safe_path(name)
    fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise


def _read_regular(parent_fd: int, name: str, budget: Budget, maximum: int,
                  expected_generation: tuple | None = None) -> tuple[bytes, tuple]:
    budget.remaining()
    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise VerificationError("file_type_size", "not a bounded regular file", name)
    original = generation(before)
    if expected_generation is not None and original != expected_generation:
        raise VerificationError("generation", "file changed after enumeration", name)
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
    try:
        if generation(os.fstat(fd)) != original:
            raise VerificationError("generation", "file changed during open", name)
        result = bytearray()
        while True:
            budget.remaining()
            block = os.read(fd, min(READ_SIZE, maximum + 1 - len(result)))
            budget.remaining()
            if not block:
                break
            result.extend(block)
            if len(result) > maximum:
                raise VerificationError("file_size", "file grew beyond byte budget", name)
        after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (generation(os.fstat(fd)) != original or generation(after) != original
                or len(result) != before.st_size):
            raise VerificationError("generation", "file changed while reading", name)
        return bytes(result), original
    finally:
        os.close(fd)


def _unique_object(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError("manifest_schema", "duplicate JSON object key")
        result[key] = value
    return result


def _bad_constant(value: str):
    raise VerificationError("manifest_schema", "nonfinite JSON constant")


def load_manifest(path: Path, expected_sha256: str, budget: Budget) -> tuple[dict, dict]:
    _hex(expected_sha256, 64, "manifest SHA256")
    parent_fd = _open_directory(path.parent)
    try:
        raw, snapshot = _read_regular(parent_fd, path.name, budget, MAX_MANIFEST_BYTES)
    finally:
        os.close(parent_fd)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise VerificationError("manifest_hash", "manifest SHA256 differs")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_bad_constant)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationError("manifest_schema", str(exc)) from exc
    if isinstance(value, dict):
        if set(value) != {"schema", "files"} or value["schema"] != MANIFEST_SCHEMA:
            raise VerificationError("manifest_schema", "unsupported manifest envelope")
        value = value["files"]
    if not isinstance(value, list) or not 0 < len(value) <= MAX_FILES:
        raise VerificationError("manifest_schema", "expected a bounded nonempty file list")
    entries = {}
    total = 0
    for item in value:
        budget.remaining()
        if not isinstance(item, dict) or set(item) != {"path", "mode", "git_blob", "bytes", "sha256"}:
            raise VerificationError("manifest_schema", "unexpected file fields")
        parts = _safe_path(item["path"])
        name = "/".join(parts)
        if name in entries:
            raise VerificationError("manifest_schema", "duplicate file path", name)
        if item["mode"] not in ("100644", "100755", "120000"):
            raise VerificationError("manifest_schema", "unsupported Git file mode", name)
        if type(item["bytes"]) is not int or not 0 <= item["bytes"] <= MAX_FILE_BYTES:
            raise VerificationError("manifest_schema", "invalid file byte count", name)
        _hex(item["git_blob"], 40, "Git blob SHA1")
        _hex(item["sha256"], 64, "file SHA256")
        total += item["bytes"]
        if total > MAX_TOTAL_BYTES:
            raise VerificationError("manifest_schema", "total source bytes exceed budget")
        entries[name] = dict(item)
    directories = {""}
    for name in entries:
        parts = name.split("/")
        directories.update("/".join(parts[:i]) for i in range(1, len(parts)))
    if set(entries) & directories:
        raise VerificationError("manifest_schema", "file is also a parent directory")
    return entries, {"sha256": expected_sha256, "bytes": len(raw),
                     "generation": snapshot, "total_source_bytes": total}


def _child_identity(pid: int) -> dict:
    with Path(f"/proc/{pid}/stat").open("rb") as stream:
        raw = stream.read(4097)
    if len(raw) > 4096:
        raise VerificationError("git_identity", "process stat exceeds byte budget")
    fields = raw.rsplit(b")", 1)[1].split()
    return {"pid": pid, "start_ticks": fields[19].decode("ascii"),
            "pgid": int(fields[2]), "sid": int(fields[3]), "state": fields[0].decode("ascii")}


def _reap_failed_git(process, identity: dict) -> None:
    """Keep an unresolved child identity in the failure for the outer owner."""
    observation = {**identity, "direct_child_reaped": False,
                   "signal_requested": int(signal.SIGKILL), "signal_sent": False}
    try:
        # This Popen child has not been waited/reaped, so its PID cannot be reused.
        group_owned = (identity.get("start_ticks") is not None
                       and identity.get("pid") == process.pid
                       and identity.get("pgid") == process.pid
                       and identity.get("sid") == process.pid)
        observation["signal_target"] = "group" if group_owned else "direct_child"
        if group_owned:
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
        observation["signal_sent"] = True
    except ProcessLookupError:
        observation["group_missing_at_signal"] = True
    except OSError as exc:
        observation["signal_error"] = type(exc).__name__ + ": " + str(exc)[:256]
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired as exc:
        try:
            observation["last_observed"] = _child_identity(process.pid)
        except (OSError, ValueError, IndexError) as read_error:
            observation["last_observation_error"] = type(read_error).__name__
        raise VerificationError(
            "git_cleanup_unresolved", "owned Git child still requires outer-supervisor reconciliation",
            cleanup_observation=observation) from exc


def _git(root: Path, args: list[str], budget: Budget) -> bytes:
    """Only fixed metadata queries; bounded pipes, no status, filters or hooks."""
    command = ["/usr/bin/git", "--no-optional-locks", "--no-replace-objects",
               "-c", "core.fsmonitor=false", "-c", "core.preloadIndex=false",
               "-c", "core.hooksPath=/dev/null", "-C", str(root), *args]
    env = {"PATH": os.defpath, "LC_ALL": "C", "LANG": "C",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0",
           "GIT_TERMINAL_PROMPT": "0", "GIT_NO_LAZY_FETCH": "1"}
    deadline = time.monotonic() + min(30, budget.remaining())
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True, env=env)
    output, errors = bytearray(), bytearray()
    reaped = False
    identity = {"pid": process.pid, "start_ticks": None, "pgid": process.pid, "sid": process.pid}
    try:
        identity = _child_identity(process.pid)
        if identity["pgid"] != process.pid or identity["sid"] != process.pid:
            raise VerificationError("git_identity", "owned Git session identity differs",
                                    cleanup_observation=identity)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, output)
            selector.register(process.stderr, selectors.EVENT_READ, errors)
            while selector.get_map():
                remaining = min(budget.remaining(), deadline - time.monotonic())
                if remaining <= 0:
                    raise VerificationError("git_timeout", "Git metadata deadline expired")
                for key, _ in selector.select(min(remaining, 0.1)):
                    block = os.read(key.fd, READ_SIZE)
                    if block:
                        key.data.extend(block)
                        if len(output) + len(errors) > MAX_GIT_BYTES:
                            raise VerificationError("git_output", "Git metadata output exceeds budget")
                    else:
                        selector.unregister(key.fileobj)
            remaining = min(budget.remaining(), deadline - time.monotonic())
            if remaining <= 0:
                raise VerificationError("git_timeout", "Git metadata deadline expired")
            code = process.wait(timeout=remaining)
            reaped = True
        budget.remaining()
        if code:
            raise VerificationError("git_error", errors.decode(errors="replace")[:512])
        return bytes(output)
    except subprocess.TimeoutExpired as exc:
        raise VerificationError("git_timeout", "Git metadata deadline expired") from exc
    finally:
        try:
            if not reaped:
                _reap_failed_git(process, identity)
        finally:
            process.stdout.close()
            process.stderr.close()


def _git_entries(raw: bytes, kind: str) -> dict:
    entries = {}
    if raw and not raw.endswith(b"\0"):
        raise VerificationError("git_metadata", "unterminated Git path list")
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, path_bytes = record.split(b"\t", 1)
            mode, second, third = metadata.decode("ascii").split()
            name = os.fsdecode(path_bytes)
        except (ValueError, UnicodeError) as exc:
            raise VerificationError("git_metadata", "invalid Git path entry") from exc
        _safe_path(name)
        if kind == "tree":
            if second != "blob":
                raise VerificationError("git_metadata", "non-blob tree entry", name)
            blob = third
        else:
            if third != "0":
                raise VerificationError("git_index", "unmerged index stage", name)
            blob = second
        _hex(blob, 40, "Git blob SHA1")
        if name in entries or len(entries) >= MAX_FILES:
            raise VerificationError("git_metadata", "duplicate or excessive Git entries")
        entries[name] = (mode, blob)
    return entries


def _git_binding(root: Path, entries: dict, head: str, tree: str, budget: Budget) -> dict:
    top = _git(root, ["rev-parse", "--show-toplevel"], budget).decode().rstrip("\n")
    if top != str(root):
        raise VerificationError("git_root", "Git toplevel differs from declared root")
    actual_head = _git(root, ["rev-parse", "--verify", "HEAD^{commit}"], budget).decode().strip()
    actual_tree = _git(root, ["rev-parse", "--verify", "HEAD^{tree}"], budget).decode().strip()
    if actual_head != head or actual_tree != tree:
        raise VerificationError("git_identity", "HEAD or tree differs")
    expected = {name: (item["mode"], item["git_blob"]) for name, item in entries.items()}
    committed = _git_entries(_git(root, ["ls-tree", "-r", "-z", "--full-tree", head], budget), "tree")
    index = _git_entries(_git(root, ["ls-files", "--stage", "-z", "--"], budget), "index")
    if committed != expected:
        raise VerificationError("git_tree", "manifest entries differ from the pinned Git tree")
    if index != expected:
        raise VerificationError("git_index", "Git index differs from the pinned manifest")
    return {"head": actual_head, "tree": actual_tree, "entries": len(expected)}


def _census(root_fd: int, entries: dict, budget: Budget) -> dict:
    expected_dirs = {""}
    for name in entries:
        parts = name.split("/")
        expected_dirs.update("/".join(parts[:i]) for i in range(1, len(parts)))
    result = {}

    def walk(fd: int, prefix: str) -> None:
        budget.remaining()
        result[prefix] = generation(os.fstat(fd))
        with os.scandir(fd) as iterator:
            for item in iterator:
                budget.remaining()
                if not prefix and item.name == ".git":
                    continue
                name = f"{prefix}/{item.name}" if prefix else item.name
                if name not in entries and name not in expected_dirs:
                    raise VerificationError("unexpected_path", "extra source path, including empty directories", name)
                info = os.stat(item.name, dir_fd=fd, follow_symlinks=False)
                if name in expected_dirs:
                    if not stat.S_ISDIR(info.st_mode):
                        raise VerificationError("directory_type", "declared directory changed type", name)
                    child_fd = os.open(item.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        if generation(os.fstat(child_fd)) != generation(info):
                            raise VerificationError("generation", "directory changed during open", name)
                        walk(child_fd, name)
                    finally:
                        os.close(child_fd)
                else:
                    result[name] = generation(info)
        if generation(os.fstat(fd)) != result[prefix]:
            raise VerificationError("generation", "directory changed during enumeration", prefix)

    walk(root_fd, "")
    if set(result) != set(entries) | expected_dirs:
        raise VerificationError("missing_path", "declared file or directory is missing")
    return result


def _link_target(name: str, links: dict, entries: dict) -> str:
    """Resolve using verified link bytes and the manifest, never external files."""
    directories = {""}
    for path in entries:
        parts = path.split("/")
        directories.update("/".join(parts[:i]) for i in range(1, len(parts)))
    resolved = name.split("/")[:-1]
    pending = deque(links[name].split("/"))
    hops = 0
    steps = 0
    if links[name].startswith("/"):
        raise VerificationError("symlink_escape", "absolute source symlink is forbidden", name)
    while pending:
        steps += 1
        if steps > 4096:
            raise VerificationError("symlink_cycle", "symlink resolution budget exceeded", name)
        part = pending.popleft()
        if part in ("", "."):
            continue
        if part == "..":
            if not resolved:
                raise VerificationError("symlink_escape", "symlink escapes source root", name)
            resolved.pop()
            continue
        if part == ".git" or "\\" in part or any(ord(c) < 32 or ord(c) == 127 for c in part):
            raise VerificationError("symlink_escape", "unsafe symlink component", name)
        candidate = "/".join([*resolved, part])
        if candidate in links:
            hops += 1
            if hops > 40:
                raise VerificationError("symlink_cycle", "symlink loop or excessive indirection", name)
            target = links[candidate]
            if target.startswith("/"):
                raise VerificationError("symlink_escape", "absolute source symlink is forbidden", candidate)
            pending.extendleft(reversed(target.split("/")))
        else:
            if candidate not in entries and candidate not in directories:
                raise VerificationError("symlink_dangling", "target is outside the declared source set", name)
            if pending and candidate not in directories:
                raise VerificationError("symlink_target", "file used as a symlink parent directory", name)
            resolved.append(part)
    return "/".join(resolved)


def verify(root: Path | str, manifest: Path | str, manifest_sha256: str,
           head: str, tree: str, timeout_seconds: float = 120) -> dict:
    """Verify exactly one snapshot; the caller must prevent later source writes."""
    budget = Budget(timeout_seconds)
    root, manifest = Path(root), Path(manifest)
    _hex(head, 40, "HEAD SHA1")
    _hex(tree, 40, "tree SHA1")
    entries, manifest_info = load_manifest(manifest, manifest_sha256, budget)
    ancestor_chain = []
    root_fd = _open_directory(root, ancestor_chain)
    try:
        initial = _census(root_fd, entries, budget)
        binding = _git_binding(root, entries, head, tree, budget)
        links = {}
        for name, item in entries.items():
            budget.remaining()
            parent_fd, leaf = _parent_fd(root_fd, name)
            try:
                before = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                if generation(before) != initial[name]:
                    raise VerificationError("generation", "source changed after census", name)
                if item["mode"] == "120000":
                    if not stat.S_ISLNK(before.st_mode):
                        raise VerificationError("file_type", "expected tracked symlink", name)
                    raw = os.fsencode(os.readlink(leaf, dir_fd=parent_fd))
                    if generation(os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)) != initial[name]:
                        raise VerificationError("generation", "symlink changed while reading", name)
                    links[name] = os.fsdecode(raw)
                else:
                    if (not stat.S_ISREG(before.st_mode) or before.st_mode & 0o7000
                            or bool(before.st_mode & stat.S_IXUSR) != (item["mode"] == "100755")):
                        raise VerificationError("file_mode", "file type or Git executable bit differs", name)
                    raw, _ = _read_regular(parent_fd, leaf, budget, item["bytes"], initial[name])
                if len(raw) != item["bytes"]:
                    raise VerificationError("file_size", "file byte count differs", name)
                blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
                if blob != item["git_blob"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
                    raise VerificationError("file_hash", "source bytes differ from frozen identity", name)
            finally:
                os.close(parent_fd)
        for name in links:
            budget.remaining()
            _link_target(name, links, entries)
        # Repeat metadata and filesystem identity checks to reject changes during
        # verification. This is not a write lock or a future immutability claim.
        if _git_binding(root, entries, head, tree, budget) != binding:
            raise VerificationError("git_identity", "Git metadata changed during verification")
        if _census(root_fd, entries, budget) != initial:
            raise VerificationError("generation", "source generation changed during verification")
        final_chain = []
        try:
            final_root_fd = _open_directory(root, final_chain)
        except OSError as exc:
            raise VerificationError("root_chain", "source ancestor chain changed type or became inaccessible") from exc
        try:
            if final_chain != ancestor_chain:
                raise VerificationError("root_chain", "source ancestor directory identity changed")
            if generation(os.fstat(final_root_fd)) != initial[""]:
                raise VerificationError("generation", "source root path was replaced")
        finally:
            os.close(final_root_fd)
        if load_manifest(manifest, manifest_sha256, budget)[1] != manifest_info:
            raise VerificationError("generation", "manifest changed during verification")
        budget.remaining()
        snapshot = {"ancestors": ancestor_chain, "entries": initial}
        digest = hashlib.sha256(json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return {"schema": SCHEMA, "complete": True, "root": str(root),
                "manifest": {"path": str(manifest), **manifest_info},
                "git": binding, "verified_files": len(entries), "verified_symlinks": len(links),
                "snapshot_sha256": digest, "seconds": round(time.monotonic() - budget.started, 6),
                "compiler_launched": False, "kernel_boot_verified": False}
    finally:
        os.close(root_fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--tree", required=True)
    parser.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args(argv)
    try:
        result = verify(args.root, args.manifest, args.manifest_sha256,
                        args.head, args.tree, args.timeout)
    except (VerificationError, OSError, UnicodeError) as exc:
        error = exc.record() if isinstance(exc, VerificationError) else {
            "code": type(exc).__name__, "detail": str(exc)[:1024], "path": None}
        result = {"schema": SCHEMA, "complete": False, "error": error,
                  "compiler_launched": False, "kernel_boot_verified": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
