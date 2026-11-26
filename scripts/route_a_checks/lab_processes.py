#!/usr/bin/env python3
"""Read-only terminal verification for a frozen, successful A01 CPP experiment.

A complete child-subreaper receipt and retained ledgers establish the owned
scope. This program emits JSON only: no signals, receipt edits, or lease release.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

MAX_RECORD = 16 << 20
MAX_LEDGER_TOTAL = 64 << 20
MAX_PROCESSES = 65536
MAX_THREADS = 4096
MAX_METADATA = 1 << 20
ABSENCE_KEYS = ("direct_child_reaped", "descendants_absent",
                "observed_processes_absent", "observed_groups_absent")


class VerificationError(RuntimeError):
    pass


def require(value, reason):
    if not value:
        raise VerificationError(reason)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def parse_json(raw):
    value = json.loads(raw, object_pairs_hook=unique_object)
    require(isinstance(value, dict), "record must be a JSON object")
    return value


def generation(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def positive_integer(value, label, *, zero=False):
    require(type(value) is int and (0 if zero else 1) <= value < (1 << 63),
            "invalid " + label)
    return value


@dataclass(frozen=True)
class Process:
    pid: int
    ticks: int
    ppid: int
    pgid: int
    sid: int
    state: str

    @property
    def key(self):
        return self.pid, self.ticks

    @property
    def structural(self):
        return self.pid, self.ticks, self.ppid, self.pgid, self.sid

    def public(self):
        return dict(pid=self.pid, ticks=str(self.ticks), ppid=self.ppid,
                    pgid=self.pgid, sid=self.sid, state=self.state)


def process_record(value):
    require(isinstance(value, dict), "missing process identity")
    ticks = value.get("ticks")
    require(isinstance(ticks, str) and re.fullmatch(r"[0-9]{1,20}", ticks),
            "invalid process start ticks")
    state = value.get("state")
    require(isinstance(state, str) and len(state) == 1, "invalid process state")
    return Process(positive_integer(value.get("pid"), "pid"),
                   positive_integer(int(ticks), "start ticks", zero=True),
                   positive_integer(value.get("ppid"), "ppid", zero=True),
                   positive_integer(value.get("pgid"), "pgid", zero=True),
                   positive_integer(value.get("sid"), "sid", zero=True), state)


class EvidenceFiles:
    """Anchor every directory component and read leaves through their parent FD."""
    def __init__(self):
        self.generations = {}
        self.directories = {}
        self.hashes = {}

    @staticmethod
    def directory_identity(value):
        return value.st_dev, value.st_ino, value.st_mode

    def directory(self, path):
        path = Path(path)
        require(path.is_absolute() and ".." not in path.parts,
                "evidence directory must be an absolute canonical path")
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
        fd = os.open("/", flags)
        current = Path("/")
        try:
            for part in (None, *path.parts[1:]):
                if part is not None:
                    before = os.stat(part, dir_fd=fd, follow_symlinks=False)
                    require(stat.S_ISDIR(before.st_mode), "evidence directory is a symlink or non-directory")
                    child_fd = os.open(part, flags, dir_fd=fd)
                    try:
                        require(self.directory_identity(os.fstat(child_fd)) == self.directory_identity(before),
                                "evidence directory changed during open")
                    except BaseException:
                        os.close(child_fd)
                        raise
                    os.close(fd)
                    fd = child_fd
                    current = current / part
                identity = self.directory_identity(os.fstat(fd))
                previous = self.directories.get(current)
                require(previous is None or identity == previous,
                        "evidence directory identity changed")
                self.directories[current] = identity
            return fd
        except BaseException:
            os.close(fd)
            raise

    def recheck_directories(self):
        # Iterating a copy permits the same helper to revalidate shared ancestors.
        for path in tuple(self.directories):
            os.close(self.directory(path))

    def read(self, path, *, limit=MAX_RECORD, expected=None):
        path = Path(path)
        require(path.is_absolute(), "evidence path must be absolute")
        parent_fd = self.directory(path.parent)
        fd = None
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                         dir_fd=parent_fd)
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_size <= limit,
                    "evidence is not a bounded regular file")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(limit + 1)
            after = os.fstat(fd)
            leaf = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            require(len(raw) <= limit and len(raw) == before.st_size
                    and generation(before) == generation(after)
                    and generation(after) == generation(leaf),
                    "evidence generation changed while reading")
        finally:
            if fd is not None:
                os.close(fd)
            os.close(parent_fd)
        digest = sha256(raw)
        require(expected is None or digest == expected, "evidence hash differs")
        self.generations[path] = generation(after)
        self.hashes[str(path)] = digest
        self.recheck_directories()
        return raw

    def recheck(self):
        self.recheck_directories()
        for path, expected in self.generations.items():
            parent_fd = self.directory(path.parent)
            try:
                actual = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
                require(generation(actual) == expected,
                        "evidence generation changed after validation")
            finally:
                os.close(parent_fd)
        self.recheck_directories()


@dataclass
class Evidence:
    scope: str
    boot_id: str
    earliest_ticks: int
    identities: list[Process]
    files: EvidenceFiles
    summary: dict


def verify_ledger(raw, phase):
    """Replay complete retained events, not the bounded observed sample."""
    cleanup = phase["cleanup"]
    history = cleanup["history"]
    require(len(raw) == history["size"] == history["expected_size"], "ledger size differs")
    require(sha256(raw) == history["sha256"], "ledger hash differs")
    lines = raw.splitlines()
    require(len(lines) == history["events"] <= 100000, "ledger event count differs")
    direct = process_record(phase["process"])
    active, identities, groups = {}, [], set()
    observed_count = retired_count = direct_exits = adopted_count = 0
    for line in lines:
        event = parse_json(line)
        kind = event.get("event")
        if kind == "observed":
            item = process_record(event.get("process"))
            require(item.key not in active, "duplicate live ledger identity")
            active[item.key] = item
            identities.append(item)
            groups.add(item.pgid)
            observed_count += 1
        elif kind == "direct_exit":
            require(event.get("pid") == direct.pid
                    and type(event.get("returncode")) is int
                    and event["returncode"] == phase["returncode"],
                    "direct exit does not match phase")
            direct_exits += 1
        elif kind in ("absent", "signal", "adopted_reaped"):
            ticks = event.get("start_ticks")
            require(isinstance(ticks, str) and re.fullmatch(r"[0-9]{1,20}", ticks),
                    "invalid ledger start ticks")
            key = (event.get("pid"), int(ticks))
            require(key in active, "ledger event has no live observed identity")
            if kind == "absent":
                del active[key]
                retired_count += 1
            elif kind == "signal":
                positive_integer(event.get("signal"), "ledger signal")
            else:
                require(type(event.get("status")) is int, "invalid reap status")
                adopted_count += 1
        elif kind == "group_absent":
            group = event.get("group")
            require(type(group) is int and group in groups,
                    "ledger group absence has no observed group")
            groups.remove(group)
        else:
            raise VerificationError("unrecognized ledger event")
    require(direct_exits == 1 and not active and not groups,
            "ledger does not close all observed lifetimes")
    require(observed_count == cleanup.get("observed_count")
            and retired_count == cleanup.get("retired_count")
            and adopted_count == cleanup.get("adopted_reaped_count"),
            "ledger totals differ from cleanup")
    return identities


def load_a01(scope, *, plan_sha256, bootstrap_sha256, receipt_sha256,
             controller_sha256, owned_processes_sha256, boot_id):
    """Validate the existing A01 success profile; no missing-receipt fallback."""
    require(re.fullmatch(r"[0-9a-f-]{36}", boot_id), "invalid original boot id")
    for value in (plan_sha256, bootstrap_sha256, receipt_sha256,
                  controller_sha256, owned_processes_sha256):
        require(re.fullmatch(r"[0-9a-f]{64}", value), "invalid expected digest")
    root = Path(scope)
    require(root.is_absolute() and root.resolve(strict=True) == root and root.is_dir(),
            "scope is not an absolute real directory")
    source = Path(str(root) + "-source")
    require(source.resolve(strict=True) == source and source.is_dir(),
            "source is not a real directory")
    files = EvidenceFiles()
    for directory in (root, source):
        os.close(files.directory(directory))
    plan_raw = files.read(source / "plan.json", expected=plan_sha256, limit=1 << 20)
    controller_raw = files.read(source / "controller.py", expected=controller_sha256, limit=1 << 20)
    owner_raw = files.read(source / "owned_processes.py", expected=owned_processes_sha256, limit=1 << 20)
    bootstrap_raw = files.read(source / "bootstrap.json", expected=bootstrap_sha256, limit=1 << 20)
    receipt_raw = files.read(root / "receipt.json", expected=receipt_sha256)
    plan, entry, receipt = map(parse_json, (plan_raw, bootstrap_raw, receipt_raw))
    require(plan.get("schema") == "route-a-a01-seven-recipe-cpp-plan-v1"
            and plan.get("output") == str(root), "plan profile or scope differs")
    recipes = plan.get("recipes")
    require(isinstance(recipes, list) and len(recipes) == 7, "A01 profile requires seven recipes")
    require(entry.get("plan_sha256") == receipt.get("plan_sha256") == plan_sha256,
            "bootstrap and receipt plan binding differs")
    payload = json.dumps({"controller.py": controller_raw.decode("utf-8"),
                          "owned_processes.py": owner_raw.decode("utf-8"),
                          "plan.json": plan_raw.decode("utf-8")},
                         separators=(",", ":")).encode()
    require(entry.get("payload_sha256") == sha256(payload), "bootstrap payload binding differs")
    controller = process_record(entry.get("process"))
    require(process_record(receipt.get("process")).structural == controller.structural,
            "bootstrap and receipt process identity differs")
    require(receipt.get("schema") == "route-a-a01-seven-recipe-cpp-observation-v1"
            and receipt.get("terminal") is True and receipt.get("complete") is True
            and type(receipt.get("planned_exit")) is int and receipt["planned_exit"] == 0
            and receipt.get("own_descendants_absent") is True and not receipt.get("error"),
            "no successful complete A01 terminal receipt")
    controller_record = receipt.get("controller", {})
    require(isinstance(controller_record, dict), "invalid controller source record")
    require(controller_record.get("sha256") == controller_sha256
            and controller_record.get("path") == str(source / "controller.py")
            and controller_record.get("size") == len(controller_raw),
            "receipt controller source binding differs")
    expected_names = ["compiler-version", "compiler-resource-dir"]
    for index, recipe in enumerate(recipes):
        require(isinstance(recipe, dict) and isinstance(recipe.get("recipe_path"), str),
                "invalid recipe record")
        label = f"{index:02d}-" + Path(recipe["recipe_path"]).name.removesuffix(".o.json")
        expected_names += [label + "-" + mode for mode in ("dependencies", "body", "macros")]
    stages = receipt.get("stages")
    require(isinstance(stages, list) and len(stages) == len(expected_names),
            "terminal phase coverage differs")
    identities, ledger_bytes, event_count = [controller], 0, 0
    for phase, name in zip(stages, expected_names):
        require(isinstance(phase, dict) and phase.get("name") == name
                and phase.get("terminal") is True
                and type(phase.get("returncode")) is int and phase["returncode"] == 0
                and not phase.get("error"), "phase order or terminal status differs")
        process = process_record(phase.get("process"))
        require(phase.get("pid") == process.pid and process.ticks >= controller.ticks,
                "phase identity differs")
        identities.append(process)
        cleanup = phase.get("cleanup", {})
        require(isinstance(cleanup, dict), "invalid phase cleanup record")
        require(all(cleanup.get(key) is True for key in ABSENCE_KEYS)
                and cleanup.get("errors") == []
                and all(cleanup.get(key) == [] for key in
                        ("remaining_descendants", "remaining_observed", "remaining_group_members")),
                "phase cleanup is incomplete")
        history = cleanup.get("history", {})
        require(isinstance(history, dict), "invalid ledger retention record")
        require(history.get("complete") is True and not history.get("error")
                and history.get("path") == str(root / (name + ".processes.jsonl")),
                "ledger path or retention differs")
        raw = files.read(Path(history["path"]), limit=min(MAX_RECORD, MAX_LEDGER_TOTAL - ledger_bytes))
        ledger_bytes += len(raw)
        identities.extend(verify_ledger(raw, phase))
        event_count += history["events"]
    require(all(item.ticks >= controller.ticks for item in identities),
            "observed child predates controller")
    files.recheck()
    return Evidence(str(root), boot_id, controller.ticks, identities, files, dict(
        profile="a01-seven-recipe-success-v1", receipt_sha256=receipt_sha256,
        bootstrap_sha256=bootstrap_sha256, plan_sha256=plan_sha256,
        controller_sha256=controller_sha256, owned_processes_sha256=owned_processes_sha256,
        phase_count=len(stages), ledger_events=event_count, ledger_bytes=ledger_bytes,
        owned_identities=len({item.key for item in identities}),
        owned_groups=len({(item.pgid, item.sid) for item in identities}),
        original_experiment_complete=True))


class ProcFS:
    def __init__(self, root=Path("/proc")):
        self.root = Path(root)

    def read(self, path, limit):
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
        require(len(raw) <= limit, "process metadata exceeds byte budget")
        return raw

    def stat(self, pid, tid=None):
        base = self.root / str(pid)
        if tid is not None:
            base = base / "task" / str(tid)
        raw = self.read(base / "stat", 65536).decode("utf-8")
        expected = pid if tid is None else tid
        prefix, delimiter, suffix = raw.rpartition(") ")
        require(delimiter and prefix.startswith(str(expected) + " ("), "invalid proc stat identity")
        fields = suffix.split()
        require(len(fields) >= 20, "truncated proc stat")
        return process_record(dict(pid=expected, state=fields[0], ppid=int(fields[1]),
                                   pgid=int(fields[2]), sid=int(fields[3]), ticks=fields[19]))

    def snapshot(self):
        names = [p.name for p in self.root.iterdir() if p.name.isdigit()]
        require(len(names) <= MAX_PROCESSES, "process count exceeds budget")
        result = {}
        for name in names:
            try:
                item = self.stat(int(name))
            except (FileNotFoundError, ProcessLookupError):
                continue
            result[item.pid] = item
        return result

    def boot_id(self):
        return self.read(self.root / "sys/kernel/random/boot_id", 128).decode().strip()

    def metadata(self, pid, kind):
        require(kind in ("cmdline", "environ"), "unknown process metadata field")
        return self.read(self.root / str(pid) / kind, MAX_METADATA)

    def thread_ids(self, pid):
        directory = self.root / str(pid) / "task"
        names = [p.name for p in directory.iterdir() if p.name.isdigit()]
        require(0 < len(names) <= MAX_THREADS, "thread enumeration exceeds budget or is empty")
        return [int(name) for name in names]

    def threads(self, pid):
        before = [self.stat(pid, tid) for tid in self.thread_ids(pid)]
        after = [self.stat(pid, tid) for tid in self.thread_ids(pid)]
        require({item.key for item in before} == {item.key for item in after},
                "zombie thread identities changed while enumerating")
        require(all(item.state in ("Z", "X", "x") for item in before + after),
                "zombie leader has an executing thread")
        return after


def ancestor_set(table, observer):
    require(observer in table, "observer absent from process snapshot")
    result, pid = set(), observer
    for _ in range(128):
        if not pid:
            return result
        require(pid not in result, "process ancestor cycle")
        result.add(pid)
        require(pid in table, "ancestor absent from process snapshot")
        pid = table[pid].ppid
    raise VerificationError("process ancestor depth exceeds budget")


def stable_process(proc, before):
    require(proc.stat(before.pid).structural == before.structural,
            "process identity changed while reading metadata")


def observe_scope(evidence, proc=None, *, observer=None):
    proc = proc or ProcFS()
    observer = os.getpid() if observer is None else observer
    require(proc.boot_id() == evidence.boot_id, "boot identity differs from original experiment")
    table = proc.snapshot()
    ancestors = ancestor_set(table, observer)
    owned = {item.key for item in evidence.identities}
    groups = {(item.pgid, item.sid) for item in evidence.identities}
    sessions = {item.sid for item in evidence.identities if item.sid}
    blockers, preexisting, zombies, unrelated_active = [], [], [], []
    zombie_threads = {}
    token = ("A01_PREPROCESS_SCOPE=" + evidence.scope).encode()
    for pid, item in sorted(table.items()):
        if pid in ancestors:
            require(item.key not in owned and (item.pgid, item.sid) not in groups
                    and item.sid not in sessions,
                    "observer is part of the owned experiment")
            continue
        if item.key in owned or (item.pgid, item.sid) in groups or item.sid in sessions:
            blockers.append(dict(reason="owned_identity_group_or_session", process=item.public()))
            continue
        if item.ticks < evidence.earliest_ticks:
            preexisting.append(item.public())
            continue
        if item.state in ("Z", "X", "x"):
            try:
                threads = proc.threads(pid)
                stable_process(proc, item)
                require(all(thread.state in ("Z", "X", "x") for thread in threads),
                        "zombie leader has an executing thread")
                zombies.append(dict(process=item.public(), thread_count=len(threads)))
                zombie_threads[pid] = {thread.key for thread in threads}
            except (OSError, VerificationError) as error:
                blockers.append(dict(reason="unclassified_zombie_threads", process=item.public(),
                                     error_type=type(error).__name__))
            continue
        try:
            command = proc.metadata(pid, "cmdline")
            environment = proc.metadata(pid, "environ")
            stable_process(proc, item)
            if evidence.scope.encode() in command or token in environment.split(b"\0"):
                blockers.append(dict(reason="scope_marker", process=item.public()))
            else:
                unrelated_active.append(item.public())
        except (OSError, VerificationError) as error:
            blockers.append(dict(reason="unclassified_active_metadata", process=item.public(),
                                 error_type=type(error).__name__))
    after = proc.snapshot()
    after_ancestors = ancestor_set(after, observer)
    before_identities = {item.structural for pid, item in table.items() if pid not in ancestors}
    after_identities = {item.structural for pid, item in after.items() if pid not in after_ancestors}
    require(before_identities == after_identities, "process table changed during observation")
    for pid, identities in zombie_threads.items():
        current = proc.threads(pid)
        require({item.key for item in current} == identities
                and all(item.state in ("Z", "X", "x") for item in current),
                "zombie thread set changed during observation")
        stable_process(proc, table[pid])
    require(proc.boot_id() == evidence.boot_id, "boot identity changed during observation")
    evidence.files.recheck()
    return dict(
        schema="route-a-lab-process-terminal-observation-v1",
        observed_utc=datetime.now(timezone.utc).isoformat(), monotonic=time.monotonic(),
        boot_id=evidence.boot_id, scope=evidence.scope, evidence=evidence.summary,
        owned_scope_terminal_verified=not blockers, blockers=blockers,
        process_snapshot_complete=True, stable_process_identities=True,
        preexisting_out_of_scope=preexisting, unowned_nonexecuting_zombies=zombies,
        unrelated_active=unrelated_active, observer_ancestors=sorted(ancestors),
        read_only=True, signals_sent=0, lease_release_performed=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", type=Path, required=True)
    for name in ("plan", "bootstrap", "receipt", "controller", "owned-processes"):
        parser.add_argument("--" + name + "-sha256", required=True)
    parser.add_argument("--boot-id", required=True,
                        help="original boot id from the frozen host dispatch envelope")
    args = parser.parse_args(argv)
    try:
        evidence = load_a01(**vars(args))
        result = observe_scope(evidence)
        code = 0 if result["owned_scope_terminal_verified"] else 2
    except (OSError, ValueError, TypeError, KeyError, RecursionError, VerificationError) as error:
        result = dict(schema="route-a-lab-process-terminal-observation-v1",
                      owned_scope_terminal_verified=False, read_only=True,
                      signals_sent=0, lease_release_performed=False,
                      error=dict(type=type(error).__name__, message=str(error)))
        code = 2
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return code


if __name__ == "__main__":
    sys.exit(main())
