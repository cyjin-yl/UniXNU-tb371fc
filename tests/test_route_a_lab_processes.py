"""Process-scope counterexamples; no real processes are signalled."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/route_a_checks/lab_processes.py"
SPEC = importlib.util.spec_from_file_location("route_a_lab_processes", SCRIPT)
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


def process(pid, ticks, *, ppid=1, pgid=None, sid=None, state="S"):
    return lab.Process(pid, ticks, ppid, pid if pgid is None else pgid,
                       pid if sid is None else sid, state)


class NoFiles:
    def recheck(self):
        pass


class FakeProc:
    def __init__(self, additions=(), *, metadata=None, thread_map=None, second=None):
        self.table = {1: process(1, 1, ppid=0), 900: process(900, 900, ppid=0)}
        self.table.update({item.pid: item for item in additions})
        self.metadata_values = metadata or {}
        self.thread_map = thread_map or {}
        self.second = second
        self.calls = []
        self.snapshots = 0
        self.boot = "11111111-2222-3333-4444-555555555555"

    def boot_id(self):
        return self.boot

    def snapshot(self):
        self.snapshots += 1
        return dict(self.table if self.snapshots == 1 or self.second is None else self.second)

    def stat(self, pid):
        return self.table[pid]

    def metadata(self, pid, kind):
        self.calls.append((pid, kind))
        value = self.metadata_values.get((pid, kind), b"")
        if isinstance(value, BaseException):
            raise value
        return value

    def threads(self, pid):
        value = self.thread_map.get(pid, [self.table[pid]])
        if isinstance(value, BaseException):
            raise value
        return value


class ScopeTests(unittest.TestCase):
    def evidence(self, identities=None):
        return lab.Evidence("/private/experiment", "11111111-2222-3333-4444-555555555555",
                            100, identities or [process(10, 100)], NoFiles(),
                            {"original_experiment_complete": True})

    def observe(self, proc, evidence=None):
        return lab.observe_scope(evidence or self.evidence(), proc, observer=900)

    def test_preexisting_protected_metadata_is_not_read(self):
        proc = FakeProc([process(36, 20, state="Z")],
                        metadata={(36, "environ"): PermissionError()})
        result = self.observe(proc)
        self.assertTrue(result["owned_scope_terminal_verified"])
        self.assertEqual(proc.calls, [])
        self.assertIn(36, [p["pid"] for p in result["preexisting_out_of_scope"]])

    def test_owned_process_denied_metadata_remains_blocking(self):
        proc = FakeProc([process(10, 100)], metadata={(10, "environ"): PermissionError()})
        self.assertFalse(self.observe(proc)["owned_scope_terminal_verified"])
        self.assertEqual(proc.calls, [])

    def test_owned_zombie_remains_blocking(self):
        result = self.observe(FakeProc([process(10, 100, state="Z")]))
        self.assertFalse(result["owned_scope_terminal_verified"])
        self.assertEqual(result["unowned_nonexecuting_zombies"], [])

    def test_unowned_zombie_does_not_require_environment(self):
        proc = FakeProc([process(20, 200, state="Z")])
        result = self.observe(proc)
        self.assertTrue(result["owned_scope_terminal_verified"])
        self.assertEqual(len(result["unowned_nonexecuting_zombies"]), 1)
        self.assertEqual(proc.calls, [])

    def test_zombie_leader_with_live_thread_is_not_terminal(self):
        proc = FakeProc([process(20, 200, state="Z")],
                        thread_map={20: [process(20, 200, state="Z"), process(21, 201)]})
        self.assertFalse(self.observe(proc)["owned_scope_terminal_verified"])

    def test_denied_zombie_thread_enumeration_is_inconclusive(self):
        proc = FakeProc([process(20, 200, state="Z")], thread_map={20: PermissionError()})
        self.assertFalse(self.observe(proc)["owned_scope_terminal_verified"])

    def test_unknown_active_permission_failure_is_inconclusive(self):
        proc = FakeProc([process(20, 200)], metadata={(20, "environ"): PermissionError()})
        result = self.observe(proc)
        self.assertFalse(result["owned_scope_terminal_verified"])
        self.assertEqual(result["blockers"][0]["reason"], "unclassified_active_metadata")

    def test_scope_marker_blocks_even_when_identity_is_unknown(self):
        proc = FakeProc([process(20, 200)],
                        metadata={(20, "environ"): b"A01_PREPROCESS_SCOPE=/private/experiment\0"})
        self.assertFalse(self.observe(proc)["owned_scope_terminal_verified"])

    def test_pid_reuse_is_not_an_owned_identity(self):
        proc = FakeProc([process(10, 200, pgid=20, sid=20)])
        self.assertTrue(self.observe(proc)["owned_scope_terminal_verified"])
        proc = FakeProc([process(10, 200, pgid=10, sid=10)])
        self.assertFalse(self.observe(proc)["owned_scope_terminal_verified"])

    def test_detached_observed_child_remains_owned(self):
        detached = process(21, 150, ppid=1, pgid=21, sid=21)
        result = self.observe(FakeProc([detached]), self.evidence([process(10, 100), detached]))
        self.assertFalse(result["owned_scope_terminal_verified"])

    def test_changed_group_within_owned_session_blocks(self):
        self.assertFalse(self.observe(FakeProc([process(20, 200, pgid=20, sid=10)]))
                         ["owned_scope_terminal_verified"])

    def test_identity_change_between_snapshots_is_rejected(self):
        proc = FakeProc([process(20, 200)])
        proc.second = {**proc.table, 20: process(20, 201)}
        with self.assertRaisesRegex(lab.VerificationError, "process table changed"):
            self.observe(proc)

    def test_zombie_threads_are_rechecked_at_end(self):
        class ChangingZombie(FakeProc):
            reads = 0
            def threads(self, pid):
                self.reads += 1
                if self.reads == 1:
                    return [process(pid, 200, state="Z")]
                return [process(pid, 200, state="Z"), process(21, 201)]
        with self.assertRaisesRegex(lab.VerificationError, "zombie thread set changed"):
            self.observe(ChangingZombie([process(20, 200, state="Z")]))

    def test_wrong_original_boot_is_rejected(self):
        proc = FakeProc()
        proc.boot = "different"
        with self.assertRaisesRegex(lab.VerificationError, "boot identity differs"):
            self.observe(proc)

    def test_observer_cannot_exclude_owned_ancestor(self):
        with self.assertRaisesRegex(lab.VerificationError, "observer is part"):
            self.observe(FakeProc(), self.evidence([process(900, 900, ppid=0)]))


class ThreadEnumerationTests(unittest.TestCase):
    def test_thread_replacement_during_enumeration_is_rejected(self):
        class ChurningProc(lab.ProcFS):
            reads = 0
            def thread_ids(self, pid):
                self.reads += 1
                # The old worker exits after creating a thread omitted by the
                # first enumeration. Every previously listed task now looks dead.
                return [pid, 21] if self.reads == 1 else [pid, 22]
            def stat(self, pid, tid=None):
                return process(tid, tid * 10, state="Z")
        with self.assertRaisesRegex(lab.VerificationError, "thread identities changed"):
            ChurningProc().threads(20)

    def test_reused_thread_id_with_new_start_ticks_is_rejected(self):
        class ReusedThread(lab.ProcFS):
            reads = 0
            def thread_ids(self, pid):
                self.reads += 1
                return [pid, 21]
            def stat(self, pid, tid=None):
                return process(tid, tid * 10 + self.reads, state="Z")
        with self.assertRaisesRegex(lab.VerificationError, "thread identities changed"):
            ReusedThread().threads(20)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.scope = Path(self.tmp.name) / "scope"
        self.scope.mkdir()
        self.source = Path(str(self.scope) + "-source")
        self.source.mkdir()
        self.boot = "11111111-2222-3333-4444-555555555555"
        self.plan = {"schema": "route-a-a01-seven-recipe-cpp-plan-v1", "output": str(self.scope),
                     "recipes": [{"recipe_path": f"/source/file{i}.o.json"} for i in range(7)]}
        self.plan_raw = json.dumps(self.plan).encode()
        self.controller_raw = b"# pinned controller\n"
        self.owner_raw = b"# pinned subreaper\n"
        for name, raw in (("plan.json", self.plan_raw), ("controller.py", self.controller_raw),
                          ("owned_processes.py", self.owner_raw)):
            (self.source / name).write_bytes(raw)
        payload = json.dumps({"controller.py": self.controller_raw.decode(),
                              "owned_processes.py": self.owner_raw.decode(),
                              "plan.json": self.plan_raw.decode()}, separators=(",", ":")).encode()
        self.identity = process(10, 100).public()
        self.entry = dict(process=self.identity, plan_sha256=lab.sha256(self.plan_raw),
                          payload_sha256=lab.sha256(payload))
        self.receipt = dict(schema="route-a-a01-seven-recipe-cpp-observation-v1",
                            plan_sha256=lab.sha256(self.plan_raw), process=self.identity,
                            terminal=True, complete=True, planned_exit=0, own_descendants_absent=True,
                            controller=dict(path=str(self.source / "controller.py"),
                                            sha256=lab.sha256(self.controller_raw),
                                            size=len(self.controller_raw)), stages=[])
        names = ["compiler-version", "compiler-resource-dir"]
        for i in range(7):
            names += [f"{i:02d}-file{i}-{mode}" for mode in ("dependencies", "body", "macros")]
        for i, name in enumerate(names):
            child = process(30 + i, 200 + i, ppid=10).public()
            raw = (json.dumps(dict(event="direct_exit", pid=child["pid"], returncode=0)) + "\n").encode()
            path = self.scope / (name + ".processes.jsonl")
            path.write_bytes(raw)
            history = dict(path=str(path), size=len(raw), expected_size=len(raw),
                           sha256=lab.sha256(raw), events=1, complete=True)
            cleanup = dict(**{key: True for key in lab.ABSENCE_KEYS}, errors=[],
                           remaining_descendants=[], remaining_observed=[], remaining_group_members=[],
                           observed_count=0, retired_count=0, adopted_reaped_count=0, history=history)
            self.receipt["stages"].append(dict(name=name, process=child, pid=child["pid"],
                                               terminal=True, returncode=0, cleanup=cleanup))
        self.save()

    def save(self):
        self.entry_raw = json.dumps(self.entry).encode()
        self.receipt_raw = json.dumps(self.receipt).encode()
        (self.source / "bootstrap.json").write_bytes(self.entry_raw)
        (self.scope / "receipt.json").write_bytes(self.receipt_raw)

    def load(self, **overrides):
        args = dict(scope=self.scope, boot_id=self.boot, plan_sha256=lab.sha256(self.plan_raw),
                    controller_sha256=lab.sha256(self.controller_raw),
                    owned_processes_sha256=lab.sha256(self.owner_raw),
                    bootstrap_sha256=lab.sha256(self.entry_raw),
                    receipt_sha256=lab.sha256(self.receipt_raw))
        args.update(overrides)
        return lab.load_a01(**args)

    def test_matching_evidence_accepts_all_23_ledgers(self):
        result = self.load()
        self.assertEqual(result.summary["phase_count"], 23)
        self.assertEqual(result.summary["ledger_events"], 23)
        self.assertEqual(result.summary["owned_identities"], 24)

    def test_truncated_ledger_is_rejected(self):
        path = Path(self.receipt["stages"][0]["cleanup"]["history"]["path"])
        path.write_bytes(path.read_bytes()[:-1])
        with self.assertRaisesRegex(lab.VerificationError, "ledger size"):
            self.load()

    def test_matching_size_with_wrong_ledger_hash_is_rejected(self):
        path = Path(self.receipt["stages"][0]["cleanup"]["history"]["path"])
        path.write_bytes(path.read_bytes().replace(b'"pid": 30', b'"pid": 31'))
        with self.assertRaisesRegex(lab.VerificationError, "ledger hash"):
            self.load()

    def test_ledger_event_count_is_bound(self):
        self.receipt["stages"][0]["cleanup"]["history"]["events"] = 2
        self.save()
        with self.assertRaisesRegex(lab.VerificationError, "event count"):
            self.load()

    def test_bootstrap_receipt_identity_mismatch_is_rejected(self):
        self.receipt["process"] = process(11, 100).public()
        self.save()
        with self.assertRaisesRegex(lab.VerificationError, "process identity differs"):
            self.load()

    def test_bootstrap_payload_mismatch_is_rejected(self):
        self.entry["payload_sha256"] = "0" * 64
        self.save()
        with self.assertRaisesRegex(lab.VerificationError, "payload binding"):
            self.load()

    def test_malformed_cleanup_is_rejected(self):
        self.receipt["stages"][0]["cleanup"] = []
        self.save()
        with self.assertRaisesRegex(lab.VerificationError, "invalid phase cleanup"):
            self.load()

    def test_external_receipt_digest_is_required(self):
        with self.assertRaisesRegex(lab.VerificationError, "evidence hash"):
            self.load(receipt_sha256="0" * 64)

    def test_partial_receipt_has_no_deadline_fallback(self):
        self.receipt["complete"] = False
        self.save()
        with self.assertRaisesRegex(lab.VerificationError, "no successful"):
            self.load()

    def test_symlinked_ledger_is_rejected(self):
        path = Path(self.receipt["stages"][0]["cleanup"]["history"]["path"])
        target = path.with_suffix(".saved")
        path.rename(target)
        path.symlink_to(target)
        with self.assertRaises((OSError, lab.VerificationError)):
            self.load()

    def test_generation_changes_after_validation_are_rejected(self):
        result = self.load()
        (self.source / "controller.py").write_bytes(self.controller_raw + b"\n")
        with self.assertRaisesRegex(lab.VerificationError, "generation changed"):
            result.files.recheck()

    def test_scope_replaced_by_symlink_after_validation_is_rejected(self):
        result = self.load()
        retained = self.scope.with_name("retained")
        self.scope.rename(retained)
        self.scope.symlink_to(retained, target_is_directory=True)
        with self.assertRaises((OSError, lab.VerificationError)):
            result.files.recheck()

    def test_hardlinked_clone_root_swap_is_rejected(self):
        replacement = self.scope.with_name("replacement")
        replacement.mkdir()
        # Make links before freezing: all later leaf generations remain equal.
        for path in self.scope.iterdir():
            os.link(path, replacement / path.name)
        result = self.load()
        self.scope.rename(self.scope.with_name("retained"))
        replacement.rename(self.scope)
        with self.assertRaisesRegex(lab.VerificationError, "directory identity changed"):
            result.files.recheck()

    def test_duplicate_json_keys_are_rejected(self):
        with self.assertRaisesRegex(lab.VerificationError, "duplicate JSON"):
            lab.parse_json(b'{"terminal": true, "terminal": false}')


if __name__ == "__main__":
    unittest.main()
