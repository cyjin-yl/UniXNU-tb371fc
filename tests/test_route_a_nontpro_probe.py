"""Real owned-process failures around synthetic A01 debugger observations."""
from contextlib import contextmanager
import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import probe_route_a_nontpro_fragments as probe


CHILD = """
import json, os, signal, sys, time
from pathlib import Path
mode, pid_name, ready_name, release_name = sys.argv[1:]
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
descendant = None
if mode == 'orphan':
    descendant = os.fork()
    if descendant == 0:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        Path(ready_name).write_text(json.dumps({'blocked': sorted(int(n) for n in signal.pthread_sigmask(signal.SIG_BLOCK, []))}))
        time.sleep(30)
        os._exit(0)
else:
    Path(ready_name).write_text(json.dumps({'blocked': sorted(int(n) for n in signal.pthread_sigmask(signal.SIG_BLOCK, []))}))
Path(pid_name).write_text(str(os.getpid()) + ((' ' + str(descendant)) if descendant else ''))
if mode == 'orphan':
    deadline = time.monotonic() + 3
    while not Path(release_name).exists():
        if time.monotonic() >= deadline:
            os._exit(2)
        time.sleep(.005)
    os._exit(0)
time.sleep(30)
"""


class FixtureLifecycle(unittest.TestCase):
    def assert_absent(self, process, pids):
        self.assertIsNotNone(process.poll())
        with self.assertRaises(ProcessLookupError):
            os.killpg(process.pid, 0)
        for pid in pids:
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def backstop(self, process, descendants):
        # Also clean the real test processes when testing the old defect.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if process.poll() is None:
            process.kill()
        process.wait(timeout=2)
        # With an old implementation there may have been no new session.
        # These PIDs are only the descendants emitted by this test's child.
        for pid in descendants:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + 2
        while True:
            try:
                child, _ = os.waitpid(-process.pid, os.WNOHANG)
                if child:
                    continue
            except ChildProcessError:
                break
            if time.monotonic() >= deadline:
                self.fail("test fixture descendant was not reaped")
            time.sleep(.01)
        for pid in descendants:
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass

    @contextmanager
    def fixture(self, *, mode="live", primary=None, spawn_signal=None, teardown_failures=False,
                incomplete_cleanup=False):
        native_popen, native_open = subprocess.Popen, Path.open
        native_cleanup, native_identity = probe.execution.stop_group, probe.file_identity
        with tempfile.TemporaryDirectory(prefix="a01-probe-") as tmp, probe.execution.owned_children():
            out = Path(tmp)
            pid_file, ready_file, release_file = (out / name for name in ("pids", "ready", "release"))
            processes, streams, closed, child_masks = [], [], [], []
            socket_handle = tempfile.TemporaryFile()

            class Connection:
                def connect(self, _address):
                    pass  # Transport is deliberately outside this test's scope.

                def close(self):
                    socket_handle.close()
                    closed.append("socket")
                    if teardown_failures:
                        raise OSError(errno.EIO, "injected socket close failure")

            class Log:
                def __init__(self, stream):
                    self.stream = stream
                    streams.append(stream)

                def fileno(self):
                    return self.stream.fileno()

                def close(self):
                    self.stream.close()
                    closed.append("log")
                    if teardown_failures:
                        raise OSError(errno.EIO, "injected log close failure")

            def open_log(path, mode="r", *args, **kwargs):
                stream = native_open(path, mode, *args, **kwargs)
                return Log(stream) if path == out / "qemu.log" and mode == "xb" else stream

            def ready():
                deadline = time.monotonic() + 2
                while True:
                    try:
                        pids = [int(value) for value in pid_file.read_text().split()]
                        mask = json.loads(ready_file.read_text())["blocked"]
                        if pids:
                            return pids, mask
                    except (FileNotFoundError, json.JSONDecodeError):
                        pass
                    if time.monotonic() >= deadline:
                        raise RuntimeError("owned test process did not become ready")
                    time.sleep(.005)

            def spawn(_argv, **kwargs):
                process = native_popen([sys.executable, "-c", CHILD, mode, str(pid_file),
                                        str(ready_file), str(release_file)], **kwargs)
                processes.append(process)
                if spawn_signal is not None:
                    _, mask = ready()
                    child_masks.append(mask)
                    # A real signal lands after process creation, before the
                    # production caller can assign the returned Popen handle.
                    os.kill(os.getpid(), spawn_signal)
                return process

            class Remote:
                def __init__(self):
                    self.reads = 0

                def validate_architecture(self):
                    ready()
                    if mode == "orphan":
                        release_file.write_text("exit")
                        processes[0].wait(timeout=2)
                    if primary is not None:
                        raise primary

                def core_registers(self, _record):
                    self.reads += 1
                    return {"pc": probe.BOOT_BASE if self.reads == 1 else probe.COMPLETED,
                            "cpsr": 5 if self.reads == 1 else 0}

                def request(self, packet):
                    return "S05" if packet == "c" else "OK"

            def identity(path):
                if teardown_failures and path == out / "qemu.log":
                    raise OSError(errno.EIO, "injected log identity failure")
                return native_identity(path)

            def cleanup(process):
                result = native_cleanup(process)
                if teardown_failures:
                    raise OSError(errno.EIO, "injected group receipt failure")
                if incomplete_cleanup:
                    result["group_absent"] = False
                return result

            args = SimpleNamespace(qemu=sys.executable, timeout=5)
            source = SimpleNamespace(text=SimpleNamespace(addr=0x1000, size=4),
                                     read=lambda *_: bytes(4))
            cases = [{"observation": None}]
            report = {}
            try:
                with patch.object(probe.subprocess, "Popen", side_effect=spawn), \
                     patch.object(Path, "open", open_log), \
                     patch.object(probe.socket, "socket", return_value=Connection()), \
                     patch.object(probe, "Remote", return_value=Remote()), \
                     patch.object(probe, "memory_read", side_effect=lambda _r, _a, n, _v: bytes(n)), \
                     patch.object(probe, "decode_model_state", return_value={"accepted": 0, "synthetic_model_verified": True}), \
                     patch.object(probe, "check_results", return_value=True), \
                     patch.object(probe, "file_identity", side_effect=identity), \
                     patch.object(probe.execution, "stop_group", side_effect=cleanup):
                    yield SimpleNamespace(launch=lambda: probe.launch(args, out, source, cases, report),
                                          report=report, processes=processes, streams=streams,
                                          socket=socket_handle, closed=closed, ready=ready,
                                          child_mask=lambda: child_masks[0])
            finally:
                for process in processes:
                    pids = [int(value) for value in pid_file.read_text().split()] if pid_file.exists() else []
                    self.backstop(process, pids[1:])
                socket_handle.close()
                for stream in streams:
                    stream.close()

    def test_observation_success_requires_complete_owned_session_cleanup(self):
        with self.fixture() as fixture:
            fixture.launch()
            receipt = fixture.report["qemu"]
            self.assert_absent(fixture.processes[0], fixture.ready()[0])
            self.assertTrue(receipt["cleanup"]["group_absent"])
            self.assertTrue(receipt["cleanup"]["direct_child_reaped"])
            self.assertEqual(receipt["exit_code"], 0)
            self.assertEqual(receipt["teardown_errors"], [])
            self.assertEqual(sorted(fixture.closed), ["log", "socket"])

    def test_real_spawn_signal_retains_and_reaps_the_unassigned_child(self):
        with self.fixture(spawn_signal=signal.SIGTERM) as fixture:
            previous = signal.getsignal(signal.SIGTERM)
            with self.assertRaises(InterruptedError):
                fixture.launch()
            self.assertIs(signal.getsignal(signal.SIGTERM), previous)
            self.assertFalse(set(fixture.child_mask()) & {int(signal.SIGTERM), int(signal.SIGINT)})
            self.assert_absent(fixture.processes[0], fixture.ready()[0])
            self.assertTrue(fixture.report["qemu"]["cleanup"]["group_absent"])
            self.assertTrue(all(stream.closed for stream in fixture.streams))
            self.assertTrue(fixture.socket.closed)

    def test_zero_exit_with_real_orphan_is_rejected_and_descendant_is_reaped(self):
        with self.fixture(mode="orphan") as fixture:
            with self.assertRaisesRegex(probe.AuditError, "exited before owned cleanup"):
                fixture.launch()
            parent, descendant = fixture.ready()[0]
            self.assert_absent(fixture.processes[0], (parent, descendant))
            receipt = fixture.report["qemu"]
            self.assertEqual(receipt["exit_before_termination"], 0)
            self.assertIn(descendant, [row["pid"] for row in receipt["cleanup"]["reaped_descendants"]])

    def test_primary_observation_failure_survives_all_teardown_errors(self):
        primary = TimeoutError("injected observation deadline")
        with self.fixture(primary=primary, teardown_failures=True) as fixture:
            with self.assertRaises(TimeoutError) as caught:
                fixture.launch()
            self.assertIs(caught.exception, primary)
            self.assert_absent(fixture.processes[0], fixture.ready()[0])
            notes = "\n".join(primary.__notes__)
            for name in ("group receipt", "socket close", "log close", "log identity"):
                self.assertIn("injected " + name + " failure", notes)
            self.assertEqual(len(fixture.report["qemu"]["teardown_errors"]), 4)
            self.assertEqual(sorted(fixture.closed), ["log", "socket"])
            self.assertTrue(fixture.socket.closed)
            self.assertTrue(all(stream.closed for stream in fixture.streams))

    def test_observation_does_not_override_an_incomplete_cleanup_receipt(self):
        with self.fixture(incomplete_cleanup=True) as fixture:
            with self.assertRaisesRegex(probe.AuditError, "did not finish cleanup"):
                fixture.launch()
            self.assertTrue(fixture.report["fixture_result_observed"])
            self.assertFalse(fixture.report["qemu"]["cleanup"]["group_absent"])
            self.assert_absent(fixture.processes[0], fixture.ready()[0])


class FailureReceipt(unittest.TestCase):
    def test_final_input_failure_cannot_replace_the_observation_error(self):
        primary = TimeoutError("injected observation failure")
        def recheck():
            raise RuntimeError("injected recheck failure")
        source = SimpleNamespace(identity={}, code_pages={}, starts=[], flat_image=lambda: b"dyld",
                                 recheck=recheck)
        with tempfile.TemporaryDirectory(prefix="a01-receipt-") as tmp:
            root = Path(tmp)
            tool_path = root / "tool"
            tool_path.write_text("tool")
            tool = (str(tool_path), {"invocation": str(tool_path),
                                    "identity": probe.invocation_identity(tool_path), "version": "synthetic"})
            args = SimpleNamespace(timeout=2, output=root / "out", input="dyld", kernel="kernel",
                                   objects="objects", prepared="source", filelist="filelist",
                                   qemu="qemu", clang="clang", lld="lld", objcopy="objcopy")
            with patch.object(probe, "Standalone", return_value=source), \
                 patch.object(probe, "entry_contract", return_value={}), \
                 patch.object(probe, "bind_syscall38", return_value={"inputs": {}}), \
                 patch.object(probe, "selected_tool", return_value=tool), \
                 patch.object(probe, "compile_fixture", side_effect=lambda out, *_: (out / "entry.bin").write_bytes(b"entry")), \
                 patch.object(probe, "build_cases", return_value=(b"inputs", [])), \
                 patch.object(probe, "page_tables", return_value=b"tables"), \
                 patch.object(probe, "launch", side_effect=primary), patch("builtins.print"):
                self.assertEqual(probe.run(args), 2)
            report = json.loads((args.output / "report.json").read_text())
            self.assertEqual(report["error"]["type"], "TimeoutError")
            self.assertEqual(report["error"]["message"], str(primary))
            self.assertIn("injected recheck failure", "\n".join(report["error"]["notes"]))
            for flag in ("fragment_execution_verified", "a01_verified", "actual_xnu_dispatch_verified",
                         "darwin_process_started", "os_boot_verified", "tb371fc_verified"):
                self.assertFalse(report[flag])


if __name__ == "__main__":
    unittest.main()
