"""Probe cleanup uses real owned processes; debugger observations are synthetic."""
from contextlib import contextmanager
import errno
import importlib.util
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
SPEC = importlib.util.spec_from_file_location(
    "corecrypto_probe_cleanup_test", ROOT / "scripts/probe_route_a_corecrypto.py")
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
from route_a_pacga_probe import run as execution


CHILD = """
import json, os, signal, sys, time
from pathlib import Path
mode, pid_name, ready_name, release_name = sys.argv[1:]
descendant = None
if mode == 'orphan':
    descendant = os.fork()
    if descendant == 0:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        Path(ready_name).write_text(json.dumps({'blocked_signals': sorted(int(n) for n in signal.pthread_sigmask(signal.SIG_BLOCK, []))}))
        time.sleep(30)
        os._exit(0)
else:
    Path(ready_name).write_text(json.dumps({'blocked_signals': sorted(int(n) for n in signal.pthread_sigmask(signal.SIG_BLOCK, []))}))
Path(pid_name).write_text(str(os.getpid()) +
                          ((' ' + str(descendant)) if descendant is not None else ''))
if mode == 'orphan':
    deadline = time.monotonic() + 3
    while not Path(release_name).is_file():
        if time.monotonic() >= deadline:
            os._exit(2)
        time.sleep(.005)
    os._exit(0)
time.sleep(30)
"""


class CallbackLayout(unittest.TestCase):
    # Actual normalized compiler row from the qualified CoreCrypto005 consumer
    # ABI record (2829 bytes, SHA256 6cd8232e032cf96756b427dcd6830855dc106a9f7d3d09d1579cbfb1a70218ae).
    ROW = "336 |   crypto_random_kmem_ctx_size_fn_t random_kmem_ctx_size_fn"

    def test_actual_normalized_compiler_indentation(self):
        record = "0 | struct crypto_functions\n" + self.ROW + "\n| [sizeof=448, align=8]\n"
        self.assertEqual(P.consumer_callback_offset(record), 336)

    def test_horizontal_spacing_keeps_the_same_offset(self):
        for row in (self.ROW.replace("|   ", "| "),
                    "\t336\t|\tcrypto_random_kmem_ctx_size_fn_t\trandom_kmem_ctx_size_fn\t"):
            with self.subTest(row=row):
                self.assertEqual(P.consumer_callback_offset(row), 336)

    def test_missing_ambiguous_or_different_field_is_rejected(self):
        for record in ("", self.ROW + "\n" + self.ROW,
                       self.ROW.replace("crypto_random_kmem_ctx_size_fn_t", "other_fn_t"),
                       self.ROW + "_other", self.ROW.replace("|   ", "|\n   ")):
            with self.subTest(record=record):
                with self.assertRaises(P.build.BuildError):
                    P.consumer_callback_offset(record)

    def test_invalid_slot_offsets_are_rejected(self):
        for offset in ("-8", "335", "337", "448", "456", "336.0"):
            with self.subTest(offset=offset):
                with self.assertRaises(P.build.BuildError):
                    P.consumer_callback_offset(self.ROW.replace("336", offset, 1))

    def test_table_endpoints_are_valid_slots(self):
        for offset in (0, 440):
            with self.subTest(offset=offset):
                self.assertEqual(P.consumer_callback_offset(self.ROW.replace("336", str(offset), 1)), offset)


class ProbeCleanup(unittest.TestCase):
    def assert_absent(self, pids, group):
        with self.assertRaises(ProcessLookupError):
            os.killpg(group, 0)
        for pid in pids:
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def reap_fixture(self, process):
        """Also clean up an old, failing implementation's own fixture group."""
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=2)
        deadline = time.monotonic() + 2
        while True:
            try:
                child, _ = os.waitpid(-process.pid, os.WNOHANG)
                if child:
                    continue
            except ChildProcessError:
                break
            if time.monotonic() >= deadline:
                self.fail("test fixture descendants were not reaped")
            time.sleep(.01)
        with self.assertRaises(ProcessLookupError):
            os.killpg(process.pid, 0)

    @contextmanager
    def fixture(self, mode="live", *, primary=None, fail_teardown=False, spawn_signal=None):
        native_popen, native_open = subprocess.Popen, Path.open
        with tempfile.TemporaryDirectory(prefix="cc-probe-") as tmp, execution.owned_children():
            out = Path(tmp)
            pid_file, ready_file, release_file = (out / name for name in ("pids", "ready", "release"))
            processes, streams, child_masks = [], [], []
            # The socket facade owns a real private FD without opening a host
            # socket: only teardown behavior is under test, never transport.
            socket_handle = tempfile.TemporaryFile()
            closed = []

            class ProbeSocket:
                def connect(self, _endpoint):
                    pass  # No debugger or guest is used by these lifecycle tests.

                def close(self):
                    socket_handle.close()
                    closed.append("socket")
                    if fail_teardown:
                        raise OSError(errno.EIO, "injected socket close failure")

                def __enter__(self):
                    return self

                def __exit__(self, *_args):
                    self.close()

            class LogStream:
                def __init__(self, stream):
                    self.stream = stream
                    streams.append(stream)

                def fileno(self):
                    return self.stream.fileno()

                def close(self):
                    self.stream.close()
                    closed.append("log")
                    if fail_teardown:
                        raise OSError(errno.EIO, "injected log close failure")

                def __enter__(self):
                    return self

                def __exit__(self, *_args):
                    self.close()

            def open_log(path, mode="r", *args, **kwargs):
                stream = native_open(path, mode, *args, **kwargs)
                return LogStream(stream) if path == out / "qemu.stderr.log" and mode == "xb" else stream

            def spawn(_argv, **kwargs):
                # Preserve the production session/stdio/limit choices, replacing
                # only the QEMU command with this test's small Python process.
                process = native_popen([sys.executable, "-c", CHILD, mode, str(pid_file),
                                        str(ready_file), str(release_file)], **kwargs)
                processes.append(process)
                if spawn_signal is not None:
                    deadline = time.monotonic() + 2
                    while True:
                        try:
                            child_masks.append(json.loads(ready_file.read_text())["blocked_signals"])
                            break
                        except (FileNotFoundError, json.JSONDecodeError):
                            pass
                        if time.monotonic() >= deadline:
                            raise RuntimeError("owned spawn-window fixture did not become ready")
                        time.sleep(.005)
                    # Deliver a real signal while the returned process handle
                    # is still inside this Popen wrapper, before caller assignment.
                    os.kill(os.getpid(), spawn_signal)
                return process

            def observed(*_args, **_kwargs):
                deadline = time.monotonic() + 2
                while not pid_file.is_file() or not ready_file.is_file():
                    if time.monotonic() >= deadline:
                        raise RuntimeError("owned fixture did not become ready")
                    time.sleep(.005)
                if mode == "orphan":
                    release_file.write_text("exit")
                    self.assertEqual(processes[0].wait(timeout=2), 0)
                if primary is not None:
                    raise primary

            args = SimpleNamespace(qemu=sys.executable, timeout=5, mode="positive")
            layout = {"physical_base": 0x40000000, "boot_args_pa": 0x52000000}
            prepared = ({}, b"", b"", {}, {}, layout, None)
            report = {}
            summary = {"CurrentEL": 4, "CNTFRQ": 62500000}
            try:
                with patch.object(P.subprocess, "Popen", side_effect=spawn), \
                        patch.object(Path, "open", open_log), \
                        patch.object(P.socket, "socket", return_value=ProbeSocket()), \
                        patch.object(P, "Remote", return_value=object()), \
                        patch.object(P.entry, "observe_entry", return_value={"fixture": "synthetic"}), \
                        patch.object(P, "observe", side_effect=observed), \
                        patch.object(P.entry, "exception_summary", return_value=summary,
                                     side_effect=(OSError(errno.EIO, "injected diagnostic failure")
                                                  if fail_teardown else None)) as diagnostic:
                    yield SimpleNamespace(
                        launch=lambda: P.launch(args, out, P.build.Journal(out), report, prepared),
                        report=report, processes=processes, streams=streams, socket=socket_handle,
                        closed=closed, diagnostic=diagnostic,
                        child_mask=lambda: child_masks[0],
                        pids=lambda: [int(value) for value in pid_file.read_text().split()])
            finally:
                # The outer subreaper is essential for testing the old defect:
                # a failing assertion must not leave its forked worker behind.
                for process in processes:
                    self.reap_fixture(process)
                socket_handle.close()
                for stream in streams:
                    stream.close()

    def test_successful_observation_cleans_and_reaps_the_live_fixture(self):
        with self.fixture() as fixture:
            fixture.launch()
            receipt = fixture.report["qemu"]
            self.assert_absent(fixture.pids(), receipt["pid"])
            self.assertIsNone(receipt["exit_before_termination"])
            self.assertTrue(receipt["reaped"])
            self.assertTrue(receipt["cleanup"]["direct_child_reaped"])
            self.assertTrue(receipt["cleanup"]["group_absent"])
            self.assertEqual(receipt["teardown_errors"], [])
            fixture.diagnostic.assert_called_once()
            self.assertEqual(sorted(fixture.closed), ["log", "socket"])
            self.assertTrue(all(stream.closed for stream in fixture.streams))
            self.assertTrue(fixture.socket.closed)

    def test_exit_zero_with_a_real_orphan_is_rejected_and_the_orphan_is_reaped(self):
        with self.fixture("orphan") as fixture:
            with self.assertRaises(P.build.BuildError):
                fixture.launch()
            parent, descendant = fixture.pids()
            self.assert_absent((parent, descendant), parent)
            receipt = fixture.report["qemu"]
            self.assertEqual(receipt["exit_before_termination"], 0)
            self.assertEqual(receipt["exit"], 0)
            self.assertTrue(receipt["cleanup"]["direct_child_reaped"])
            self.assertTrue(receipt["cleanup"]["group_absent"])
            self.assertIn(descendant, [item["pid"] for item in receipt["cleanup"]["reaped_descendants"]])
            self.assertIn("SIGKILL", receipt["cleanup"]["signals"])

    def test_observation_error_survives_diagnostic_and_both_close_failures(self):
        primary = TimeoutError("injected observer deadline")
        with self.fixture(primary=primary, fail_teardown=True) as fixture:
            with self.assertRaises(TimeoutError) as caught:
                fixture.launch()
            self.assertIs(caught.exception, primary)
            receipt = fixture.report["qemu"]
            self.assert_absent(fixture.pids(), receipt["pid"])
            self.assertTrue(receipt["cleanup"]["direct_child_reaped"])
            self.assertTrue(receipt["cleanup"]["group_absent"])
            notes = "\n".join(primary.__notes__)
            errors = json.dumps(receipt["teardown_errors"])
            for label in ("diagnostic", "socket close", "log close"):
                self.assertIn("injected " + label + " failure", notes)
                self.assertIn("injected " + label + " failure", errors)
            fixture.diagnostic.assert_called_once()
            self.assertEqual(sorted(fixture.closed), ["log", "socket"])
            self.assertTrue(all(stream.closed for stream in fixture.streams))
            self.assertTrue(fixture.socket.closed)

    def test_real_signal_before_popen_handle_assignment_cleans_owned_child(self):
        with self.fixture(spawn_signal=signal.SIGTERM) as fixture:
            previous = signal.getsignal(signal.SIGTERM)
            with self.assertRaisesRegex(InterruptedError, "PACGA fixture interrupted by signal 15"):
                fixture.launch()
            self.assertIs(signal.getsignal(signal.SIGTERM), previous)
            self.assertNotIn(int(signal.SIGTERM), fixture.child_mask())
            self.assertNotIn(int(signal.SIGINT), fixture.child_mask())
            process = fixture.processes[0]
            self.assertIsNotNone(process.poll(), "real child remained alive after launch failed")
            self.assert_absent((process.pid,), process.pid)
            receipt = fixture.report["qemu"]
            self.assertEqual(receipt["pid"], process.pid)
            self.assertTrue(receipt["cleanup"]["direct_child_reaped"])
            self.assertTrue(receipt["cleanup"]["group_absent"])
            self.assertTrue(all(stream.closed for stream in fixture.streams))
            self.assertTrue(fixture.socket.closed)


if __name__ == "__main__":
    unittest.main()
