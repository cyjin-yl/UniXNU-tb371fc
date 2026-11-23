"""Probe construction and process isolation tests; no foreign ISA runs on x86."""

import hashlib
import json
import os
from pathlib import Path
import signal
import struct
import sys
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from route_a_native_probe import _run_isolated, build_payload, run_probe


class PayloadTests(unittest.TestCase):
    def test_payload_is_stable_and_has_independent_baselines(self):
        first, second = build_payload(), build_payload()
        self.assertEqual(first, second)
        payload = dict(first)
        claimed = payload.pop("payload_sha256")
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        self.assertEqual(claimed, hashlib.sha256(canonical).hexdigest())
        self.assertFalse(first["performance_measurement"])
        self.assertFalse(first["original_pauth_words_executed"])
        self.assertEqual(len(first["cases"]), 23)
        for case in first["cases"]:
            self.assertEqual(len(case["input_words"]), len(case["output_words"]))
            self.assertEqual(case["output_words"], case["baseline_words"])
            self.assertNotEqual(case["input_words"], case["output_words"])
            code = b"".join(struct.pack("<I", int(word, 16)) for word in case["output_words"])
            self.assertEqual(case["output_sha256"], hashlib.sha256(code).hexdigest())

    def test_call_through_x30_has_valid_return_continuation(self):
        case = next(c for c in build_payload()["cases"] if c["name"] == "blraaz_x30_target")
        words = [int(w, 16) for w in case["output_words"]]
        self.assertEqual(words[0], 0xA9BF7BFD)  # STP saves caller LR
        self.assertEqual(words[2], 0xD63F03C0)  # BLR reads old X30
        self.assertEqual(words[3], 0xA8C17BFD)  # continuation restores caller LR
        self.assertEqual(words[4], 0xD65F03C0)  # RET to ctypes caller
        adr = words[1]
        immediate = (((adr >> 5) & 0x7FFFF) << 2) | ((adr >> 29) & 3)
        self.assertEqual(4 + immediate, 5 * 4)  # helper starts at word 5

    def test_data_writeback_cases_check_both_observable_results(self):
        cases = [c for c in build_payload()["cases"] if c["expected"]["writeback_index"] is not None]
        self.assertEqual(len(cases), 4)
        for case in cases:
            self.assertEqual(case["arguments"][1], {"kind": "result"})
            self.assertEqual(case["output_words"][1:3], ["f9000022", "f9000420"])
            index = case["expected"]["writeback_index"]
            self.assertEqual(case["expected"]["return"], case["data_u64"][index])

    def test_non_arm_host_never_enters_native_executor(self):
        fake = {"machine": "x86_64", "pointer_bits": 64, "byteorder": "little"}
        with mock.patch("route_a_native_probe.host_facts", return_value=fake):
            with mock.patch("route_a_native_probe._run_isolated") as isolated:
                report = run_probe()
                isolated.assert_not_called()
        self.assertEqual(report["status"], "unsupported_host")
        self.assertEqual(report["cases"], [])


@unittest.skipUnless(hasattr(os, "fork"), "requires POSIX fork")
class IsolationTests(unittest.TestCase):
    def test_success_and_exception_are_reported(self):
        self.assertEqual(_run_isolated(lambda: {"status": "passed", "actual": 42}, 1),
                         {"status": "passed", "actual": 42})
        def fail():
            raise RuntimeError("probe fixture failure")
        result = _run_isolated(fail, 1)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error_type"], "RuntimeError")

    def test_illegal_instruction_signal_stays_in_child(self):
        def sigill():
            os.kill(os.getpid(), signal.SIGILL)
        result = _run_isolated(sigill, 1)
        self.assertEqual(result["status"], "signal")
        self.assertEqual(result["signal_name"], "SIGILL")

    def test_timeout_kills_and_reaps_child(self):
        result = _run_isolated(lambda: time.sleep(2), 0.05)
        self.assertEqual(result["status"], "timeout")
        with self.assertRaises(ChildProcessError):
            os.waitpid(-1, os.WNOHANG)

    def test_invalid_timeout_is_rejected(self):
        for timeout in (-1, 0, float("inf"), float("nan"), 61):
            with self.assertRaises(ValueError):
                _run_isolated(lambda: {"status": "passed"}, timeout)


if __name__ == "__main__":
    unittest.main()
