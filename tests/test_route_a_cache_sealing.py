"""Final-phase failures cannot discard diagnostics or publish an unsealed proof."""
from contextlib import redirect_stderr
from copy import deepcopy
import errno
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_route_a_proof import cache_bytes, module


class FinalSealingTests(unittest.TestCase):
    def exercise_failure(self, mode, *, receipt_failure=None):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache, work = root / "cache", root / "proof"
            cache.write_bytes(cache_bytes())
            driver = module("prove-zeta-dyld-cache")
            original_seal, original_publish = driver.seal_summary, driver.publish_record
            original_dump = driver.json.dump
            timeout = subprocess.TimeoutExpired(["llvm-mc", "--version"], 60)
            failure = ValueError("cannot identify llvm-mc decoder: synthetic late timeout")
            partial_attempts = []

            def seal(*args, **kwargs):
                if mode == "decoder":
                    raise failure from timeout
                result = original_seal(*args, **kwargs)
                field = "rules" if mode == "rules" else "source_manifest"
                result[field] = {"injected_drift": True}
                return result

            def publish(path, record):
                if path.name == "partial.json":
                    partial_attempts.append(deepcopy(record))
                return original_publish(path, record)

            def dump(record, stream, **kwargs):
                if Path(stream.name).name == "partial.tmp" and (
                        receipt_failure == "persistent" or
                        receipt_failure == "transient" and len(partial_attempts) == 1):
                    stream.write('{"injected_incomplete_record":')
                    stream.flush()
                    raise OSError(errno.ENOSPC, "injected mid-write receipt storage exhaustion")
                return original_dump(record, stream, **kwargs)

            stderr = io.StringIO()
            with patch.dict(sys.modules, {driver.__name__: driver}), \
                 patch.object(driver, "seal_summary", side_effect=seal), \
                 patch.object(driver, "publish_record", side_effect=publish), \
                 patch.object(driver.json, "dump", side_effect=dump), \
                 redirect_stderr(stderr):
                with self.assertRaises(ValueError) as caught:
                    driver.main(["--cache", str(cache), "--work", str(work), "--jobs", "1"])
            if mode == "decoder":
                self.assertIs(caught.exception, failure)
                self.assertIs(caught.exception.__cause__, timeout)
            else:
                expected = "rules changed" if mode == "rules" else "input bytes or inventory changed"
                self.assertIn(expected, str(caught.exception))
            self.assertFalse((work / "summary.json").exists())
            self.assertFalse((work / "partial.tmp").exists())
            self.assertEqual(driver.STATE, {})
            self.assertEqual(len(list(work.glob("*.own.done.json"))), 1)
            self.assertEqual(len(list(work.glob("*.npz"))), 1)
            self.assertTrue(partial_attempts)
            record = partial_attempts[0]
            self.assertEqual(record["phase"], "sealing")
            self.assertEqual(record["error"], "ValueError")
            self.assertFalse(record["complete"])
            self.assertEqual(record["completed_phases"], {"own roots": [0]})
            self.assertEqual(record["closure_round_count"], 0)
            self.assertIn("unproven", record["totals"])
            for name, key in (("initial-input.json", "input_sha256"),
                              ("initial-rules.json", "rules_sha256")):
                initial = json.loads((work / name).read_text())
                self.assertEqual(record[key], driver.json_digest(initial))
            self.assertEqual(record["error_message"], str(caught.exception))
            if receipt_failure:
                self.assertEqual(len(partial_attempts), 2)
                self.assertEqual(partial_attempts[0], partial_attempts[1])
                self.assertIn("partial receipt write failed during sealing", stderr.getvalue())
            if receipt_failure == "persistent":
                self.assertFalse((work / "partial.json").exists())
            else:
                self.assertEqual(json.loads((work / "partial.json").read_text()), record)

    def test_late_decoder_timeout_preserves_completed_work_and_primary_cause(self):
        self.exercise_failure("decoder")

    def test_late_rules_and_input_drift_still_reject_publication(self):
        for mode in ("rules", "input"):
            with self.subTest(mode=mode):
                self.exercise_failure(mode)

    def test_transient_final_receipt_enospc_retries_the_same_diagnostic(self):
        self.exercise_failure("decoder", receipt_failure="transient")

    def test_persistent_final_receipt_enospc_does_not_replace_decoder_failure(self):
        self.exercise_failure("decoder", receipt_failure="persistent")


class AtomicReceiptFailureTests(unittest.TestCase):
    def exercise_close_failure(self, *, write_failure=False):
        driver = module("prove-zeta-dyld-cache")
        first = OSError(errno.ENOSPC, "first write failure")
        second = OSError(errno.EIO, "buffered close failure")
        original_open = Path.open
        opened = []

        class ClosingFailure:
            def __init__(self, stream):
                self.stream, self.close_count = stream, 0

            def __getattr__(self, name):
                return getattr(self.stream, name)

            def close(self):
                self.close_count += 1
                self.stream.close()
                raise second

        def open_with_close_failure(path, *args, **kwargs):
            stream = ClosingFailure(original_open(path, *args, **kwargs))
            opened.append(stream)
            return stream

        original_dump = driver.json.dump

        def dump(record, stream, **kwargs):
            if write_failure:
                stream.write('{"incomplete":')
                raise first
            return original_dump(record, stream, **kwargs)

        record = {"complete": False, "phase": "sealing"}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "partial.json"
            with patch.object(Path, "open", autospec=True, side_effect=open_with_close_failure), \
                 patch.object(driver.json, "dump", side_effect=dump):
                with self.assertRaises(OSError) as caught:
                    driver.publish_record(path, record)
            self.assertIs(caught.exception, first if write_failure else second)
            self.assertEqual(len(opened), 1)
            self.assertEqual(opened[0].close_count, 1)
            self.assertTrue(opened[0].stream.closed)
            self.assertFalse(path.with_suffix(".tmp").exists())
            self.assertFalse(path.exists())
            driver.publish_record(path, record)
            self.assertEqual(json.loads(path.read_text()), record)

    def test_write_and_close_failure_retains_the_original_write_error(self):
        self.exercise_close_failure(write_failure=True)

    def test_close_failure_cleans_its_temporary_and_allows_retry(self):
        self.exercise_close_failure()

    def test_preexisting_temporary_is_preserved(self):
        driver = module("prove-zeta-dyld-cache")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "partial.json"
            temporary = path.with_suffix(".tmp")
            temporary.write_text("preexisting owner")
            with self.assertRaises(FileExistsError):
                driver.publish_record(path, {"complete": False})
            self.assertEqual(temporary.read_text(), "preexisting owner")
            self.assertFalse(path.exists())

    def test_midwrite_failure_preserves_a_replaced_temporary(self):
        driver = module("prove-zeta-dyld-cache")
        failure = OSError(errno.ENOSPC, "injected mid-write failure")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "partial.json"
            temporary = path.with_suffix(".tmp")

            def dump(record, stream, **kwargs):
                temporary.unlink()
                temporary.write_text("replacement owner")
                raise failure

            with patch.object(driver.json, "dump", side_effect=dump):
                with self.assertRaises(OSError) as caught:
                    driver.publish_record(path, {"complete": False})
            self.assertIs(caught.exception, failure)
            self.assertEqual(temporary.read_text(), "replacement owner")
            self.assertFalse(path.exists())

    def test_cleanup_failure_does_not_mask_the_write_failure(self):
        driver = module("prove-zeta-dyld-cache")
        failure = OSError(errno.ENOSPC, "primary write failure")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "partial.json"
            with patch.object(driver.json, "dump", side_effect=failure), \
                 patch.object(Path, "unlink", side_effect=PermissionError("cleanup denied")):
                with self.assertRaises(OSError) as caught:
                    driver.publish_record(path, {"complete": False})
            self.assertIs(caught.exception, failure)
            self.assertTrue(path.with_suffix(".tmp").exists())
            self.assertFalse(path.exists())

    def test_failed_rename_cleans_its_temporary_and_allows_retry(self):
        driver = module("prove-zeta-dyld-cache")
        failure = OSError(errno.ENOSPC, "rename failure")
        record = {"complete": False, "phase": "sealing"}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "partial.json"
            with patch.object(Path, "replace", side_effect=failure):
                with self.assertRaises(OSError) as caught:
                    driver.publish_record(path, record)
            self.assertIs(caught.exception, failure)
            self.assertFalse(path.with_suffix(".tmp").exists())
            self.assertFalse(path.exists())
            driver.publish_record(path, record)
            self.assertEqual(json.loads(path.read_text()), record)


if __name__ == "__main__":
    unittest.main()
