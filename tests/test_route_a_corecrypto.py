"""Failure boundaries and independently known vectors; no fixture is a guest boot."""
import copy
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import re
import struct
import tempfile
import time
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


P = module("corecrypto_runtime_test", ROOT / "scripts/probe_route_a_corecrypto.py")
B = P.build


def image():
    base = 0xfffffff007004000
    data = bytearray(128)
    # caller: BL callee; CBNZ W0, +8; NOP; BL panic; NOP; RET
    struct.pack_into("<6I", data, 0, 0x94000010, 0x35000040, 0xd503201f, 0x94000015, 0xd503201f, 0xd65f03c0)
    symbols = [{"name": name, "n_type": 15, "n_desc": 0, "n_sect": 1, "value": base + offset}
               for name, offset in (("_caller", 0), ("_callee", 64), ("_panic", 96))]
    strict = {"metadata": {"symbols": {"records": symbols}, "sections": [
        {"name": "__text", "segment": "__TEXT_EXEC", "addr": base, "offset": 0, "size": len(data), "flags": 0x80000000}]},
        "segments": [{"name": "__TEXT_EXEC", "vmaddr": base, "vmsize": len(data), "fileoff": 0, "filesize": len(data), "initprot": 5}]}
    return strict, bytes(data), base


class SourceContracts(unittest.TestCase):
    def test_output_parent_alias_cannot_put_artifacts_in_the_repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            alias = Path(tmp) / "source"; alias.symlink_to(ROOT, target_is_directory=True)
            with self.assertRaises(B.BuildError): B.fresh(alias / "forbidden-generated-output")
            self.assertFalse((ROOT / "forbidden-generated-output").exists())

    def test_framework_header_directory_retarget_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first, second = root / "first", root / "second"
            first.mkdir(); second.mkdir()
            (first / "api.h").write_text("int api(void);\n")
            (second / "api.h").write_text("void api(int);\n")
            alias = root / "include"; alias.symlink_to(first, target_is_directory=True)
            journal = B.Journal(root); journal.headers((alias,))
            self.assertTrue(journal.recheck()["unchanged"])
            alias.unlink(); alias.symlink_to(second, target_is_directory=True)
            self.assertFalse(journal.recheck()["unchanged"])

    def test_known_digest_hmac_vectors_are_independently_correct(self):
        text = (B.GLUE / "consumer_probe.h").read_text()
        vectors = re.findall(r'\{CRYPTO_DIGEST_ALG_(\w+), (\d+), "([0-9a-f]+)", "([0-9a-f]+)"\}', text)
        self.assertEqual(len(vectors), 5)
        for name, size, digest, tag in vectors:
            with self.subTest(name=name):
                self.assertEqual(int(size), hashlib.new(name.lower()).digest_size)
                self.assertEqual(digest, hashlib.new(name.lower(), b"abc").hexdigest())
                self.assertEqual(tag, hmac.digest(b"key", b"The quick brown fox jumps over the lazy dog", name.lower()).hex())
        for array, expected in (("empty_digests", lambda n: hashlib.new(n).hexdigest()),
                                ("empty_hmacs", lambda n: hmac.digest(b"", b"", n).hex())):
            block = re.search(r"static const char \*" + array + r"\[\] = \{(.*?)\};", text, re.S)[1]
            values = re.findall(r'"([0-9a-f]+)"', block)
            self.assertEqual(values, [expected(name.lower()) for name, *_ in vectors])
        self.assertIn(hmac.digest(bytes([0xaa]) * 131, b"Test Using Larger Than Block-Size Key - Hash Key First", "sha256").hex(), text)

    def test_fixed_namespace_and_unique_13_callback_assignments(self):
        self.assertEqual(B.sha((B.GLUE / "namespace.h").read_bytes()), B.PINS["namespace"])
        text = (B.GLUE / "adapter.h").read_text()
        fields = re.findall(r"^    RA_ASSIGN\((\w+),", text, re.M)
        self.assertEqual(tuple(fields), B.ADDED_FIELDS)
        self.assertEqual(len(set(fields)), 13)
        self.assertIn("__builtin_types_compatible_p", text)

    def test_exact_bootstrap_patch_reconstruction_rejects_context_or_count_drift(self):
        original = b"first\nsecond\nlast\n"
        header = (b"diff --git a/osfmk/prng/prng_random.c b/osfmk/prng/prng_random.c\n"
                  b"index 504b3fa..310719a 100644\n--- a/osfmk/prng/prng_random.c\n+++ b/osfmk/prng/prng_random.c\n")
        patch_bytes = header + b"@@ -2,2 +2,3 @@ context\n second\n last\n+added\n"
        self.assertEqual(B.apply_bootstrap_append(original, patch_bytes), original + b"added\n")
        for bad in (patch_bytes.replace(b" second", b" wrong"), patch_bytes.replace(b"+2,3", b"+2,4"),
                    patch_bytes + b"@@ -1,1 +1,1 @@\n x\n", patch_bytes.replace(b"+added", b"-added")):
            with self.subTest(bad=bad):
                with self.assertRaises(B.BuildError): B.apply_bootstrap_append(original, bad)

    def test_layout_normalizes_only_two_declared_field_aliases(self):
        text = "*** Dumping AST Record Layout\n0 | struct crypto_functions\n8 | const struct ccdigest_info * cc14_ccsha256_di\n[sizeof=448, align=8]\n"
        normalized = B.record_layouts(text)["crypto_functions"]
        self.assertIn("* ccsha256_di", normalized)
        self.assertNotEqual(normalized, B.record_layouts(text.replace("8 |", "16 |"))["crypto_functions"])
        self.assertNotEqual(normalized, B.record_layouts(text.replace("const struct", "struct"))["crypto_functions"])
        self.assertIn("cc14_other", B.record_layouts(text.replace("cc14_ccsha256_di", "cc14_other"))["crypto_functions"])

    def test_overlay_rejects_duplicate_registration_and_existing_adapter_slot(self):
        assignments = "\n".join(f"    kpis.field{i} = &callback{i};" for i in range(43))
        provider = ('#include <libkern/crypto/register_crypto.h>\n' + assignments + '\n    register_crypto_functions(&kpis);').encode()
        bootstrap = b'void f(void) {\n\tif (bad) {\n\t\tpanic("source corecrypto initialization failed: %d", source_corecrypto14_status);\n\t}\n}\n'
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            result = B.prepare_overlay(provider, bootstrap, directory)
            self.assertEqual(result["assignment_types_asserted"], 56)
            generated = (directory / "corecrypto_kext.c").read_text()
            self.assertLess(generated.index("route_a_complete_crypto_table(&kpis)"), generated.index("register_crypto_functions(&kpis)"))
            self.assertEqual((directory / "prng_random.c").read_text().count("route_a_crypto_consumer_check();"), 1)
            for bad in (provider + b"\n    register_crypto_functions(&kpis);", provider.replace(b"field0 =", b"digest_fn =")):
                with self.assertRaises(B.BuildError): B.prepare_overlay(bad, bootstrap, directory)


class MachineContracts(unittest.TestCase):
    def test_real_owned_subprocess_timeout_is_terminated_and_reaped(self):
        with tempfile.TemporaryDirectory() as tmp:
            journal = B.Journal(Path(tmp))
            with self.assertRaises(subprocess.TimeoutExpired):
                journal.execute([sys.executable, "-c", "import time; time.sleep(30)"], "timeout", timeout=.03)
            self.assertTrue(journal.commands[0]["reaped"])
            self.assertLess(journal.commands[0]["exit"], 0)
            self.assertTrue((Path(tmp) / "commands.json").is_file())

    def test_real_bl_resolution_and_duplicate_or_wrong_target_rejected(self):
        strict, data, base = image()
        found = P.call_return(strict, data, "_caller", "_callee")
        self.assertEqual(found["va"], base + 4)
        changed = bytearray(data); struct.pack_into("<I", changed, 8, 0x9400000e)
        with self.assertRaises(B.BuildError): P.call_return(strict, bytes(changed), "_caller", "_callee")
        changed = bytearray(data); struct.pack_into("<I", changed, 0, 0x14000010)
        with self.assertRaises(B.BuildError): P.call_return(strict, bytes(changed), "_caller", "_callee")

    def test_code_extent_and_strong_symbol_checks_are_not_skipped(self):
        strict, data, base = image()
        for mutation in (lambda s: s["metadata"]["symbols"]["records"][0].update(n_type=0x2f),
                         lambda s: s["metadata"]["symbols"]["records"][0].update(n_desc=0x80),
                         lambda s: s["segments"][0].update(initprot=1),
                         lambda s: s["segments"][0].update(filesize=2)):
            current = copy.deepcopy(strict); mutation(current)
            with self.assertRaises(B.BuildError): B.symbol_span(current, data, "_caller", 4, executable=True)

    def test_captured_blr_lr_requires_the_actual_unchanged_operand(self):
        strict, data, base = image(); changed = bytearray(data)
        struct.pack_into("<I", changed, 0, 0xd63f0100)  # BLR X8
        target = B.symbol_span(strict, data, "_callee", 4, executable=True)
        regs = {"x30": base + 4, "x8": target["va"]}
        self.assertEqual(P.return_from_entry(strict, changed, regs, target)["va"], base + 4)
        with self.assertRaises(B.BuildError): P.return_from_entry(strict, changed, {**regs, "x8": base}, target)
        struct.pack_into("<I", changed, 0, 0xd63f03c0)  # BLR X30 destroys its operand
        with self.assertRaises(B.BuildError): P.return_from_entry(strict, changed, regs, target)

    def test_deadline_before_send_prevents_continue_and_cleanup_packets(self):
        connection = SimpleNamespace(sendall=lambda data: self.fail("packet sent after deadline"))
        remote = P.Remote(connection, time.monotonic() - 1)
        for command in ("c", "Z1,1234,4", "z1,1234,4", "m1234,8"):
            with self.assertRaises(B.BuildError): remote.send(command)

    def test_bounded_state_read_retains_error_and_does_not_accept_short_reply(self):
        strict, data, base = image()
        remote = SimpleNamespace(deadline=time.monotonic() + 2, request=lambda command: "00")
        report = {}; observer = P.Observe(remote, strict, data, {}, report)
        with self.assertRaises(B.BuildError): observer.read({"va": base, "size": 8}, "state")
        self.assertEqual(report["reads"][0]["bytes_read"], 1)
        self.assertEqual(report["reads"][0]["status"], "read-error")

    def test_runtime_failure_or_input_change_revokes_all_qualification_gates(self):
        for change in (False, True):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp) / "out"
                args = SimpleNamespace(output=output, mode="positive", timeout=2)
                def launch(args, out, journal, report, prepared):
                    report.update(dict.fromkeys(P.FLAGS, True))
                    if not change: raise ValueError("later failure")
                with patch.object(P, "prepare", return_value=None), patch.object(P, "launch", launch), \
                     patch.object(P.build.Journal, "recheck", return_value={"unchanged": not change, "changes": ["x"] if change else []}):
                    report = P.run(args)
                self.assertEqual(report["status"], "failed")
                self.assertFalse(any(report[name] for name in P.FLAGS))
                self.assertFalse(report["os_boot_verified"])


if __name__ == "__main__": unittest.main()
