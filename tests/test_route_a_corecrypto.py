"""Failure boundaries and independently known vectors; no fixture is a guest boot."""
import copy
import errno
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
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
    def reap_fixture_group(self, group):
        """Keep even a failing regression from leaving its own fixture process."""
        if group is None: return
        try: os.killpg(group, signal.SIGKILL)
        except ProcessLookupError: pass
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try: reaped, _ = os.waitpid(-group, os.WNOHANG)
            except ChildProcessError: break
            if not reaped: time.sleep(.01)
        with self.assertRaises(ProcessLookupError): os.killpg(group, 0)

    def test_real_owned_subprocess_timeout_is_terminated_and_reaped(self):
        with tempfile.TemporaryDirectory() as tmp:
            journal = B.Journal(Path(tmp))
            with self.assertRaises(subprocess.TimeoutExpired):
                journal.execute([sys.executable, "-c", "import time; time.sleep(30)"], "timeout", timeout=.03)
            self.assertTrue(journal.commands[0]["reaped"])
            self.assertLess(journal.commands[0]["exit"], 0)
            self.assertTrue(journal.commands[0]["cleanup"]["group_absent"])
            self.assertTrue(journal.commands[0]["cleanup"]["direct_child_reaped"])
            self.assertTrue((Path(tmp) / "commands.json").is_file())

    def test_successful_command_records_an_already_absent_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            journal = B.Journal(Path(tmp))
            for label in ("first", "second"):
                self.assertEqual(journal.execute([sys.executable, "-c", "print('finished')"], label),
                                 b"finished\n")
                receipt = journal.commands[-1]
                self.assertTrue(receipt["group_absent_after_wait"])
                self.assertTrue(receipt["cleanup"]["group_absent"])
                self.assertEqual(receipt["cleanup"]["signals"], [])
                self.assertEqual(receipt["cleanup"]["direct_exit_code"], 0)

    def test_real_forked_worker_is_reaped_on_orphan_timeout_and_signal(self):
        from route_a_pacga_probe import run as execution
        child_source = """
import os, signal, sys, time
from pathlib import Path
mode, pid_name, ready_name = sys.argv[1:]
descendant = os.fork()
if descendant == 0:
    if mode == 'orphan':
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    Path(ready_name).write_text('ready')
    while True:
        time.sleep(30)
deadline = time.monotonic() + 2
while not Path(ready_name).is_file():
    if time.monotonic() >= deadline:
        os._exit(2)
    time.sleep(.005)
Path(pid_name).write_text(str(os.getpid()) + ' ' + str(descendant))
if mode == 'orphan':
    os._exit(0)
if mode == 'signal':
    os.kill(os.getppid(), signal.SIGTERM)
time.sleep(30)
"""
        for mode, expected in (("orphan", B.BuildError), ("timeout", subprocess.TimeoutExpired),
                               ("signal", InterruptedError)):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp)
                pid_file, ready_file = output / "fixture.pids", output / "fixture.ready"
                journal = B.Journal(output)
                # The outer subreaper is also test cleanup for the pre-fix
                # implementation: a failed assertion must not leave its orphan.
                with execution.owned_children():
                    try:
                        with self.assertRaises(expected):
                            journal.execute([sys.executable, "-c", child_source, mode,
                                             str(pid_file), str(ready_file)], mode, timeout=3)
                        parent, descendant = map(int, pid_file.read_text().split())
                        receipt = journal.commands[0]
                        self.assertEqual(receipt["pid"], parent)
                        self.assertFalse(receipt["group_absent_after_wait"])
                        self.assertTrue(receipt["cleanup"]["group_absent"])
                        self.assertTrue(receipt["cleanup"]["direct_child_reaped"])
                        self.assertIn(descendant, [item["pid"] for item in receipt["cleanup"]["reaped_descendants"]])
                        if mode == "orphan":
                            self.assertEqual(receipt["exit"], 0)
                            self.assertIn("SIGKILL", receipt["cleanup"]["signals"])
                        with self.assertRaises(ProcessLookupError): os.killpg(parent, 0)
                        for pid in (parent, descendant):
                            with self.assertRaises(ProcessLookupError): os.kill(pid, 0)
                        disk = json.loads((output / "commands.json").read_text())
                        self.assertEqual(disk[0]["cleanup"], receipt["cleanup"])
                        with self.assertRaisesRegex(B.BuildError, "after a failed journal command"):
                            journal.execute([sys.executable, "-c", "pass"], "must-not-start")
                        self.assertEqual(len(journal.commands), 1)
                        self.assertFalse((output / "must-not-start.stdout").exists())
                    finally:
                        if pid_file.is_file():
                            self.reap_fixture_group(int(pid_file.read_text().split()[0]))

    def test_group_probe_failure_still_cleans_the_live_owned_process(self):
        from route_a_pacga_probe import run as execution
        original_killpg = os.killpg
        injected = False

        def fail_probe_once(group, sig):
            nonlocal injected
            if sig == 0 and not injected:
                injected = True
                raise OSError(errno.EIO, "injected group probe failure")
            return original_killpg(group, sig)

        with tempfile.TemporaryDirectory() as tmp, execution.owned_children():
            journal = B.Journal(Path(tmp))
            try:
                with patch.object(B.os, "killpg", side_effect=fail_probe_once), \
                        patch.object(execution, "stop_group", wraps=execution.stop_group) as cleanup:
                    with self.assertRaises(subprocess.TimeoutExpired) as caught:
                        journal.execute([sys.executable, "-c", "import time; time.sleep(30)"],
                                        "probe-failure", timeout=.03)
                cleanup.assert_called_once()
                self.assertTrue(injected)
                self.assertTrue(journal.commands[0]["cleanup"]["group_absent"])
                self.assertIn("group-probe", "\n".join(caught.exception.__notes__))
                self.assertTrue(journal.failed)
            finally:
                self.reap_fixture_group(journal.commands[0].get("pid"))

    def test_pid_or_cleanup_receipt_failure_preserves_the_primary_exception(self):
        from route_a_pacga_probe import run as execution
        original_save = B.save
        for mode in ("timeout-receipt", "pid-receipt"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp, execution.owned_children():
                journal = B.Journal(Path(tmp))
                calls = 0

                def fail_receipt(path, value):
                    nonlocal calls
                    calls += 1
                    if calls >= (2 if mode == "pid-receipt" else 3):
                        raise OSError(errno.ENOSPC, "injected " + ("PID receipt" if calls == 2 else "cleanup receipt"))
                    return original_save(path, value)

                expected = OSError if mode == "pid-receipt" else subprocess.TimeoutExpired
                try:
                    with patch.object(B, "save", side_effect=fail_receipt):
                        with self.assertRaises(expected) as caught:
                            journal.execute([sys.executable, "-c", "import time; time.sleep(30)"],
                                            mode, timeout=.03)
                    if mode == "pid-receipt":
                        self.assertEqual(caught.exception.errno, errno.ENOSPC)
                        self.assertIn("PID receipt", str(caught.exception))
                    self.assertIn("cleanup receipt", "\n".join(caught.exception.__notes__))
                    self.assertTrue(journal.commands[0]["cleanup"]["group_absent"])
                    self.assertTrue(journal.commands[0]["cleanup"]["direct_child_reaped"])
                    self.assertTrue(journal.failed)
                finally:
                    self.reap_fixture_group(journal.commands[0].get("pid"))

    def test_stream_close_failure_preserves_timeout_and_closes_both_logs(self):
        from route_a_pacga_probe import run as execution
        original_open = Path.open
        closed, streams = [], []

        class FailingClose:
            def __init__(self, stream, label):
                self.stream, self.label = stream, label
                streams.append(stream)
            def fileno(self): return self.stream.fileno()
            def close(self):
                self.stream.close()
                closed.append(self.label)
                if self.label == "stdout":
                    raise OSError(errno.EIO, "injected stdout close failure")

        def wrapped_open(path, mode="r", *args, **kwargs):
            stream = original_open(path, mode, *args, **kwargs)
            if mode == "xb" and path.suffix in (".stdout", ".stderr"):
                return FailingClose(stream, path.suffix[1:])
            return stream

        with tempfile.TemporaryDirectory() as tmp, execution.owned_children():
            journal = B.Journal(Path(tmp))
            try:
                with patch.object(Path, "open", new=wrapped_open):
                    with self.assertRaises(subprocess.TimeoutExpired) as caught:
                        journal.execute([sys.executable, "-c", "import time; time.sleep(30)"],
                                        "close-failure", timeout=.03)
                self.assertEqual(closed, ["stdout", "stderr"])
                self.assertTrue(all(stream.closed for stream in streams))
                self.assertIn("stdout-close", "\n".join(caught.exception.__notes__))
                self.assertTrue(journal.commands[0]["cleanup"]["group_absent"])
                self.assertEqual(journal.commands[0]["teardown_errors"][0]["phase"], "stdout-close")
                self.assertTrue(journal.failed)
            finally:
                self.reap_fixture_group(journal.commands[0].get("pid"))

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


class CoreCryptoReviewRegressions(unittest.TestCase):
    """Synthetic receipts exercise the verifier; they never claim a real build."""
    def test_reproduction_requires_independent_successful_compile_receipts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            compiler = root / "fixture-clang"; compiler.write_bytes(b"fixed compiler fixture\n")
            compiler_record = B.loader.platform_link.tool_identity(compiler)
            archive = root / "source.tar.gz"; archive.write_bytes(b"fixed source fixture\n")
            archive_record = B.loader.identity(archive)
            header = root / "external.h"; header.write_text("/* original unused header */\n")
            header_original = header.read_bytes()
            platform = root / "platform"; platform.mkdir()
            originals = []
            for name in ("cpu.o", "prng_random.o", "sleh.o"):
                path = platform / name; path.write_bytes(("original " + name).encode())
                originals.append(B.loader.identity(path))
            callback = platform / "cpu.callback.o"; callback.write_bytes(b"retained CPU callback")
            callback_record = B.loader.identity(callback)
            baseline_members = [callback_record, *originals[1:]]
            original_filelist = platform / "link.filelist"
            original_filelist.write_text("".join(item["path"] + "\n" for item in originals))
            platform_filelist = platform / "platform-link.filelist"
            platform_filelist.write_text("".join(item["path"] + "\n" for item in baseline_members))
            inventory = platform / "inventory.json"
            inventory.write_text(json.dumps([*originals, callback_record]))
            baseline = {"commands": [{"argv": [str(compiler), "--fixture-link", "-filelist", str(platform_filelist),
                                                  "-o", str(platform / "kernel"), "-Wl,-map," + str(platform / "platform.map")], "cwd": str(platform)}],
                        "protected_input_inventory": B.loader.identity(inventory),
                        "kernel_callback": {"filelist_replacement": {
                            "original_filelist": B.loader.identity(original_filelist),
                            "platform_filelist": B.loader.identity(platform_filelist),
                            "line_index": 0, "original_entry": originals[0]["path"],
                            "replacement_entry": str(callback), "replacement_count": 1}}}
            baseline_path = platform / "report.json"; baseline_path.write_text(json.dumps(baseline))
            baseline_record = B.loader.identity(baseline_path)
            baseline_inputs = [*originals, callback_record, B.loader.identity(original_filelist),
                               B.loader.identity(platform_filelist), B.loader.identity(inventory), baseline_record]

            def synthetic_seal(raw):
                # This receipt fixture tests binding/replay, not Mach-O parsing,
                # static-if instructions or actual provider integrity execution.
                sealed = b"synthetic sealed bytes:" + raw
                return sealed, {"input_sha256": B.sha(raw), "kernel_sha256": B.sha(sealed), "fixture": True}


            def make_build(name):
                output = root / name; output.mkdir()
                glue = output / "glue"; glue.mkdir()
                source = glue / "prng_random.c"; source.write_text("int bootstrap;\n")
                bootstrap = output / "bootstrap/prng_random.o"; bootstrap.parent.mkdir()
                bootstrap.write_bytes(b"bootstrap object fixture")
                inputs = [compiler_record, B.loader.identity(header), B.loader.identity(source), *baseline_inputs]
                commands = []
                def command(source, obj):
                    dependency = obj.with_suffix(".d")
                    dependency.write_text(str(obj) + ": " + str(source) + " " + str(header) + "\n")
                    return ({"argv": [str(compiler), "-include", str(header), "-c", str(source), "-o", str(obj),
                                      "-MD", "-MF", str(dependency), "-I" + str(glue),
                                      "-ffile-prefix-map=" + str(output) + "=route-a-corecrypto",
                                      "-fdebug-prefix-map=" + str(output / "sources") + "=sources",
                                      "-fmacro-prefix-map=" + str(output) + "=macros"],
                             "cwd": str(output), "environment": {"TMPDIR": str(output), "LANG": "C"},
                             "exit": 0, "reaped": True},
                            {"dependency_file": B.loader.identity(dependency), "input_count": 2})
                bootstrap_command, bootstrap_dependencies = command(source, bootstrap)
                commands.append(bootstrap_command)
                objects = []
                for index in range(529):
                    relative = "corecrypto_kext/corecrypto_kext.c" if index == 0 else f"cc/src/input-{index:03d}.c"
                    source = glue / "corecrypto_kext.c" if index == 0 else output / B.SOURCE_ROOT / relative
                    source.parent.mkdir(parents=True, exist_ok=True)
                    source.write_text(f"int source_{index};\n")
                    source_record = B.loader.identity(source); inputs.append(source_record)
                    obj = output / f"objects/input-{index:03d}.o"; obj.parent.mkdir(exist_ok=True)
                    obj.write_bytes(f"object fixture {index}".encode())
                    compile_command, dependencies = command(source, obj)
                    objects.append({"source": relative, "source_sha256": source_record["sha256"],
                                    "object": B.loader.identity(obj), "dependencies": dependencies})
                    commands.append(compile_command)
                commands.append({"argv": [str(compiler), "--fixture-archive", str(output / "archive"),
                                           "-Wl,-map," + str(output / "platform.map"),
                                           "-Wl,-oso_prefix," + str(output) + "/"],
                                 "cwd": str(output), "environment": {"TMPDIR": str(output), "LANG": "C"},
                                 "exit": 0, "reaped": True})
                manifest = output / "objects.jsonl"
                manifest.write_text("".join(json.dumps(item) + "\n" for item in objects))
                report = {"schema": "route-a-corecrypto-build-v1", "build_verified": True,
                          "input_recheck": {"unchanged": True}, "source_revision": B.SOURCE_REVISION,
                          "compiled_c_sources": 529, "source_archive": archive_record,
                          "deterministic_environment": {"SOURCE_DATE_EPOCH": B.SOURCE_DATE_EPOCH},
                          "object_manifest": B.loader.identity(manifest), "bootstrap": B.loader.identity(bootstrap),
                          "bootstrap_dependencies": bootstrap_dependencies, "commands": commands, "inputs": inputs}
                for key in ("archive", "kernel", "loaded_image"):
                    artifact = output / key; artifact.write_bytes((key + " fixture").encode())
                    report[key] = B.loader.identity(artifact)
                layouts = {name: "0 | struct " + name + "\n0 | int fixture\n[sizeof=4, align=4]\n"
                           for name in B.ABI_RECORDS}
                abi = {"matches": True, "mismatches": [], "records": {
                    name: {side: B.sha(text.encode()) for side in ("provider", "consumer")}
                    for name, text in layouts.items()}, "normalization": "synthetic fixture"}
                report["abi"] = abi
                report["abi_outputs"] = {}
                for side in ("provider", "consumer"):
                    path = output / ("abi-" + side + ".stdout")
                    path.write_text("".join("*** Dumping AST Record Layout\n" + text for text in layouts.values()))
                    record = B.loader.identity(path); report["abi_outputs"][side] = record
                    commands.append({"argv": [str(compiler), "-Xclang", "-fdump-record-layouts-complete", "-fsyntax-only"],
                                     "cwd": str(output), "environment": {"TMPDIR": str(output), "LANG": "C"},
                                     "exit": 0, "reaped": True, "stdout": record})
                abi_path = output / "abi.json"; abi_path.write_text(json.dumps(abi))
                report["abi_receipt"] = B.loader.identity(abi_path)
                unsealed = output / "kernel.unsealed.macho"; unsealed.write_bytes(b"fixed synthetic link output")
                sealed, seal = synthetic_seal(unsealed.read_bytes())
                (output / "kernel").write_bytes(sealed); report["kernel"] = B.loader.identity(output / "kernel")
                seal_path = output / "seal.json"; seal_path.write_text(json.dumps(seal))
                report["seal"] = seal; report["seal_receipt"] = B.loader.identity(seal_path)
                members = [callback_record, report["bootstrap"], originals[2]]
                generated = output / "platform.filelist"
                generated.write_text("".join(item["path"] + "\n" for item in members))
                report["link_contract"] = {"schema": "route-a-corecrypto-ordered-link-v1",
                    "baseline_report": baseline_record, "baseline_filelist": B.loader.identity(platform_filelist),
                    "original_members": baseline_members, "ordered_members": members,
                    "substitutions": [{"index": 1, "kind": "bootstrap", "old": originals[1], "new": report["bootstrap"]}],
                    "filelist": B.loader.identity(generated), "provider_archive": report["archive"],
                    "unsealed_kernel": B.loader.identity(unsealed)}
                inputs.extend([report["bootstrap"], report["archive"], report["abi_receipt"], report["seal_receipt"],
                               B.loader.identity(unsealed), B.loader.identity(generated)])
                commands.append({"argv": [str(compiler), "--fixture-link", "-filelist", str(generated),
                                          "-o", str(unsealed), "-Wl,-map," + str(output / "platform.map"),
                                          "-Wl,-oso_prefix," + str(output) + "/", report["archive"]["path"]],
                                 "cwd": str(platform), "environment": {"TMPDIR": str(output), "LANG": "C"},
                                 "exit": 0, "reaped": True})
                for entry in commands:
                    entry.update(group_absent_after_wait=True,
                                 cleanup={"group_absent": True, "direct_child_reaped": True,
                                          "direct_exit_code": 0}, teardown_errors=[])
                receipt = output / "report.json"; receipt.write_text(json.dumps(report))
                return receipt, report

            first_path, first = make_build("first")
            second_path, second = make_build("second")
            mutable_paths = [second_path.parent / name for name in ("platform.filelist", "abi-consumer.stdout", "seal.json")]
            preserved_artifacts = {path: path.read_bytes() for path in mutable_paths}
            with patch.dict(B.PINS, {"archive": archive_record["sha256"], "compiler": compiler_record["sha256"],
                                    "platform_report": baseline_record["sha256"]}), \
                    patch.object(B.loader.platform_link, "FILELIST_SHA256", B.sha(original_filelist.read_bytes())), \
                    patch.object(B.loader.platform_link, "FILELIST_OBJECT_COUNT", 3), \
                    patch.object(B, "seal_kernel", side_effect=synthetic_seal):
                self.assertTrue(B.compare_builds(first_path, second_path)["verified"])
                def changed_external_input(report):
                    header.write_text("/* changed unused header; artifacts are identical */\n")
                    report["inputs"][1] = B.loader.identity(header)
                def changed_filelist(report):
                    path = Path(report["link_contract"]["filelist"]["path"])
                    lines = path.read_text().splitlines(keepends=True)
                    path.write_text("".join(reversed(lines)))
                    identity = B.loader.identity(path)
                    report["link_contract"]["filelist"] = identity
                    for index, record in enumerate(report["inputs"]):
                        if record["path"] == str(path): report["inputs"][index] = identity
                def changed_abi_output(report):
                    previous = report["abi_outputs"]["consumer"]
                    path = Path(previous["path"]); path.write_text(path.read_text().replace("0 | int fixture", "8 | int fixture", 1))
                    identity = B.loader.identity(path)
                    report["abi_outputs"]["consumer"] = identity
                    for command in report["commands"]:
                        if command.get("stdout") == previous: command["stdout"] = identity
                def changed_seal_receipt(report):
                    path = Path(report["seal_receipt"]["path"])
                    report["seal"]["input_sha256"] = "0" * 64
                    path.write_text(json.dumps(report["seal"]))
                    identity = B.loader.identity(path); report["seal_receipt"] = identity
                    for index, record in enumerate(report["inputs"]):
                        if record["path"] == str(path): report["inputs"][index] = identity
                mutations = {
                    "copied-first-build-commands": lambda r: r.update(commands=copy.deepcopy(first["commands"])),
                    "failed-compile": lambda r: r["commands"][0].update(exit=1),
                    "unreaped-compile": lambda r: r["commands"][0].update(reaped=False),
                    "missing-group-cleanup": lambda r: r["commands"][0].pop("cleanup"),
                    "live-group-after-exit-zero": lambda r: r["commands"][0].update(group_absent_after_wait=False),
                    "group-still-present-after-cleanup": lambda r: r["commands"][0]["cleanup"].update(group_absent=False),
                    "cleanup-has-unreaped-direct-child": lambda r: r["commands"][0]["cleanup"].update(direct_child_reaped=False),
                    "cleanup-disagrees-with-exit-zero": lambda r: r["commands"][0]["cleanup"].update(direct_exit_code=1),
                    "teardown-error-on-success": lambda r: r["commands"][0]["teardown_errors"].append({"phase": "group-probe", "type": "OSError", "error": "fixture"}),
                    "archive-has-live-group": lambda r: next(c for c in r["commands"] if "--fixture-archive" in c["argv"])["cleanup"].update(group_absent=False),
                    "duplicate-output": lambda r: r["commands"].__setitem__(1, copy.deepcopy(r["commands"][0])),
                    "different-compile-flags": lambda r: r["commands"][0]["argv"].append("-DDIFFERENT_BUILD=1"),
                    "different-compile-environment": lambda r: r["commands"][0]["environment"].update(LANG="other"),
                    "different-archive-stage": lambda r: next(c for c in r["commands"] if "--fixture-archive" in c["argv"])["argv"].append("--changed-option"),
                    "external-input-drift-with-identical-artifacts": changed_external_input,
                    "generated-filelist-drift-with-updated-hash-and-identical-artifacts": changed_filelist,
                    "actual-abi-output-drift-with-updated-log-identity": changed_abi_output,
                    "seal-receipt-drift-with-updated-hash-and-identical-kernel": changed_seal_receipt,
                }
                for name, mutate in mutations.items():
                    with self.subTest(name=name):
                        changed = copy.deepcopy(second); mutate(changed)
                        second_path.write_text(json.dumps(changed))
                        with self.assertRaises(B.BuildError): B.compare_builds(first_path, second_path)
                        header.write_bytes(header_original)
                        for path, raw in preserved_artifacts.items(): path.write_bytes(raw)
                second_path.write_text(json.dumps(second))
                with self.subTest(name="external-paths-contain-output-prefix"):
                    for receipt, report in ((first_path, first), (second_path, second)):
                        external = root / "mirror" / str(receipt.parent).lstrip("/") / "external.h"
                        external.parent.mkdir(parents=True)
                        external.write_bytes(b"same external file bytes at distinct paths")
                        changed = copy.deepcopy(report)
                        changed["inputs"].append(B.loader.identity(external))
                        changed["commands"][0]["argv"].append("-I" + str(external.parent))
                        receipt.write_text(json.dumps(changed))
                    with self.assertRaises(B.BuildError): B.compare_builds(first_path, second_path)
                first_path.write_text(json.dumps(first))
                second_path.write_text(json.dumps(second))
                self.assertTrue(B.compare_builds(first_path, second_path)["verified"])

    def test_prng_ready_reads_the_complete_xnu_int_state(self):
        strict, original, base = image()
        kernel = bytearray(1024); kernel[:len(original)] = original
        struct.pack_into("<I", kernel, 32, 0x9400000c)  # BL ctx_size at offset 80
        functions = (("_corecrypto_kext_start", 0), ("_vm_map_store_crypto_init", 32),
                     ("_fipspost_post", 64), ("_crypto_random_kmem_ctx_size", 80), ("_panic", 96),
                     ("_DebuggerTrapWithState", 112), ("_bsd_init", 128), ("_cc_kext_random_kmem_ctx_size", 144))
        cells = (("_g_crypto_funcs", 0), ("_crypto_init", 8), ("_prng_ready", 12),
                 ("_source_corecrypto14_status", 16), ("_route_a_crypto_consumer_status", 20),
                 ("_route_a_crypto_consumer_vectors", 24), ("_kpis", 256))
        symbols = [{"name": name, "n_type": 15, "n_desc": 0, "n_sect": 1, "value": base + offset}
                   for name, offset in functions]
        symbols.extend({"name": name, "n_type": 15, "n_desc": 0, "n_sect": 2, "value": base + 4096 + offset}
                       for name, offset in cells)
        strict["metadata"]["symbols"]["records"] = symbols
        strict["metadata"]["sections"] = [
            {"name": "__text", "segment": "__TEXT_EXEC", "addr": base, "offset": 0, "size": 256, "flags": 0x80000000},
            {"name": "__data", "segment": "__DATA", "addr": base + 4096, "offset": 256, "size": 768, "flags": 0}]
        strict["segments"] = [
            {"name": "__TEXT_EXEC", "vmaddr": base, "vmsize": 256, "fileoff": 0, "filesize": 256, "initprot": 5},
            {"name": "__DATA", "vmaddr": base + 4096, "vmsize": 768, "fileoff": 256, "filesize": 768, "initprot": 3}]
        declared = P.targets(strict, bytes(kernel))
        for prng_ready in (0x100, 0x101):
            with self.subTest(prng_ready=prng_ready):
                memory = bytearray(768); struct.pack_into("<I", memory, 12, prng_ready)
                def read(packet):
                    self.assertTrue(packet.startswith("m"))
                    address, count = (int(field, 16) for field in packet[1:].split(","))
                    offset = address - base - 4096
                    self.assertGreaterEqual(offset, 0)
                    self.assertLessEqual(offset + count, len(memory))
                    return memory[offset:offset + count].hex()
                remote = SimpleNamespace(deadline=time.monotonic() + 5, request=read)
                observer = P.Observe(remote, strict, bytes(kernel), declared, {})
                actual = observer.state()["_prng_ready"]
                self.assertEqual(actual, prng_ready)
                self.assertNotIn(actual, (0, 1))


class PacgaLinkAdmission(unittest.TestCase):
    """Synthetic receipts exercise admission, never claim compiler or guest execution."""

    def test_pacga_patch_replay_requires_all_three_exact_files_and_contexts(self):
        originals, expected, parts = {}, {}, []
        for relative, count in zip(B.PACGA_SOURCES, B.PACGA_HUNKS):
            name = relative.encode()
            originals[relative] = b"one\ntwo\nthree\nfour\nfive\nsix\n"
            part = b"diff --git a/" + name + b" b/" + name + b"\n--- a/" + name + b"\n+++ b/" + name + b"\n"
            part += b"@@ -2,2 +2,3 @@\n two\n+first\n three\n"
            expected[relative] = b"one\ntwo\nfirst\nthree\nfour\nfive\nsix\n"
            if count == 2:
                part += b"@@ -5,2 +6,3 @@\n five\n+second\n six\n"
                expected[relative] = b"one\ntwo\nfirst\nthree\nfour\nfive\nsecond\nsix\n"
            parts.append(part)
        patch_bytes = b"".join(parts)
        self.assertEqual(B.apply_pacga_patch(originals, patch_bytes), expected)
        for bad in (patch_bytes.replace(b"a/osfmk/arm64/locore.s", b"a/other.s", 1),
                    patch_bytes.replace(b" two\n", b" TWO\n", 1),
                    patch_bytes.replace(b"-2,2", b"-2,3", 1),
                    patch_bytes.replace(b"+2,3", b"+2,4", 1),
                    patch_bytes.replace(b"+6,3", b"+5,3", 1),
                    patch_bytes.replace(b"-5,2 +6,3", b"-3,2 +4,3", 1),
                    patch_bytes.replace(b"+first\n", b"-first\n", 1),
                    b"".join(parts[:2]), parts[1] + parts[0] + parts[2],
                    patch_bytes + parts[0], patch_bytes[:-1]):
            with self.subTest(patch=bad[:100]), self.assertRaises(B.BuildError):
                B.apply_pacga_patch(originals, bad)

    def fixture(self, root):
        from arm64_lowering import pacga
        from route_a_pacga_probe import run as execution
        kb, output = root / "kernel-build", root / "stage"
        xnu = kb / ".cache/xnu-work"
        output.mkdir()
        patch_bytes = (B.ROOT / pacga.PATCH).read_bytes()
        originals = {}
        # Only reviewed patch contexts are real; unaffected lines are synthetic.
        for section in patch_bytes.split(b"diff --git ")[1:]:
            header, body = section.split(b"\n", 1)
            relative = header.split()[0][2:].decode()
            source = []
            for match in re.finditer(rb"^@@ -([0-9]+),[0-9]+ \+[0-9]+,[0-9]+ @@\n(.*?)(?=^@@|\Z)", body, re.M | re.S):
                start = int(match[1]) - 1
                old = [line[1:] for line in match[2].splitlines(keepends=True) if line.startswith(b" ")]
                source.extend([b"/* synthetic unaffected context */\n"] * max(0, start + len(old) - len(source)))
                source[start:start + len(old)] = old
            originals[relative] = b"".join(source)
        rebuilt = B.apply_pacga_patch(originals, patch_bytes)
        for relative, raw in originals.items():
            source = xnu / relative; source.parent.mkdir(parents=True, exist_ok=True); source.write_bytes(raw)
            staged = output / "source" / relative; staged.parent.mkdir(parents=True, exist_ok=True); staged.write_bytes(rebuilt[relative])
        helper = output / "source/osfmk/arm64/route_a_pacga_qarma5.h"
        abi = helper.with_name("route_a_pacga_abi.h")
        helper.write_bytes((B.ROOT / pacga.HEADER).read_bytes())
        abi.write_bytes((B.ROOT / pacga.ABI_HEADER).read_bytes())
        patch_path = output / "runtime.patch"; patch_path.write_bytes(patch_bytes)
        assym = kb / B.ASSYM_REL; assym.parent.mkdir(parents=True, exist_ok=True)
        assym.write_bytes(b"synthetic retained offsets; not an XNU layout\n")
        genassym = xnu / "osfmk/arm64/genassym.c"; genassym.write_bytes(b"synthetic retained provenance\n")
        identity, tool = pacga.implementation(), execution.tool_identity(sys.executable)
        frozen = {key: execution.file_identity(path) for key, path in (
            ("helper", helper), ("abi_header", abi), ("patch", patch_path), ("assym", assym), ("genassym", genassym),
            ("stage", B.ROOT / "scripts/build_route_a_pacga.py"), ("execution", Path(execution.__file__)))}
        for relative in B.PACGA_SOURCES:
            frozen["source:" + relative] = execution.file_identity(output / "source" / relative)
            frozen["prepared:" + relative] = execution.file_identity(xnu / relative)
        stage = {"schema": "route-a-pacga-stage-v2", "compile_passed": True, "compile_exit_code": 0,
                 "compile_timeout_seconds": 300, "abi": pacga.ABI, "implementation": identity, "xnu_commit": pacga.XNU_COMMIT,
                 "descriptor_hex": pacga.descriptor().hex(), "prepared_sources": {k: B.sha(v) for k, v in originals.items()},
                 "staged_sources": {k: B.sha(v) for k, v in rebuilt.items()}, "frozen": frozen, "tools": {"clang": tool},
                 "translation_units": {}, "commands": []}
        for key in ("helper", "abi_header", "patch"):
            stage[key + "_sha256"] = frozen[key]["sha256"]

        def command(name, argv, directory, timeout):
            return {"name": name, "arguments": argv, "directory": str(directory), "timeout_seconds": timeout,
                    "status": "finished", "exit_code": 0, "cleanup": {"group_absent": True, "direct_child_reaped": True}}
        stage["commands"].append(command("compiler-version", [tool["invocation"], "--version"], output, 60))
        previous_records, recipes = [], {}
        for unit, relative in zip(("sleh", "locore"), B.PACGA_SOURCES):
            source, staged, obj = xnu / relative, output / "source" / relative, output / (unit + ".o")
            recipe_path = kb / Path(B.RECIPE_REL).with_name(unit + ".o.json")
            previous = recipe_path.parent / (unit + ".o"); previous.write_bytes(("retained " + unit).encode())
            previous_records.append(B.loader.identity(previous))
            old_output = "sleh.o" if unit == "sleh" else "/tmp/locore-fixture.s"
            recipe = {"file": str(source), "output": old_output, "directory": str(recipe_path.parent),
                      "arguments": [tool["invocation"], *(["-xassembler-with-cpp"] if unit == "locore" else []),
                                    "-c", str(source), "-o", old_output]}
            recipe_path.write_text(json.dumps(recipe)); recipes[unit] = recipe_path
            data = pacga.descriptor() if unit == "sleh" else struct.pack("<I", 0xd503201f)
            segment_name, section_name = (b"__DATA_CONST", b"__unixnu_pacga") if unit == "sleh" else (b"__TEXT", b"__text")
            offset = 32 + 152 + 24 + 24
            segment = struct.pack("<2I16s4Q4I", 0x19, 152, b"", 0, len(data), offset, len(data), 3, 3, 1, 0)
            segment += struct.pack("<16s16s2Q8I", section_name, segment_name, 0, len(data), offset, 0, 0, 0,
                                   0 if unit == "sleh" else 0x80000000, 0, 0, 0)
            version = struct.pack("<6I", 0x32, 24, 2, 27 << 16, 27 << 16, 0)
            symbols = struct.pack("<6I", 2, 24, offset + len(data), 0, offset + len(data), 1)
            obj.write_bytes(struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 1, 3, 200, 0, 0)
                            + segment + version + symbols + data + b"\0")
            arguments = list(recipe["arguments"])
            arguments[arguments.index(str(source))] = str(staged)
            arguments[arguments.index("-o") + 1] = str(obj)
            arguments[1:1] = ["-I", str(output / "source/osfmk")]
            arguments += ["-march=armv8-a", "-DCONFIG_ROUTE_A_PACGA_SVC=1",
                          '-DROUTE_A_PACGA_IMPLEMENTATION_SHA256="' + identity["sha256"] + '"']
            if unit == "sleh": arguments += ["-mgeneral-regs-only"]
            arguments += ["-MD", "-MF", str(output / (unit + ".d"))]
            if unit == "sleh":
                arguments += ["-Werror=implicit-function-declaration", "-Werror=incompatible-function-pointer-types", "-Werror=return-type"]
            discovery = list(arguments)
            discovery[discovery.index("-MD")] = "-M"
            discovery[discovery.index("-MF") + 1] = str(output / (unit + ".discovered.d"))
            discovery[discovery.index("-o") + 1] = str(output / (unit + ".discovered.stdout"))
            config = list(arguments); config.remove("-c"); config.remove("-MD")
            at = config.index("-MF"); del config[at:at + 2]
            config[config.index("-o") + 1] = str(output / (unit + ".macros.txt")); config += ["-E", "-dM"]
            macros = output / (unit + ".macros.txt")
            macros.write_bytes(b"#define CONFIG_ROUTE_A_PACGA_SVC 1\n#define __ARM_KERNEL_PROTECT__ 0\n"
                               + (b"#define __ASSEMBLER__ 1\n" if unit == "locore" else b""))
            paths = [staged, helper, abi] if unit == "sleh" else [staged, abi, output / "source" / B.PACGA_SOURCES[2], assym]
            closure = {str(path): execution.file_identity(path) for path in paths}
            for suffix in (".d", ".discovered.d"):
                (output / (unit + suffix)).write_text(str(obj) + ": " + " ".join(map(str, paths)) + "\n")
            dependencies = output / (unit + ".dependencies.json")
            dependencies.write_text(json.dumps({name: record["sha256"] for name, record in closure.items()}))
            frozen.update({key + ":" + unit: execution.file_identity(path)
                           for key, path in (("recipe", recipe_path), ("object", obj), ("configuration", macros))})
            frozen.update({"dependency:" + path: record for path, record in closure.items()})
            stage["translation_units"][unit] = {
                "source_file": relative, "recipe_sha256": B.sha(recipe_path.read_bytes()), "compile_exit_code": 0,
                "arguments": arguments, "directory": recipe["directory"],
                "previous_object": {"name": unit + ".o", "sha256": previous_records[-1]["sha256"]},
                "object": {"name": unit + ".o", "bytes": obj.stat().st_size, "sha256": B.sha(obj.read_bytes()),
                           "cpu_type": "arm64", "cpu_subtype": 0},
                "configuration": {"macros_sha256": B.sha(macros.read_bytes()), "route_a_pacga_svc": 1,
                                  "arm_kernel_protect": 0, "language": "c" if unit == "sleh" else "assembler-with-cpp"},
                "header_closure": closure, "dependency_count": len(closure), "dependencies_sha256": B.sha(dependencies.read_bytes())}
            stage["commands"].extend(command(unit + suffix, argv, recipe_path.parent, deadline)
                                     for suffix, argv, deadline in (("-discover-headers", discovery, 300),
                                                                   ("-config", config, 300), ("-compile", arguments, 300)))
        pins = {"source": stage["prepared_sources"][B.PACGA_SOURCES[0]],
                "locore_source": stage["prepared_sources"][B.PACGA_SOURCES[1]],
                "exception_asm_source": stage["prepared_sources"][B.PACGA_SOURCES[2]],
                "recipe": B.sha(recipes["sleh"].read_bytes()), "locore_recipe": B.sha(recipes["locore"].read_bytes()),
                **{key: frozen[key]["sha256"] for key in ("assym", "genassym")},
                **{key + "_driver": frozen[key]["sha256"] for key in ("stage", "execution")}}
        return SimpleNamespace(stage=stage, output=output, kb=kb, tool=tool, pins=pins, originals=previous_records,
                               journal=B.Journal(root), report=output / "stage-report.json", helper=helper, recipes=recipes)

    def admit(self, fixture):
        fixture.report.write_text(json.dumps(fixture.stage))
        with patch.dict(B.PACGA_PINS, fixture.pins), patch.dict(B.PINS, {"compiler": fixture.tool["binary"]["sha256"]}):
            return B.admit_pacga_stage(fixture.journal, fixture.report, fixture.kb, fixture.originals)

    def rebind(self, fixture, path):
        """An adversarial report may update every self-reported digest."""
        from route_a_pacga_probe import run as execution
        stage = fixture.stage; identity = execution.file_identity(path)
        for key, record in list(stage["frozen"].items()):
            if record["path"] == str(path): stage["frozen"][key] = identity
        for relative in B.PACGA_SOURCES:
            if path == fixture.output / "source" / relative: stage["staged_sources"][relative] = identity["sha256"]
        for unit, record in stage["translation_units"].items():
            if str(path) in record["header_closure"]: record["header_closure"][str(path)] = identity
            dependencies = fixture.output / (unit + ".dependencies.json")
            dependencies.write_text(json.dumps({name: item["sha256"] for name, item in record["header_closure"].items()}))
            record["dependencies_sha256"] = B.sha(dependencies.read_bytes())
            if path == fixture.output / (unit + ".macros.txt"): record["configuration"]["macros_sha256"] = identity["sha256"]
            if path == fixture.output / (unit + ".o"): record["object"].update(bytes=path.stat().st_size, sha256=identity["sha256"])

    def test_v2_binds_both_recipes_configuration_dependencies_and_objects(self):
        failures = (None, "v1", "one-tu", "third-tu", "failed", "unreaped", "wrong-previous", "extra-flags",
                    "wrong-timeout", "bad-bound", "unit-failed", "missing-member", "duplicate-member", "arm64e",
                    "descriptor", "depfile", "configuration", "assembler", "source-forgery", "header-drift", "producer")
        for failure in failures:
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                fixture = self.fixture(Path(tmp)); stage = fixture.stage; unit = stage["translation_units"]["locore"]
                if failure == "v1": stage["schema"] = "route-a-pacga-stage-v1"
                if failure == "one-tu": del stage["translation_units"]["locore"]
                if failure == "third-tu": stage["translation_units"]["other"] = copy.deepcopy(unit)
                if failure == "failed": stage["compile_passed"] = False
                if failure == "unreaped": stage["commands"][-1]["cleanup"]["group_absent"] = False
                if failure == "wrong-previous": unit["previous_object"]["sha256"] = "0" * 64
                if failure == "extra-flags": unit["arguments"].append("-DUNREVIEWED_FLAG=1")
                if failure == "wrong-timeout": stage["commands"][-1]["timeout_seconds"] = 301
                if failure == "bad-bound": stage["compile_timeout_seconds"] = True
                if failure == "unit-failed": unit["compile_exit_code"] = False
                if failure == "missing-member": fixture.originals.pop()
                if failure == "duplicate-member": fixture.originals.append(fixture.originals[-1])
                if failure in ("arm64e", "descriptor"):
                    path = fixture.output / ("locore.o" if failure == "arm64e" else "sleh.o")
                    raw = bytearray(path.read_bytes())
                    if failure == "arm64e": struct.pack_into("<I", raw, 8, 2)
                    else: raw[32 + 152 + 24 + 24] ^= 1
                    path.write_bytes(raw); self.rebind(fixture, path)
                if failure == "depfile": (fixture.output / "locore.d").write_text("locore.o: " + str(fixture.helper) + "\n")
                if failure in ("configuration", "assembler"):
                    path = fixture.output / "locore.macros.txt"
                    raw = path.read_bytes().replace(b"__ARM_KERNEL_PROTECT__ 0", b"__ARM_KERNEL_PROTECT__ 1") if failure == "configuration" else path.read_bytes().replace(b"#define __ASSEMBLER__ 1\n", b"")
                    path.write_bytes(raw); self.rebind(fixture, path)
                if failure == "source-forgery":
                    path = fixture.output / "source" / B.PACGA_SOURCES[2]
                    path.write_bytes(path.read_bytes() + b"unreviewed change\n"); self.rebind(fixture, path)
                if failure == "header-drift": fixture.helper.write_bytes(b"changed helper\n")
                if failure == "producer":
                    from route_a_pacga_probe import run as execution
                    producer = fixture.output / "unreviewed-stage.py"; producer.write_bytes(b"unreviewed producer\n")
                    stage["frozen"]["stage"] = execution.file_identity(producer)
                if failure is None:
                    admitted = self.admit(fixture)
                    self.assertEqual(set(admitted["translation_units"]), {"sleh", "locore"})
                    self.assertFalse(admitted["runtime_boot_verified"])
                    for index, name in enumerate(("sleh", "locore")):
                        self.assertEqual(admitted["translation_units"][name]["object"], B.loader.identity(fixture.output / (name + ".o")))
                        self.assertEqual(admitted["translation_units"][name]["previous_object"], fixture.originals[index])
                else:
                    with self.assertRaises(B.BuildError): self.admit(fixture)

    def test_self_consistent_dependency_reports_cannot_drop_or_shadow_the_exception_overlay(self):
        from route_a_pacga_probe import run as execution
        for failure in ("missing-overlay", "original-exception", "shadow-header", "shared-generation"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                fixture = self.fixture(Path(tmp)); unit = fixture.stage["translation_units"]["locore"]
                closure = unit["header_closure"]
                expected = str(fixture.output / "source" / B.PACGA_SOURCES[2])
                if failure in ("missing-overlay", "original-exception"):
                    del closure[expected]
                    if failure == "original-exception":
                        original = fixture.kb / ".cache/xnu-work" / B.PACGA_SOURCES[2]
                        closure[str(original)] = execution.file_identity(original)
                if failure == "shadow-header":
                    shadow = fixture.output / "source/osfmk/arm64/unreviewed.h"; shadow.write_bytes(b"shadow\n")
                    closure[str(shadow)] = execution.file_identity(shadow)
                if failure == "shared-generation":
                    abi = str(fixture.output / "source/osfmk/arm64/route_a_pacga_abi.h")
                    closure[abi] = copy.deepcopy(closure[abi]); closure[abi]["generation"]["inode"] += 1
                frozen = fixture.stage["frozen"]
                for key in list(frozen):
                    if key.startswith("dependency:"): del frozen[key]
                for item in fixture.stage["translation_units"].values():
                    frozen.update({"dependency:" + name: record for name, record in item["header_closure"].items()})
                for suffix in (".d", ".discovered.d"):
                    (fixture.output / ("locore" + suffix)).write_text("locore.o: " + " ".join(closure) + "\n")
                publication = fixture.output / "locore.dependencies.json"
                publication.write_text(json.dumps({name: record["sha256"] for name, record in closure.items()}))
                unit.update(dependency_count=len(closure), dependencies_sha256=B.sha(publication.read_bytes()))
                with self.assertRaises(B.BuildError): self.admit(fixture)

    def test_generated_receipts_and_prepared_generations_cannot_change_after_semantic_checks(self):
        for target in ("locore.d", "locore.discovered.d", "locore.dependencies.json", "locore.macros.txt", "prepared", "helper"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                fixture = self.fixture(Path(tmp))
                path = (fixture.kb / ".cache/xnu-work" / B.PACGA_SOURCES[1] if target == "prepared" else
                        fixture.helper if target == "helper" else fixture.output / target)
                original, visits, changed = fixture.journal.protect, [], []
                def protect(item, **kwargs):
                    if Path(item) == path:
                        visits.append(item)
                        if len(visits) == (1 if target == "helper" else 2):
                            path.write_bytes(path.read_bytes() + b"late drift\n"); changed.append(item)
                    return original(item, **kwargs)
                with patch.object(fixture.journal, "protect", side_effect=protect), self.assertRaises(B.BuildError):
                    self.admit(fixture)
                self.assertEqual(len(changed), 1)

    def test_current_validation_source_cannot_be_adopted_after_its_pin_check(self):
        from arm64_lowering import pacga
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); fixture = self.fixture(root)
            consumer = root / "consumer-source"
            relatives = ("scripts/build_route_a_pacga.py", "scripts/route_a_pacga_probe/run.py",
                         "scripts/arm64_lowering/pacga.py", pacga.HEADER, pacga.ABI_HEADER, pacga.PATCH)
            for relative in relatives:
                path = consumer / relative; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((B.ROOT / relative).read_bytes())
            target = consumer / relatives[0]
            original_pin, changed = B.pin, []
            def pin_then_change(path, digest):
                raw = original_pin(path, digest)
                if Path(path) == target and not changed:
                    target.write_bytes(raw + b"\n# changed after fixed identity check\n"); changed.append(path)
                return raw
            with patch.object(B, "ROOT", consumer), patch.object(B, "pin", side_effect=pin_then_change), self.assertRaises(B.BuildError):
                self.admit(fixture)
            self.assertEqual(len(changed), 1)

    def test_macro_admission_rejects_ambiguous_or_unreviewed_configuration(self):
        good = b"#define CONFIG_ROUTE_A_PACGA_SVC 1\n#define __ASSEMBLER__ 1\n"
        self.assertEqual(B.pacga_configuration(good, "locore")["arm_kernel_protect"], 0)
        for raw in (good + b"#define CONFIG_ROUTE_A_PACGA_SVC 1\n",
                    good + b"#define __ARM_KERNEL_PROTECT__ 1\n",
                    good + b"#define __ARM_KERNEL_PROTECT__ 0\n#define __ARM_KERNEL_PROTECT__ 0\n",
                    good.replace(b"__ASSEMBLER__ 1", b"__ASSEMBLER__ 0")):
            with self.assertRaises(B.BuildError): B.pacga_configuration(raw, "locore")

    def test_link_filelist_replaces_exactly_bootstrap_sleh_and_locore_in_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); original = root / "original"; original.mkdir()
            records = []
            for name in ("first.o", "locore.o", "prng_random.o", "sleh.o", "last.o"):
                path = original / name; path.write_bytes(name.encode()); records.append(B.loader.identity(path))
            baseline = original / "baseline.json"; baseline.write_text("{}")
            original_list = original / "filelist"; original_list.write_text("".join(record["path"] + "\n" for record in records))
            plan = {"original_members": records, "baseline_report": B.loader.identity(baseline),
                    "baseline_filelist": B.loader.identity(original_list)}
            out = root / "fresh"; out.mkdir(); journal = B.Journal(out)
            bootstrap = out / "prng_random.o"; bootstrap.write_bytes(b"new bootstrap")
            archive = out / "provider.a"; archive.write_bytes(b"provider archive")
            overlay = {"translation_units": {}}
            for name, index in (("sleh", 3), ("locore", 1)):
                path = out / (name + ".o"); path.write_bytes(("admitted " + name).encode())
                overlay["translation_units"][name] = {"object": B.loader.identity(path), "previous_object": records[index]}
            contract = B.write_link_filelist(journal, plan, bootstrap, archive, overlay)
            self.assertEqual((out / "platform.filelist").read_text().splitlines(),
                             [records[0]["path"], str(out / "locore.o"), str(bootstrap), str(out / "sleh.o"), records[4]["path"]])
            self.assertEqual([(entry["index"], entry["kind"]) for entry in contract["substitutions"]],
                             [(2, "bootstrap"), (3, "pacga"), (1, "pacga")])
            for failure in ("missing", "extra", "wrong-previous"):
                bad = copy.deepcopy(overlay)
                if failure == "missing": del bad["translation_units"]["locore"]
                if failure == "extra": bad["translation_units"]["other"] = bad["translation_units"]["sleh"]
                if failure == "wrong-previous": bad["translation_units"]["locore"]["previous_object"] = records[0]
                with self.subTest(failure=failure), self.assertRaises(B.BuildError):
                    B.write_link_filelist(journal, plan, bootstrap, archive, bad)


if __name__ == "__main__": unittest.main()
