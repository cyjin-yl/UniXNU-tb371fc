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

            def make_build(name):
                output = root / name; output.mkdir()
                glue = output / "glue"; glue.mkdir()
                source = glue / "prng_random.c"; source.write_text("int bootstrap;\n")
                bootstrap = output / "bootstrap/prng_random.o"; bootstrap.parent.mkdir()
                bootstrap.write_bytes(b"bootstrap object fixture")
                inputs = [compiler_record, B.loader.identity(header), B.loader.identity(source)]
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
                receipt = output / "report.json"; receipt.write_text(json.dumps(report))
                return receipt, report

            first_path, first = make_build("first")
            second_path, second = make_build("second")
            with patch.dict(B.PINS, {"archive": archive_record["sha256"], "compiler": compiler_record["sha256"]}):
                self.assertTrue(B.compare_builds(first_path, second_path)["verified"])
                def changed_external_input(report):
                    header.write_text("/* changed unused header; artifacts are identical */\n")
                    report["inputs"][1] = B.loader.identity(header)
                mutations = {
                    "copied-first-build-commands": lambda r: r.update(commands=copy.deepcopy(first["commands"])),
                    "failed-compile": lambda r: r["commands"][0].update(exit=1),
                    "unreaped-compile": lambda r: r["commands"][0].update(reaped=False),
                    "duplicate-output": lambda r: r["commands"].__setitem__(-2, copy.deepcopy(r["commands"][-3])),
                    "different-compile-flags": lambda r: r["commands"][0]["argv"].append("-DDIFFERENT_BUILD=1"),
                    "different-compile-environment": lambda r: r["commands"][0]["environment"].update(LANG="other"),
                    "different-archive-stage": lambda r: r["commands"][-1]["argv"].append("--changed-option"),
                    "external-input-drift-with-identical-artifacts": changed_external_input,
                }
                for name, mutate in mutations.items():
                    with self.subTest(name=name):
                        changed = copy.deepcopy(second); mutate(changed)
                        second_path.write_text(json.dumps(changed))
                        with self.assertRaises(B.BuildError): B.compare_builds(first_path, second_path)
                        header.write_bytes(header_original)
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


if __name__ == "__main__": unittest.main()
