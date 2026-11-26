"""LLVM protocol, actual owned-child cleanup and fork identity regressions.

All instruction bytes and subprocess programs here are synthetic. The optional
real llvm-mc vector test is required by the CI job that installs LLVM 18.
"""
from contextlib import nullcontext
from copy import deepcopy
import hashlib
import multiprocessing
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from arm64_lowering import proof
from route_a_zeta import zeta_llvm_oracle as llvm
from route_a_zeta import zeta_elf_tools as elf
from route_a_zeta import zeta_userland_code as code
from test_route_a_proof import module

NOP, RET, INVALID = 0xd503201f, 0xd65f03c0, 0xffffffff
VERSION = b"Debian LLVM version 18.1.3\n  Optimized build.\n"


def warning(words, index):
    # Independent formatting, including exact input bytes and the column-1 caret.
    word = words[index - 1]
    source = " ".join("0x%02x" % byte for byte in word.to_bytes(4, "little"))
    return f"<stdin>:{index}:1: warning: invalid instruction encoding\n{source}\n^\n"


def make_session(executable):
    # Identity/FD/generation code is real. Only the LLVM version subprocess is
    # replaced. The closure resolver is separate from these file/child-lifetime
    # unit tests; the actual LLVM test below exercises it without either mock.
    with patch.object(llvm.shutil, "which", return_value=str(executable)), \
            patch.object(llvm.DecoderSession, "_bind_libraries", return_value=None), \
            patch.object(llvm.DecoderSession, "run", return_value=(VERSION, b"")):
        return llvm.DecoderSession()


def fork_use_decoder(connection, expected):
    try:
        llvm.bind_initial_rules(expected)
        with llvm.session(expected) as decoder:
            out, err = decoder.run(["-c", "print('inherited-fd')"], b"", 5)
            connection.send((decoder.manifest(), out, err))
    except BaseException as error:
        connection.send((type(error).__name__, str(error)))
    finally:
        connection.close()


def elf_fixture(*, needed=("libFixture.so.1",), soname=None, interpreter="/lib64/ld-linux-x86-64.so.2",
                extra=()):
    """Handwritten file-backed ELF64 geometry, never executed."""
    data = bytearray(0x1000)
    strings = bytearray(b"\0")
    def string(value):
        index = len(strings)
        strings.extend(value.encode("ascii") + b"\0")
        return index
    entries = [(1, string(name)) for name in needed]
    if soname is not None:
        entries.append((14, string(soname)))
    entries += list(extra)
    entries += [(5, 0x400400), (10, len(strings)), (0, 0)]
    count = 3 if interpreter else 2
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    data[:64] = struct.pack("<16sHHIQQQIHHHHHH", ident, 3, 62, 1, 0, 64, 0, 0, 64, 56, count, 0, 0, 0)
    segments = [(1, 5, 0, 0x400000, 0, len(data), len(data), 0x1000),
                (2, 6, 0x200, 0x400200, 0, len(entries) * 16, len(entries) * 16, 8)]
    if interpreter:
        path = interpreter.encode("ascii") + b"\0"
        data[0x180:0x180 + len(path)] = path
        segments.append((3, 4, 0x180, 0x400180, 0, len(path), len(path), 1))
    for index, segment in enumerate(segments):
        struct.pack_into("<IIQQQQQQ", data, 64 + index * 56, *segment)
    for index, entry in enumerate(entries):
        struct.pack_into("<qQ", data, 0x200 + index * 16, *entry)
    data[0x400:0x400 + len(strings)] = strings
    return data


class ELFClosureProtocolTests(unittest.TestCase):
    def info(self, data):
        return elf.elf_info(lambda offset, size: bytes(data[offset:offset + size]), len(data))

    def test_explicit_interpreter_needed_and_soname_are_read_from_real_fields(self):
        info = self.info(elf_fixture(soname="fixture"))
        self.assertEqual(info["machine"], 62)
        self.assertEqual(info["needed"], ["libFixture.so.1"])
        self.assertEqual(info["soname"], "fixture")
        self.assertEqual(info["interpreter"], "/lib64/ld-linux-x86-64.so.2")

    def test_dynamic_strings_can_span_contiguous_file_backed_loads(self):
        data = elf_fixture()
        struct.pack_into("<H", data, 56, 4)
        struct.pack_into("<IIQQQQQQ", data, 64, 1, 4, 0, 0x400000, 0, 0x409, 0x409, 0x1000)
        struct.pack_into("<IIQQQQQQ", data, 64 + 3 * 56, 1, 4, 0x409, 0x400409, 0,
                         len(data) - 0x409, len(data) - 0x409, 0x1000)
        self.assertEqual(self.info(data)["needed"], ["libFixture.so.1"])

    def test_wrong_elf_class_endianness_or_program_header_bounds_reject(self):
        cases = []
        for offset, value in ((4, 1), (5, 2)):
            data = elf_fixture(); data[offset] = value; cases.append(data)
        data = elf_fixture(); struct.pack_into("<Q", data, 32, 0xfff); cases.append(data)
        cases.append(elf_fixture()[:63])
        for data in cases:
            with self.subTest(prefix=bytes(data[:8])), self.assertRaises(ValueError):
                self.info(data)

    def test_path_dependencies_duplicates_filters_and_auditors_reject(self):
        cases = [elf_fixture(needed=("../libX.so",)), elf_fixture(needed=("/tmp/libX.so",)),
                 elf_fixture(needed=("same.so", "same.so"))]
        cases += [elf_fixture(extra=((tag, 1),)) for tag in (0x7ffffffd, 0x7fffffff, 0x6ffffefb, 0x6ffffefc)]
        for data in cases:
            with self.subTest(data=data[0x200:0x240].hex()), self.assertRaises(ValueError):
                self.info(data)

    def test_dynamic_strings_require_bounded_unique_file_backing(self):
        cases = []
        data = elf_fixture(); struct.pack_into("<Q", data, 0x218, 0x900000); cases.append(data)
        data = elf_fixture(); struct.pack_into("<Q", data, 0x208, 0xffff); cases.append(data)
        data = elf_fixture(); size = struct.unpack_from("<Q", data, 0x228)[0]
        data[0x400:0x400 + size] = b"X" * size; cases.append(data)
        for data in cases:
            with self.subTest(data=data[0x200:0x240].hex()), self.assertRaises(ValueError):
                self.info(data)

    def test_loader_list_accepts_only_explicit_resolved_records(self):
        text = (b"\tlinux-vdso.so.1 (0x00007fff)\n"
                b"\tlibFixture.so.1 => /usr/lib/libFixture.so.1 (0x00007aaa)\n"
                b"\t/lib64/ld-linux-x86-64.so.2 (0x00007bbb)\n")
        libraries, direct = llvm.parse_loader_list(text, b"")
        self.assertEqual(libraries, {"libFixture.so.1": "/usr/lib/libFixture.so.1"})
        self.assertEqual(direct, ["/lib64/ld-linux-x86-64.so.2"])
        for wrong in (text + text, text + b"ignored\n", text.replace(b"/usr/lib/libFixture.so.1 (0x00007aaa)", b"not found")):
            with self.assertRaises(ValueError):
                llvm.parse_loader_list(wrong, b"")
        with self.assertRaises(ValueError):
            llvm.parse_loader_list(text, b"warning: changed search path\n")

    def frozen_decoder(self):
        decoder = object.__new__(llvm.DecoderSession)
        decoder.fd, decoder.directory_fd = 10, 12
        decoder.invocation, decoder.path = "/tools/llvm-mc", "/tools/real-llvm-mc"
        decoder.loader = SimpleNamespace(fd=11, invocation="/lib64/ld.so", path="/lib/real-ld.so")
        decoder.libraries = {"libLLVM.so": SimpleNamespace(fd=13, invocation="/lib/libLLVM.so", path="/lib/real-LLVM.so")}
        return decoder

    def test_frozen_list_rejects_any_return_to_a_system_search_path(self):
        decoder = self.frozen_decoder()
        good = b"\tlibLLVM.so => /proc/self/fd/12/libLLVM.so (0x1234)\n\t/lib64/ld.so (0x5678)\n"
        decoder._check_frozen_list(good, b"")
        for wrong in (good.replace(b"/proc/self/fd/12/libLLVM.so", b"/lib/libLLVM.so"),
                      good.replace(b"/proc/self/fd/12/libLLVM.so", b"/proc/self/fd/99/libLLVM.so"),
                      good + b"\tlibExtra.so => /tmp/libExtra.so (0x9999)\n"):
            with self.assertRaises(ValueError):
                decoder._check_frozen_list(wrong, b"")

    def test_actual_argv_disables_cache_and_all_main_and_library_rpath_aliases(self):
        decoder = self.frozen_decoder()
        argv, executable, descriptors = decoder._command(["--version"])
        self.assertEqual(executable, 11)
        self.assertEqual(descriptors, (10, 11, 12, 13))
        self.assertIn("--inhibit-cache", argv)
        self.assertEqual(argv[argv.index("--library-path") + 1], "/proc/self/fd/12")
        self.assertEqual(argv[argv.index("--argv0") + 1], "/tools/llvm-mc")
        aliases = set(argv[argv.index("--inhibit-rpath") + 1].split(":"))
        self.assertTrue({"", "/tools/llvm-mc", "/tools/real-llvm-mc", "/proc/self/fd/10",
                         "/lib/libLLVM.so", "/lib/real-LLVM.so", "/proc/self/fd/12/libLLVM.so",
                         "/proc/self/fd/13"} <= aliases)


class OracleProtocolTests(unittest.TestCase):
    def parse(self, words, stdout, stderr="", features="+v9.5a,+pauth"):
        return llvm.parse_output(words, features, stdout, stderr)

    def test_valid_records_preserve_word_order_and_zero_operands(self):
        words = [NOP, 0x91000400]
        self.assertEqual(self.parse(words, "\t.text\n\tnop\n\tadd\tx0, x0, #1\n"),
                         {NOP: ("nop", ""), 0x91000400: ("add", "x0, x0, #1")})

    def test_invalid_word_requires_its_complete_warning_and_context(self):
        words = [INVALID, NOP]
        self.assertEqual(self.parse(words, "\t.text\n\tnop\n", warning(words, 1)), {NOP: ("nop", "")})
        self.assertEqual(self.parse([INVALID], "\t.text\n", warning([INVALID], 1)), {})

    def test_requested_unsupported_feature_warning_is_explicitly_allowed(self):
        stderr = "'+v9.5a' is not a recognized feature for this target (ignoring feature)\n"
        self.assertEqual(self.parse([NOP], "\t.text\n\tnop\n", stderr), {NOP: ("nop", "")})

    def test_unrequested_or_changed_feature_warning_is_rejected(self):
        for diagnostic in (
                "'+unknown' is not a recognized feature for this target (ignoring feature)\n",
                "'+v9.5a' is not a recognized feature for this target (ignoring error)\n",
                "warning: unsupported feature +v9.5a\n"):
            with self.subTest(diagnostic=diagnostic), self.assertRaises(ValueError):
                self.parse([NOP], "\t.text\n\tnop\n", diagnostic)

    def test_all_other_diagnostics_and_soft_fail_are_rejected(self):
        for diagnostic in ("error: unexpected failure\n", "fatal error: stopped\n", "LLVM ERROR: broken\n",
                           "<stdin>:1:1: warning: potentially undefined instruction encoding\n",
                           "\x1b[31mwarning\x1b[0m: invalid instruction encoding\n"):
            with self.subTest(diagnostic=diagnostic), self.assertRaises(ValueError):
                self.parse([NOP], "\t.text\n\tnop\n", diagnostic)

    def test_invalid_index_zero_outside_duplicate_or_noninitial_column_rejects(self):
        valid = warning([INVALID], 1)
        for diagnostic in (valid.replace(":1:1:", ":0:1:"), valid.replace(":1:1:", ":2:1:"),
                           valid.replace(":1:1:", ":1:2:"), valid + valid):
            with self.subTest(diagnostic=diagnostic), self.assertRaises(ValueError):
                self.parse([INVALID], "\t.text\n", diagnostic)

    def test_changed_missing_or_extra_invalid_context_rejects(self):
        valid = warning([INVALID], 1)
        for diagnostic in (valid.replace("0xff", "0x00", 1), valid.replace("^\n", " ^\n"),
                           valid.rsplit("^", 1)[0], valid + "note: still ignored\n"):
            with self.subTest(diagnostic=diagnostic), self.assertRaises(ValueError):
                self.parse([INVALID], "\t.text\n", diagnostic)

    def test_missing_and_extra_instructions_reject_without_partial_mapping(self):
        for output in ("\t.text\n", "\t.text\n\tnop\n\tnop\n"):
            with self.subTest(output=output), self.assertRaisesRegex(ValueError, "count differs"):
                self.parse([NOP], output)

    def test_every_stdout_directive_and_line_is_consumed(self):
        for output in ("\tnop\n", "\t.text\n\t.text\n\tnop\n", "\t.text\n\tnop\n\t.text\n",
                       "\t.text\n\t.word\t0xd503201f\n", "\t.text\n\tnop\nignored\n",
                       "\t.text\n\t<unknown>\n", "\t.text\n\tnop\x00\n"):
            with self.subTest(output=output), self.assertRaises(ValueError):
                self.parse([NOP], output)

    def test_rejected_encoding_cannot_also_emit_a_silent_extra_instruction(self):
        with self.assertRaisesRegex(ValueError, "count differs"):
            self.parse([INVALID], "\t.text\n\tnop\n", warning([INVALID], 1))

    def test_control_and_transaction_forms_remain_unknown_after_oracle(self):
        mnemonics = ("b", "bl", "br", "blr", "b.eq", "bc.eq", "cbz", "tbnz", "ret", "retaa",
                     "eret", "brk", "svc", "hvc", "smc", "tstart", "tcommit", "tcancel", "ttest")
        responses = {index: (mnemonic, "x0") for index, mnemonic in enumerate(mnemonics)}
        with patch.object(llvm, "disassemble", return_value=responses):
            self.assertEqual(code.llvm_oracle(set(responses)), {})

    def test_existing_amx_words_need_no_llvm_subprocess(self):
        with patch.object(llvm, "disassemble", side_effect=AssertionError("unnecessary tool")):
            self.assertEqual(code.llvm_oracle({0x00201000})[0x00201000][0], "amx")

    def test_batch_limit_preserves_all_inputs_and_checks_last_partial_batch(self):
        calls = []
        class SyntheticDecoder:
            def run(self, argv, data, timeout):
                lines = data.decode("ascii").splitlines()
                calls.append((argv, len(lines), timeout))
                return ("\t.text\n" + "\tnop\n" * len(lines)).encode(), b""
            def verify(self):
                pass
            def reject(self, message):
                raise ValueError(message)
        words = list(range(llvm.BATCH_WORDS * 2 + 1))
        with patch.object(llvm, "session", return_value=nullcontext(SyntheticDecoder())):
            result = llvm.disassemble(words, "+pauth")
        self.assertEqual(set(result), set(words))
        self.assertEqual([count for _, count, _ in calls], [llvm.BATCH_WORDS, llvm.BATCH_WORDS, 1])
        self.assertTrue(all(timeout == 60 for _, _, timeout in calls))


class OracleIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.tool = self.root / "llvm-mc"
        self.tool.write_bytes(Path(sys.executable).resolve().read_bytes())
        self.tool.chmod(0o755)

    def decoder(self, executable=None):
        result = make_session(executable or self.tool)
        self.addCleanup(result.close)
        return result

    def attach_directory(self, decoder):
        library = elf.BoundELF(self.tool)
        decoder.libraries["libFixture.so"] = library
        directory = tempfile.TemporaryDirectory(dir=self.root)
        decoder.directory = directory
        Path(directory.name, "libFixture.so").symlink_to(f"/proc/self/fd/{library.fd}")
        os.chmod(directory.name, 0o555)
        decoder.directory_fd = os.open(directory.name, os.O_RDONLY | os.O_DIRECTORY)
        decoder.directory_generation = llvm.generation(os.fstat(decoder.directory_fd))
        decoder.directory_entries = {"libFixture.so": llvm.generation(os.lstat(Path(directory.name, "libFixture.so")))}
        return directory

    def test_manifest_binds_content_and_paths_but_not_reopen_generation(self):
        first, second = self.decoder(), self.decoder()
        self.assertEqual(first.manifest(), second.manifest())
        self.assertEqual(first.manifest()["binary"]["sha256"], hashlib.sha256(self.tool.read_bytes()).hexdigest())
        self.assertEqual(first.manifest()["binary"]["path"], str(self.tool))
        self.assertEqual(first.manifest()["invocation"], str(self.tool))
        self.assertNotIn("generation", repr(first.manifest()))

    def test_repeated_manifest_calls_do_not_rehash_or_rerun_version(self):
        decoder = self.decoder()
        with patch.object(llvm.os, "pread", side_effect=AssertionError("unexpected second content read")), \
                patch.object(decoder, "run", side_effect=AssertionError("unexpected second version")):
            for _ in range(4):
                decoder.bind(decoder.manifest())

    def test_content_change_then_restore_is_sticky_even_with_restored_mtime(self):
        decoder = self.decoder()
        original, before = self.tool.read_bytes(), self.tool.stat()
        self.tool.write_bytes(original + b"changed")
        os.utime(self.tool, ns=(before.st_atime_ns, before.st_mtime_ns))
        with self.assertRaisesRegex(ValueError, "generation changed"):
            decoder.verify()
        self.tool.write_bytes(original)
        os.utime(self.tool, ns=(before.st_atime_ns, before.st_mtime_ns))
        with self.assertRaisesRegex(ValueError, "generation changed"):
            decoder.verify()

    def test_replacement_and_restore_between_checks_cannot_hide_generation_drift(self):
        decoder = self.decoder()
        retained = self.root / "retained"
        self.tool.rename(retained)
        self.tool.write_bytes(retained.read_bytes())
        self.tool.chmod(0o755)
        os.replace(retained, self.tool)
        with self.assertRaisesRegex(ValueError, "generation changed"):
            decoder.verify()

    def test_symlink_retarget_and_restore_is_detected(self):
        alias = self.root / "alias"
        alias.symlink_to(self.tool)
        decoder = self.decoder(alias)
        alias.unlink(); alias.symlink_to(sys.executable)
        alias.unlink(); alias.symlink_to(self.tool)
        with self.assertRaisesRegex(ValueError, "generation changed"):
            decoder.verify()

    def test_wrong_initial_identity_is_rejected_and_sticky(self):
        decoder = self.decoder()
        changed = decoder.manifest()
        changed["binary"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "initial rules identity"):
            decoder.bind(changed)
        with self.assertRaisesRegex(ValueError, "initial rules identity"):
            decoder.manifest()

    def test_absence_cannot_silently_enable_a_later_tool(self):
        with patch.object(llvm.shutil, "which", return_value=None):
            decoder = llvm.DecoderSession()
            self.addCleanup(decoder.close)
            self.assertIsNone(decoder.manifest())
            decoder.bind(None)
        with patch.object(llvm.shutil, "which", return_value=str(self.tool)):
            with self.assertRaisesRegex(ValueError, "after absence"):
                decoder.verify()
        with patch.object(llvm.shutil, "which", return_value=None):
            with self.assertRaisesRegex(ValueError, "after absence"):
                decoder.verify()

    def test_interpreter_wrapper_is_not_a_bound_native_decoder(self):
        self.tool.write_text("#!/bin/sh\necho LLVM version 18\n")
        self.tool.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "native ELF"):
            self.decoder()

    def test_failed_identification_closes_the_held_binary(self):
        opened = []
        original_open = llvm.os.open
        def capture(*args, **kwargs):
            result = original_open(*args, **kwargs)
            opened.append(result)
            return result
        with patch.object(llvm.shutil, "which", return_value=str(self.tool)), \
                patch.object(llvm.os, "open", side_effect=capture), \
                patch.object(llvm.DecoderSession, "_bind_libraries", return_value=None), \
                patch.object(llvm.DecoderSession, "run", return_value=(VERSION, b"unexpected diagnostic")):
            with self.assertRaisesRegex(ValueError, "version emitted diagnostics"):
                llvm.DecoderSession()
        self.assertEqual(len(opened), 1)
        with self.assertRaises(OSError):
            os.fstat(opened[0])

    def test_session_nesting_and_failure_close_only_the_owner(self):
        decoder = self.decoder()
        fd = decoder.fd
        with patch.object(llvm, "DecoderSession", return_value=decoder):
            with self.assertRaisesRegex(RuntimeError, "sentinel"):
                with llvm.session() as outer:
                    with llvm.session(outer.manifest()) as inner:
                        self.assertIs(inner, outer)
                    self.assertFalse(outer.closed)
                    raise RuntimeError("sentinel")
        self.assertIsNone(llvm._ACTIVE)
        self.assertTrue(decoder.closed)
        with self.assertRaises(OSError):
            os.fstat(fd)

    def test_cleanup_failure_preserves_primary_and_releases_other_owned_fds(self):
        decoder = self.decoder()
        directory = self.attach_directory(decoder)
        descriptors = [decoder.fd, decoder.directory_fd, decoder.libraries["libFixture.so"].fd]
        real_cleanup = directory.cleanup
        primary = RuntimeError("primary oracle failure")
        try:
            with patch.object(llvm, "DecoderSession", return_value=decoder), \
                    patch.object(llvm.os, "fchmod", side_effect=OSError("permission cleanup failure")), \
                    patch.object(directory, "cleanup", side_effect=OSError("unlink cleanup failure")) as cleanup:
                with self.assertRaises(RuntimeError) as caught:
                    with llvm.session():
                        raise primary
                self.assertIs(caught.exception, primary)
                self.assertTrue(any("permission cleanup failure" in note and "unlink cleanup failure" in note
                                    for note in getattr(primary, "__notes__", ())))
                cleanup.assert_called_once()
            self.assertIsNone(llvm._ACTIVE)
            for descriptor in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
        finally:
            os.chmod(directory.name, 0o700)
            real_cleanup()

    def test_cleanup_failure_without_primary_is_reported_after_all_fd_releases(self):
        decoder = self.decoder()
        directory = self.attach_directory(decoder)
        descriptors = [decoder.fd, decoder.directory_fd, decoder.libraries["libFixture.so"].fd]
        real_cleanup = directory.cleanup
        try:
            with patch.object(llvm, "DecoderSession", return_value=decoder), \
                    patch.object(directory, "cleanup", side_effect=OSError("unlink cleanup failure")):
                with self.assertRaisesRegex(ValueError, "decoder cleanup failed"):
                    with llvm.session():
                        pass
            for descriptor in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
        finally:
            real_cleanup()

    def test_private_fd_library_directory_change_and_restore_is_rejected(self):
        decoder = self.decoder()
        directory = self.attach_directory(decoder)
        decoder.verify()
        os.chmod(directory.name, 0o700)
        unexpected = Path(directory.name, "unbound.so")
        unexpected.symlink_to("/tmp/unbound.so")
        unexpected.unlink()
        os.chmod(directory.name, 0o555)
        with self.assertRaisesRegex(ValueError, "directory generation changed"):
            decoder.verify()

    def test_system_preload_must_be_absent_even_if_existing_file_is_empty(self):
        decoder = self.decoder()
        directory = self.root / "synthetic-etc"
        directory.mkdir()
        (directory / "ld.so.preload").touch()
        with patch.object(llvm, "SYSTEM_PRELOAD_DIRECTORY", str(directory)):
            with self.assertRaisesRegex(ValueError, "preload file is unsupported"):
                decoder._bind_system_preload()

    def test_transient_system_preload_creation_cannot_hide_after_removal(self):
        decoder = self.decoder()
        directory = self.root / "synthetic-etc"
        directory.mkdir()
        with patch.object(llvm, "SYSTEM_PRELOAD_DIRECTORY", str(directory)):
            decoder._bind_system_preload()
            preload = directory / "ld.so.preload"
            preload.write_text("/tmp/unbound.so\n")
            preload.unlink()
            with self.assertRaisesRegex(ValueError, "preload directory generation changed"):
                decoder.verify()

    def test_initial_rules_mismatch_rejects_before_cache_or_workers(self):
        driver = module("prove-zeta-dyld-cache")
        decoder = self.decoder()
        wrong = decoder.manifest()
        wrong["binary"]["sha256"] = "0" * 64
        with patch.object(llvm, "DecoderSession", return_value=decoder), llvm.session():
            with self.assertRaisesRegex(ValueError, "initial rules identity"):
                driver.run_attempt(object(), object(), {"decoders": {"llvm_mc": wrong}}, {})

    def test_rules_manifest_records_binary_identity_and_oracle_source(self):
        decoder = self.decoder()
        with patch.object(llvm, "DecoderSession", return_value=decoder), llvm.session():
            rules = proof.rules_manifest()
            self.assertEqual(rules["decoders"]["llvm_mc"], decoder.manifest())
            name = "route_a_zeta/zeta_llvm_oracle.py"
            self.assertEqual(rules["sources"][name], hashlib.sha256((ROOT / "scripts" / name).read_bytes()).hexdigest())

    def test_dependency_change_cannot_hide_behind_unchanged_main_binary(self):
        decoder = self.decoder()
        library = self.root / "libLLVM-fixture.so"
        library.write_bytes(self.tool.read_bytes())
        bound = elf.BoundELF(library)
        decoder.libraries["libLLVM-fixture.so"] = bound
        before = decoder.program.identity.copy()
        library.write_bytes(library.read_bytes() + b"changed decoder dependency")
        with self.assertRaisesRegex(ValueError, "generation changed"):
            decoder.verify()
        self.assertEqual(decoder.program.identity, before)

    def test_content_budget_rejects_before_any_elf_read_or_hash(self):
        with patch.object(elf.os, "pread", side_effect=AssertionError("must not read over-budget file")):
            with self.assertRaisesRegex(ValueError, "remaining content-byte budget"):
                elf.BoundELF(self.tool, max_bytes=self.tool.stat().st_size - 1)


@unittest.skipUnless(sys.platform.startswith("linux"), "held executable FD protocol is Linux-specific")
class OracleOwnedProcessTests(unittest.TestCase):
    def decoder(self):
        result = make_session(sys.executable)
        self.addCleanup(result.close)
        return result

    def test_execution_uses_held_fd_and_removes_loader_injection_environment(self):
        decoder = self.decoder()
        original = llvm.subprocess.Popen
        observed = []
        def capture(*args, **kwargs):
            observed.append(kwargs)
            return original(*args, **kwargs)
        with patch.object(llvm.subprocess, "Popen", side_effect=capture), \
                patch.dict(os.environ, {"PATH": "/nonexistent", "LD_PRELOAD": "/bad/injected.so"}):
            out, err = decoder.run(["-c", "print('held-binary')"], b"", 5)
        self.assertEqual((out, err), (b"held-binary\n", b""))
        self.assertEqual(observed[0]["executable"], f"/proc/self/fd/{decoder.fd}")
        self.assertEqual(observed[0]["pass_fds"], (decoder.fd,))
        self.assertNotIn("LD_PRELOAD", observed[0]["env"])

    def test_nonzero_exit_cannot_supply_acceptable_looking_stdout(self):
        decoder = self.decoder()
        with self.assertRaisesRegex(ValueError, "status 7"):
            decoder.run(["-c", "import sys; print('\\t.text\\n\\tnop'); sys.exit(7)"], b"", 5)
        self.assertTrue(decoder.failed)
        self.assertFalse(llvm._UNREAPED)

    def test_timeout_kills_and_reaps_owned_child_and_fails_session(self):
        decoder = self.decoder()
        original = llvm.subprocess.Popen
        children = []
        def capture(*args, **kwargs):
            result = original(*args, **kwargs)
            children.append(result)
            return result
        with patch.object(llvm.subprocess, "Popen", side_effect=capture):
            with self.assertRaisesRegex(ValueError, "timed out"):
                decoder.run(["-c", "import time; time.sleep(60)"], b"", 0.1)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)
        self.assertTrue(llvm._group_absent(children[0].pid))
        self.assertFalse(llvm._UNREAPED)
        with self.assertRaises(ValueError):
            decoder.verify()

    def test_oversized_output_is_stopped_before_unbounded_capture(self):
        decoder = self.decoder()
        with patch.object(llvm, "OUTPUT_BYTES", 4096):
            with self.assertRaisesRegex(ValueError, "output exceeds"):
                decoder.run(["-c", "import os; os.write(1, b'x' * 65536)"], b"", 5)
        self.assertFalse(llvm._UNREAPED)

    def test_executable_generation_is_checked_after_actual_child_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            alias = Path(tmp) / "llvm-mc"
            alias.symlink_to(Path(sys.executable).resolve())
            decoder = make_session(alias)
            self.addCleanup(decoder.close)
            real_communicate = llvm._communicate_bounded
            def change_after_child(*args):
                result = real_communicate(*args)
                alias.unlink()
                alias.symlink_to(Path(sys.executable).resolve())
                return result
            with patch.object(llvm, "_communicate_bounded", side_effect=change_after_child):
                with self.assertRaisesRegex(ValueError, "generation changed"):
                    decoder.run(["-c", "print('already-finished')"], b"", 5)
            self.assertFalse(llvm._UNREAPED)

    def test_fork_inherits_same_identified_binary_and_initial_binding(self):
        decoder = self.decoder()
        expected = decoder.manifest()
        context = multiprocessing.get_context("fork")
        parent, child = context.Pipe(duplex=False)
        with patch.object(llvm, "DecoderSession", return_value=decoder), llvm.session(expected):
            worker = context.Process(target=fork_use_decoder, args=(child, expected))
            worker.start()
            child.close()
            try:
                self.assertTrue(parent.poll(10), "fork worker did not return a bounded response")
                response = parent.recv()
                worker.join(timeout=10)
                self.assertFalse(worker.is_alive())
                self.assertEqual(worker.exitcode, 0)
                self.assertEqual(response, (expected, b"inherited-fd\n", b""))
                self.assertFalse(decoder.closed)
            finally:
                if worker.is_alive():
                    worker.kill(); worker.join(timeout=5)
                parent.close()


@unittest.skipUnless(shutil.which("llvm-mc"), "install llvm-mc for the real oracle protocol vectors")
class ActualLLVMProtocolTests(unittest.TestCase):
    def test_real_llvm_valid_invalid_feature_warning_and_control_vectors(self):
        with llvm.session() as decoder:
            identity = decoder.manifest()
            if decoder.program.elf["interpreter"] is not None:
                self.assertIsNotNone(identity["loader"])
                self.assertTrue(identity["dependencies"])
                argv, executable, descriptors = decoder._command([], listing=True)
                decoder._check_frozen_list(*decoder._invoke(argv, executable, descriptors, b"", 60))
            result = llvm.disassemble([NOP, RET, INVALID], code.LLVM_FEATURES + ",+route-a-unsupported-fixture")
            self.assertEqual(result[NOP], ("nop", ""))
            self.assertEqual(result[RET][0], "ret")
            self.assertNotIn(INVALID, result)
            self.assertNotIn(RET, code.llvm_oracle({RET}))
            self.assertEqual(decoder.manifest(), identity)


if __name__ == "__main__":
    unittest.main()
