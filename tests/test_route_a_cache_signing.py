"""Synthetic cache signatures exercise the actual signer and preflight gates.

CFG/proof admission is mocked only in main-level signer tests; it has its own
suite. All cache bytes, signatures, trust entries and expected edits are local
fixtures, not Apple payloads.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from arm64_lowering.macho import MachOError
from arm64_lowering.pipeline import validated_code_directory, verify_code_pages

SPEC = importlib.util.spec_from_file_location(
    "route_a_cache_signer_tests", ROOT / "scripts/route_a_zeta/rewrite-zeta-dyld-cache.py")
signer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(signer)

SIGNATURE_OFFSET, SIGNATURE_SIZE, EDIT_OFFSET = 0x4000, 0x4000, 0x1000
BEFORE, AFTER = 0xD65F0FFF, 0xD65F03C0
ATTRIBUTES = bytes((2, 0x12, 7, 0))


def signed_cache(*, version=0x20100, limit64=0):
    data = bytearray(SIGNATURE_OFFSET + SIGNATURE_SIZE)
    data[:16] = b"dyld_v1  arm64e".ljust(16, b"\0")
    data[0x58:0x68] = bytes(range(1, 17))
    struct.pack_into("<II", data, 0x10, 0x200, 1)
    struct.pack_into("<QQ", data, 0x28, SIGNATURE_OFFSET, SIGNATURE_SIZE)
    struct.pack_into("<QQQII", data, 0x200, 0x180000000, SIGNATURE_OFFSET, 0, 5, 5)
    struct.pack_into("<I", data, EDIT_OFFSET, BEFORE)
    ident = b"route-a.cache.fixture\0"
    header = 64 if version >= 0x20300 else 48
    special = 1
    hash_offset = (header + len(ident) + 7) // 8 * 8 + special * 32
    directory = bytearray(hash_offset + 32)
    struct.pack_into(">9I4BI", directory, 0, 0xFADE0C02, len(directory), version,
                     0x10002, hash_offset, header, special, 1, SIGNATURE_OFFSET,
                     32, 2, 7, 14, 0)
    if version >= 0x20300:
        struct.pack_into(">Q", directory, 56, limit64)
    directory[header:header + len(ident)] = ident
    directory[hash_offset - 32:hash_offset] = b"S" * 32
    directory[hash_offset:] = hashlib.sha256(data[:SIGNATURE_OFFSET]).digest()
    signature = struct.pack(">5I", 0xFADE0CC0, 20 + len(directory), 1, 0, 20) + directory
    data[SIGNATURE_OFFSET:SIGNATURE_OFFSET + len(signature)] = signature
    return bytes(data)


def der(tag, data):
    size = len(data)
    length = bytes((size,)) if size < 128 else bytes((0x82,)) + size.to_bytes(2, "big")
    return bytes((tag,)) + length + data


def trust_cache(original, kind="trcs"):
    cdhash = signer.verify_signature(original, SIGNATURE_OFFSET, SIGNATURE_SIZE)
    payload = struct.pack("<I16sI", 2, bytes(16), 1) + bytes.fromhex(cdhash) + ATTRIBUTES
    return der(0x30, der(0x16, b"IM4P") + der(0x16, kind.encode()) +
               der(0x16, b"synthetic trust") + der(4, payload))


class CacheSigningTests(unittest.TestCase):
    def test_all_signing_entrypoints_reject_scatter_bad_limit64_and_unknown_version(self):
        for version, relative, encoding, value, reason in (
            (0x20100, 44, ">I", 4, "scatter"),
            (0x20300, 56, ">Q", SIGNATURE_OFFSET + 4, "codeLimit64 disagree"),
            (0x20300, 8, ">I", 0x20700, "unsupported CodeDirectory version"),
        ):
            data = bytearray(signed_cache(version=version))
            struct.pack_into(encoding, data, SIGNATURE_OFFSET + 20 + relative, value)
            for function in (
                lambda: signer.code_directory(data, SIGNATURE_OFFSET, SIGNATURE_SIZE),
                lambda: signer.verify_signature(data, SIGNATURE_OFFSET, SIGNATURE_SIZE),
                lambda: signer.resign(data, SIGNATURE_OFFSET, SIGNATURE_SIZE, [EDIT_OFFSET]),
                lambda: signer.signature_length(data, SIGNATURE_OFFSET, SIGNATURE_SIZE, 12),
                lambda: signer.rebuilt_signature(memoryview(data)[:SIGNATURE_OFFSET], data,
                                                   SIGNATURE_OFFSET, SIGNATURE_SIZE, 12),
            ):
                with self.subTest(reason=reason), self.assertRaisesRegex(MachOError, reason):
                    function()

    def test_rebuilding_preserves_matching_limit64_policy_and_special_slots(self):
        original = signed_cache(version=0x20300, limit64=SIGNATURE_OFFSET)
        verify_code_pages(original, dict(offset=SIGNATURE_OFFSET, size=SIGNATURE_SIZE))
        code = bytearray(memoryview(original)[:SIGNATURE_OFFSET])
        struct.pack_into("<I", code, EDIT_OFFSET, AFTER)
        rebuilt, cdhash = signer.rebuilt_signature(code, original, SIGNATURE_OFFSET, SIGNATURE_SIZE, 12)
        self.assertEqual(len(rebuilt), signer.signature_length(original, SIGNATURE_OFFSET, SIGNATURE_SIZE, 12))
        output = code + rebuilt + bytes(SIGNATURE_SIZE - len(rebuilt))
        verified = verify_code_pages(output, dict(offset=SIGNATURE_OFFSET, size=SIGNATURE_SIZE))
        self.assertEqual(verified["cdhash"], cdhash)
        self.assertEqual(verified["code_pages_verified"], 4)
        layout = validated_code_directory(output, dict(offset=SIGNATURE_OFFSET, size=SIGNATURE_SIZE))
        self.assertEqual(layout["code_limit64"], SIGNATURE_OFFSET)
        self.assertEqual(layout["flags"], 0x10002)
        self.assertEqual(output[layout["at"] + 38], 7)
        start = layout["at"] + layout["hash_offset"]
        self.assertEqual(output[start - 32:start], b"S" * 32)

    def prepare_run(self, root, original, *, kind="trcs", edited=True, page_shift=None):
        source, trust, proof = root / "dyld_shared_cache_arm64e", root / "trust", root / "proof"
        source.write_bytes(original)
        trust.write_bytes(trust_cache(original, kind))
        proof.mkdir()
        # This signer-only fixture mocks admission with the default reject
        # policy; no PACGA runtime is selected by that policy.
        (proof / "summary.json").write_text(json.dumps(
            {"totals": {"edits": int(edited)}, "rules": {"pacga_runtime": None}}))
        output, report = root / "output", root / "report.json"
        args = ["--cache", str(source), "--proof", str(proof), "--output", str(output),
                "--apple-trust-cache", str(trust), "--report", str(report)]
        if page_shift is not None:
            args += ["--page-shift", str(page_shift)]
        edits = {0: np.array([[EDIT_OFFSET, BEFORE, AFTER]], dtype=np.uint64)} if edited else {}
        return source, output, report, args, edits

    def invoke(self, args, edits):
        with mock.patch.object(signer, "validate_summary", return_value=edits), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return signer.main(args)

    def test_tampered_original_is_rejected_before_output_or_signer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output, report, args, edits = self.prepare_run(root, signed_cache())
            tampered = bytearray(source.read_bytes())
            tampered[0x2000] ^= 1
            source.write_bytes(tampered)
            with mock.patch.object(signer, "resign") as resign:
                self.assertEqual(self.invoke(args, edits), 2)
                resign.assert_not_called()
            self.assertFalse(output.exists())
            self.assertFalse(report.exists())

    def test_later_subcache_is_checked_before_any_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output, report, args, edits = self.prepare_run(root, signed_cache())
            bad = bytearray(signed_cache())
            bad[0x2000] ^= 1
            cache = SimpleNamespace(files=[
                SimpleNamespace(path=source, data=signed_cache(), signature=(SIGNATURE_OFFSET, SIGNATURE_SIZE)),
                SimpleNamespace(path=root / "subcache", data=bad, signature=(SIGNATURE_OFFSET, SIGNATURE_SIZE)),
            ])
            with mock.patch.object(signer.dc, "Cache", return_value=cache):
                self.assertEqual(self.invoke(args, edits), 2)
            self.assertFalse(output.exists())
            self.assertFalse(report.exists())

    def test_actual_rewrite_and_copy_record_independent_checks_and_original_attributes(self):
        cases = (("trst", None, True), ("trcs", None, True),
                 ("trcs", 12, True), ("trcs", 12, False), ("trst", None, False))
        for kind, shift, edited in cases:
            with self.subTest(kind=kind, shift=shift, edited=edited), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source, output, report, args, edits = self.prepare_run(
                    root, signed_cache(), kind=kind, edited=edited, page_shift=shift)
                self.assertEqual(self.invoke(args, edits), 0)
                metadata = json.loads(report.read_text())
                entry = metadata["files"][0]
                actual = (output / source.name).read_bytes()
                verified = verify_code_pages(actual, dict(offset=SIGNATURE_OFFSET, size=SIGNATURE_SIZE))
                self.assertEqual(entry["independent_signature"], verified)
                self.assertEqual(entry["original_signature"]["code_pages_verified"], 1)
                self.assertEqual(verified["code_pages_verified"], 4 if shift == 12 else 1)
                self.assertEqual(struct.unpack_from("<I", actual, EDIT_OFFSET)[0], AFTER if edited else BEFORE)
                self.assertEqual(metadata["apple_trust_sources"][0]["im4p_type"], kind)
                for field in ("target_isa_audited", "os_boot_verified", "hardware_tested"):
                    self.assertIs(metadata[field], False)
                self.assertTrue(metadata["all_original_code_pages_verified"])
                self.assertTrue(metadata["all_output_code_pages_verified"])
                if edited or shift is not None:
                    trust = entry["trust_cache_entry"]
                    self.assertEqual((trust["hash_type"], trust["flags"], trust["constraint_category"], trust["reserved0"]),
                                     tuple(ATTRIBUTES))
                    self.assertEqual(trust["attributes_hex"], ATTRIBUTES.hex())
                    self.assertEqual(metadata["files_changed"], 1)

    def test_unknown_trust_envelope_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, output, report, args, edits = self.prepare_run(root, signed_cache(), kind="trca")
            self.assertEqual(self.invoke(args, edits), 2)
            self.assertFalse(output.exists())
            self.assertFalse(report.exists())

    def test_independent_output_verifier_catches_a_faulty_signer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = signed_cache()
            source, output, report, args, edits = self.prepare_run(root, original)
            cdhash = signer.verify_signature(original, SIGNATURE_OFFSET, SIGNATURE_SIZE)
            with mock.patch.object(signer, "resign", return_value=(cdhash, 1)):
                self.assertEqual(self.invoke(args, edits), 2)
            self.assertFalse((output / source.name).exists())
            self.assertFalse(report.exists())


if __name__ == "__main__":
    unittest.main()
