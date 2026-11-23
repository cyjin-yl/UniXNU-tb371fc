"""End-to-end CFG, code/data separation and signature checks on original fixtures."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from arm64_lowering.macho import MachOError, parse_macho
from arm64_lowering.pipeline import audit_userland, load_rewriter, rewrite_userland, verify_code_pages
import route_a


def signed_fixture(words=(0xD503233F, 0xD2800540, 0xDAC143E0, 0xD65F0BFF), *,
                   version=0x20100, code_limit64=0):
    """An original arm64e Mach-O: return 42, with PAC-shaped non-code data."""
    base, text_offset, const_offset = 0x100000000, 0x400, 0x500
    signature_offset = 0x1000
    identifier = b"route-a.synthetic\0"
    ident_offset = next(size for minimum, size in (
        (0x20600, 108), (0x20500, 96), (0x20400, 88), (0x20300, 64),
        (0x20200, 52), (0x20100, 48), (0x20001, 44)) if version >= minimum)
    hash_offset = max(88, (ident_offset + len(identifier) + 7) // 8 * 8)
    directory = bytearray(hash_offset + 32)
    struct.pack_into(">9I4BI", directory, 0, 0xFADE0C02, len(directory), version,
                     2, hash_offset, ident_offset, 0, 1, signature_offset, 32, 2, 0, 12, 0)
    if version >= 0x20300:
        struct.pack_into(">Q", directory, 56, code_limit64)
    directory[ident_offset:ident_offset + len(identifier)] = identifier
    signature_size = 20 + len(directory)

    def section(name, offset, size, flags):
        return struct.pack("<16s16s2Q8I", name.encode(), b"__TEXT", base + offset,
                           size, offset, 2, 0, 0, flags, 0, 0, 0)

    text = (struct.pack("<2I16s4Q4I", 0x19, 232, b"__TEXT", base, 0x1000,
                        0, 0x1000, 5, 5, 2, 0)
            + section("__text", text_offset, len(words) * 4, 0x80000400)
            + section("__const", const_offset, 16, 0))
    linkedit = struct.pack("<2I16s4Q4I", 0x19, 72, b"__LINKEDIT", base + 0x1000,
                           0x1000, 0x1000, signature_size, 1, 1, 0, 0)
    commands = [text, linkedit, struct.pack("<2I2Q", 0x80000028, 24, text_offset, 0),
                struct.pack("<4I", 0x1D, 16, signature_offset, signature_size)]
    data = bytearray(signature_offset + signature_size)
    header = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0x80000002, 2,
                         len(commands), sum(map(len, commands)), 0, 0)
    data[:32] = header
    at = 32
    for command in commands:
        data[at:at + len(command)] = command
        at += len(command)
    struct.pack_into(f"<{len(words)}I", data, text_offset, *words)
    struct.pack_into("<4I", data, const_offset, 0xDAC143E0, 0xD65F0BFF, 0x9AC23020, 0)
    directory[hash_offset:hash_offset + 32] = hashlib.sha256(data[:signature_offset]).digest()
    data[signature_offset:] = struct.pack(">5I", 0xFADE0CC0, signature_size, 1, 0, 20) + directory
    return bytes(data)


class PipelineTests(unittest.TestCase):
    def test_cfg_rewrites_code_preserves_pac_shaped_data_and_rehashes(self):
        original = signed_fixture()
        output, report = rewrite_userland(original, plain_pointers=True)
        self.assertEqual(struct.unpack_from("<4I", output, 0x400),
                         (0xD503233F, 0xD2800540, 0xD503201F, 0xD65F03C0))
        self.assertEqual(output[0x500:0x510], original[0x500:0x510])
        self.assertEqual(struct.unpack_from("<I", output, 8)[0], 0)
        self.assertEqual(report["instruction_edits"], 2)
        self.assertFalse(report["os_boot_verified"])
        self.assertFalse(report["authentication_preserved"])
        self.assertEqual(report["platform_identifier"], 0)
        self.assertEqual(report["code_directory_flags"], "0x2")
        self.assertNotEqual(report["original_cdhash"], report["cdhash"])
        # Verify the output page directly, independently of both signers.
        self.assertEqual(output[0x1000 + 20 + 88:0x1000 + 20 + 120],
                         hashlib.sha256(output[:0x1000]).digest())
        self.assertEqual(original, signed_fixture())

    def test_audit_counts_only_instruction_candidates_and_does_not_claim_proof(self):
        report = audit_userland(signed_fixture())
        self.assertEqual(report["candidate_pauth_counts"], {"PACIASP": 1, "RETAA": 1, "XPACI": 1})
        self.assertFalse(report["scan_is_code_proof"])
        self.assertEqual(report["unsupported_candidates"], [])
        self.assertEqual(report["preflight_status"], "candidate_scan_completed")

    def test_known_code_directory_headers_and_matching_64bit_limits(self):
        for version in (0x20001, 0x20100, 0x20200, 0x20300, 0x20400, 0x20500, 0x20600):
            with self.subTest(version=hex(version)):
                data = signed_fixture(version=version, code_limit64=0x1000 if version >= 0x20300 else 0)
                output, report = rewrite_userland(data, plain_pointers=True)
                self.assertEqual(report["independent_signature"]["effective_code_limit"], 0x1000)
                self.assertEqual(report["independent_signature"]["code_directory_version"], hex(version))
                self.assertEqual(report["instruction_edits"], 2)
                verify_code_pages(output, parse_macho(output).code_signature)

    def test_unsupported_signature_layouts_cannot_bypass_public_rewriter(self):
        engine = load_rewriter()
        cases = (
            (0x20100, 44, ">I", 0x726F7574, "scatter"),
            (0x20300, 56, ">Q", 16, "codeLimit64 disagree"),
            (0x20500, 92, ">I", 128, "pre-encryption"),
            (0x20600, 96, ">B", 2, "linked"),
            (0x20600, 8, ">I", 0x20700, "unsupported CodeDirectory version"),
        )
        for version, offset, encoding, value, reason in cases:
            with self.subTest(reason=reason):
                data = bytearray(signed_fixture(version=version))
                struct.pack_into(encoding, data, 0x1014 + offset, value)
                with self.assertRaisesRegex(MachOError, reason):
                    rewrite_userland(bytes(data), plain_pointers=True)
                with self.assertRaisesRegex(MachOError, reason):
                    engine.rewrite(bytes(data))

    def test_versioned_header_and_identifier_bounds_are_enforced(self):
        for field, value, reason in ((4, 100, "versioned CodeDirectory header"),
                                     (20, 44, "identifier offset")):
            with self.subTest(reason=reason):
                data = bytearray(signed_fixture(version=0x20600))
                struct.pack_into(">I", data, 0x1014 + field, value)
                with self.assertRaisesRegex(MachOError, reason):
                    verify_code_pages(bytes(data), parse_macho(data).code_signature)

    def test_modified_original_signature_is_rejected_before_rewrite(self):
        data = bytearray(signed_fixture())
        data[0x500] ^= 1
        with self.assertRaisesRegex(MachOError, "hash mismatch"):
            rewrite_userland(bytes(data), plain_pointers=True)
        # The public vendor API and the tree rewriter must not bypass this gate.
        with self.assertRaisesRegex(MachOError, "hash mismatch"):
            load_rewriter().rewrite(bytes(data))

    def test_pacga_refuses_a_plausible_but_semantically_invalid_replacement(self):
        data = signed_fixture((0x9AC23020, 0xD65F0BFF))
        with self.assertRaisesRegex(ValueError, "PACGA|pacga"):
            rewrite_userland(data, plain_pointers=True)

    def test_plain_pointer_contract_is_required(self):
        with self.assertRaisesRegex(MachOError, "explicitly"):
            rewrite_userland(signed_fixture())

    def test_explicit_signing_overrides_are_rehashed(self):
        output, report = rewrite_userland(signed_fixture(), plain_pointers=True,
                                         platform_identifier=26, hardened_runtime=True)
        self.assertEqual(report["platform_identifier"], 26)
        self.assertEqual(report["code_directory_flags"], "0x10002")
        verify_code_pages(output, parse_macho(output).code_signature)

    def test_cli_writes_a_new_staged_artifact_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output, report = root / "input", root / "output", root / "report.json"
            source.write_bytes(signed_fixture())
            command = [sys.executable, str(ROOT / "scripts/route_a.py"), "rewrite", "--profile", "ipados27",
                       "--input", str(source), "--output", str(output), "--report", str(report),
                       "--plain-pointer-abi"]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            saved = output.read_bytes()
            metadata = json.loads(report.read_text())
            self.assertFalse(metadata["target"]["manifest_verified"])
            self.assertFalse(metadata["owner_trust_entry_ready"])
            self.assertFalse(metadata["os_boot_verified"])
            again = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(again.returncode, 0)
            self.assertEqual(output.read_bytes(), saved)

    def test_cli_audit_unsupported_candidate_is_nonzero_and_not_code_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            source, report = Path(directory) / "input", Path(directory) / "report.json"
            source.write_bytes(signed_fixture((0x9AC23020, 0xD65F0BFF)))
            result = subprocess.run([sys.executable, str(ROOT / "scripts/route_a.py"), "audit",
                                     "--profile", "ipados27", "--input", str(source), "--report", str(report)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stderr)
            metadata = json.loads(report.read_text())
            self.assertEqual(metadata["preflight_status"], "blocked")
            self.assertEqual(metadata["unsupported_candidates"][0]["mnemonic"], "PACGA")
            self.assertFalse(metadata["scan_is_code_proof"])

    def test_bad_report_parent_leaves_no_output_or_temporary_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output, report = root / "input", root / "output", root / "absent" / "report.json"
            source.write_bytes(signed_fixture())
            result = subprocess.run([sys.executable, str(ROOT / "scripts/route_a.py"), "rewrite",
                                     "--profile", "ipados27", "--input", str(source), "--output", str(output),
                                     "--report", str(report), "--plain-pointer-abi"], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(output.exists())
            self.assertFalse(report.exists())
            self.assertEqual(list(root.iterdir()), [source])

    def test_publication_collision_preserves_other_file_and_rolls_back_own_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, report = root / "output", root / "report.json"
            original_link = os.link

            def competing_writer(source, target, **kwargs):
                if target == output:
                    output.write_bytes(b"other writer")
                return original_link(source, target, **kwargs)

            with mock.patch.object(route_a.os, "link", side_effect=competing_writer):
                with self.assertRaises(FileExistsError):
                    with route_a.staged_new_outputs(output, report) as (output_stage, report_stage):
                        output_stage.write_bytes(b"our staged binary")
                        report_stage.write_text("{}\n")
            self.assertEqual(output.read_bytes(), b"other writer")
            self.assertFalse(report.exists())
            self.assertEqual(list(root.iterdir()), [output])


if __name__ == "__main__":
    unittest.main()
