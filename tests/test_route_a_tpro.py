"""TPRO audit regression tests with original synthetic Mach-O fixtures.

No Apple binary, kernel boot or Cortex-A77 execution is required or implied.
"""
import contextlib
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import audit_route_a_tpro as tpro
from test_route_a_pipeline import signed_fixture


class TproInstructionInventoryTests(unittest.TestCase):
    def test_direct_branch_goldens_include_signed_immediates(self):
        # A64 B .+4 / BL .-4 / B.EQ .+8 / CBZ X0,.-4 / CBNZ W1,.+8.
        vectors = [
            (0x14000001, "b", 0x1004),
            (0x97FFFFFF, "bl", 0x0FFC),
            (0x54000040, "b.cond", 0x1008),
            (0xB4FFFFE0, "cbz", 0x0FFC),
            (0x35000041, "cbnz", 0x1008),
        ]
        for word, kind, target in vectors:
            with self.subTest(word=hex(word)):
                decoded = tpro.direct_branch(word, 0x1000)
                self.assertEqual(decoded["kind"], kind)
                self.assertEqual(decoded["target"], target)
        self.assertEqual(tpro.direct_branch(0xB4FFFFE0, 0x1000)["width"], 64)
        self.assertEqual(tpro.direct_branch(0x35000041, 0x1000)["width"], 32)

    def test_bit_test_branches_preserve_bit_32_and_negative_target(self):
        decoded = tpro.direct_branch(0xB707FFE3, 0x1000)  # TBNZ X3,#32,.-4
        self.assertEqual(decoded, {"kind": "tbnz", "register": 3, "bit": 32, "target": 0x0FFC})
        decoded = tpro.direct_branch(0x36780042, 0x1000)  # TBZ W2,#15,.+8
        self.assertEqual(decoded, {"kind": "tbz", "register": 2, "bit": 15, "target": 0x1008})

    def test_unmodeled_control_flow_is_not_invented(self):
        for word in (0xD61F0000, 0xD63F0000, 0xD65F03C0, 0x54000050, 0xD5900040):
            self.assertIsNone(tpro.direct_branch(word, 0x1000))

    def test_system_register_fields_and_direction(self):
        self.assertEqual(tpro.system_register(0xD53EF1A0),
                         {"kind": "mrs", "system_register": "s3_6_c15_c1_5", "register": 0})
        self.assertEqual(tpro.system_register(0xD51EF1A9),
                         {"kind": "msr", "system_register": "s3_6_c15_c1_5", "register": 9})
        self.assertEqual(tpro.system_register(0xD53B4062),
                         {"kind": "mrs", "system_register": "s3_3_c4_c0_3", "register": 2})
        self.assertEqual(tpro.system_register(0xD53BD040)["system_register"], "s3_3_c13_c0_2")

    def test_sys_hints_and_tchange_are_not_register_transfers(self):
        for word in (0xD503201F, 0xD5080000, 0xD5280000, 0xD5900040, 0xD5940000):
            self.assertIsNone(tpro.system_register(word))

    def test_adr_and_adrp_add_goldens(self):
        self.assertEqual(tpro.materialized_address(0x10000040, None, 0x1000),
                         {"kind": "adr", "target": 0x1008, "register": 0, "instruction_count": 1})
        self.assertEqual(tpro.materialized_address(0x10FFFFE0, None, 0x1000)["target"], 0x0FFC)
        # ADRP X0,.-4096; ADD X0,X0,#0x123 at an unaligned PC.
        self.assertEqual(tpro.materialized_address(0xF0FFFFE0, 0x91048C00, 0x2128),
                         {"kind": "adrp+add", "target": 0x1123, "register": 0, "instruction_count": 2})

    def test_adrp_pair_rejects_gaps_other_registers_flags_and_shifted_add(self):
        for following in (None, 0xD503201F, 0x91048C01, 0x91048C20, 0xB1048C00, 0x91448C00):
            self.assertIsNone(tpro.materialized_address(0xF0FFFFE0, following, 0x2128))
        self.assertIsNone(tpro.materialized_address(0x1000005F, None, 0x1000))
        self.assertIsNone(tpro.materialized_address(0xD503201F, 0x91000000, 0x1000))

    def test_census_respects_instruction_sections(self):
        fixture = bytearray(signed_fixture(words=(0xD5900040, 0xD5940000, 0xD53EF1A0, 0xD65F03C0)))
        struct.pack_into("<I", fixture, 0x500, 0xD5900040)  # non-code __const
        report = tpro.candidate_inventory(bytes(fixture))
        self.assertEqual(len(report["transitions"]), 2)
        self.assertEqual(len(report["system_registers"]), 1)
        self.assertEqual(report["candidate_word_count"], 4)
        self.assertEqual([r["file_offset"] for r in report["transitions"]], ["0x400", "0x404"])
        self.assertFalse(report["scan_is_code_proof"])

    def test_unknown_neighbor_does_not_enter_transition_census(self):
        report = tpro.candidate_inventory(signed_fixture(words=(0xD5901040, 0xD5941000, 0xD65F03C0)))
        self.assertEqual(report["transitions"], [])

    def test_inventory_pairs_do_not_cross_section_end(self):
        # The word after __text is zero padding, and a fabricated pair in
        # __const must not become an instruction reference.
        fixture = bytearray(signed_fixture(words=(0x90000000,)))
        struct.pack_into("<2I", fixture, 0x500, 0x90000000, 0x91000000)
        report = tpro.candidate_inventory(bytes(fixture))
        self.assertEqual(report["materialized_addresses"], [])


class TproSourceAndContractTests(unittest.TestCase):
    def test_default_audit_diagnostics_do_not_decode_or_access_image(self):
        decoder = mock.Mock(side_effect=AssertionError("disassembly must be opt-in"))
        with mock.patch.dict(sys.modules, {"zeta_userland_code": SimpleNamespace(decode=decoder)}):
            self.assertEqual(tpro.collect_disassembly_windows(b"", object()), [])
        decoder.assert_not_called()

    def test_opt_in_diagnostics_use_requested_windows(self):
        decoder = mock.Mock(return_value={0x3BE0: ("nop", ""), 0x5A90: ("ret", "")})
        image = tpro.parse_macho(signed_fixture())
        with mock.patch.dict(sys.modules, {"zeta_userland_code": SimpleNamespace(decode=decoder)}):
            windows = tpro.collect_disassembly_windows(b"synthetic", image, enabled=True)
        decoder.assert_called_once()
        self.assertEqual(windows[0]["instructions"], [{"address": "0x3be0", "mnemonic": "nop", "operands": ""}])
        self.assertFalse(any(row["address"] == "0x5a90" for window in windows for row in window["instructions"]))

    def test_source_pin_cannot_be_satisfied_by_valid_synthetic_macho(self):
        with self.assertRaisesRegex(tpro.AuditError, "source mismatch"):
            tpro.audit_bytes(signed_fixture())

    def test_empty_or_zero_feature_values_are_still_present(self):
        for key in tpro.FEATURE_KEYS:
            for suffix in ("=", "=0", "=1", "=false"):
                with self.subTest(key=key, suffix=suffix):
                    report = tpro.check_apple_vector([key + suffix])
                    self.assertEqual(report["present_keys"], [key])
                    self.assertFalse(report["non_tpro_keys_absent"])

    def test_bare_feature_name_is_rejected_as_malformed(self):
        report = tpro.check_apple_vector(["dyld_hw_tpro"])
        self.assertEqual(report["present_keys"], [])
        self.assertEqual(report["malformed_feature_entries"], ["dyld_hw_tpro"])
        self.assertFalse(report["non_tpro_keys_absent"])

    def test_two_independent_feature_keys_and_exact_matching(self):
        report = tpro.check_apple_vector(["dyld_hw_tpro=0", "dyld_hw_tpro_pagers=0"])
        self.assertEqual(report["present_keys"], list(tpro.FEATURE_KEYS))
        report = tpro.check_apple_vector(["dyld_hw_tpro_extra=1", "PATH=dyld_hw_tpro=1"])
        self.assertTrue(report["non_tpro_keys_absent"])
        self.assertFalse(report["runtime_dispatch_verified"])
        self.assertFalse(report["commpage_verified"])
        self.assertFalse(report["vm_protection_verified"])

    def test_vector_rejects_embedded_nuls_and_non_strings(self):
        for entries in (["dyld_hw_tpro\0=0"], [0], [None], [{}]):
            with self.assertRaises(tpro.AuditError):
                tpro.check_apple_vector(entries)

    def test_cli_refuses_existing_report_without_touching_it(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            output = path / "report.json"
            output.write_text("keep", encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                rc = tpro.main(["--input", str(path / "missing"), "--report", str(output)])
            self.assertEqual(rc, 2)
            self.assertEqual(output.read_text(encoding="utf-8"), "keep")

    def test_cli_wrong_source_or_vector_produces_no_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            binary, vector, output = path / "synthetic", path / "apple.json", path / "report.json"
            binary.write_bytes(signed_fixture())
            vector.write_text(json.dumps({"dyld_hw_tpro": "0"}), encoding="utf-8")
            for extra in ([], ["--apple-vector", str(vector)]):
                with contextlib.redirect_stderr(io.StringIO()):
                    rc = tpro.main(["--input", str(binary), "--report", str(output), *extra])
                self.assertEqual(rc, 2)
                self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
