"""Trust-cache container types encountered in the official 27 restore input."""

import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from route_a import add_trust_entry


def tlv(tag, data):
    if len(data) >= 128:
        raise ValueError("the original test fixture uses only short DER lengths")
    return bytes((tag, len(data))) + data


def container(kind, original):
    payload = (struct.pack("<I", 2) + bytes(range(16)) + struct.pack("<I", 1)
               + bytes.fromhex(original) + bytes((2, 1, 3, 0)))
    return tlv(0x30, tlv(0x16, b"IM4P") + tlv(0x16, kind.encode())
               + tlv(0x16, b"synthetic trust") + tlv(0x04, payload))


class TrustInputTests(unittest.TestCase):
    def test_static_and_cryptex_types_preserve_original_attributes(self):
        original, rewritten = "12" * 20, "34" * 20
        for kind in ("trst", "trcs"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "synthetic.trustcache"
                data = container(kind, original)
                path.write_bytes(data)
                report = dict(original_cdhash=original, cdhash=rewritten)
                add_trust_entry(report, [path])
                self.assertTrue(report["owner_trust_entry_ready"])
                self.assertFalse(report["owner_trust_bundle_installed"])
                self.assertEqual(report["trust_cache_entry"], dict(
                    cdhash=rewritten, hash_type=2, flags=1,
                    constraint_category=3, copied_from_original=True))
                self.assertEqual(report["trust_cache_inputs"][0]["im4p_type"], kind)
                self.assertEqual(report["trust_cache_inputs"][0]["sha256"], hashlib.sha256(data).hexdigest())

    def test_other_im4p_type_is_not_accepted_by_payload_shape(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "other.im4p"
            path.write_bytes(container("krnl", "12" * 20))
            with self.assertRaisesRegex(ValueError, "unexpected trust-cache IM4P type"):
                add_trust_entry(dict(original_cdhash="12" * 20, cdhash="34" * 20), [path])


if __name__ == "__main__":
    unittest.main()
