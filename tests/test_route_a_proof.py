"""Synthetic cache fixtures exercise proof admission and the actual rewriter gate.

No Apple binaries are included. Expected RETAB -> RET encodings are fixed
architectural vectors, independent of the implementation's edit generator.
"""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from arm64_lowering.proof import seal_summary, validate_summary
from route_a_zeta import zeta_dyld_cache as dc

BASE = 0x180000000
BEFORE, AFTER = 0xD65F0FFF, 0xD65F03C0


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts/route_a_zeta" / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def cache_bytes(images=1, *, island=False):
    data = bytearray(0x5000)
    data[:16] = b"dyld_v1  arm64e".ljust(16, b"\0")
    data[0x58:0x68] = bytes(range(1, 17))
    struct.pack_into("<II", data, 0x10, 0x200, 1)
    struct.pack_into("<QQ", data, 0x28, 0x4000, 0x1000)
    struct.pack_into("<QQQII", data, 0x200, BASE, 0x3000, 0x1000, 5, 5)
    struct.pack_into("<II", data, 0x1C0, 0x300, images)
    if island:
        # A distinct executable mapping marks a stub island. All geometry is
        # read through the real cache parser, not a mocked inventory helper.
        struct.pack_into("<II", data, 0x10, 0x200, 2)
        struct.pack_into("<QQQII", data, 0x200, BASE, 0x2000, 0x1000, 5, 5)
        struct.pack_into("<QQQII", data, 0x220, BASE + 0x2000, 0x1000, 0x3000, 5, 5)
        struct.pack_into("<II", data, 0x138, 0x240, 1)
        struct.pack_into("<QQQQQQII", data, 0x240, BASE + 0x2000, 0x1000, 0x3000, 0, 0, 8, 5, 5)
        struct.pack_into("<I", data, 0x3000, BEFORE)
    for index in range(images):
        address, offset = BASE + index * 0x1000, 0x1000 + index * 0x1000
        path_offset = 0x400 + index * 64
        name = f"/usr/lib/test{index}.dylib".encode() + b"\0"
        data[path_offset:path_offset + len(name)] = name
        struct.pack_into("<QQQI", data, 0x300 + 32 * index, address, 0, 0, path_offset)
        struct.pack_into("<8I", data, offset, 0xFEEDFACF, 0x0100000C, 2, 6, 1, 152, 0x80000000, 0)
        struct.pack_into("<2I16s4Q4I", data, offset + 32, 0x19, 152, b"__TEXT", address,
                         0x1000, offset, 0x1000, 5, 5, 1, 0)
        struct.pack_into("<16s16s2Q8I", data, offset + 104, b"__text", b"__TEXT",
                         address + 0x100, 4, offset + 0x100, 2, 0, 0, 0x80000400, 0, 0, 0)
        struct.pack_into("<I", data, offset + 0x100, BEFORE)
    return data


def signed_image(*, platform=7, flags=2):
    """A tiny ad-hoc executable with a function-start root and real page slots."""
    data = bytearray(0x1300)
    text = struct.pack("<2I16s4Q4I", 0x19, 152, b"__TEXT", BASE, 0x1000, 0, 0x1000, 5, 5, 1, 0)
    text += struct.pack("<16s16s2Q8I", b"__text", b"__TEXT", BASE + 0x400,
                        4, 0x400, 2, 0, 0, 0x80000400, 0, 0, 0)
    linkedit = struct.pack("<2I16s4Q4I", 0x19, 72, b"__LINKEDIT", BASE + 0x1000,
                           0x1000, 0x1000, 0x300, 1, 1, 0, 0)
    commands = text + linkedit + struct.pack("<4I", 0x26, 16, 0x1000, 3)
    commands += struct.pack("<4I", 0x1D, 16, 0x1100, 0x200)
    struct.pack_into("<8I", data, 0, 0xFEEDFACF, 0x0100000C, 0x80000002, 2, 4, len(commands), 0, 0)
    data[32:32 + len(commands)] = commands
    struct.pack_into("<I", data, 0x400, BEFORE)
    data[0x1000:0x1003] = bytes([0x80, 0x08, 0])
    struct.pack_into(">5I", data, 0x1100, 0xFADE0CC0, 180, 1, 0, 20)
    struct.pack_into(">9I4B", data, 0x1114, 0xFADE0C02, 160, 0x20400, flags,
                     96, 88, 0, 2, 0x1100, 32, 2, platform, 12)
    data[0x1114 + 88:0x1114 + 96] = b"fixture\0"
    import hashlib
    for index in range(2):
        page = data[index * 4096:min((index + 1) * 4096, 0x1100)]
        data[0x1114 + 96 + 32 * index:0x1114 + 128 + 32 * index] = hashlib.sha256(page).digest()
    return bytes(data)


class CacheProofTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.cache_path = self.work / "dyld_shared_cache_arm64e"
        self.cache_path.write_bytes(cache_bytes())
        self.cache = self.open_cache()
        self.summary = self.make_summary(self.cache)

    def open_cache(self):
        cache = dc.Cache(self.cache_path)
        for item in cache.files:
            self.addCleanup(item.handle.close)
            self.addCleanup(item.data.close)
        return cache

    def write_result(self, name, edits, unproven=()):
        np.savez_compressed(self.work / name, edits=np.array(edits, dtype=np.uint64).reshape(-1, 5),
                            unproven=np.array(unproven, dtype=np.uint64).reshape(-1, 2),
                            kept_data=np.zeros((0, 3), dtype=np.uint64))

    def make_summary(self, cache):
        summary = dict(images={}, islands=[], totals={"edits": 0, "unproven": 0, "unlowerable": 0})
        for index, (address, path) in enumerate(cache.images):
            _, offset, _ = cache.locate(address + 0x100)
            name = f"image{index}.npz"
            self.write_result(name, [(address + 0x100, offset, BEFORE, AFTER, 0)])
            summary["images"][path] = dict(file=0, unlowerable=[], unproven_count=0, edit_count=1,
                                            edits_by_evidence={"unwind": 1}, result_file=name)
            summary["totals"]["edits"] += 1
        summary["totals"]["edits:unwind"] = summary["totals"]["edits"]
        return seal_summary(cache, summary, self.work)

    def refresh(self):
        self.summary = seal_summary(self.cache, self.summary, self.work)

    def rejected(self, pattern):
        with self.assertRaisesRegex(ValueError, pattern):
            validate_summary(self.cache, self.summary, self.work)

    def test_complete_bound_proof_admits_expected_edit(self):
        result = validate_summary(self.cache, self.summary, self.work)
        self.assertEqual(result[0].tolist(), [[0x1100, BEFORE, AFTER]])

    def test_whole_input_digest_rejects_non_edit_change(self):
        changed = bytearray(self.cache.files[0].data)
        changed[0x800] ^= 1
        self.cache_path.write_bytes(changed)
        self.cache = self.open_cache()
        self.rejected("file set/content/UUID")

    def test_uuid_or_size_mismatch_is_not_just_filename_binding(self):
        for field, value in (("uuid", "f" * 32), ("size", 1)):
            with self.subTest(field=field):
                original = self.summary["source_manifest"]["files"][0][field]
                self.summary["source_manifest"]["files"][0][field] = value
                self.rejected("file set/content/UUID")
                self.summary["source_manifest"]["files"][0][field] = original

    def test_added_subcache_is_rejected(self):
        original = self.cache.files[0]
        import types
        child = bytearray(original.data)
        child[0x58:0x68] = bytes(range(17, 33))
        self.cache.files.append(types.SimpleNamespace(path=Path(str(original.path) + ".1"), data=child))
        self.rejected("file set/content/UUID")

    def test_digest_checks_result_even_when_words_match(self):
        with (self.work / "image0.npz").open("ab") as stream:
            stream.write(b"changed")
        self.rejected("result digest")

    def test_partial_only_proof_is_never_admitted(self):
        self.summary = seal_summary(self.cache, self.summary, self.work, partial=True)
        self.rejected("partial proof")

    def test_omitted_image_is_detected_from_input(self):
        self.cache_path.write_bytes(cache_bytes(images=2))
        self.cache = self.open_cache()
        self.summary = self.make_summary(self.cache)
        del self.summary["images"]["/usr/lib/test1.dylib"]
        self.rejected("every code-bearing image")

    def test_omitted_island_is_detected_from_input(self):
        self.cache_path.write_bytes(cache_bytes(island=True))
        self.cache = self.open_cache()
        self.summary = self.make_summary(self.cache)
        self.rejected("every stub island")

    def test_complete_island_inventory_is_admitted(self):
        self.cache_path.write_bytes(cache_bytes(island=True))
        self.cache = self.open_cache()
        self.summary = self.make_summary(self.cache)
        self.write_result("island.npz", [(BASE + 0x2000, 0x3000, BEFORE, AFTER, 4)])
        self.summary["islands"] = [dict(address=hex(BASE + 0x2000), size=0x1000, file=0,
                                         unlowerable=[], unproven_count=0, edit_count=1,
                                         edits_by_evidence={"call": 1}, result_file="island.npz")]
        self.summary["totals"]["edits"] = 2
        self.summary["totals"]["edits:call"] = 1
        self.refresh()
        self.assertEqual(len(validate_summary(self.cache, self.summary, self.work)[0]), 2)

    def test_unproven_and_unlowerable_cannot_be_hidden_in_counts(self):
        for field in ("unproven", "unlowerable"):
            with self.subTest(field=field):
                self.summary["totals"][field] = 1
                self.rejected("unproven or unlowerable")
                self.summary["totals"][field] = 0
        self.summary["images"]["/usr/lib/test0.dylib"]["unlowerable"] = ["PACGA"]
        self.rejected("entry contains")

    def test_unproven_array_cannot_be_hidden_by_zero_count(self):
        self.write_result("image0.npz", [(BASE + 0x100, 0x1100, BEFORE, AFTER, 0)], [(BASE, BEFORE)])
        self.refresh()
        self.rejected("array contains unproven")

    def test_current_rule_recomputed_after_result_is_resealed(self):
        self.write_result("image0.npz", [(BASE + 0x100, 0x1100, BEFORE, 0xD503201F, 0)])
        self.refresh()
        self.rejected("replacement differs")

    def test_omitted_edit_cannot_be_hidden_by_zero_count(self):
        self.write_result("image0.npz", [])
        self.summary["images"]["/usr/lib/test0.dylib"].update(edit_count=0, edits_by_evidence={})
        self.summary["totals"] = dict(edits=0, unproven=0, unlowerable=0)
        self.refresh()
        self.rejected("every PAuth candidate")

    def test_candidate_cannot_be_relabelled_as_data_without_dispatch(self):
        np.savez_compressed(self.work / "image0.npz", edits=np.zeros((0, 5), dtype=np.uint64),
                            unproven=np.zeros((0, 2), dtype=np.uint64),
                            kept_data=np.array([[BASE + 0x100, 0x1100, BEFORE]], dtype=np.uint64))
        self.summary["images"]["/usr/lib/test0.dylib"].update(edit_count=0, edits_by_evidence={}, kept={"table": 1})
        self.summary["totals"] = dict(edits=0, unproven=0, unlowerable=0)
        self.refresh()
        self.rejected("not in a decoded jump table")

    def test_duplicate_edits_are_rejected(self):
        row = (BASE + 0x100, 0x1100, BEFORE, AFTER, 0)
        self.write_result("image0.npz", [row, row])
        entry = self.summary["images"]["/usr/lib/test0.dylib"]
        entry.update(edit_count=2, edits_by_evidence={"unwind": 2})
        self.summary["totals"].update(edits=2, **{"edits:unwind": 2})
        self.refresh()
        self.rejected("share a word")

    def test_misaligned_outside_code_and_forged_virtual_address(self):
        for address, offset, pattern in ((BASE + 0x101, 0x1101, "unaligned"),
                                         (BASE + 0x104, 0x1104, "outside its"),
                                         (BASE + 0x104, 0x1100, "outside its"),
                                         (BASE + 0x3000, 0x4000, "inside signature")):
            with self.subTest(offset=offset, address=address):
                self.write_result("image0.npz", [(address, offset, BEFORE, AFTER, 0)])
                self.refresh()
                self.rejected(pattern + "|every PAuth candidate")

    def test_rule_revision_rejects_stale_proof(self):
        self.summary["rules"]["pacga_policy"] = "invent-a-result"
        self.rejected("rules differ")

    def test_decoder_revision_rejects_stale_proof(self):
        self.summary["rules"]["decoders"]["capstone"] = "different-decoder"
        self.rejected("rules differ")

    def test_result_path_escape_rejected(self):
        self.summary["images"]["/usr/lib/test0.dylib"]["result_file"] = "../image0.npz"
        with self.assertRaisesRegex(ValueError, "local .npz filename"):
            seal_summary(self.cache, self.summary, self.work)

    def test_cache_rewriter_calls_gate_before_creating_output(self):
        self.summary["complete"] = False
        (self.work / "summary.json").write_text(json.dumps(self.summary))
        rewriter = module("rewrite-zeta-dyld-cache")
        output = self.work / "output"
        with patch.object(rewriter.dc, "Cache", return_value=self.cache):
            status = rewriter.main(["--cache", str(self.cache_path), "--proof", str(self.work),
                                    "--output", str(output), "--report", str(self.work / "report.json"),
                                    "--apple-trust-cache", str(self.work / "does-not-exist")])
        self.assertEqual(status, 2)
        self.assertFalse(output.exists())

    def test_prover_only_and_unproven_runs_exit_nonzero(self):
        class InlinePool:
            def __init__(self, jobs, initializer, initargs):
                initializer(*initargs)

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def imap_unordered(self, function, jobs):
                return map(function, jobs)

        prover = module("prove-zeta-dyld-cache")
        for only in (False, True):
            with self.subTest(only=only):
                args = ["--cache", str(self.cache_path), "--work", str(self.work), "--jobs", "1"]
                if only:
                    args += ["--only", "test0.dylib"]
                with patch.object(prover.dc, "Cache", return_value=self.cache), \
                     patch.object(prover.multiprocessing, "Pool", InlinePool), \
                     patch.object(prover.multiprocessing, "set_start_method"):
                    self.assertEqual(prover.main(args), 1)
                result = json.loads((self.work / "summary.json").read_text())
                self.assertEqual(result["complete"], not only)
                self.assertEqual(result["totals"]["unproven"], 1)
                with self.assertRaisesRegex(ValueError, "partial proof|unproven or unlowerable"):
                    validate_summary(self.cache, result, self.work)


class StandaloneSigningTests(unittest.TestCase):
    def test_default_preserves_platform_and_runtime(self):
        rewriter = module("rewrite-zeta-userland")
        original = signed_image(platform=7, flags=2)
        rewritten, report = rewriter.rewrite(original)
        self.assertEqual(report["instruction_edits"], 1)
        self.assertEqual(struct.unpack_from("<I", rewritten, 0x400)[0], AFTER)
        self.assertEqual(report["platform_identifier"], 7)
        self.assertEqual(report["code_directory_flags"], "0x2")
        self.assertEqual(struct.unpack_from("<I", rewritten, 8)[0], 0)

    def test_policy_override_must_be_explicit(self):
        rewriter = module("rewrite-zeta-userland")
        _, report = rewriter.rewrite(signed_image(), platform_identifier=26, hardened_runtime=True)
        self.assertEqual(report["platform_identifier"], 26)
        self.assertEqual(report["code_directory_flags"], "0x10002")

    def test_invalid_platform_value_rejected(self):
        rewriter = module("rewrite-zeta-userland")
        with self.assertRaisesRegex(ValueError, "byte value"):
            rewriter.rewrite(signed_image(), platform_identifier=256)


if __name__ == "__main__":
    unittest.main()
