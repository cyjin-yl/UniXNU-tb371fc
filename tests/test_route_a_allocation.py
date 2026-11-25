"""Regress the allocation ownership gap without accessing a real firmware map."""
import ctypes
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import probe_route_a_allocation as probe


class BootstrapIntervalTests(unittest.TestCase):
    def test_fixed_candidate_prefix_and_unmapped_tail_are_distinct(self):
        intervals = probe.bootstrap_intervals(0x50004000, probe.WINDOW, 0x1600000)
        self.assertEqual(intervals["initial_mapping"], [0x50000000, 0x60000000])
        self.assertEqual(intervals["required_allocation"], [0x50000000, 0x60004000])
        self.assertEqual(intervals["advertised_tail_not_initially_mapped"], [0x60000000, 0x60004000])
        self.assertTrue(intervals["used_end_initially_mapped"])

    def test_loader_headroom_covers_every_page_aligned_prefix(self):
        for prefix in range(0, probe.BLOCK, probe.PAGE):
            intervals = probe.bootstrap_intervals(0x50000000 + prefix, probe.WINDOW, probe.WINDOW - probe.BLOCK)
            self.assertLessEqual(intervals["zeroed"][1], intervals["initial_mapping"][1])

    def test_rejects_unsupported_mapping_assumptions(self):
        for address, window, used in [(0x50004001, probe.WINDOW, 0),
                                      (0x50004000, probe.WINDOW + probe.PAGE, 0),
                                      (0x50004000, probe.WINDOW, probe.WINDOW)]:
            with self.assertRaises(probe.ProbeError):
                probe.bootstrap_intervals(address, window, used)


@unittest.skipUnless(os.environ.get("ROUTE_A_ALLOCATION_SOURCES") and shutil.which("cc"),
                     "set ROUTE_A_ALLOCATION_SOURCES to the fixed public source directory; cc required")
class ExtractedAllocatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="route-a-allocation-")
        cls.work = Path(cls.temporary.name)
        cls.source_root = Path(os.environ["ROUTE_A_ALLOCATION_SOURCES"])
        cls.config = probe.read_config()
        cls.sources = probe.verified_sources(cls.source_root, cls.config)
        cls.original = cls.sources[probe.SOURCE].decode()
        cls.patched = probe.apply_patch(cls.sources, cls.work / "patched", cls.config)
        header = cls.sources["DarwinBootPkg/Driver/WindowSize.h"].decode()
        cls.old, _ = probe.build_host(cls.original, header, False, cls.work / "original", Path(shutil.which("cc")))
        cls.new, _ = probe.build_host(cls.patched, header, True, cls.work / "fixed", Path(shutil.which("cc")))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_original_allocation_does_not_own_mapped_prefix(self):
        entries = [(7, 0x50000000, probe.WINDOW + 0x4000)]
        old = probe.allocate(self.old, entries)
        new = probe.allocate(self.new, entries)
        self.assertEqual(old["status"], 0)
        self.assertEqual(new["status"], 0)
        self.assertEqual(old["address"], new["address"])
        self.assertEqual(old["owned_address"], 0x50004000)
        self.assertEqual(new["owned_address"], 0x50000000)
        self.assertEqual(new["owned_size"], probe.WINDOW + 0x4000)
        self.assertEqual(old["owned_address"] + old["owned_size"], new["owned_address"] + new["owned_size"])

    def test_allocate_free_cache_and_zero_calls_agree(self):
        old = probe.exercise_call_sites(self.old)
        new = probe.exercise_call_sites(self.new)
        self.assertFalse(old["prefix_zero"])
        self.assertTrue(old["payload_zero"])
        self.assertTrue(new["prefix_zero"] and new["payload_zero"] and new["guards_intact"])
        self.assertEqual(new["zero_start"], new["host_buffer"])
        self.assertEqual(new["zero_size"], 0x7000)
        self.assertEqual(new["cache_start"], new["free_start"])
        self.assertEqual(new["cache_size"], new["free_pages"] * probe.PAGE)
        self.assertEqual(new["cache_size"], probe.WINDOW + 0x4000)

    def test_allocation_at_zero_is_freed_by_size_not_address(self):
        new = probe.allocate(self.new, [(7, 0, probe.WINDOW + 0x4000)])
        self.assertEqual(new["status"], 0)
        self.assertEqual(new["owned_address"], 0)
        result = probe.Calls()
        self.new.probe_release(0, new["owned_size"], 0x4000, ctypes.byref(result))
        self.assertEqual(result.free_pages * probe.PAGE, new["owned_size"])
        self.new.probe_release(0, 0, 0x4000, ctypes.byref(result))
        self.assertEqual(result.free_pages, 0)

    def test_prefix_zero_and_largest_page_aligned_prefix(self):
        for prefix in (0, probe.BLOCK - probe.PAGE):
            base = (probe.BASE & ~(probe.BLOCK - 1)) + prefix
            new = probe.allocate(self.new, [(7, 0x50000000, probe.WINDOW + prefix)], base=base)
            self.assertEqual(new["status"], 0)
            self.assertEqual(new["address"], 0x50000000 + prefix)
            self.assertEqual(new["owned_size"], probe.WINDOW + prefix)

    def test_partial_and_reserved_runs_do_not_count_as_owned(self):
        cases = [[], [(0, 0x50000000, probe.WINDOW * 2)],
                 [(7, 0x50000000, probe.WINDOW + 0x3000)],
                 [(7, 0x50000000, 0x8000000), (0, 0x58000000, probe.PAGE),
                  (7, 0x58001000, 0x8003000)]]
        for entries in cases:
            new = probe.allocate(self.new, entries)
            self.assertNotEqual(new["status"], 0)
            self.assertEqual((new["address"], new["owned_address"], new["owned_size"]), (0, 0, 0))

    def test_adjacent_unordered_descriptors_and_fallback(self):
        entries = [(7, 0x58000000, 0x8004000), (7, 0x50000000, 0x8000000)]
        self.assertEqual(probe.allocate(self.new, entries)["status"], 0)
        entries = [(7, 0x50000000, probe.WINDOW + 0x4000), (7, 0x80000000, probe.WINDOW + 0x4000)]
        new = probe.allocate(self.new, entries, reject=1)
        self.assertEqual(new["status"], 0)
        self.assertEqual(new["attempts"], 2)
        self.assertEqual(new["owned_address"], 0x80000000)

    def test_bad_size_alignment_and_overflow_are_refused(self):
        entries = [(7, 0x50000000, probe.WINDOW * 2)]
        for base, window in [(probe.BASE + 1, probe.WINDOW), (probe.BASE, 0),
                             (probe.BASE, probe.WINDOW + probe.PAGE), (probe.BASE, 0x202000000)]:
            new = probe.allocate(self.new, entries, base=base, window=window)
            self.assertNotEqual(new["status"], 0)
            self.assertEqual(new["attempts"], 0)
        malformed = [(7, (1 << 64) - probe.PAGE, 2 * probe.PAGE)]
        new = probe.allocate(self.new, malformed)
        self.assertNotEqual(new["status"], 0)
        self.assertEqual(new["attempts"], 0)

    def test_boot_argument_semantics_and_allocation_call_are_preserved(self):
        for statement in ("Args->VirtualBase = Kernel.Base;", "Args->PhysicalBase = Address;",
                          "Args->MemorySize = WindowSize;", "Args->MemorySizeActual = WindowSize;",
                          "Args->TopOfKernelData = Address + Used;",
                          "Args->DeviceTree = Kernel.Base + TreeAddress - Address;",
                          "if (Used > WindowSize - BLOCK_SIZE)"):
            self.assertEqual(self.original.count(statement), 1)
            self.assertEqual(self.patched.count(statement), 1)
        self.assertEqual(self.patched.count("AllocateWindow (&Kernel, WindowSize, &Address, &AllocationAddress, &AllocationSize)"), 1)

    def test_report_retains_host_only_scope_and_rejects_overwrite(self):
        output = self.work / "report-run"
        report = probe.run_probe(self.source_root, output)
        self.assertTrue(report["host_allocator_contract_verified"], report.get("error"))
        self.assertEqual(len(report["cases"]), 8)
        for flag in self.config["qualification"]:
            self.assertFalse(report[flag], flag)
        self.assertEqual(json.loads((output / "report.json").read_text()), report)
        with self.assertRaises(probe.ProbeError):
            probe.run_probe(self.source_root, output)


if __name__ == "__main__":
    unittest.main()
