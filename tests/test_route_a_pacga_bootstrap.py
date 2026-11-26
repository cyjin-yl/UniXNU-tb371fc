"""Synthetic observation boundaries; these tests do not execute a guest."""
import copy
from pathlib import Path
import struct
import time
import unittest
from unittest.mock import Mock, patch

from test_route_a_corecrypto import P, B, image


def bootstrap_image():
    strict, data, base = image()
    records = strict["metadata"]["symbols"]["records"]
    records[0]["name"] = "_route_a_pacga_bootstrap"
    records[1]["name"] = "_read_random"
    address = base + 0x1000
    strict["metadata"]["sections"].append(
        {"name": "__data", "segment": "__DATA", "addr": address, "offset": len(data),
         "size": 32, "flags": 0})
    strict["segments"].append(
        {"name": "__DATA", "vmaddr": address, "vmsize": 32, "fileoff": len(data),
         "filesize": 32, "initprot": 3})
    records.extend({"name": name, "n_type": 14, "n_desc": 0, "n_sect": 2, "value": address + offset}
                   for name, offset in (("_route_a_pacga_boot_key", 0), ("_route_a_pacga_ready", 16)))
    return strict, data + bytes(32), base


def definitions():
    strict, data, base = bootstrap_image()
    return {"pacga": P.pacga_bootstrap_targets(strict, data),
            "cells": {"_kpis": {"va": base + 0x2000}}}


def published_provider(defined, *, ready=0):
    return {"_g_crypto_funcs": defined["cells"]["_kpis"]["va"], "_crypto_init": 1,
            "_prng_ready": 1, "_source_corecrypto14_status": 0, "_route_a_pacga_ready": ready}


class BootstrapObservation:
    def __init__(self, defined, states, arguments=None):
        self.defined, self.states, self.calls = defined, list(states), []
        self.arguments = arguments or {
            "x0": defined["pacga"]["key_destination"]["va"], "x1": 16}

    def expect(self, target, label, register_names=()):
        self.calls.append((target, tuple(register_names)))
        return dict(self.arguments) if target is self.defined["pacga"]["call"] else {}

    def state(self):
        return self.states.pop(0)

    def read(self, span, label):
        raise AssertionError("the bootstrap observer must never request key bytes")


class PacgaBootstrapContracts(unittest.TestCase):
    def test_targets_bind_the_actual_bl_and_bounded_separate_data_cells(self):
        strict, data, base = bootstrap_image()
        target = P.pacga_bootstrap_targets(strict, data)
        self.assertEqual(target["call"]["va"], base)
        self.assertEqual(target["returned"]["va"], base + 4)
        self.assertEqual(target["key_destination"]["size"], 16)
        self.assertEqual(target["ready"]["size"], 4)
        self.assertEqual(target["ready"]["va"], target["key_destination"]["va"] + 16)
        for mutation in ("duplicate-call", "overlapping-cell", "same-address-cell", "weak-key"):
            current, raw = copy.deepcopy(strict), bytearray(data)
            if mutation == "duplicate-call":
                struct.pack_into("<I", raw, 8, 0x9400000e)
            elif mutation == "overlapping-cell":
                current["metadata"]["symbols"]["records"][-1]["value"] -= 8
            elif mutation == "same-address-cell":
                current["metadata"]["symbols"]["records"][-1]["value"] -= 16
            else:
                current["metadata"]["symbols"]["records"][-2]["n_desc"] = 0x80
            with self.subTest(mutation=mutation), self.assertRaises(B.BuildError):
                P.pacga_bootstrap_targets(current, bytes(raw))

    def test_key_cannot_alias_any_observed_state_cell_or_table(self):
        strict, data, _ = bootstrap_image()
        key = P.pacga_bootstrap_targets(strict, data)["key_destination"]
        for offset, size in ((0, 1), (0, 4), (0, 448), (-8, 16), (8, 16), (15, 1)):
            cell = {"va": key["va"] + offset, "size": size}
            with self.subTest(offset=offset, size=size), self.assertRaises(B.BuildError):
                P.pacga_bootstrap_targets(strict, data, [cell])
        for cell in ({"va": key["va"] - 4, "size": 4}, {"va": key["va"] + 16, "size": 4}):
            self.assertEqual(P.pacga_bootstrap_targets(strict, data, [cell])["key_destination"], key)

    def test_memory_guard_rejects_key_overlap_before_any_remote_request(self):
        strict, data, _ = bootstrap_image()
        defined = {"pacga": P.pacga_bootstrap_targets(strict, data)}
        key = defined["pacga"]["key_destination"]["va"]
        remote = Mock()
        observer = P.Observe(remote, strict, data, defined, {})
        for address, size in ((key, 16), (key, 4), (key - 4, 8), (key + 15, 2)):
            with self.subTest(address=address, size=size), self.assertRaises(B.BuildError):
                observer.read({"va": address, "size": size}, "must-not-read")
        remote.request.assert_not_called()
        self.assertEqual(observer.report, {})
        self.assertTrue(observer.permits_memory_read(key - 4, 4))
        self.assertTrue(observer.permits_memory_read(key + 16, 4))

    def test_panic_strings_cannot_request_key_or_a_window_crossing_it(self):
        strict, data, _ = bootstrap_image()
        defined = {"pacga": P.pacga_bootstrap_targets(strict, data)}
        key = defined["pacga"]["key_destination"]["va"]
        # A string can start outside the key while its bounded request reaches it.
        strict["metadata"]["sections"][-1].update(addr=key - 16, size=64)
        strict["segments"][-1].update(vmaddr=key - 16, vmsize=64, filesize=64)
        remote = Mock()
        observer = P.Observe(remote, strict, data, defined, {})
        panic = observer.capture_panic({"x0": 3, "x1": key, "x2": key - 8, "x7": 0})
        for label in ("message", "format"):
            self.assertEqual(panic[label]["status"], "protected-pacga-key-range")
            self.assertEqual(panic[label]["data_hex"], "")
        remote.request.assert_not_called()

    def test_descriptor_requires_matching_explicit_kernel_and_overlay_identity(self):
        actual = {"kernel": {"sha256": "a" * 64}, "implementation": {"sha256": "b" * 64},
                  "runtime_boot_verified": False}
        strict = {"metadata": {"sections": [{"name": "__unixnu_pacga"}]}}
        built = {"pacga_runtime": actual, "pacga_overlay": {
            "implementation": actual["implementation"], "runtime_boot_verified": False}}
        with patch.object(P.pacga, "runtime_kernel", return_value=actual) as verify:
            self.assertEqual(P.select_pacga_runtime(built, strict, Path("/kernel")), actual)
            verify.assert_called_once_with(Path("/kernel"))
            for failure in ("omitted-overlay", "different-kernel", "different-implementation", "boot-claim"):
                changed = copy.deepcopy(built)
                if failure == "omitted-overlay":
                    changed.pop("pacga_overlay")
                elif failure == "different-kernel":
                    changed["pacga_runtime"]["kernel"]["sha256"] = "c" * 64
                elif failure == "different-implementation":
                    changed["pacga_overlay"]["implementation"] = {"sha256": "d" * 64}
                else:
                    changed["pacga_overlay"]["runtime_boot_verified"] = True
                with self.subTest(failure=failure), self.assertRaises(B.BuildError):
                    P.select_pacga_runtime(changed, strict, Path("/kernel"))
        self.assertIsNone(P.select_pacga_runtime({}, {"metadata": {"sections": []}}, Path("/unused")))

    def test_only_requested_registers_are_read_after_validated_xml(self):
        remote = P.Remote.__new__(P.Remote)
        remote.core_layout_validated = True
        remote.deadline = time.monotonic() + 5
        calls = []
        replies = {"p20": (0xfffffff007004004).to_bytes(8, "little").hex(),
                   "p21": (5).to_bytes(4, "little").hex(), "p0": (16).to_bytes(8, "little").hex()}

        def request(command):
            calls.append(command)
            return replies[command]

        remote.request = request
        self.assertEqual(remote.selected_registers(("pc", "cpsr", "x0")),
                         {"pc": 0xfffffff007004004, "cpsr": 5, "x0": 16})
        self.assertEqual(calls, ["p20", "p21", "p0"])
        calls.clear()
        remote.core_layout_validated = False
        with self.assertRaises(B.BuildError):
            remote.selected_registers(("pc",))
        self.assertEqual(calls, [])

    def test_selected_register_errors_and_ambiguous_shapes_fail_closed(self):
        for reply in ("", "E14", "00", "00" * 9, "xx" * 8, "00" * 8 + ";tail"):
            remote = P.Remote.__new__(P.Remote)
            remote.core_layout_validated = True
            remote.request = lambda command: reply
            with self.subTest(reply=reply), self.assertRaises(B.BuildError):
                remote.selected_registers(("x0",))
        for names in (("pc", "pc"), ("v0",), ("x31",)):
            with self.subTest(names=names), self.assertRaises(B.BuildError):
                remote.selected_registers(names)

    def test_random_return_stop_reads_no_general_register_or_key_bytes(self):
        strict, data, base = bootstrap_image()
        target = P.pacga_bootstrap_targets(strict, data)["returned"]
        remote = P.Remote.__new__(P.Remote)
        remote.core_layout_validated = True
        remote.deadline = time.monotonic() + 5
        calls = []

        def request(command):
            calls.append(command)
            if command == "c":
                return "T05thread:1;unneeded-expedited-registers;"
            if command == "p20":
                return target["va"].to_bytes(8, "little").hex()
            if command == "p21":
                return (5).to_bytes(4, "little").hex()
            if command == f'm{target["va"]:x},4':
                return data[target["file_offset"]:target["file_offset"] + 4].hex()
            raise AssertionError("unexpected or excess observation request: " + command)

        remote.request = request
        report = {}
        observer = P.Observe(remote, strict, data, {"debugger": {"va": base + 96}}, report)
        observer.installed[target["va"]] = target
        registers = observer.continue_to("random return")
        self.assertEqual(set(registers), {"pc", "cpsr"})
        self.assertEqual(calls, ["c", "p20", "p21", f'm{target["va"]:x},4'])
        self.assertEqual(report["events"][0]["stop"], "T05")
        self.assertNotIn("unneeded-expedited", str(report))
        self.assertNotIn("raw_core_reply", str(report))

    def test_key_initialization_requires_the_observed_call_return_then_ready(self):
        defined = definitions()
        state = published_provider(defined)
        observer = BootstrapObservation(defined, [dict(state), dict(state)])
        report = dict.fromkeys(P.FLAGS, False)
        P.observe_pacga_bootstrap(observer, defined, report)
        self.assertEqual([names for _, names in observer.calls], [("x0", "x1"), ()])
        self.assertTrue(report["pacga_bootstrap"]["random_call_observed"])
        self.assertTrue(report["pacga_bootstrap"]["random_return_observed"])
        self.assertFalse(report["pacga_bootstrap"]["key_storage_requested"])
        self.assertFalse(report["pacga_bootstrap"]["random_return_gprs_requested"])
        self.assertFalse(report["pacga_bootstrap"]["bulk_register_packet_requested"])
        self.assertFalse(report["pacga_key_initialization_verified"])
        P.qualify_pacga_bootstrap(defined, published_provider(defined, ready=1), report)
        self.assertTrue(report["pacga_key_initialization_verified"])
        self.assertFalse(report["runtime_provider_verified"])
        self.assertFalse(report["pacga_negative_post_unpublished_verified"])

    def test_wrong_prerequisite_destination_size_or_early_ready_prevents_qualification(self):
        defined = definitions()
        for failure in ("provider", "crypto", "prng", "status", "ready-before", "destination", "size", "ready-at-return"):
            before, after = published_provider(defined), published_provider(defined)
            arguments = {"x0": defined["pacga"]["key_destination"]["va"], "x1": 16}
            if failure == "provider":
                before["_g_crypto_funcs"] += 8
            elif failure == "crypto":
                before["_crypto_init"] = 0
            elif failure == "prng":
                before["_prng_ready"] = 0
            elif failure == "status":
                before["_source_corecrypto14_status"] = 1
            elif failure == "ready-before":
                before["_route_a_pacga_ready"] = 1
            elif failure == "destination":
                arguments["x0"] += 8
            elif failure == "size":
                arguments["x1"] = 8
            else:
                after["_route_a_pacga_ready"] = 1
            report = dict.fromkeys(P.FLAGS, False)
            observer = BootstrapObservation(defined, [before, after], arguments)
            with self.subTest(failure=failure), self.assertRaises(B.BuildError):
                P.observe_pacga_bootstrap(observer, defined, report)
            self.assertFalse(report["pacga_key_initialization_verified"])
            self.assertFalse(report.get("pacga_bootstrap", {}).get("random_return_observed", False))

    def test_ready_alone_or_missing_ready_cannot_qualify_initialization(self):
        defined = definitions()
        for ready, call, returned in ((1, False, True), (1, True, False), (0, True, True), (2, True, True)):
            report = {"pacga_bootstrap": {"random_call_observed": call, "random_return_observed": returned}}
            with self.subTest(ready=ready, call=call, returned=returned), self.assertRaises(B.BuildError):
                P.qualify_pacga_bootstrap(defined, published_provider(defined, ready=ready), report)
            self.assertNotIn("pacga_key_initialization_verified", report)

    def test_negative_post_must_remain_unpublished_at_both_actual_stop_points(self):
        strict, data, base = image()
        defined = {"post": P.call_return(strict, data, "_caller", "_callee"),
                   "debugger": {"va": base + 96}, "pacga": {}}
        zeros = dict.fromkeys(("_g_crypto_funcs", "_crypto_init", "_prng_ready",
                               "_route_a_crypto_consumer_status", "_route_a_crypto_consumer_vectors",
                               "_route_a_pacga_ready"), 0)
        for first, second in ((0, 0), (1, 0), (0, 1)):
            states = [{**zeros, "_route_a_pacga_ready": first},
                      {**zeros, "_route_a_pacga_ready": second}]
            cleanup = []

            class NegativeObservation:
                def breakpoint(self, target):
                    pass

                def expect(self, target, label, register_names=()):
                    return {"x0": 1}

                def state(self):
                    return states.pop(0)

                def continue_to(self, label):
                    return {"pc": base + 96, "x0": 3, "x7": base + 16}

                def capture_panic(self, registers):
                    return {"format": {"nul_terminated": True, "text_utf8": "POST failed"}}

                def cleanup(self):
                    cleanup.append(True)

            report = dict.fromkeys(P.FLAGS, False)
            with self.subTest(first=first, second=second), patch.object(P, "Observe", return_value=NegativeObservation()):
                if first or second:
                    with self.assertRaises(B.BuildError):
                        P.observe(None, strict, data, defined, report, "negative-post", 0)
                    self.assertFalse(report["negative_post_rejection_verified"])
                    self.assertFalse(report["pacga_negative_post_unpublished_verified"])
                else:
                    P.observe(None, strict, data, defined, report, "negative-post", 0)
                    self.assertTrue(report["negative_post_rejection_verified"])
                    self.assertTrue(report["pacga_negative_post_unpublished_verified"])
                self.assertEqual(cleanup, [True])

    def test_indirect_consumer_call_reads_only_its_actual_target_register(self):
        strict, data, base = image()
        raw = bytearray(data)
        struct.pack_into("<I", raw, 0, 0xd63f0100)  # BLR X8
        target = B.symbol_span(strict, data, "_callee", 4, executable=True)
        reads = []

        def read_register(name):
            reads.append(name)
            return target["va"]

        returned = P.return_from_entry(strict, raw, {"x30": base + 4}, target, read_register)
        self.assertEqual(returned["va"], base + 4)
        self.assertEqual(reads, ["x8"])
        with self.assertRaises(B.BuildError):
            P.return_from_entry(strict, raw, {"x30": base + 4}, target, lambda name: base)


if __name__ == "__main__":
    unittest.main()
