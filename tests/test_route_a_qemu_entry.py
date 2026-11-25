"""Bounded QEMU input/observation contracts; no fixture counts as a kernel boot."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


M = module("qemu_entry", ROOT / "scripts/probe_route_a_qemu_entry.py")
FIXTURE = module("loader_fixture", ROOT / "tests/test_route_a_loader.py")


def inputs():
    kernel = bytes(FIXTURE.fixture())
    config = copy.deepcopy(FIXTURE.CONFIG)
    config["candidate"].update(size=len(kernel), sha256=M.digest(kernel))
    strict = M.loader.strict_kernel(kernel)
    contract = strict["metadata"]["load_contract"]
    image = bytearray(contract["memory_span"])
    for s in strict["segments"]:
        at = s["vmaddr"] - contract["virtual_base"]
        image[at:at + s["filesize"]] = kernel[s["fileoff"]:s["fileoff"] + s["filesize"]]
    symbols = M.loader.check_entry_symbols(strict, config, kernel)
    report = {
        "status": "host_loader_contract_verified", "host_loader_probe_verified": True,
        "kernel_segment_bytes_verified": True, "boot_args_abi_verified": True,
        "protected_inputs_recheck": {"unchanged": True},
        "kernel": {"sha256": M.digest(kernel)},
        "byte_load": {"image": {"size": len(image), "sha256": M.digest(image)}},
        "load_contract": {**contract, "virtual_slide": 0}, "entry_symbols": symbols,
    }
    return kernel, bytes(image), report, config


def parse_adt(data, cursor=0):
    props, children = struct.unpack_from("<II", data, cursor)
    cursor += 8
    values = {}
    for _ in range(props):
        name, size = struct.unpack_from("<32sI", data, cursor)
        cursor += 36
        values[name.rstrip(b"\0").decode()] = data[cursor:cursor + size]
        cursor += (size + 3) & ~3
    nested = []
    for _ in range(children):
        child, cursor = parse_adt(data, cursor)
        nested.append(child)
    return {"properties": values, "children": nested}, cursor


class InputTests(unittest.TestCase):
    def test_synthetic_exact_image_and_report_validate(self):
        data = inputs()
        strict, symbols = M.validate_inputs(*data)
        self.assertEqual(symbols["entry"]["value"], strict["metadata"]["entry"])

    def test_fixed_candidate_digest_is_not_optional(self):
        kernel, image, report, config = inputs()
        changed = kernel[:-1] + bytes([kernel[-1] ^ 1])
        report["kernel"]["sha256"] = M.digest(changed)
        with self.assertRaisesRegex(M.loader.ProbeError, "pinned bytes differ"):
            M.validate_inputs(changed, image, report, config)

    def test_self_consistent_changed_image_still_fails_reconstruction(self):
        kernel, image, report, config = inputs()
        changed = bytearray(image)
        changed[0x5000] = 1  # BSS must actually remain zero.
        report["byte_load"]["image"]["sha256"] = M.digest(changed)
        with self.assertRaisesRegex(M.EntryError, "segments or zero fill"):
            M.validate_inputs(kernel, bytes(changed), report, config)

    def test_report_missing_production_gate_is_rejected(self):
        for flag in ("host_loader_probe_verified", "kernel_segment_bytes_verified", "boot_args_abi_verified"):
            kernel, image, report, config = inputs()
            report[flag] = False
            with self.subTest(flag=flag), self.assertRaisesRegex(M.EntryError, flag):
                M.validate_inputs(kernel, image, report, config)

    def test_report_changed_inputs_are_rejected(self):
        kernel, image, report, config = inputs()
        report["protected_inputs_recheck"]["unchanged"] = False
        with self.assertRaisesRegex(M.EntryError, "declared inputs changed"):
            M.validate_inputs(kernel, image, report, config)

    def test_entry_evidence_is_recomputed(self):
        kernel, image, report, config = inputs()
        report["entry_symbols"]["early_cpu"]["value"] += 4
        with self.assertRaisesRegex(M.EntryError, "entry evidence"):
            M.validate_inputs(kernel, image, report, config)

    def test_nonzero_virtual_slide_fails(self):
        kernel, image, report, config = inputs()
        report["load_contract"]["virtual_slide"] = 0x200000
        with self.assertRaisesRegex(M.EntryError, "zero-slide"):
            M.validate_inputs(kernel, image, report, config)


class LayoutTests(unittest.TestCase):
    def setUp(self):
        self.contract = inputs()[2]["load_contract"]

    def test_boot_args_fields_and_virtual_tree_pointer(self):
        boot, layout = M.make_boot_args(self.contract, 0x50004000, 0x52000000, b"test-adt", "-v")
        self.assertEqual(len(boot), 0x4000)
        self.assertEqual(struct.unpack_from("<HH", boot), (2, 2))
        self.assertEqual(struct.unpack_from("<Q", boot, 8)[0], self.contract["virtual_base"])
        self.assertEqual(struct.unpack_from("<Q", boot, 0x20)[0], 0x52004000)
        self.assertEqual(struct.unpack_from("<QI", boot, 0x60), (layout["device_tree_va"], 8))
        self.assertEqual(boot[0x1000:0x1008], b"test-adt")
        self.assertEqual(boot[0x6C:0x6F], b"-v\0")
        self.assertGreaterEqual(layout["bootstrap_prefix_start"], M.RAM_BASE)

    def test_wrong_two_megabyte_congruence_fails(self):
        with self.assertRaisesRegex(M.EntryError, "low 21 bits"):
            M.make_boot_args(self.contract, 0x50000000, 0x52000000, b"", "")

    def test_boot_args_near_ram_end_fails_even_when_payload_fits_ram(self):
        with self.assertRaisesRegex(M.EntryError, "conservative initial block mapping"):
            M.make_boot_args(self.contract, 0x50004000, 0x5FF00000, b"", "")

    def test_boot_args_kernel_overlap_fails(self):
        contract = {**self.contract, "memory_span": 0x4000000}
        with self.assertRaisesRegex(M.EntryError, "follow the complete kernel"):
            M.make_boot_args(contract, 0x50004000, 0x52000000, b"", "")

    def test_kernel_cannot_overwrite_the_trampoline(self):
        with self.assertRaisesRegex(M.EntryError, "trampoline"):
            M.make_boot_args(self.contract, 0x40004000, 0x52000000, b"", "")

    def test_commandline_and_adt_bounds(self):
        with self.assertRaisesRegex(M.EntryError, "command line"):
            M.make_boot_args(self.contract, 0x50004000, 0x52000000, b"", "a" * 1024)
        with self.assertRaisesRegex(M.EntryError, "command line"):
            M.make_boot_args(self.contract, 0x50004000, 0x52000000, b"", "a\0b")
        with self.assertRaisesRegex(M.EntryError, "ADT"):
            M.make_boot_args(self.contract, 0x50004000, 0x52000000, bytes(0x3001), "")

    def test_no_adt_leaves_both_fields_zero(self):
        boot, layout = M.make_boot_args(self.contract, 0x50004000, 0x52000000, b"", "")
        self.assertEqual(struct.unpack_from("<QI", boot, 0x60), (0, 0))
        self.assertIsNone(layout["device_tree_pa"])

    def test_adt_describes_cpu_and_gic_that_the_fixture_uses(self):
        data = M.make_adt("cortex-a76", bytes(range(256)))
        tree, consumed = parse_adt(data)
        self.assertEqual(consumed, len(data))
        nodes = {}
        def visit(node):
            p = node["properties"]
            nodes[p["name"].rstrip(b"\0").decode()] = p
            for child in node["children"]:
                visit(child)
        visit(tree)
        self.assertEqual(nodes["cpu0"]["compatible"], b"arm,cortex-a76\0")
        self.assertEqual(nodes["intc"]["compatible"], b"arm,gic-v3\0")
        self.assertEqual(struct.unpack("<4Q", nodes["intc"]["reg"]), (0, 0x10000, 0xA0000, 0xF60000))
        self.assertNotIn("ufshc", nodes)
        self.assertNotIn(b"qcom,", data)
        self.assertEqual(nodes["chosen"]["random-seed"], bytes(range(256)))


class FakeSocket:
    def __init__(self, payload):
        self.data = bytearray(payload)
        self.sent = []

    def settimeout(self, _):
        pass

    def recv(self, size):
        result = bytes(self.data[:size])
        del self.data[:size]
        return result

    def sendall(self, payload):
        self.sent.append(payload)


class RemoteTests(unittest.TestCase):
    def test_fragmented_packet_ack_checksum_and_rle(self):
        data = b"0* "  # Four zeros: initial zero plus three repeats.
        socket = FakeSocket(b"+" + b"$" + data + b"#" + f"{sum(data) % 256:02x}".encode())
        remote = M.Remote(socket, time.monotonic() + 2)
        self.assertEqual(remote.request("g"), "0000")
        self.assertEqual(socket.sent, [b"$g#67", b"+"])

    def test_checksum_mismatch_is_not_acknowledged(self):
        socket = FakeSocket(b"$OK#00")
        with self.assertRaisesRegex(M.EntryError, "checksum"):
            M.Remote(socket, time.monotonic() + 2).receive()
        self.assertEqual(socket.sent, [])

    def test_escaped_repeat_character_stays_literal(self):
        self.assertEqual(M.decode_rsp(b"}\x0a"), b"*")
        for data in (b"}", b"* ", b"a*\x01"):
            with self.subTest(data=data), self.assertRaises(M.EntryError):
                M.decode_rsp(data)

    def test_deadline_is_checked_before_read(self):
        with self.assertRaisesRegex(M.EntryError, "timed out"):
            M.Remote(FakeSocket(b""), time.monotonic() - 1).receive()

    def test_register_read_uses_verified_aarch64_offsets(self):
        raw = bytearray(268)
        struct.pack_into("<Q", raw, 0, 0x52000000)
        struct.pack_into("<Q", raw, 256, 0x50511488)
        struct.pack_into("<I", raw, 264, 0x3C5)
        remote = M.Remote(None, 0)
        remote.request = lambda command: raw.hex()
        self.assertEqual(remote.registers(), {"x0": 0x52000000, "pc": 0x50511488, "cpsr": 0x3C5})

    def test_unexpected_pc_after_step_cannot_verify_entry(self):
        kernel, image, report, config = inputs()
        _, symbols = M.validate_inputs(kernel, image, report, config)
        _, layout = M.make_boot_args(report["load_contract"], 0x50004000, 0x52000000, b"", "")
        class FakeRemote:
            def __init__(self):
                self.stepped = False
            def validate_architecture(self):
                pass
            def request(self, command):
                if command.startswith("m"):
                    return struct.pack("<I", symbols["trampoline"]["instruction_word"]).hex()
                if command == "s":
                    self.stepped = True
                return "T05" if command in ("c", "s") else "OK"
            def registers(self):
                return {"x0": layout["boot_args_pa"], "pc": layout["entry_pa"] + (4 if self.stepped else 0), "cpsr": 5}
        with self.assertRaisesRegex(M.EntryError, "did not reach"):
            M.observe_entry(FakeRemote(), layout, symbols)


class EvidenceTests(unittest.TestCase):
    def test_multicall_tool_keeps_selected_symlink_basename(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            binary = root / "multicall"
            binary.write_text('#!/bin/sh\ncase "$0" in */ld.lld) echo "test LLD";; *) exit 42;; esac\n')
            binary.chmod(0o755)
            selected = root / "ld.lld"
            selected.symlink_to(binary.name)
            invocation, record = M.select_tool(str(selected))
            self.assertEqual(invocation, str(selected))
            self.assertEqual(record["invocation_path"], str(selected))
            self.assertEqual(record["resolved_binary"]["path"], str(binary))
            self.assertEqual(record["resolved_binary"]["sha256"], M.digest(binary.read_bytes()))
            self.assertEqual(record["version"], "test LLD\n")
            with self.assertRaisesRegex(M.EntryError, "version check failed"):
                M.select_tool(str(binary))

    def test_uart_intent_does_not_establish_instruction_execution(self):
        kernel, image, report, config = inputs()
        strict, _ = M.validate_inputs(kernel, image, report, config)
        _, layout = M.make_boot_args(report["load_contract"], 0x50004000, 0x52000000, b"", "")
        result = M.exception_summary("", "ENTRY-PROBE: entering unchanged kernel\r\n", strict, image, layout)
        self.assertFalse(result["exception_observed"])
        self.assertNotIn("qemu_kernel_entry_executed", result)

    def test_physical_fault_maps_to_real_candidate_instruction(self):
        kernel, image, report, config = inputs()
        strict, symbols = M.validate_inputs(kernel, image, report, config)
        _, layout = M.make_boot_args(report["load_contract"], 0x50004000, 0x52000000, b"", "")
        trace = f"Taking exception 1 [Undefined Instruction]\n...with ELR 0x{layout['entry_pa']:x}\n"
        result = M.exception_summary(trace, "", strict, image, layout)
        self.assertEqual(result["first_exception"], {"number": 1, "description": "Undefined Instruction", "cpu": None})
        self.assertEqual(result["fault_va"], symbols["entry"]["value"])
        self.assertEqual(result["fault_address_space"], "kernel-physical")
        self.assertEqual(result["fault_opcode"], "0x14000004")

    def test_vendored_source_identity_matches_manifest(self):
        manifest = json.loads((M.SOURCES / "sources.json").read_text())
        self.assertEqual(manifest["commit"], "8542980d02b4d2cc5c32ee3542de1760b2562aac")
        for record in manifest["files"]:
            M.loader.verify_bytes((M.SOURCES / record["path"]).read_bytes(), record, record["path"])


if __name__ == "__main__":
    unittest.main()
