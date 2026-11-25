"""Bounded QEMU input/observation contracts; no fixture counts as a kernel boot."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


M = module("qemu_entry", ROOT / "scripts/probe_route_a_qemu_entry.py")
FIXTURE = module("loader_fixture", ROOT / "tests/test_route_a_loader.py")


def inputs(kernel=None):
    kernel = bytes(FIXTURE.fixture() if kernel is None else kernel)
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


def debugger_fixture():
    """Extend the authored Mach-O with a real third nlist, not an address override."""
    data = FIXTURE.fixture()
    strings = b"\0__start\0_start_first_cpu\0_DebuggerTrapWithState\0"
    cursor = 32
    while struct.unpack_from("<I", data, cursor)[0] != 2:
        cursor += struct.unpack_from("<I", data, cursor + 4)[0]
    struct.pack_into("<6I", data, cursor, 2, 24, 0x3000, 3, 0x3030, len(strings))
    struct.pack_into("<IBBHQ", data, 0x3020, strings.index(b"_DebuggerTrapWithState"), 15, 1, 0, FIXTURE.BASE + 0x2040)
    data[0x3030:0x3030 + len(strings)] = strings
    return bytes(data)


def core_packet(registers):
    return struct.pack("<33QI", *(registers[name] for name in M.CORE_NAMES)).hex()


class SnapshotRemote(M.Remote):
    """In-memory RSP peer only; never launches an emulator or subprocess."""
    def __init__(self):
        super().__init__(None, time.monotonic() + 10)
        self.kernel, self.image, self.loader_report, config = inputs(debugger_fixture())
        self.strict, _ = M.validate_inputs(self.kernel, self.image, self.loader_report, config)
        _, self.layout = M.make_boot_args(self.loader_report["load_contract"], 0x50004000, 0x52000000, b"", "")
        self.target = M.debugger_target(self.strict, self.kernel)
        self.window = M.debugger_read_window(self.strict, self.layout)
        self.values = {name: index for index, name in enumerate(M.CORE_NAMES)}
        self.values.update(x0=3, x1=FIXTURE.BASE + 0x2800, x2=FIXTURE.BASE + 0x2880,
                           x3=FIXTURE.BASE + 0x4000, x7=FIXTURE.BASE + 0x2050,
                           x29=FIXTURE.BASE + 0x4110, x30=FIXTURE.BASE + 0x2060,
                           sp=FIXTURE.BASE + 0x4100, pc=int(self.target["va"], 16), cpsr=0x600003C4)
        self.memory, self.commands, self.responses = {}, [], {}
        self.store(int(self.target["va"], 16), bytes.fromhex(self.target["instruction_bytes"]))
        self.store(self.values["x1"], b"panic message\0".ljust(64, b"\0"))
        self.store(self.values["x2"], b"bad %lld\0".ljust(64, b"\0"))
        self.store(self.values["x3"], struct.pack("<Q", FIXTURE.BASE + 0x4200))
        self.store(self.values["sp"], bytes(256))
        self.store(FIXTURE.BASE + 0x4200, bytes(range(256)))

    def store(self, address, data):
        self.memory.update({address + i: byte for i, byte in enumerate(data)})

    def request(self, command):
        self.commands.append(command)
        if command in self.responses:
            response = self.responses[command]
            if isinstance(response, Exception):
                raise response
            return response
        if command.startswith(("Z1,", "z1,")):
            return "OK"
        if command == "c":
            return "T05thread:01;"
        if command == "g":
            return core_packet(self.values)
        if command.startswith("m"):
            address, length = (int(value, 16) for value in command[1:].split(","))
            try:
                return bytes(self.memory[address + i] for i in range(length)).hex()
            except KeyError:
                return "E14"
        raise AssertionError(f"unexpected or mutating command: {command}")


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
    @staticmethod
    def qemu_xml():
        # The shape emitted by QEMU v10.0.0 get_feature_xml(), also observed
        # from the Debian 10.0.13 binary. The xi prefix is intentionally absent.
        target = ('<?xml version="1.0"?><!DOCTYPE target SYSTEM "gdb-target.dtd">'
                  '<target><architecture>aarch64</architecture>'
                  '<xi:include href="aarch64-core.xml"/>'
                  '<xi:include href="aarch64-fpu.xml"/></target>')
        regs = [(f"x{i}", 64) for i in range(31)] + [("sp", 64), ("pc", 64), ("cpsr", 32)]
        core = ('<?xml version="1.0"?><!DOCTYPE feature SYSTEM "gdb-target.dtd">'
                '<feature name="org.gnu.gdb.aarch64.core">' +
                ''.join(f'<reg name="{name}" bitsize="{size}"/>' for name, size in regs) + '</feature>')
        return {"target.xml": target, "aarch64-core.xml": core}

    def test_qemu_unbound_xi_include_preserves_architecture_checks(self):
        xml = self.qemu_xml()
        remote = M.Remote(None, time.monotonic() + 2)
        remote.request = lambda command: "l" + xml[command.split(":")[3]]
        # No DTD loader or network resolver is used by the finite XML parser.
        with patch("builtins.open", side_effect=AssertionError("unexpected external resource read")):
            remote.validate_architecture()
        self.assertEqual(remote.xml_records[0]["raw_xml_text"], xml["target.xml"])
        self.assertTrue(remote.xml_records[0]["complete"])
        xml["target.xml"] = xml["target.xml"].replace("<architecture>aarch64", "<architecture>arm")
        with self.assertRaisesRegex(M.EntryError, "architecture"):
            remote.validate_architecture()

    def test_qemu_xml_checks_entire_core_register_layout(self):
        for original, changed in [('name="x1" bitsize="64"', 'name="x1" bitsize="32"'),
                                  ('name="sp" bitsize="64"', 'name="x0" bitsize="64"'),
                                  ('name="pc" bitsize="64"', 'name="pc" bitsize="64" regnum="33"')]:
            xml = self.qemu_xml()
            xml["aarch64-core.xml"] = xml["aarch64-core.xml"].replace(original, changed)
            remote = M.Remote(None, time.monotonic() + 2)
            remote.request = lambda command: "l" + xml[command.split(":")[3]]
            with self.subTest(changed=changed), self.assertRaisesRegex(M.EntryError, "core register layout"):
                remote.validate_architecture()

    def test_only_the_known_xi_include_form_is_accepted(self):
        valid = self.qemu_xml()["target.xml"]
        declared = valid.replace("<target>", '<target xmlns:xi="http://www.w3.org/2001/XInclude">')
        self.assertEqual(M.parse_gdb_xml(declared, "target.xml").tag, "target")
        for bad in (valid.replace("xi:include", "other:include"),
                    valid.replace('href="aarch64-core.xml"', 'href="https://invalid.example/core.xml"'),
                    valid.replace('href="aarch64-core.xml"', 'href="../aarch64-core.xml"'),
                    declared.replace("http://www.w3.org/2001/XInclude", "urn:other")):
            with self.subTest(xml=bad), self.assertRaises(M.EntryError):
                M.parse_gdb_xml(bad, "target.xml")

    def test_dtd_internal_subset_and_entities_are_rejected(self):
        valid = self.qemu_xml()["target.xml"]
        for bad in (valid.replace('SYSTEM "gdb-target.dtd"', 'SYSTEM "file:///tmp/external.dtd"'),
                    valid.replace('SYSTEM "gdb-target.dtd">', '[<!ENTITY a "aarch64">]>'),
                    valid.replace('SYSTEM "gdb-target.dtd">', '[<!ENTITY a SYSTEM "https://invalid.example/e">]>')):
            with self.subTest(xml=bad), self.assertRaisesRegex(M.EntryError, "DTD or internal subset"):
                M.parse_gdb_xml(bad, "target.xml")

    def test_undeclared_entities_cannot_silently_change_identifiers(self):
        xml = self.qemu_xml()
        variants = [
            ("target.xml", xml["target.xml"].replace("aarch64</architecture>", "aarch64&undefined;</architecture>")),
            ("target.xml", xml["target.xml"].replace('href="aarch64-core.xml"', 'href="aarch64&undefined;-core.xml"')),
            ("aarch64-core.xml", xml["aarch64-core.xml"].replace('name="x0"', 'name="x&undefined;0"')),
            ("target.xml", xml["target.xml"].replace("aarch64</architecture>", "aarch&#54;4</architecture>")),
        ]
        for annex, text in variants:
            with self.subTest(annex=annex, xml=text), self.assertRaisesRegex(M.EntryError, "entity/reference"):
                M.parse_gdb_xml(text, annex)

    def test_raw_xml_and_responses_survive_parse_failure(self):
        text = '<target><architecture>aarch64</architecture><xi:include href="aarch64-core.xml"/>'
        with tempfile.TemporaryDirectory() as folder:
            records = []
            remote = M.Remote(None, time.monotonic() + 2, Path(folder), records)
            remote.request = lambda command: "l" + text
            with self.assertRaisesRegex(M.EntryError, "invalid target.xml"):
                remote.xml("target.xml")
            self.assertEqual((Path(folder) / "gdb-target.xml").read_text(), text)
            packets = json.loads((Path(folder) / "gdb-target.xml.responses.json").read_text())
            self.assertEqual(packets, [{"command": "qXfer:features:read:target.xml:0,800", "response": "l" + text}])
            self.assertEqual(records[0]["raw_xml"]["sha256"], M.digest(text.encode()))
            self.assertEqual(records[0]["packet_count"], 1)

    def test_core_must_be_the_first_include(self):
        xml = self.qemu_xml()
        xml["target.xml"] = xml["target.xml"].replace('<xi:include href="aarch64-core.xml"/>', '')
        remote = M.Remote(None, time.monotonic() + 2)
        remote.request = lambda command: "l" + xml[command.split(":")[3]]
        with self.assertRaisesRegex(M.EntryError, "first and exactly once"):
            remote.validate_architecture()

    def test_empty_continuation_xml_response_is_rejected(self):
        remote = M.Remote(None, time.monotonic() + 2)
        remote.request = lambda command: "m"
        with self.assertRaisesRegex(M.EntryError, "empty continuation"):
            remote.xml("target.xml")
        self.assertFalse(remote.xml_records[0]["complete"])

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


class DebuggerTargetTests(unittest.TestCase):
    def test_actual_nlist_section_and_file_bytes_define_target(self):
        remote = SnapshotRemote()
        target = remote.target
        self.assertEqual(target["symbol"], "_DebuggerTrapWithState")
        self.assertEqual(target["va"], hex(FIXTURE.BASE + 0x2040))
        self.assertEqual(target["file_offset"], "0x1040")
        self.assertEqual(target["segment"], "__TEXT_EXEC")
        self.assertEqual(target["instruction_bytes"], remote.kernel[0x1040:0x1044].hex())

    def test_missing_duplicate_weak_or_nonsection_symbol_fails(self):
        remote = SnapshotRemote()
        for variant in ("missing", "duplicate", "weak", "type", "ordinal"):
            strict = copy.deepcopy(remote.strict)
            records = strict["metadata"]["symbols"]["records"]
            symbol = next(s for s in records if s["name"] == M.DEBUGGER_SYMBOL)
            if variant == "missing":
                records.remove(symbol)
            elif variant == "duplicate":
                records.append(dict(symbol))
            elif variant == "weak":
                symbol["n_desc"] |= 0x80
            elif variant == "type":
                symbol["n_type"] = 0xE
            else:
                symbol["n_sect"] = 255
            with self.subTest(variant=variant), self.assertRaises(M.EntryError):
                M.debugger_target(strict, remote.kernel)

    def test_unaligned_noncode_or_non_file_backed_targets_fail(self):
        remote = SnapshotRemote()
        for variant in ("unaligned", "section-end", "not-pure", "not-executable", "file-end", "wrong-segment"):
            strict = copy.deepcopy(remote.strict)
            symbol = next(s for s in strict["metadata"]["symbols"]["records"] if s["name"] == M.DEBUGGER_SYMBOL)
            section = strict["metadata"]["sections"][symbol["n_sect"] - 1]
            segment = next(s for s in strict["segments"] if s["name"] == "__TEXT_EXEC")
            if variant == "unaligned":
                symbol["value"] += 2
            elif variant == "section-end":
                section["size"] = 0x40
            elif variant == "not-pure":
                section["flags"] = 0
            elif variant == "not-executable":
                segment["initprot"] = 1
            elif variant == "file-end":
                segment["filesize"] = 0x40
            else:
                section["segment"] = "__DATA"
            with self.subTest(variant=variant), self.assertRaises(M.EntryError):
                M.debugger_target(strict, remote.kernel)

    def test_read_window_intersects_ram_and_rejects_uint64_overflow(self):
        remote = SnapshotRemote()
        start, end = remote.window
        self.assertEqual(start, FIXTURE.BASE)
        self.assertEqual(end, FIXTURE.BASE + 0x5FE00000 - 0x50004000)
        changed = {**remote.layout, "ram_size": 0x11000000}
        self.assertEqual(M.debugger_read_window(remote.strict, changed)[1], FIXTURE.BASE + 0x51000000 - 0x50004000)
        strict = copy.deepcopy(remote.strict)
        strict["metadata"]["load_contract"]["virtual_base"] = M.UINT64_END - 16
        with self.assertRaisesRegex(M.EntryError, "read window"):
            M.debugger_read_window(strict, remote.layout)


class BoundedReadTests(unittest.TestCase):
    def reader(self, response):
        remote = SimpleNamespace(deadline=time.monotonic() + 10, commands=[])
        def request(command):
            remote.commands.append(command)
            return response(command)
        remote.request = request
        return remote

    def test_null_and_invalid_pointer_paths_never_request_memory(self):
        remote = self.reader(lambda _: self.fail("unexpected memory request"))
        window = (FIXTURE.BASE, FIXTURE.BASE + 0x1000)
        self.assertEqual(M.bounded_memory_read(remote, 0, 8, window, nullable=True)["status"], "null")
        for address in (0, -1, 0x52000000, FIXTURE.BASE - 1, window[1], M.UINT64_END):
            with self.subTest(address=address):
                result = M.bounded_memory_read(remote, address, 8, window)
                self.assertEqual(result["status"], "invalid-pointer")
        result = M.bounded_memory_read(remote, M.UINT64_END - 8, 16, (M.UINT64_END - 0x1000, M.UINT64_END))
        self.assertEqual(result["status"], "invalid-pointer")
        self.assertEqual(remote.commands, [])

    def test_string_stops_at_nul_without_reading_the_next_page(self):
        remote = self.reader(lambda _: "4100")
        result = M.bounded_memory_read(remote, FIXTURE.BASE + 0xFFE, 512,
                                       (FIXTURE.BASE, FIXTURE.BASE + 0x2000), c_string=True)
        self.assertEqual(remote.commands, [f"m{FIXTURE.BASE + 0xFFE:x},2"])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["text_utf8"], "A")
        self.assertEqual(result["data_hex"], "4100")
        self.assertTrue(result["nul_terminated"])

    def test_nonterminated_string_has_fixed_limit_and_is_truncated(self):
        remote = self.reader(lambda command: "41" * int(command.split(",")[1], 16))
        result = M.bounded_memory_read(remote, FIXTURE.BASE, 512,
                                       (FIXTURE.BASE, FIXTURE.BASE + 0x1000), c_string=True)
        self.assertEqual(result["status"], "truncated")
        self.assertEqual(result["truncation_reason"], "byte-limit")
        self.assertEqual(result["bytes_read"], 512)
        self.assertEqual(len(remote.commands), 8)
        self.assertFalse(result["nul_terminated"])

    def test_fixed_window_boundary_preserves_only_in_range_bytes(self):
        remote = self.reader(lambda command: "a5" * int(command.split(",")[1], 16))
        result = M.bounded_memory_read(remote, FIXTURE.BASE + 0xFF8, 256,
                                       (FIXTURE.BASE, FIXTURE.BASE + 0x1000), alignment=8)
        self.assertEqual(remote.commands, [f"m{FIXTURE.BASE + 0xFF8:x},8"])
        self.assertEqual(result["status"], "truncated")
        self.assertEqual(result["truncation_reason"], "read-window-end")
        self.assertEqual(result["data_hex"], "a5" * 8)

    def test_bad_reply_fails_and_retains_partial_or_error_response(self):
        for reply, count in (("E14", 0), ("abc", 0), ("00" * 65, 0), ("ff", 1)):
            remote = self.reader(lambda _, reply=reply: reply)
            with self.subTest(reply=reply):
                result = M.bounded_memory_read(remote, FIXTURE.BASE, 64, (FIXTURE.BASE, FIXTURE.BASE + 0x1000))
                self.assertEqual(result["status"], "read-error")
                self.assertEqual(result["bytes_read"], count)
                self.assertEqual(result["chunks"][0]["response"], reply)

    def test_later_error_and_deadline_keep_previous_bytes(self):
        remote = self.reader(lambda _: "41" * 64 if len(remote.commands) == 1 else "E14")
        result = M.bounded_memory_read(remote, FIXTURE.BASE, 512,
                                       (FIXTURE.BASE, FIXTURE.BASE + 0x1000), c_string=True)
        self.assertEqual(result["status"], "read-error")
        self.assertEqual(result["data_hex"], "41" * 64)
        self.assertEqual(result["chunks"][1]["response"], "E14")
        remote = self.reader(lambda _: self.fail("request after deadline"))
        remote.deadline = time.monotonic() - 1
        result = M.bounded_memory_read(remote, FIXTURE.BASE, 8, (FIXTURE.BASE, FIXTURE.BASE + 0x1000))
        self.assertEqual(result["status"], "read-error")
        self.assertIn("timed out", result["error"])
        self.assertEqual(remote.commands, [])


class DebuggerSnapshotTests(unittest.TestCase):
    def observe(self, remote):
        record = {"target": remote.target}
        M.observe_debugger(remote, remote.target, remote.window, record)
        return record

    def test_snapshot_captures_all_core_and_one_raw_varargs_indirection(self):
        remote = SnapshotRemote()
        record = self.observe(remote)
        self.assertTrue(record["verified"])
        self.assertEqual(record["registers"], {k: hex(v) for k, v in remote.values.items()})
        self.assertEqual(len(record["registers"]), 34)
        self.assertEqual(record["raw_core_reply"], core_packet(remote.values))
        self.assertEqual(record["memory"]["panic_format"]["text_utf8"], "bad %lld")
        self.assertEqual(record["va_list_cursor"], hex(FIXTURE.BASE + 0x4200))
        self.assertEqual(record["memory"]["va_list_slots"]["data_hex"], bytes(range(256)).hex())
        self.assertEqual(record["callers"]["panic_caller_x7"], hex(remote.values["x7"]))
        self.assertEqual(remote.commands.count("c"), 1)
        self.assertEqual(remote.commands[-1], f"z1,{remote.target['va'][2:]},4")
        self.assertTrue(all(command == "c" or command == "g" or command.startswith(("Z1,", "z1,", "m"))
                            for command in remote.commands))

    def test_null_debugger_arguments_are_valid_but_null_sp_is_not(self):
        remote = SnapshotRemote()
        remote.values.update(x0=4, x1=0, x2=0, x3=0)
        record = self.observe(remote)
        self.assertTrue(record["verified"])
        self.assertTrue(all(record["memory"][name]["status"] == "null"
                            for name in ("message", "panic_format", "va_list_cell", "va_list_slots")))
        remote = SnapshotRemote()
        remote.values["sp"] = 0
        record = self.observe(remote)
        self.assertFalse(record["verified"])
        self.assertTrue(record["registers_captured"])
        self.assertEqual(record["memory"]["stack"]["status"], "invalid-pointer")

    def test_unreadable_cell_invalid_cursor_and_short_slot_range_are_distinct(self):
        for mode in ("cell", "cursor", "short", "null-cursor"):
            remote = SnapshotRemote()
            if mode == "cell":
                del remote.memory[remote.values["x3"]]
            elif mode == "cursor":
                remote.store(remote.values["x3"], struct.pack("<Q", 0x52000000))
            elif mode == "short":
                remote.store(remote.values["x3"], struct.pack("<Q", remote.window[1] - 8))
                remote.store(remote.window[1] - 8, b"lastdata")
            else:
                remote.store(remote.values["x3"], bytes(8))
            record = self.observe(remote)
            with self.subTest(mode=mode):
                self.assertTrue(record["registers_captured"])
                self.assertEqual(record["memory"]["message"]["text_utf8"], "panic message")
                self.assertEqual(record["memory"]["va_list_slots"]["status"],
                                 {"cell": "not-read", "cursor": "invalid-pointer", "short": "truncated", "null-cursor": "null"}[mode])
                self.assertEqual(record["verified"], mode == "null-cursor")

    def test_truncated_message_preserves_registers_and_other_fields_but_fails_gate(self):
        remote = SnapshotRemote()
        remote.values["x1"] = FIXTURE.BASE + 0x2400
        remote.store(remote.values["x1"], b"A" * 512)
        record = self.observe(remote)
        self.assertFalse(record["verified"])
        self.assertTrue(record["debugger_entry_observed"])
        self.assertEqual(record["status"], "partial")
        self.assertEqual(record["memory"]["message"]["status"], "truncated")
        self.assertEqual(record["memory"]["stack"]["bytes_read"], 256)

    def test_wrong_pc_non_aarch64_el1_or_changed_instruction_cannot_pass(self):
        for mode in ("pc", "el0", "aarch32-mode", "instruction"):
            remote = SnapshotRemote()
            if mode == "pc":
                remote.values["pc"] += 4
            elif mode == "el0":
                remote.values["cpsr"] = 0
            elif mode == "aarch32-mode":
                remote.values["cpsr"] = 0x14
            else:
                remote.store(int(remote.target["va"], 16), bytes(4))
            record = self.observe(remote)
            with self.subTest(mode=mode):
                self.assertFalse(record["verified"])
                self.assertTrue(record["registers_captured"])
                self.assertFalse(record["debugger_entry_observed"])
                self.assertTrue(record["breakpoint_removed"])
                self.assertNotIn("memory", record)

    def test_malformed_register_packet_is_preserved_without_claiming_capture(self):
        for mode in ("short", "odd", "unavailable"):
            remote = SnapshotRemote()
            packet = core_packet(remote.values)
            remote.responses["g"] = {"short": packet[:-2], "odd": packet + "0", "unavailable": "xx" + packet[2:]}[mode]
            record = self.observe(remote)
            with self.subTest(mode=mode):
                self.assertFalse(record["verified"])
                self.assertFalse(record["registers_captured"])
                self.assertEqual(record["raw_core_reply"], remote.responses["g"][:536])
                self.assertTrue(record["breakpoint_removed"])

    def test_rejected_breakpoint_unexpected_stop_and_cleanup_failure_do_not_resume(self):
        for mode in ("install", "stop", "cleanup"):
            remote = SnapshotRemote()
            command = {"install": f"Z1,{remote.target['va'][2:]},4", "stop": "c", "cleanup": f"z1,{remote.target['va'][2:]},4"}[mode]
            remote.responses[command] = "S0b" if mode == "stop" else "E22"
            record = self.observe(remote)
            with self.subTest(mode=mode):
                self.assertFalse(record["verified"])
                self.assertEqual(remote.commands.count("c"), 0 if mode == "install" else 1)
                if mode == "cleanup":
                    self.assertTrue(record["debugger_entry_observed"])
                    self.assertIn("cleanup_error", record)

    def test_deadline_after_breakpoint_ack_prevents_continue(self):
        remote = SnapshotRemote()
        original = remote.request
        def request(command):
            reply = original(command)
            if command.startswith("Z1,"):
                remote.deadline = time.monotonic() - 1
            return reply
        remote.request = request
        record = self.observe(remote)
        self.assertFalse(record["verified"])
        self.assertIn("timed out", record["error"])
        self.assertEqual(remote.commands, [f"Z1,{remote.target['va'][2:]},4"])


class SeedAndReportTests(unittest.TestCase):
    def test_exact_seed_rebuilds_identical_adt_and_boot_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "seed.bin"
            original = bytes(range(256))
            path.write_bytes(original)
            seed, identity = M.read_seed(path)
            self.assertEqual(seed, original)
            self.assertEqual(identity, M.identity(path))
            contract = inputs()[2]["load_contract"]
            replay_adt = M.make_adt("cortex-a76", seed)
            original_adt = M.make_adt("cortex-a76", original)
            replay, _ = M.make_boot_args(contract, 0x50004000, 0x52000000, replay_adt, "-v")
            original_boot, _ = M.make_boot_args(contract, 0x50004000, 0x52000000, original_adt, "-v")
            self.assertEqual(replay_adt, original_adt)
            self.assertEqual(replay, original_boot)

    def test_wrong_size_symlink_directory_and_fifo_seeds_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            seed = root / "seed.bin"
            for size in (0, 255, 257):
                seed.write_bytes(bytes(size))
                with self.subTest(size=size), self.assertRaisesRegex(M.EntryError, "exactly 256"):
                    M.read_seed(seed)
            seed.write_bytes(bytes(256))
            link = root / "link.bin"
            link.symlink_to(seed)
            fifo = root / "fifo"
            os.mkfifo(fifo)
            for path in (link, root, fifo):
                with self.subTest(path=path), self.assertRaisesRegex(M.EntryError, "regular input"):
                    M.read_seed(path)

    def run_report_fixture(self, root, *, snapshot=True, seed_file=True, adt="qemu-virt",
                           mutate_seed=False, current_el=4, counter=62500000, partial=False,
                           clock_mode="host-virtual", qemu_driver=None):
        """Exercise report/input invalidation with authored bytes and fake tools.

        Neither the compiler nor QEMU is executed. Real entry execution remains
        a separate external experiment, regardless of any fixture report flags.
        """
        folder = root / "inputs"
        folder.mkdir()
        kernel, image, loader_report, config = inputs(debugger_fixture())
        for name, data in (("kernel", kernel), ("image", image),
                           ("loader.json", json.dumps(loader_report).encode()),
                           ("config.json", json.dumps(config).encode()),
                           ("seed.bin", bytes(range(256))), ("tool", b"authored-tool-fixture")):
            (folder / name).write_bytes(data)
        args = SimpleNamespace(output=root / "out", kernel=folder / "kernel", loaded_image=folder / "image",
                               loader_report=folder / "loader.json", seed_file=folder / "seed.bin" if seed_file else None,
                               adt=adt, cpu="cortex-a76", physical_base=0x50004000, boot_args_pa=0x52000000,
                               command_line="-v", timeout=10, debugger_snapshot=snapshot,
                               clock_mode=clock_mode,
                               clang="fake-clang", linker="fake-linker", objcopy="fake-objcopy", qemu="fake-qemu")
        observed = []
        def fake_tool(_):
            path = folder / "tool"
            return str(path), {"invocation_path": str(path), "resolved_binary": M.identity(path), "version": "fixture"}
        def fake_compile(argv, **_):
            Path(argv[-1]).write_bytes(b"authored-trampoline-fixture")
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        def fake_qemu(args, output, layout, symbols, image, strict, report):
            observed.append(True)
            report.update(qemu_kernel_entry_executed=True, qemu_early_cpu_entry_observed=True,
                          exception={"CurrentEL": current_el, "CNTFRQ": counter})
            report["entry_observation"] = {
                "before_branch": {"pc": layout["entry_pa"], "x0": layout["boot_args_pa"], "cpsr": 5},
                "after_branch": {"pc": layout["entry_pa"] + 16, "x0": layout["boot_args_pa"], "cpsr": 5}}
            report["qemu"] = {"stop_reason": "first-exception"}
            if args.debugger_snapshot:
                peer = SnapshotRemote()
                if partial:
                    peer.values["sp"] = 0
                M.observe_debugger(peer, report["debugger_snapshot"]["target"], M.debugger_read_window(strict, layout), report["debugger_snapshot"])
                report["qemu_debugger_snapshot_verified"] = report["debugger_snapshot"]["verified"]
                report["qemu"]["stop_reason"] = "debugger-snapshot" if report["qemu_debugger_snapshot_verified"] else "debugger-snapshot-incomplete"
            if mutate_seed:
                (folder / "seed.bin").write_bytes(b"x" * 256)
        with patch.object(M.loader, "CONFIG", folder / "config.json"), \
                patch.object(M, "select_tool", side_effect=fake_tool), \
                patch.object(M.subprocess, "run", side_effect=fake_compile), \
                patch.object(M, "run_qemu", side_effect=qemu_driver or fake_qemu):
            report = M.run(args)
        self.assertEqual(report, json.loads((args.output / "report.json").read_text()))
        return report, observed

    def test_seed_is_a_protected_input_and_snapshot_addresses_are_exact_strings(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            report, observed = self.run_report_fixture(root)
            self.assertEqual(observed, [True])
            self.assertEqual(report["status"], "qemu_debugger_snapshot_observed")
            self.assertTrue(report["qemu_debugger_snapshot_verified"])
            self.assertIn(M.identity(root / "inputs/seed.bin"), report["inputs"])
            self.assertEqual(report["random_seed"]["sha256"], M.digest(bytes(range(256))))
            self.assertEqual(report["layout"]["device_tree_va"], "0xfffffff009001000")
            self.assertEqual(report["debugger_snapshot"]["registers"]["pc"], hex(FIXTURE.BASE + 0x2040))
            self.assertFalse(report["runtime_kernel_slide_verified"])
            self.assertFalse(report["board_adt_verified"])
            self.assertFalse(report["tb371fc_kernel_qualified"])
            self.assertFalse(report["os_boot_verified"])

    def test_seed_change_invalidates_all_execution_and_snapshot_gates(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            report, _ = self.run_report_fixture(root, mutate_seed=True)
            self.assertEqual(report["status"], "failed")
            self.assertEqual(report["input_recheck"]["changed_paths"], [str(root / "inputs/seed.bin")])
            for flag in ("qemu_kernel_entry_executed", "qemu_early_cpu_entry_observed", "qemu_debugger_snapshot_verified"):
                self.assertFalse(report[flag])
            self.assertFalse(report["debugger_snapshot"]["verified"])
            self.assertEqual(report["debugger_snapshot"]["status"], "invalidated-input-change")
            self.assertEqual(len(report["debugger_snapshot"]["registers"]), 34)

    def test_post_observation_el_or_counter_failure_revokes_snapshot_success(self):
        for changes in ({"current_el": 0}, {"counter": 1}):
            with self.subTest(changes=changes), tempfile.TemporaryDirectory() as folder:
                report, _ = self.run_report_fixture(Path(folder), **changes)
                self.assertEqual(report["status"], "failed")
                self.assertFalse(report["qemu_debugger_snapshot_verified"])
                self.assertFalse(report["debugger_snapshot"]["verified"])
                self.assertEqual(report["debugger_snapshot"]["status"], "invalidated-diagnostic-failure")
                self.assertTrue(report["debugger_snapshot"]["registers_captured"])

    def test_partial_snapshot_returns_failure_and_preserves_entry_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            report, _ = self.run_report_fixture(Path(folder), partial=True)
            self.assertEqual(report["status"], "failed")
            self.assertFalse(report["qemu_debugger_snapshot_verified"])
            self.assertTrue(report["qemu_kernel_entry_executed"])
            self.assertEqual(report["debugger_snapshot"]["status"], "partial")

    def test_seed_without_adt_is_rejected_before_emulator_stage(self):
        with tempfile.TemporaryDirectory() as folder:
            report, observed = self.run_report_fixture(Path(folder), adt="none")
            self.assertEqual(observed, [])
            self.assertEqual(report["status"], "failed")
            self.assertIn("seed file requires", report["error"])
            self.assertFalse(report["qemu_debugger_snapshot_verified"])

    def test_default_report_keeps_entry_status_and_legacy_fields_without_snapshot(self):
        with tempfile.TemporaryDirectory() as folder, \
                patch.object(M, "debugger_target", side_effect=AssertionError("opt-in resolver called by default")):
            report, _ = self.run_report_fixture(Path(folder), snapshot=False, seed_file=False)
            self.assertEqual(report["status"], "qemu_entry_observed")
            self.assertNotIn("debugger_snapshot", report)
            self.assertNotIn("address_encoding", report)
            self.assertIsInstance(report["layout"]["device_tree_va"], int)
            self.assertEqual(report["random_seed"]["source"], "generated")


    def test_unknown_clock_mode_is_rejected_before_any_emulator_stage(self):
        with tempfile.TemporaryDirectory() as folder:
            report, observed = self.run_report_fixture(Path(folder), clock_mode="auto")
            self.assertEqual(observed, [])
            self.assertEqual(report["status"], "failed")
            self.assertIn("unsupported clock mode", report["error"])
            self.assertNotIn("qemu", report)
            self.assertFalse(report["qemu_debugger_snapshot_verified"])

    def test_clock_report_matches_actual_launch_and_preserves_generated_input_identity(self):
        # Exercise the real launcher/report path while replacing the process,
        # socket and target peer. This does not launch QEMU or any compiler.
        actual_driver = M.run_qemu
        records = []
        class Process:
            pid, returncode = 1234, None
            def poll(self):
                return self.returncode
            def terminate(self):
                self.returncode = 0
            def wait(self, timeout):
                return self.returncode
        for mode in ("host-virtual", "instruction-1ns"):
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                peer = SnapshotRemote()
                launched = []
                def launch(argv, **_):
                    launched.append(list(argv))
                    serial = Path(argv[argv.index("-serial") + 1].removeprefix("file:"))
                    serial.write_text("ENTRY-PROBE: CurrentEL=0x4\nENTRY-PROBE: CNTFRQ=0x3b9aca0\n")
                    return Process()
                def remote(connection, deadline, *_):
                    peer.deadline = deadline
                    return peer
                connection = SimpleNamespace(connect=lambda _: None, close=lambda: None)
                observed_entry = {"before_branch": {"pc": peer.layout["entry_pa"], "x0": 0x52000000, "cpsr": 5},
                                  "after_branch": {"pc": peer.layout["entry_pa"] + 16, "x0": 0x52000000, "cpsr": 5}}
                with patch.object(M.subprocess, "Popen", side_effect=launch), \
                        patch.object(M.socket, "socket", return_value=connection), \
                        patch.object(M, "Remote", side_effect=remote), \
                        patch.object(M, "observe_entry", return_value=observed_entry):
                    report, _ = self.run_report_fixture(root, clock_mode=mode, qemu_driver=actual_driver)
                self.assertEqual(report["status"], "qemu_debugger_snapshot_observed")
                self.assertEqual(len(launched), 1)
                self.assertEqual(report["qemu"]["argv"], launched[0])
                self.assertEqual(report["qemu"]["clock_mode"], mode)
                argv = launched[0]
                icount = [argv[i + 1] for i, value in enumerate(argv) if value == "-icount"]
                self.assertEqual(icount, [] if mode == "host-virtual" else ["shift=0,align=off,sleep=off"])
                self.assertEqual(report["qemu"]["icount"], icount[0] if icount else None)
                if icount:
                    at = argv.index("-icount")
                    argv = argv[:at] + argv[at + 2:]
                records.append(([value.replace(str(root), "<fixture>") for value in argv],
                                {Path(item["path"]).name: (item["size"], item["sha256"])
                                 for item in report["generated_inputs"]}))
        self.assertEqual(records[0], records[1])


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
