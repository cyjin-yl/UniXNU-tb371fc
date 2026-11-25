#!/usr/bin/env python3
"""Execute the fixed Route A kernel's entry branch in an isolated QEMU virt.

The input remains the host-verified ordinary ARM64 candidate. A synthetic ADT,
boot_args and an EL1 trampoline replace firmware; no TB371FC device is accessed.
A GDB hardware breakpoint plus one instruction step establishes actual execution
of __start's branch. UART intent or translated code alone never passes that gate.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import socket
import stat
import struct
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from xml.parsers import expat

sys.path.insert(0, str(Path(__file__).resolve().parent))
import probe_route_a_loader as loader

ROOT = Path(__file__).resolve().parents[1]
SOURCES = Path(__file__).resolve().parent / "route_a_qemu_entry"
RAM_BASE, RAM_SIZE, BLOCK = 0x40000000, 0x20000000, 0x200000
STUB_BASE, STUB_LIMIT, BOOT_SIZE = 0x40080000, 0x40090000, 0x4000
MAX_LOG = 16 * 1024 * 1024
UINT64_END = 1 << 64
DEBUGGER_SYMBOL = "_DebuggerTrapWithState"
STRING_LIMIT, STACK_LIMIT, VA_LIST_LIMIT, READ_CHUNK = 512, 256, 256, 64
CORE_NAMES = tuple(f"x{i}" for i in range(31)) + ("sp", "pc", "cpsr")
CPUS = ("cortex-a53", "cortex-a57", "cortex-a72", "cortex-a76", "cortex-a710")
QUALIFICATION = {
    "qemu_kernel_entry_executed": False,
    "qemu_early_cpu_entry_observed": False,
    "qemu_debugger_snapshot_verified": False,
    "runtime_kernel_slide_verified": False,
    "uefi_allocation_verified": False,
    "board_adt_verified": False,
    "tb371fc_kernel_qualified": False,
    "os_boot_verified": False,
}


class EntryError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise EntryError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def identity(path):
    path = Path(path)
    data = path.read_bytes()
    return {"path": str(path), "size": len(data), "sha256": digest(data)}


def regular(path):
    path = Path(path).absolute()
    require(path.is_file() and not path.is_symlink(), f"not a regular input: {path}")
    path = path.resolve()
    require(not any(c in str(path) for c in ",\r\n"), "QEMU input path contains a delimiter")
    return path


def read_seed(path):
    """Read exactly one regular 256-byte seed, never a stream or a symlink."""
    path = regular(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size == 256,
                "seed file must be regular and exactly 256 bytes")
        seed = stream.read(257)
    require(len(seed) == 256, "seed file changed size while reading")
    return seed, {"path": str(path), "size": len(seed), "sha256": digest(seed)}


def select_tool(name):
    """Preserve argv[0] for multicall drivers while identifying their binary."""
    selected = shutil.which(name)
    require(selected is not None, f"tool missing: {name}")
    invocation = os.path.abspath(selected)
    binary = str(Path(invocation).resolve(strict=True))
    version = subprocess.run([invocation, "--version"], capture_output=True, timeout=10)
    require(version.returncode == 0, f"tool version check failed: {invocation}")
    return invocation, {
        "invocation_path": invocation,
        "resolved_binary": identity(binary),
        "version": (version.stdout + version.stderr).decode(errors="replace")[:4096],
    }


def adt_node(name, properties=(), children=()):
    """Apple flattened-tree format; values are explicitly little-endian here."""
    properties = [("name", name.encode("ascii") + b"\0"), *properties]
    require(len({key for key, _ in properties}) == len(properties), "duplicate ADT property")
    encoded = bytearray(struct.pack("<II", len(properties), len(children)))
    for key, value in properties:
        key = key.encode("ascii")
        require(0 < len(key) <= 31 and b"\0" not in key, "invalid ADT property name")
        encoded += struct.pack("<32sI", key, len(value)) + value + bytes(-len(value) % 4)
    return bytes(encoded) + b"".join(children)


def make_adt(cpu, seed):
    """Describe only the single-CPU, GICv3, PL011 QEMU fixture used below.

    The format and platform properties follow the pinned upstream make-dt.py;
    no QCOM UFS placeholder, iPad identity, storage or trust sidecar is emitted.
    The random seed is captured in the generated ADT, so every run is replayable.
    """
    require(cpu in CPUS and len(seed) == 256, "unsupported CPU or entropy length")
    u32 = lambda value: struct.pack("<I", value)
    u64 = lambda value: struct.pack("<Q", value)
    return adt_node("device-tree", [("model", b"route-a-qemu-entry-fixture\0"),
                    ("compatible", b"linux,dummy-virt\0")], [
        adt_node("chosen", [("random-seed", seed), ("dram-base", u64(RAM_BASE)),
                            ("dram-size", u64(RAM_SIZE))],
                 [adt_node("memory-map"), adt_node("manifest-properties")]),
        adt_node("cpus", children=[adt_node("cpu0", [
            ("state", b"running\0"), ("reg", u32(0)), ("device_type", b"cpu\0"),
            ("compatible", ("arm," + cpu).encode("ascii") + b"\0"),
            ("timebase-frequency", u32(62500000))])]),
        adt_node("defaults", [("vmm-present", u32(1))]),
        adt_node("product", [("product-name", b"QEMU virt\0"),
                             ("model", b"linux,dummy-virt\0")]),
        adt_node("arm-io", [("device_type", b"qemu-virt\0"),
                            ("ranges", struct.pack("<QQQ", 0, 0x08000000, 0x04000000))], [
            adt_node("intc", [("compatible", b"arm,gic-v3\0"),
                              ("reg", struct.pack("<4Q", 0, 0x10000, 0xA0000, 0xF60000))]),
            adt_node("uart", [("compatible", b"arm,pl011\0"),
                              ("reg", struct.pack("<QQ", 0x01000000, 0x1000))]),
        ]),
    ])


def make_boot_args(contract, physical_base, args_pa, adt, command_line):
    base, span = contract["virtual_base"], contract["memory_span"]
    ram_end = RAM_BASE + RAM_SIZE
    require(physical_base % BLOCK == base % BLOCK,
            "physical and virtual bases must have identical low 21 bits")
    require(RAM_BASE <= physical_base < ram_end and physical_base % 4096 == 0,
            "physical base is outside fixture RAM or not page aligned")
    require(physical_base >= STUB_LIMIT, "kernel overlaps the entry trampoline")
    require(args_pa % 0x4000 == 0 and physical_base + span <= args_pa,
            "boot_args must be 16 KiB aligned and follow the complete kernel image")
    require(args_pa + BOOT_SIZE <= ram_end, "boot_args exceeds fixture RAM")
    memory_size = ram_end - physical_base
    # Even with a downward-rounded number of 2 MiB bootstrap blocks, all inputs
    # fit. QEMU owns the 16 KiB prefix too; this does not prove UEFI ownership.
    mapped_start = physical_base & -BLOCK
    conservative_end = mapped_start + (memory_size & -BLOCK)
    require(RAM_BASE <= mapped_start and args_pa + BOOT_SIZE <= conservative_end,
            "payload does not fit the conservative initial block mapping")
    require(len(adt) <= BOOT_SIZE - 0x1000, "synthetic ADT exceeds its reserved buffer")
    encoded = command_line.encode("ascii")
    require(len(encoded) < 1024 and b"\0" not in encoded, "invalid boot command line")
    boot = bytearray(BOOT_SIZE)
    struct.pack_into("<HH4xQQQQ", boot, 0, 2, 2, base, physical_base,
                     memory_size, args_pa + BOOT_SIZE)
    boot[0x6C:0x6C + len(encoded)] = encoded
    struct.pack_into("<Q", boot, 0x478, memory_size)
    if adt:
        boot[0x1000:0x1000 + len(adt)] = adt
        struct.pack_into("<QI", boot, 0x60, base + args_pa + 0x1000 - physical_base, len(adt))
    return bytes(boot), {
        "ram_base": RAM_BASE, "ram_size": RAM_SIZE, "physical_base": physical_base,
        "entry_pa": physical_base + contract["entry_offset"], "boot_args_pa": args_pa,
        "device_tree_pa": args_pa + 0x1000 if adt else None,
        "device_tree_va": base + args_pa + 0x1000 - physical_base if adt else None,
        "top_of_kernel_data": args_pa + BOOT_SIZE, "memory_size": memory_size,
        "bootstrap_prefix_start": mapped_start,
        "conservative_bootstrap_mapped_end": conservative_end,
        "virtual_slide": 0, "synthetic_fixture": True,
    }


def validate_inputs(kernel, image, report, config):
    loader.verify_bytes(kernel, config["candidate"], "fixed platform candidate")
    require(report.get("status") == "host_loader_contract_verified", "loader report did not pass")
    for flag in ("host_loader_probe_verified", "kernel_segment_bytes_verified", "boot_args_abi_verified"):
        require(report.get(flag) is True, f"loader report lacks {flag}")
    require(report.get("protected_inputs_recheck", {}).get("unchanged") is True,
            "loader report's declared inputs changed")
    require(report.get("kernel", {}).get("sha256") == digest(kernel), "kernel/report identity mismatch")
    image_record = report.get("byte_load", {}).get("image", {})
    require(image_record.get("size") == len(image) and image_record.get("sha256") == digest(image),
            "loaded image/report identity mismatch")
    strict = loader.strict_kernel(kernel)
    contract = strict["metadata"]["load_contract"]
    require(all(report.get("load_contract", {}).get(k) == v for k, v in contract.items()),
            "loader geometry differs from the actual candidate")
    require(report["load_contract"].get("virtual_slide") == 0, "only the zero-slide candidate is supported")
    require(len(image) == contract["memory_span"], "loaded image span differs")
    expected = bytearray(len(image))
    for segment in strict["segments"]:
        at, size = segment["vmaddr"] - contract["virtual_base"], segment["filesize"]
        expected[at:at + size] = kernel[segment["fileoff"]:segment["fileoff"] + size]
    require(image == expected, "loaded image differs from the candidate's segments or zero fill")
    symbols = loader.check_entry_symbols(strict, config, kernel)
    require(symbols == report.get("entry_symbols"), "loader entry evidence differs from actual symbols")
    return strict, symbols


def debugger_target(strict, kernel):
    """Resolve the fixed candidate's actual symbol; no user-supplied PC root."""
    info = strict["metadata"]
    found = [s for s in info["symbols"]["records"] if s["name"] == DEBUGGER_SYMBOL]
    require(len(found) == 1, "debugger symbol absent or ambiguous")
    symbol = found[0]
    require(symbol["n_type"] == 0xF and not symbol["n_desc"] & 0x80
            and 1 <= symbol["n_sect"] <= len(info["sections"]),
            "debugger symbol is not a unique strong section definition")
    address = symbol["value"]
    section = info["sections"][symbol["n_sect"] - 1]
    require(0 <= address <= UINT64_END - 4 and address % 4 == 0,
            "debugger symbol address is unaligned or outside uint64")
    require(section["flags"] & 0x80000000 and section["flags"] & 0xFF == 0
            and section["addr"] <= address and address + 4 <= section["addr"] + section["size"],
            "debugger section does not contain a complete pure instruction")
    owners = [s for s in strict["segments"] if s["initprot"] & 4
              and s["vmaddr"] <= address and address + 4 <= s["vmaddr"] + s["filesize"]]
    require(len(owners) == 1 and owners[0]["name"] == section["segment"],
            "debugger symbol is not in its file-backed executable segment")
    offset = owners[0]["fileoff"] + address - owners[0]["vmaddr"]
    require(0 <= offset and offset + 4 <= len(kernel), "debugger instruction is outside the candidate file")
    return {"symbol": DEBUGGER_SYMBOL, "va": hex(address), "file_offset": hex(offset),
            "segment": owners[0]["name"], "section": section["name"],
            "section_ordinal": symbol["n_sect"], "n_type": hex(symbol["n_type"]),
            "instruction_bytes": kernel[offset:offset + 4].hex()}


def debugger_read_window(strict, layout):
    """Only the declared initial linear mapping intersected with owned RAM.

    This is an upper bound for reads, not a page-table/mapping qualification.
    The debugger must still return every requested byte successfully.
    """
    base = strict["metadata"]["load_contract"]["virtual_base"]
    physical = layout["physical_base"]
    start_pa = max(physical, layout["ram_base"])
    end_pa = min(physical + layout["memory_size"], layout["ram_base"] + layout["ram_size"],
                 layout["conservative_bootstrap_mapped_end"])
    start, end = base + start_pa - physical, base + end_pa - physical
    require(0 <= start < end <= UINT64_END, "invalid debugger read window")
    return start, end


def decode_rsp(payload):
    """Decode GDB escaping and run-length packets after checking wire checksum."""
    out, cursor = bytearray(), 0
    while cursor < len(payload):
        byte = payload[cursor]
        cursor += 1
        if byte == 0x7D:
            require(cursor < len(payload), "truncated GDB escape")
            out.append(payload[cursor] ^ 0x20)
            cursor += 1
        elif byte == 0x2A:
            require(out and cursor < len(payload), "invalid GDB run length")
            repeat = payload[cursor] - 29
            require(3 <= repeat <= 97, "unsupported GDB run length")
            out.extend([out[-1]] * repeat)
            cursor += 1
        else:
            out.append(byte)
        require(len(out) <= 1 << 20, "oversized GDB response")
    return bytes(out)


def parse_gdb_xml(text, annex):
    """Parse QEMU's finite GDB XML dialect without fetching any DTD/include.

    QEMU get_feature_xml emits literal xi:include tags under <target> without
    declaring xmlns:xi. Expat without namespace expansion preserves that known
    spelling; it does not silently discard architecture or include information.
    The only external declaration accepted is inert gdb-target.dtd metadata.
    """
    require(annex in ("target.xml", "aarch64-core.xml"), "unexpected GDB XML annex")
    # Neither of these fixed QEMU descriptions needs character/entity references.
    # Expat can silently omit undeclared entities after an unread external DTD,
    # including in attributes where SkippedEntityHandler is not called. Reject
    # reference syntax before parsing instead of accepting altered identifiers.
    require("&" not in text, "GDB XML entity/reference syntax is not supported")
    expected_root = "target" if annex == "target.xml" else "feature"
    builder = ET.TreeBuilder()
    parser = expat.ParserCreate()  # No namespace separator: xi:include is literal.
    parser.StartElementHandler = builder.start
    parser.EndElementHandler = builder.end
    parser.CharacterDataHandler = builder.data
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    def doctype(name, system, public, internal):
        require(name == expected_root and system == "gdb-target.dtd" and public is None and not internal,
                "unsupported GDB XML DTD or internal subset")
    def reject_entity(*_):
        raise EntryError("GDB XML entities and external resources are not supported")
    parser.StartDoctypeDeclHandler = doctype
    parser.EntityDeclHandler = reject_entity
    parser.ExternalEntityRefHandler = reject_entity
    parser.SkippedEntityHandler = reject_entity
    try:
        parser.Parse(text, True)
        root = builder.close()
    except expat.ExpatError as exc:
        raise EntryError(f"invalid {annex}: {exc}") from exc
    require(root.tag == expected_root, "unexpected GDB XML root")
    if annex == "target.xml":
        require(root.attrib in ({}, {"xmlns:xi": "http://www.w3.org/2001/XInclude"}),
                "unsupported GDB target namespace or attributes")
        for child in root:
            require(child.tag in ("architecture", "xi:include") and not list(child),
                    "unsupported GDB target element")
            if child.tag == "architecture":
                require(not child.attrib, "unexpected GDB architecture attributes")
            else:
                require(set(child.attrib) == {"href"} and
                        re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]*\.xml", child.attrib["href"]) is not None,
                        "GDB include must name a local feature annex")
    else:
        require(root.attrib == {"name": "org.gnu.gdb.aarch64.core"}, "unexpected GDB core feature")
        require(all(child.tag == "reg" and not list(child) for child in root), "unsupported GDB core element")
    return root


class Remote:
    """Small ACK-mode GDB remote client, on a private local Unix socket."""
    def __init__(self, connection, deadline, evidence_directory=None, xml_records=None):
        self.connection, self.deadline = connection, deadline
        self.evidence_directory = evidence_directory
        self.xml_records = xml_records if xml_records is not None else []

    def byte(self):
        while True:
            remaining = self.deadline - time.monotonic()
            require(remaining > 0, "entry observation timed out")
            self.connection.settimeout(min(remaining, 1))
            try:
                data = self.connection.recv(1)
            except socket.timeout:
                continue
            require(data, "QEMU debugger closed before observation completed")
            return data

    def receive(self):
        while self.byte() != b"$":
            pass
        packet = bytearray()
        while (byte := self.byte()) != b"#":
            packet += byte
            require(len(packet) <= 1 << 20, "oversized GDB wire packet")
        checksum = self.byte() + self.byte()
        require(re.fullmatch(b"[0-9a-fA-F]{2}", checksum) is not None and
                int(checksum, 16) == sum(packet) % 256, "GDB response checksum mismatch")
        self.connection.sendall(b"+")
        return decode_rsp(packet).decode("ascii")

    def send(self, command):
        raw = command.encode("ascii")
        self.connection.sendall(b"$" + raw + b"#" + f"{sum(raw) % 256:02x}".encode())

    def request(self, command):
        self.send(command)
        return self.receive()

    def xml(self, name):
        require(name in ("target.xml", "aarch64-core.xml"), "unexpected GDB XML annex")
        result, packets = "", []
        record = {"annex": name, "complete": False}
        self.xml_records.append(record)
        try:
            while len(result) <= 65536:
                command = f"qXfer:features:read:{name}:{len(result):x},800"
                part = self.request(command)
                packets.append({"command": command, "response": part})
                require(part[:1] in ("m", "l"), "QEMU did not provide its register XML")
                require(part[0] == "l" or len(part) > 1, "QEMU returned an empty continuation XML packet")
                result += part[1:]
                require(len(result) <= 65536, "oversized QEMU register XML")
                if part[0] == "l":
                    record["complete"] = True
                    break
        finally:
            raw = result.encode("ascii")
            record.update(size=len(raw), sha256=digest(raw), packet_count=len(packets))
            if self.evidence_directory is not None:
                xml_path = self.evidence_directory / ("gdb-" + name)
                responses_path = self.evidence_directory / ("gdb-" + name + ".responses.json")
                xml_path.write_bytes(raw)
                responses_path.write_text(json.dumps(packets, indent=2) + "\n")
                record.update(raw_xml=identity(xml_path), responses=identity(responses_path))
            else:
                record.update(raw_xml_text=result, responses=packets)
        return parse_gdb_xml(result, name)

    def validate_architecture(self):
        target = self.xml("target.xml")
        architectures = target.findall("architecture")
        require(len(architectures) == 1 and architectures[0].text == "aarch64", "unexpected QEMU GDB architecture")
        includes = [node.attrib["href"] for node in target if node.tag == "xi:include"]
        require(includes and includes[0] == "aarch64-core.xml" and includes.count("aarch64-core.xml") == 1,
                "QEMU target does not declare the core feature first and exactly once")
        core = self.xml("aarch64-core.xml")
        registers, number = [], 0
        for reg in core.iter("reg"):
            number = int(reg.get("regnum", str(number)))
            registers.append((reg.get("name"), number, int(reg.get("bitsize", "0"))))
            number += 1
        expected = [(f"x{i}", i, 64) for i in range(31)] + [("sp", 31, 64), ("pc", 32, 64), ("cpsr", 33, 32)]
        require(registers == expected, "unexpected AArch64 core register layout")

    def core_registers(self, record=None):
        if record is not None:
            require(time.monotonic() < self.deadline, "debugger snapshot timed out")
        packet = self.request("g")
        if record is not None:
            # The verified core prefix contains all 34 core registers. Do not
            # copy unneeded FPU/system-register tails into the snapshot report.
            record.update(raw_core_reply=packet[:536], register_reply_chars=len(packet),
                          register_reply_sha256=digest(packet.encode("ascii")))
        require(536 <= len(packet) <= 1 << 20 and len(packet) % 2 == 0
                and re.fullmatch("[0-9a-fA-F]+", packet) is not None,
                "invalid AArch64 core register reply")
        raw = bytes.fromhex(packet[:536])
        return dict(zip(CORE_NAMES, struct.unpack("<33QI", raw)))

    def registers(self):
        core = self.core_registers()
        return {name: core[name] for name in ("x0", "pc", "cpsr")}


def observe_entry(remote, layout, symbols):
    remote.request("qSupported")
    remote.validate_architecture()
    entry = layout["entry_pa"]
    early = entry + symbols["early_cpu"]["value"] - symbols["entry"]["value"]
    require(remote.request(f"Z1,{entry:x},4") == "OK", "QEMU rejected entry hardware breakpoint")
    stopped = remote.request("c")
    require(stopped.startswith(("T05", "S05")), f"unexpected entry stop: {stopped}")
    before = remote.registers()
    require(before["pc"] == entry and before["x0"] == layout["boot_args_pa"]
            and before["cpsr"] & 15 == 5, "entry breakpoint does not show expected PC, x0 and EL1h")
    expected = struct.pack("<I", symbols["trampoline"]["instruction_word"])
    require(remote.request(f"m{entry:x},4") == expected.hex(), "actual entry instruction differs")
    stepped = remote.request("s")
    require(stepped.startswith(("T05", "S05")), f"unexpected single-step stop: {stepped}")
    after = remote.registers()
    require(after["pc"] == early and after["x0"] == layout["boot_args_pa"],
            "single-stepped __start branch did not reach start_first_cpu")
    require(remote.request(f"z1,{entry:x},4") == "OK", "QEMU could not remove entry breakpoint")
    return {"before_branch": before, "after_branch": after,
            "instruction_bytes": expected.hex(), "gdb_stop_before": stopped, "gdb_stop_after": stepped,
            "scope": "one unchanged kernel B instruction actually single-stepped in QEMU; early CPU body not yet qualified"}


def bounded_memory_read(remote, address, limit, window, *, c_string=False, nullable=False, alignment=1):
    """Read small page-bounded chunks; retain partial bytes and every status.

    Limits are fixed by this diagnostic, never derived from guest strings or a
    format specifier. A short/error response is not silently treated as data.
    """
    result = {"address": hex(address), "limit_bytes": limit, "status": "not-read",
              "bytes_read": 0, "data_hex": "", "chunks": []}
    if c_string:
        result.update(nul_terminated=False, truncated=False)
    data = bytearray()
    try:
        start, end = window
        require(0 < limit <= STRING_LIMIT and 0 <= start < end <= UINT64_END,
                "invalid bounded memory read limits")
        if address == 0 and nullable:
            result["status"] = "null"
            return result
        require(0 < address < UINT64_END and address + limit <= UINT64_END
                and start <= address < end and address % alignment == 0,
                "pointer is outside the declared linear RAM window, overflows, or is unaligned")
        available = min(limit, end - address)
        while len(data) < available:
            require(time.monotonic() < remote.deadline, "debugger snapshot timed out")
            at = address + len(data)
            count = min(READ_CHUNK, available - len(data), 0x1000 - at % 0x1000)
            command = f"m{at:x},{count:x}"
            chunk = {"address": hex(at), "requested_bytes": count, "command": command}
            result["chunks"].append(chunk)
            reply = remote.request(command)
            chunk.update(response=reply[:2 * count + 32], response_chars=len(reply),
                         response_sha256=digest(reply.encode("ascii")))
            valid_hex = len(reply) % 2 == 0 and re.fullmatch("[0-9a-fA-F]*", reply) is not None
            if valid_hex and len(reply) <= 2 * count:
                data += bytes.fromhex(reply)
            require(valid_hex and len(reply) == 2 * count, "GDB memory read returned an error or wrong byte count")
            if c_string and b"\0" in data:
                nul = data.index(0)
                result.update(status="complete", nul_terminated=True, nul_offset=nul,
                              text_utf8=data[:nul].decode("utf-8", errors="replace"))
                break
        else:
            result["status"] = "truncated" if c_string or available < limit else "complete"
            if result["status"] == "truncated":
                result.update(truncated=True, truncation_reason="read-window-end" if available < limit else "byte-limit")
                if c_string:
                    result["text_utf8"] = data.decode("utf-8", errors="replace")
    except (EntryError, OSError, ValueError) as exc:
        result.update(status="read-error" if result["chunks"] else "invalid-pointer" if "pointer" in str(exc) else "read-error",
                      error=f"{type(exc).__name__}: {exc}")
    finally:
        result.update(bytes_read=len(data), data_hex=data.hex())
    return result


def observe_debugger(remote, target, window, record):
    """Stop at the real function entry and read; never resume past this stop."""
    address = int(target["va"], 16)
    record.update(status="observing", verified=False, registers_captured=False,
                  debugger_entry_observed=False, breakpoint_installed=False, breakpoint_removed=False,
                  read_window={"start": hex(window[0]), "end_exclusive": hex(window[1]),
                               "scope": "declared linear RAM upper bound; actual reads must also succeed"})
    paused = False
    def request(command):
        require(time.monotonic() < remote.deadline, "debugger snapshot timed out")
        return remote.request(command)
    try:
        reply = request(f"Z1,{address:x},4")
        record["breakpoint_set_response"] = reply[:64]
        require(reply == "OK", "QEMU rejected debugger hardware breakpoint")
        record["breakpoint_installed"] = True
        stopped = request("c")
        record.update(gdb_stop=stopped[:4096], gdb_stop_chars=len(stopped))
        paused = len(stopped) >= 3 and stopped[0] in ("T", "S") and re.fullmatch("[0-9a-fA-F]{2}", stopped[1:3]) is not None
        require(stopped.startswith(("T05", "S05")) and len(stopped) <= 4096,
                "unexpected stop before debugger entry")
        registers = remote.core_registers(record)
        record.update(registers={name: hex(value) for name, value in registers.items()}, registers_captured=True)
        require(registers["pc"] == address and registers["cpsr"] & 0x1F in (4, 5),
                "debugger breakpoint does not show expected PC and EL1")
        instruction = bounded_memory_read(remote, address, 4, window, alignment=4)
        record["instruction_read"] = instruction
        require(instruction["status"] == "complete" and instruction["data_hex"] == target["instruction_bytes"],
                "actual debugger entry instruction differs or is unreadable")
        record["debugger_entry_observed"] = True
        record["callers"] = {"panic_caller_x7": hex(registers["x7"]),
                             "link_register_x30": hex(registers["x30"]),
                             "frame_pointer_x29": hex(registers["x29"]),
                             "scope": "raw register values; no caller attribution or frame unwinding"}
        fields = record["memory"] = {}
        fields["message"] = bounded_memory_read(remote, registers["x1"], STRING_LIMIT, window, c_string=True, nullable=True)
        fields["panic_format"] = bounded_memory_read(remote, registers["x2"], STRING_LIMIT, window, c_string=True, nullable=True)
        cell = fields["va_list_cell"] = bounded_memory_read(remote, registers["x3"], 8, window, nullable=True, alignment=8)
        if cell["status"] in ("complete", "null"):
            # Darwin va_list is char*. This parameter is va_list*: exactly one
            # LE64 cursor cell, then a fixed raw slot window, not a pointer walk.
            cursor = int.from_bytes(bytes.fromhex(cell["data_hex"]), "little") if cell["status"] == "complete" else 0
            record["va_list_cursor"] = hex(cursor)
            fields["va_list_slots"] = bounded_memory_read(remote, cursor, VA_LIST_LIMIT, window, nullable=True, alignment=8)
        else:
            fields["va_list_slots"] = {"status": "not-read", "reason": "va_list_cell_incomplete", "bytes_read": 0, "data_hex": ""}
        fields["stack"] = bounded_memory_read(remote, registers["sp"], STACK_LIMIT, window, alignment=16)
        record["memory_complete"] = all(item["status"] in ("complete", "null") for item in fields.values())
        if not record["memory_complete"]:
            record["error"] = "one or more bounded memory fields failed or were truncated"
    except (EntryError, OSError, ValueError) as exc:
        record["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        # If c timed out the guest may still be running. Do not issue a packet
        # which assumes it is stopped; run_qemu will terminate/reap it instead.
        if paused and record["breakpoint_installed"] and time.monotonic() < remote.deadline:
            try:
                reply = remote.request(f"z1,{address:x},4")
                record["breakpoint_remove_response"] = reply[:64]
                require(reply == "OK", "QEMU could not remove debugger breakpoint")
                record["breakpoint_removed"] = True
            except (EntryError, OSError, ValueError) as exc:
                record["cleanup_error"] = f"{type(exc).__name__}: {exc}"
        record["verified"] = bool(record["debugger_entry_observed"] and record.get("memory_complete")
                                  and record["breakpoint_removed"])
        record["status"] = "captured" if record["verified"] else "partial" if record["debugger_entry_observed"] else "failed"


def read_text(path):
    return path.read_bytes()[:MAX_LOG].decode("utf-8", errors="replace") if path.exists() else ""


def exception_summary(trace, serial, strict, image, layout):
    result = {"exception_observed": "Taking exception" in trace or "exception captured" in serial,
              "qemu_trace_prefix": trace[:8192]}
    event = re.search(r"Taking exception (\d+) \[([^\]]+)\](?: on CPU (\d+))?", trace)
    if event:
        result["first_exception"] = {"number": int(event[1]), "description": event[2],
                                     "cpu": int(event[3]) if event[3] else None}
    syndrome = re.search(r"with ESR (0x[0-9a-fA-F]+(?:/0x[0-9a-fA-F]+)?)", trace)
    if syndrome:
        result["qemu_esr_text"] = syndrome[1]
    for register in ("CurrentEL", "MMFR0", "CNTFRQ", "ESR_EL1", "ELR_EL1", "FAR_EL1"):
        match = re.search(r"ENTRY-PROBE: " + register + r"=0x([0-9a-fA-F]+)", serial)
        if match:
            result[register] = int(match[1], 16)
    match = re.search(r"with ELR 0x([0-9a-fA-F]+)", trace)
    pc = int(match[1], 16) if match else result.get("ELR_EL1")
    if pc is None:
        return result
    base, pa = strict["metadata"]["load_contract"]["virtual_base"], layout["physical_base"]
    virtual = pc if base <= pc < base + len(image) else (base + pc - pa if pa <= pc < pa + len(image) else None)
    result.update(fault_pc=pc, fault_va=virtual,
                  fault_address_space="kernel-virtual" if virtual == pc else "kernel-physical" if virtual is not None else "outside-kernel")
    for segment in strict["segments"]:
        if virtual is not None and segment["vmaddr"] <= virtual and virtual + 4 <= segment["vmaddr"] + segment["filesize"]:
            result.update(fault_segment=segment["name"],
                          fault_opcode=f"0x{struct.unpack_from('<I', image, virtual - base)[0]:08x}")
    return result


def run_qemu(args, output, layout, symbols, image, strict, report):
    endpoint = output / "gdb.sock"
    require(len(os.fsencode(endpoint)) <= 100, "output path is too long for the local GDB socket")
    serial, trace = output / "serial.log", output / "exceptions.log"
    argv = [args.qemu, "-M", "virt,virtualization=off,secure=off,gic-version=3", "-accel", "tcg",
            "-cpu", args.cpu, "-m", "512", "-smp", "1", "-display", "none", "-monitor", "none",
            "-nic", "none", "-no-reboot", "-serial", f"file:{serial}", "-kernel", str(output / "entry.bin"),
            "-d", "int", "-D", str(trace), "-S", "-gdb", f"unix:{endpoint},server=on,wait=off",
            "-device", f"loader,file={args.loaded_image},addr={layout['physical_base']:#x},force-raw=on",
            "-device", f"loader,file={output / 'boot-args.bin'},addr={layout['boot_args_pa']:#x},force-raw=on"]
    report["qemu"] = {"argv": argv, "cpu": args.cpu, "gic_version": 3, "timeout_seconds": args.timeout,
                      "max_file_bytes": MAX_LOG, "storage_devices": [], "network_devices": []}
    started = time.monotonic()
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_LOG, MAX_LOG))
    with (output / "qemu.stderr.log").open("wb") as stderr:
        process = subprocess.Popen(argv, stdout=stderr, stderr=stderr, stdin=subprocess.DEVNULL,
                                   preexec_fn=limits)
        report["qemu"]["pid"] = process.pid
        try:
            deadline = started + args.timeout
            while True:
                require(process.poll() is None, f"QEMU exited before debugger attachment: {process.returncode}")
                require(time.monotonic() < deadline, "QEMU debugger socket did not become ready")
                try:
                    connection.connect(str(endpoint))
                    break
                except (FileNotFoundError, ConnectionRefusedError):
                    time.sleep(0.02)
            remote = Remote(connection, deadline, output, report.setdefault("gdb_xml", []))
            report["entry_observation"] = observe_entry(remote, layout, symbols)
            report["qemu_kernel_entry_executed"] = True
            report["qemu_early_cpu_entry_observed"] = True
            if getattr(args, "debugger_snapshot", False):
                snapshot = report["debugger_snapshot"]
                observe_debugger(remote, snapshot["target"], debugger_read_window(strict, layout), snapshot)
                report["qemu_debugger_snapshot_verified"] = snapshot["verified"]
                reason = "debugger-snapshot" if snapshot["verified"] else "debugger-snapshot-incomplete"
            else:
                remote.send("c")
                reason = "timeout"
                while process.poll() is None and time.monotonic() < deadline:
                    if "Taking exception" in read_text(trace) or "exception captured" in read_text(serial):
                        reason = "first-exception"
                        break
                    if any(p.exists() and p.stat().st_size >= MAX_LOG for p in (serial, trace)):
                        reason = "log-limit"
                        break
                    time.sleep(0.05)
            if process.poll() is not None:
                reason = "qemu-exit"
            report["qemu"]["stop_reason"] = reason
        finally:
            connection.close()
            report["qemu"]["termination"] = "already-exited"
            if process.poll() is None:
                report["qemu"]["termination"] = "SIGTERM"
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    report["qemu"]["termination"] = "SIGKILL-after-2s"
                    process.kill()
                    process.wait(timeout=2)
            report["qemu"].update(exit_code=process.returncode, reaped=process.poll() is not None,
                                   elapsed_seconds=round(time.monotonic() - started, 6))
            report["exception"] = exception_summary(read_text(trace), read_text(serial), strict, image, layout)


def run(args):
    output = args.output.absolute()
    require(not output.exists(), f"output already exists: {output}")
    require(not any(c in str(output) for c in ",\r\n"), "QEMU output path contains a delimiter")
    output = output.resolve()
    require(ROOT not in output.parents and output != ROOT, "write generated outputs outside the repository")
    output.mkdir(parents=True, exist_ok=False)
    report = {"schema": "route-a-qemu-entry-v1", "status": "failed", **QUALIFICATION,
              "started_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "scope": "isolated single-CPU QEMU virt entry diagnostic with synthetic firmware inputs"}
    if getattr(args, "debugger_snapshot", False):
        report["debugger_snapshot"] = {"requested": True, "verified": False, "status": "not-started"}
    inputs = []
    try:
        require(0.5 <= args.timeout <= 60, "timeout must be between 0.5 and 60 seconds")
        for name in ("kernel", "loaded_image", "loader_report"):
            setattr(args, name, regular(getattr(args, name)))
            require(getattr(args, name).parent not in output.parents, "output must not be inside an input directory")
            inputs.append(identity(getattr(args, name)))
        config = json.loads(loader.CONFIG.read_text())
        kernel, image = args.kernel.read_bytes(), args.loaded_image.read_bytes()
        strict, symbols = validate_inputs(kernel, image, json.loads(args.loader_report.read_text()), config)
        seed_file = getattr(args, "seed_file", None)
        require(seed_file is None or args.adt == "qemu-virt", "seed file requires --adt qemu-virt")
        if seed_file is not None:
            seed, seed_identity = read_seed(seed_file)
            inputs.append(seed_identity)
        else:
            seed = os.urandom(256) if args.adt == "qemu-virt" else b""
        adt = make_adt(args.cpu, seed) if args.adt == "qemu-virt" else b""
        if seed:
            report["random_seed"] = {"source": "file" if seed_file is not None else "generated",
                                     "size": len(seed), "sha256": digest(seed)}
        boot, layout = make_boot_args(strict["metadata"]["load_contract"], args.physical_base,
                                      args.boot_args_pa, adt, args.command_line)
        report.update(layout=layout, adt={"kind": args.adt, "bytes": len(adt), "sha256": digest(adt),
                                        "synthetic": True, "board_identity": False})
        if getattr(args, "debugger_snapshot", False):
            report["debugger_snapshot"]["target"] = debugger_target(strict, kernel)
            debugger_read_window(strict, layout)  # Validate the declared bound before QEMU launch.
        (output / "boot-args.bin").write_bytes(boot)
        if adt:
            (output / "synthetic-qemu.adt").write_bytes(adt)
        manifest = json.loads((SOURCES / "sources.json").read_text())
        for record in manifest["files"]:
            path = regular(SOURCES / record["path"])
            loader.verify_bytes(path.read_bytes(), record, str(path))
            inputs.append(identity(path))
        report["entry_source"] = manifest
        for path in (Path(__file__).resolve(), SOURCES / "sources.json", loader.CONFIG,
                     Path(loader.__file__), Path(loader.platform_link.__file__)):
            inputs.append(identity(path))
        report["tools"] = {}
        for name in ("clang", "linker", "objcopy", "qemu"):
            invocation, record = select_tool(getattr(args, name))
            setattr(args, name, invocation)
            # Recheck both selection and bytes: retargeting a driver symlink
            # must not silently substitute a different executable mid-run.
            inputs.append(identity(invocation))
            if record["resolved_binary"]["path"] != invocation:
                inputs.append(record["resolved_binary"])
            report["tools"][name] = record
        report["compile"] = []
        commands = [
            [args.clang, "--target=aarch64-none-elf", "-c", f"-DBOOT_ARGS_PA={args.boot_args_pa}",
             f"-DKERNEL_ENTRY_PA={layout['entry_pa']}", str(SOURCES / "entry.S"), "-o", str(output / "entry.o")],
            [args.linker, "-T", str(SOURCES / "link.ld"), str(output / "entry.o"), "-o", str(output / "entry.elf")],
            [args.objcopy, "-O", "binary", str(output / "entry.elf"), str(output / "entry.bin")],
        ]
        for index, argv in enumerate(commands):
            completed = subprocess.run(argv, capture_output=True, timeout=30)
            (output / f"compile-{index}.stdout").write_bytes(completed.stdout)
            (output / f"compile-{index}.stderr").write_bytes(completed.stderr)
            report["compile"].append({"argv": argv, "exit_code": completed.returncode})
            require(completed.returncode == 0, f"trampoline build failed at step {index}")
        require((output / "entry.bin").stat().st_size <= STUB_LIMIT - STUB_BASE, "trampoline exceeds its reserved range")
        report["generated_inputs"] = [identity(output / "entry.bin"), identity(output / "boot-args.bin")]
        if adt:
            report["generated_inputs"].append(identity(output / "synthetic-qemu.adt"))
        inputs.extend(report["generated_inputs"])
        run_qemu(args, output, layout, symbols, image, strict, report)
        require(report["qemu_kernel_entry_executed"], "entry instruction execution was not established")
        require(report["exception"].get("CurrentEL") == 4, "trampoline did not report EL1")
        if adt:
            require(report["exception"].get("CNTFRQ") == 62500000,
                    "actual QEMU counter frequency differs from the synthetic ADT")
        require(report["qemu"]["stop_reason"] != "qemu-exit", "QEMU exited unexpectedly; inspect logs")
        if getattr(args, "debugger_snapshot", False):
            require(report["qemu_debugger_snapshot_verified"], "debugger snapshot was not complete; inspect partial evidence")
            report["status"] = "qemu_debugger_snapshot_observed"
        else:
            report["status"] = "qemu_entry_observed"
    except (EntryError, loader.ProbeError, loader.platform_link.LinkError, OSError,
            ValueError, KeyError, ET.ParseError, subprocess.SubprocessError) as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
        if "debugger_snapshot" in report:
            report["qemu_debugger_snapshot_verified"] = False
            report["debugger_snapshot"]["verified"] = False
            if report["debugger_snapshot"]["status"] == "captured":
                report["debugger_snapshot"].update(status="invalidated-diagnostic-failure",
                                                   qualification_error=report["error"])
    finally:
        changes = []
        for before in inputs:
            try:
                if identity(before["path"]) != before:
                    changes.append(before["path"])
            except OSError:
                changes.append(before["path"])
        report["inputs"] = inputs
        report["input_recheck"] = {"unchanged": not changes, "changed_paths": changes}
        if changes:
            report.update(status="failed", error="declared inputs changed during the diagnostic",
                          qemu_kernel_entry_executed=False, qemu_early_cpu_entry_observed=False,
                          qemu_debugger_snapshot_verified=False)
            if "debugger_snapshot" in report:
                report["debugger_snapshot"].update(verified=False, status="invalidated-input-change")
        if "debugger_snapshot" in report:
            # The opt-in report uses strings for legacy address/register fields
            # too, so JavaScript readers cannot round high virtual addresses.
            # Keep the default execution/report path compatible with run003.
            report["address_encoding"] = "hex-strings"
            for name in ("boot_args_pa", "bootstrap_prefix_start", "conservative_bootstrap_mapped_end",
                         "device_tree_pa", "device_tree_va", "entry_pa", "physical_base", "ram_base",
                         "top_of_kernel_data", "virtual_slide"):
                value = report.get("layout", {}).get(name)
                if value is not None:
                    report["layout"][name] = hex(value)
            for branch in ("before_branch", "after_branch"):
                values = report.get("entry_observation", {}).get(branch, {})
                for name, value in values.items():
                    values[name] = hex(value)
            for name in ("fault_pc", "fault_va", "CurrentEL", "MMFR0", "ESR_EL1", "ELR_EL1", "FAR_EL1"):
                value = report.get("exception", {}).get(name)
                if value is not None:
                    report["exception"][name] = hex(value)
        report["outputs"] = [identity(p) for p in sorted(output.iterdir()) if p.is_file() and not p.is_symlink()]
        report["finished_at_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--loaded-image", type=Path, required=True)
    parser.add_argument("--loader-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--physical-base", type=lambda value: int(value, 0), default=0x50004000)
    parser.add_argument("--boot-args-pa", type=lambda value: int(value, 0), default=0x52000000)
    parser.add_argument("--adt", choices=("none", "qemu-virt"), default="qemu-virt")
    parser.add_argument("--seed-file", type=Path, help="replay an exact regular 256-byte synthetic ADT seed")
    parser.add_argument("--debugger-snapshot", action="store_true",
                        help="stop at the real DebuggerTrapWithState entry and capture bounded read-only state")
    parser.add_argument("--cpu", choices=CPUS, default="cortex-a76")
    parser.add_argument("--command-line", default="-v serial=3 debug=0x14e")
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--linker", default="ld.lld")
    parser.add_argument("--objcopy", default="llvm-objcopy")
    parser.add_argument("--qemu", default="qemu-system-aarch64")
    args = parser.parse_args()
    try:
        report = run(args)
    except EntryError as exc:
        parser.error(str(exc))
    print(json.dumps({k: report.get(k) for k in ("status", "error", "qemu_kernel_entry_executed",
                     "qemu_early_cpu_entry_observed", "qemu_debugger_snapshot_verified",
                     "tb371fc_kernel_qualified", "os_boot_verified")}, sort_keys=True))
    return 0 if report["status"] in ("qemu_entry_observed", "qemu_debugger_snapshot_observed") else 2


if __name__ == "__main__":
    raise SystemExit(main())
