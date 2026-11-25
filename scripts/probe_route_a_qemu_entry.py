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
import struct
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
import probe_route_a_loader as loader

ROOT = Path(__file__).resolve().parents[1]
SOURCES = Path(__file__).resolve().parent / "route_a_qemu_entry"
RAM_BASE, RAM_SIZE, BLOCK = 0x40000000, 0x20000000, 0x200000
STUB_BASE, STUB_LIMIT, BOOT_SIZE = 0x40080000, 0x40090000, 0x4000
MAX_LOG = 16 * 1024 * 1024
CPUS = ("cortex-a53", "cortex-a57", "cortex-a72", "cortex-a76", "cortex-a710")
QUALIFICATION = {
    "qemu_kernel_entry_executed": False,
    "qemu_early_cpu_entry_observed": False,
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


class Remote:
    """Small ACK-mode GDB remote client, on a private local Unix socket."""
    def __init__(self, connection, deadline):
        self.connection, self.deadline = connection, deadline

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
        result = ""
        while len(result) <= 65536:
            part = self.request(f"qXfer:features:read:{name}:{len(result):x},800")
            require(part[:1] in ("m", "l"), "QEMU did not provide its register XML")
            result += part[1:]
            if part[0] == "l":
                return ET.fromstring(result)
        raise EntryError("oversized QEMU register XML")

    def validate_architecture(self):
        target = self.xml("target.xml")
        require(target.findtext("architecture") == "aarch64", "unexpected QEMU GDB architecture")
        core = self.xml("aarch64-core.xml")
        registers, number = {}, 0
        for reg in core.iter("reg"):
            number = int(reg.get("regnum", str(number)))
            registers[reg.get("name")] = (number, int(reg.get("bitsize", "0")))
            number += 1
        require(registers.get("x0") == (0, 64) and registers.get("pc") == (32, 64)
                and registers.get("cpsr") == (33, 32), "unexpected AArch64 core register layout")

    def registers(self):
        packet = self.request("g")
        require(len(packet) >= 536 and re.fullmatch("[0-9a-fA-F]+", packet) is not None,
                "invalid AArch64 core register reply")
        raw = bytes.fromhex(packet)
        return {"x0": struct.unpack_from("<Q", raw, 0)[0],
                "pc": struct.unpack_from("<Q", raw, 256)[0],
                "cpsr": struct.unpack_from("<I", raw, 264)[0]}


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
            remote = Remote(connection, deadline)
            report["entry_observation"] = observe_entry(remote, layout, symbols)
            report["qemu_kernel_entry_executed"] = True
            report["qemu_early_cpu_entry_observed"] = True
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
        adt = make_adt(args.cpu, os.urandom(256)) if args.adt == "qemu-virt" else b""
        boot, layout = make_boot_args(strict["metadata"]["load_contract"], args.physical_base,
                                      args.boot_args_pa, adt, args.command_line)
        report.update(layout=layout, adt={"kind": args.adt, "bytes": len(adt), "sha256": digest(adt),
                                        "synthetic": True, "board_identity": False})
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
            path = shutil.which(getattr(args, name))
            require(path is not None, f"tool missing: {getattr(args, name)}")
            path = str(Path(path).resolve())
            setattr(args, name, path)
            item = identity(path)
            inputs.append(item)
            version = subprocess.run([path, "--version"], capture_output=True, timeout=10)
            require(version.returncode == 0, f"tool version check failed: {path}")
            report["tools"][name] = {**item, "version": (version.stdout + version.stderr).decode(errors="replace")[:4096]}
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
        report["status"] = "qemu_entry_observed"
    except (EntryError, loader.ProbeError, loader.platform_link.LinkError, OSError,
            ValueError, KeyError, ET.ParseError, subprocess.SubprocessError) as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
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
                          qemu_kernel_entry_executed=False, qemu_early_cpu_entry_observed=False)
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
                     "qemu_early_cpu_entry_observed", "tb371fc_kernel_qualified", "os_boot_verified")}, sort_keys=True))
    return 0 if report["status"] == "qemu_entry_observed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
