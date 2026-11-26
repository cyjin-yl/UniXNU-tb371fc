#!/usr/bin/env python3
"""Observe the real source provider and later XNU initialization in QEMU virt.

All breakpoints come from the independently parsed, build-identified kernel.
The negative case flips only one stored POST HMAC byte, then requires actual
panic entry before table/PRNG publication. Guest instructions are never patched.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
from pathlib import Path
import re
import resource
import signal
import socket
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_route_a_corecrypto as build
import probe_route_a_qemu_entry as entry

require = build.require
MODES = ("positive", "negative-post")
FLAGS = ("runtime_post_verified", "negative_post_rejection_verified", "runtime_provider_verified",
         "consumer_vectors_verified", "real_consumer_return_verified", "post_consumer_return_verified")


def value(number):
    return int(number, 16) if isinstance(number, str) else number


def instruction(data, span, offset=0):
    require(offset % 4 == 0 and 0 <= offset <= span["size"] - 4, "instruction outside symbol extent")
    return struct.unpack_from("<I", data, span["file_offset"] + offset)[0]


def branch_target(word, pc):
    require(word & 0xfc000000 == 0x94000000, "expected a direct BL instruction")
    immediate = word & 0x3ffffff
    if immediate & 0x2000000: immediate -= 0x4000000
    return pc + immediate * 4


def call_return(strict, data, caller, callee):
    source = build.function_span(strict, data, caller)
    target = build.symbol_span(strict, data, callee, 4, executable=True)
    calls = []
    for offset in range(0, source["size"] - 4, 4):
        word = instruction(data, source, offset)
        if word & 0xfc000000 == 0x94000000 and branch_target(word, source["va"] + offset) == target["va"]:
            calls.append(offset)
    require(len(calls) == 1, f"expected one real BL {caller} -> {callee}")
    offset = calls[0]
    return {"symbol": caller + " -> " + callee + " return", "va": source["va"] + offset + 4,
            "file_offset": source["file_offset"] + offset + 4, "size": 4,
            "caller": source, "callee": target,
            "call_bytes": data[source["file_offset"] + offset:source["file_offset"] + offset + 8].hex()}


def storage_span(strict, name, size):
    found = [s for s in strict["metadata"]["symbols"]["records"] if s["name"] == name]
    require(len(found) == 1, f"missing or ambiguous state cell: {name}")
    symbol = found[0]
    require(symbol["n_type"] in (0xe, 0xf) and not symbol["n_desc"] & 0x80
            and 1 <= symbol["n_sect"] <= len(strict["metadata"]["sections"]), "invalid state cell definition")
    section = strict["metadata"]["sections"][symbol["n_sect"] - 1]
    address = symbol["value"]
    require(0 < size <= 448 and address % min(size, 8) == 0 and 0 <= address <= (1 << 64) - size,
            "state cell alignment/size/overflow")
    require(section["addr"] <= address and address + size <= section["addr"] + section["size"]
            and not section["flags"] & 0x80000400, "state cell outside data section")
    next_symbols = [s["value"] for s in strict["metadata"]["symbols"]["records"]
                    if s["n_type"] in (0xe, 0xf) and s["n_sect"] == symbol["n_sect"] and s["value"] > address]
    require(not next_symbols or address + size <= min(next_symbols), "state cell extends into another symbol")
    owners = [s for s in strict["segments"] if s["name"] == section["segment"]
              and s["vmaddr"] <= address and address + size <= s["vmaddr"] + s["vmsize"]]
    require(len(owners) == 1 and owners[0]["initprot"] & 1, "state cell has no readable declared segment")
    return {"symbol": name, "va": address, "size": size, "section": section["name"], "segment": section["segment"]}


def targets(strict, kernel):
    result = {"post": call_return(strict, kernel, "_corecrypto_kext_start", "_fipspost_post"),
              "consumer_entry": build.symbol_span(strict, kernel, "_vm_map_store_crypto_init", 4, executable=True),
              "consumer_return": call_return(strict, kernel, "_vm_map_store_crypto_init", "_crypto_random_kmem_ctx_size"),
              "debugger": build.symbol_span(strict, kernel, "_DebuggerTrapWithState", 4, executable=True),
              "bsd": build.symbol_span(strict, kernel, "_bsd_init", 4, executable=True),
              "provider_ctx": build.symbol_span(strict, kernel, "_cc_kext_random_kmem_ctx_size", 4, executable=True)}
    post = result["post"]
    word = struct.unpack_from("<I", kernel, post["file_offset"])[0]
    require(word & 0xff00001f == 0x35000000, "POST return must test nonzero W0 with CBNZ")
    displacement = (word >> 5) & 0x7ffff
    if displacement & 0x40000: displacement -= 0x80000
    fail = post["va"] + 4 * displacement
    source = post["caller"]
    require(source["va"] <= fail < source["va"] + source["size"], "POST failure branch leaves its actual provider function")
    post["failure_branch_va"] = fail
    result["cells"] = {name: storage_span(strict, name, size) for name, size in (
        ("_g_crypto_funcs", 8), ("_crypto_init", 1), ("_prng_ready", 4), ("_source_corecrypto14_status", 4),
        ("_route_a_crypto_consumer_status", 4), ("_route_a_crypto_consumer_vectors", 4), ("_kpis", 448))}
    return result


class Remote(entry.Remote):
    def send(self, command):
        require(time.monotonic() < self.deadline, "provider observation deadline expired before send")
        super().send(command)


class Observe:
    def __init__(self, remote, strict, kernel, defined, report):
        self.remote, self.strict, self.kernel, self.targets, self.report = remote, strict, kernel, defined, report
        self.installed, self.paused = {}, True

    def breakpoint(self, target):
        address = target["va"]
        require(address not in self.installed, "breakpoint already installed")
        require(self.remote.request(f"Z1,{address:x},4") == "OK", "hardware breakpoint rejected")
        self.installed[address] = target

    def remove(self, target):
        address = target["va"]
        require(address in self.installed, "breakpoint was not installed")
        require(self.remote.request(f"z1,{address:x},4") == "OK", "hardware breakpoint removal rejected")
        del self.installed[address]

    def read(self, span, label):
        record = entry.bounded_memory_read(self.remote, span["va"], span["size"],
                                          (span["va"], span["va"] + span["size"]))
        self.report.setdefault("reads", []).append({"label": label, "declaration": span, **record})
        require(record["status"] == "complete", f"incomplete declared read: {label}")
        return bytes.fromhex(record["data_hex"])

    def state(self):
        return {name: int.from_bytes(self.read(span, name), "little") for name, span in self.targets["cells"].items()
                if name != "_kpis"}

    def continue_to(self, label):
        self.paused = False
        stop = self.remote.request("c")
        self.paused = stop.startswith(("T05", "S05"))
        event = {"label": label, "stop": stop[:4096]}
        self.report.setdefault("events", []).append(event)
        require(self.paused and len(stop) <= 4096, "unexpected stop during provider observation")
        registers = self.remote.core_registers(event)
        event["registers"] = {name: hex(number) for name, number in registers.items()}
        require(registers["pc"] in self.installed and registers["cpsr"] & 31 in (4, 5), "unknown breakpoint or wrong EL")
        target = self.installed[registers["pc"]]
        expected = self.kernel[target["file_offset"]:target["file_offset"] + 4]
        actual = self.read({**target, "size": 4}, "stopped instruction")
        require(actual == expected, "stopped instruction differs from identified candidate")
        event["symbol"] = target["symbol"]
        return registers

    def expect(self, target, label):
        self.breakpoint(target)
        registers = self.continue_to(label)
        if registers["pc"] == self.targets["debugger"]["va"]:
            self.capture_panic(registers)
            raise build.BuildError(f"panic before {label}")
        require(registers["pc"] == target["va"], "wrong observation target")
        self.remove(target)
        return registers

    def static_string(self, address):
        candidates = [s for s in self.strict["metadata"]["sections"]
                      if s["addr"] <= address < s["addr"] + s["size"] and s["flags"] & 0xff != 1
                      and not s["flags"] & 0x80000400]
        if len(candidates) != 1:
            return {"address": hex(address), "status": "outside-static-data", "data_hex": ""}
        sec = candidates[0]
        limit = min(512, sec["addr"] + sec["size"] - address)
        owners = [s for s in self.strict["segments"] if s["name"] == sec["segment"]
                  and s["vmaddr"] <= address and address + limit <= s["vmaddr"] + s["filesize"]]
        if len(owners) != 1:
            return {"address": hex(address), "status": "not-file-backed", "data_hex": ""}
        return entry.bounded_memory_read(self.remote, address, limit, (sec["addr"], sec["addr"] + sec["size"]), c_string=True)

    def capture_panic(self, registers):
        record = {"db_op": registers["x0"], "panic_caller": hex(registers["x7"]),
                  "message": self.static_string(registers["x1"]), "format": self.static_string(registers["x2"]),
                  "scope": "core registers and at most two 512-byte strings in declared file-backed data sections; no stack or varargs reads"}
        self.report["panic"] = record
        return record

    def cleanup(self):
        if self.paused:
            for target in list(self.installed.values()):
                self.remove(target)


def return_from_entry(strict, kernel, registers, target):
    """Bind a captured LR to an actual BL/BLR and its still-unmodified operand."""
    address = registers["x30"]
    records = strict["metadata"]["symbols"]["records"]
    before = [s for s in records if s["n_type"] in (0xe, 0xf) and s["value"] <= address - 4]
    require(before and address % 4 == 0, "consumer LR is not a candidate code address")
    owner = max(before, key=lambda s: s["value"])
    function = build.function_span(strict, kernel, owner["name"])
    offset = address - 4 - function["va"]
    require(0 <= offset and offset + 8 <= function["size"], "consumer caller return leaves its function")
    word = instruction(kernel, function, offset)
    if word & 0xfc000000 == 0x94000000:
        require(branch_target(word, address - 4) == target["va"], "captured LR BL targets another function")
    else:
        require(word & 0xfffffc1f == 0xd63f0000, "captured LR is not from BL or BLR")
        register = (word >> 5) & 31
        require(register < 30 and registers[f"x{register}"] == target["va"], "BLR entry register does not identify the consumer")
    return {"symbol": "return from " + target["symbol"], "va": address, "size": 4,
            "file_offset": function["file_offset"] + offset + 4, "caller": function,
            "call_bytes": kernel[function["file_offset"] + offset:function["file_offset"] + offset + 8].hex()}


def observe(remote, strict, kernel, defined, report, mode, callback_offset):
    observation = Observe(remote, strict, kernel, defined, report)
    observation.breakpoint(defined["debugger"])
    try:
        post = observation.expect(defined["post"], "actual POST return")
        report["post_return_w0"] = post["x0"] & 0xffffffff
        if mode == "negative-post":
            require(report["post_return_w0"] != 0, "corrupt HMAC did not fail POST")
            at_return = observation.state(); report["negative_state_at_post_return"] = at_return
            require(all(at_return[k] == 0 for k in ("_g_crypto_funcs", "_crypto_init", "_prng_ready",
                                                   "_route_a_crypto_consumer_status", "_route_a_crypto_consumer_vectors")),
                    "negative POST already published state")
            registers = observation.continue_to("actual POST rejection panic")
            require(registers["pc"] == defined["debugger"]["va"] and registers["x0"] == 3, "negative POST did not enter panic debugger")
            panic = observation.capture_panic(registers)
            source = defined["post"]["caller"]
            caller = registers["x7"]
            require(source["va"] <= caller - 4 and caller <= source["va"] + source["size"], "negative panic caller is not the provider")
            word = instruction(kernel, source, caller - 4 - source["va"])
            panic_target = build.symbol_span(strict, kernel, "_panic", 4, executable=True)
            require(branch_target(word, caller - 4) == panic_target["va"], "negative caller did not actually BL panic")
            state = observation.state(); report["negative_state_at_panic"] = state
            require(all(state[k] == 0 for k in ("_g_crypto_funcs", "_crypto_init", "_prng_ready",
                                               "_route_a_crypto_consumer_status", "_route_a_crypto_consumer_vectors")),
                    "negative POST published table/PRNG before panic")
            require(panic["format"].get("nul_terminated") is True and "POST" in panic["format"].get("text_utf8", ""),
                    "negative panic format is not the bounded POST failure message")
            report["negative_post_rejection_verified"] = True
            return
        require(report["post_return_w0"] == 0, "real positive POST did not succeed")
        report["runtime_post_verified"] = True
        entered = observation.expect(defined["consumer_entry"], "real XNU crypto consumer entry")
        after_consumer = return_from_entry(strict, kernel, entered, defined["consumer_entry"])
        report["real_consumer_caller"] = after_consumer
        returned = observation.expect(defined["consumer_return"], "actual kmem ctx-size return")
        state = observation.state(); report["positive_state"] = state
        require(state["_g_crypto_funcs"] == defined["cells"]["_kpis"]["va"] and state["_crypto_init"] == 1
                and state["_prng_ready"] == 1 and state["_source_corecrypto14_status"] == 0, "provider publication not complete")
        table = observation.read(defined["cells"]["_kpis"], "all published table slots")
        pointers = struct.unpack("<56Q", table)
        require(all(pointers) and pointers[callback_offset // 8] == defined["provider_ctx"]["va"], "table callback identity differs")
        report["table_slots"] = [hex(p) for p in pointers]
        require(state["_route_a_crypto_consumer_status"] == 1 and state["_route_a_crypto_consumer_vectors"] == 5,
                "independent XNU table consumer vectors did not finish")
        require(0 < returned["x0"] <= 4096, "real provider returned an invalid bounded context size")
        report.update(consumer_vectors_verified=True, real_consumer_return_verified=True,
                      actual_kmem_context_size=returned["x0"])
        observation.expect(after_consumer, "return from complete vm_map_store_crypto_init")
        report.update(post_consumer_return_verified=True, runtime_provider_verified=True)
        observation.breakpoint(defined["bsd"])
        later = observation.continue_to("later XNU initialization or next panic")
        if later["pc"] == defined["bsd"]["va"]:
            report["later_initialization"] = "bsd_init-entry"
        else:
            observation.capture_panic(later)
            report["later_initialization"] = "next-panic-after-complete-crypto-consumer"
    finally:
        observation.cleanup()


def prepare(args, out, journal, report):
    receipt = build.regular(args.build_report); journal.protect(receipt)
    built = json.loads(receipt.read_text())
    require(built.get("schema") == "route-a-corecrypto-build-v1" and built.get("build_verified") is True
            and built.get("input_recheck", {}).get("unchanged") is True, "build was not verified")
    for key in ("kernel", "loaded_image", "loader_report"):
        path = build.regular(built[key]["path"])
        require(journal.protect(path) == built[key], f"build artifact changed: {key}")
    kernel = Path(built["kernel"]["path"]).read_bytes()
    image = Path(built["loaded_image"]["path"]).read_bytes()
    strict = entry.loader.strict_kernel(kernel)
    contract = strict["metadata"]["load_contract"]
    require(len(image) == contract["memory_span"], "loaded image span differs")
    expected = bytearray(len(image))
    for segment in strict["segments"]:
        at = segment["vmaddr"] - contract["virtual_base"]
        expected[at:at + segment["filesize"]] = kernel[segment["fileoff"]:segment["fileoff"] + segment["filesize"]]
    require(image == expected, "loaded image does not exactly match segments and zero fill")
    provider_abi = receipt.parent / "consumer.crypto_functions"
    require(build.sha(provider_abi.read_bytes()) == built["abi"]["records"]["crypto_functions"]["consumer"], "consumer ABI record changed")
    journal.protect(provider_abi)
    matches = re.findall(r"^\s*(\d+) \| crypto_random_kmem_ctx_size_fn_t random_kmem_ctx_size_fn$", provider_abi.read_text(), re.M)
    require(len(matches) == 1 and int(matches[0]) % 8 == 0 and 0 <= int(matches[0]) < 448, "callback table offset missing")
    callback_offset = int(matches[0])
    if args.mode == "negative-post":
        offset = value(built["seal"]["hmac_file_offset"])
        require(kernel[offset:offset + 32].hex() == built["seal"]["hmac_sha256"], "stored HMAC differs from seal receipt")
        owners = [s for s in strict["segments"] if s["fileoff"] <= offset and offset + 32 <= s["fileoff"] + s["filesize"]]
        require(len(owners) == 1, "HMAC bytes have no unique segment mapping")
        load_offset = owners[0]["vmaddr"] - contract["virtual_base"] + offset - owners[0]["fileoff"]
        altered, loaded = bytearray(kernel), bytearray(image)
        altered[offset] ^= 1; loaded[load_offset] ^= 1
        kernel, image = bytes(altered), bytes(loaded)
        report["negative_mutation"] = {"kind": "stored-post-hmac-one-bit", "kernel_offset": hex(offset),
                                       "loaded_offset": hex(load_offset), "xor": 1, "instructions_changed": False}
    kernel_path, image_path = out / "kernel.macho", out / "kernel.load.bin"
    kernel_path.write_bytes(kernel); image_path.write_bytes(image)
    journal.protect(kernel_path); journal.protect(image_path)
    config = json.loads(entry.loader.CONFIG.read_text())
    symbols = entry.loader.check_entry_symbols(strict, config, kernel)
    defined = targets(strict, kernel)
    seed, seed_record = entry.read_seed(args.seed_file); journal.protect(args.seed_file)
    adt = entry.make_adt("cortex-a76", seed)
    boot, layout = entry.make_boot_args(contract, 0x50004000, 0x52000000, adt, "-v serial=3 debug=0x14e")
    (out / "boot-args.bin").write_bytes(boot); (out / "synthetic-qemu.adt").write_bytes(adt)
    report.update(build_report=entry.identity(receipt), targets=defined, layout=layout, seed=seed_record,
                  kernel=entry.identity(kernel_path), loaded_image=entry.identity(image_path))
    manifest = json.loads((entry.SOURCES / "sources.json").read_text())
    for record in manifest["files"]:
        path = build.regular(entry.SOURCES / record["path"])
        entry.loader.verify_bytes(path.read_bytes(), record, str(path)); journal.protect(path)
    for name in ("clang", "linker", "objcopy", "qemu"):
        invocation, identity = entry.select_tool(str(getattr(args, name)))
        setattr(args, name, invocation); journal.protect(invocation, tool=True)
        report.setdefault("tools", {})[name] = identity
    commands = [
        [args.clang, "--target=aarch64-none-elf", "-c", "-DBOOT_ARGS_PA=1375731712",
         f"-DKERNEL_ENTRY_PA={layout['entry_pa']}", str(entry.SOURCES / "entry.S"), "-o", str(out / "entry.o")],
        [args.linker, "-T", str(entry.SOURCES / "link.ld"), str(out / "entry.o"), "-o", str(out / "entry.elf")],
        [args.objcopy, "-O", "binary", str(out / "entry.elf"), str(out / "entry.bin")],
    ]
    for index, argv in enumerate(commands): journal.execute(argv, f"entry-compile-{index}", timeout=30)
    require((out / "entry.bin").stat().st_size <= entry.STUB_LIMIT - entry.STUB_BASE, "entry stub exceeds reserved range")
    for name in ("boot-args.bin", "synthetic-qemu.adt", "entry.bin"): journal.protect(out / name)
    return strict, kernel, image, symbols, defined, layout, callback_offset


def launch(args, out, journal, report, prepared):
    strict, kernel, image, symbols, defined, layout, callback_offset = prepared
    endpoint = out / "gdb.sock"
    require(len(os.fsencode(endpoint)) <= 100, "private debugger socket path too long")
    serial, trace = out / "serial.log", out / "exceptions.log"
    argv = [args.qemu, "-M", "virt,virtualization=off,secure=off,gic-version=3", "-accel", "tcg",
            "-icount", entry.INSTRUCTION_CLOCK, "-cpu", "cortex-a76", "-m", "512", "-smp", "1",
            "-display", "none", "-monitor", "none", "-nic", "none", "-no-reboot", "-serial", f"file:{serial}",
            "-kernel", str(out / "entry.bin"), "-d", "int", "-D", str(trace), "-S",
            "-gdb", f"unix:{endpoint},server=on,wait=off", "-device",
            f"loader,file={out / 'kernel.load.bin'},addr={layout['physical_base']:#x},force-raw=on", "-device",
            f"loader,file={out / 'boot-args.bin'},addr={layout['boot_args_pa']:#x},force-raw=on"]
    report["qemu"] = {"argv": argv, "timeout_seconds": args.timeout, "clock_mode": "instruction-1ns",
                      "max_file_bytes": entry.MAX_LOG, "storage_devices": [], "network_devices": []}
    def limits(): resource.setrlimit(resource.RLIMIT_FSIZE, (entry.MAX_LOG, entry.MAX_LOG))
    process = None
    started = time.monotonic()
    with (out / "qemu.stderr.log").open("xb") as err, socket.socket(socket.AF_UNIX) as sock:
        try:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=err, stderr=err,
                                       start_new_session=True, preexec_fn=limits)
            report["qemu"]["pid"] = process.pid
            deadline = started + args.timeout
            while True:
                require(process.poll() is None and time.monotonic() < deadline, "QEMU exited or debugger attachment timed out")
                try: sock.connect(str(endpoint)); break
                except (FileNotFoundError, ConnectionRefusedError): time.sleep(.02)
            remote = Remote(sock, deadline, out, report.setdefault("gdb_xml", []))
            report["entry"] = entry.observe_entry(remote, layout, symbols)
            observe(remote, strict, kernel, defined, report, args.mode, callback_offset)
        finally:
            if process is not None:
                report["qemu"]["exit_before_termination"] = process.poll()
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try: process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=2)
                report["qemu"].update(exit=process.returncode, reaped=process.poll() is not None,
                                       elapsed_seconds=round(time.monotonic() - started, 6))
            report["exception"] = entry.exception_summary(entry.read_text(trace), entry.read_text(serial), strict, image, layout)
    require(report["qemu"]["exit_before_termination"] is None and report["qemu"]["reaped"], "QEMU exited unexpectedly")
    require(report["exception"].get("CurrentEL") == 4 and report["exception"].get("CNTFRQ") == 62500000,
            "actual fixture EL/counter differs")


def run(args):
    out = build.fresh(args.output); journal = build.Journal(out)
    report = {"schema": "route-a-corecrypto-runtime-v1", "status": "failed", "mode": args.mode,
              **dict.fromkeys(FLAGS, False), "os_boot_verified": False, "tb371fc_kernel_qualified": False,
              "started_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    try:
        require(args.mode in MODES and 1 <= args.timeout <= 60, "unsupported mode or timeout")
        for path in (Path(__file__), Path(build.__file__), Path(entry.__file__), Path(entry.loader.__file__),
                     Path(entry.loader.platform_link.__file__), Path(entry.loader.platform_link.toolchain.__file__),
                     entry.loader.CONFIG, entry.SOURCES / "sources.json", Path(sys.executable).resolve()):
            journal.protect(path)
        frozen = out / "driver-source"; frozen.mkdir()
        for path in list(journal.records):
            p = Path(path)
            if p.suffix in (".py", ".json"): (frozen / p.name).write_bytes(p.read_bytes())
        prepared = prepare(args, out, journal, report)
        launch(args, out, journal, report, prepared)
        require(report["negative_post_rejection_verified"] if args.mode == "negative-post" else report["runtime_provider_verified"],
                "requested provider runtime gate did not finish")
        report["status"] = "negative_post_rejection_observed" if args.mode == "negative-post" else "provider_and_consumer_observed"
    except Exception as exc:
        report.update(status="failed", error=f"{type(exc).__name__}: {exc}", **dict.fromkeys(FLAGS, False))
    finally:
        report["inputs"] = list(journal.records.values()); report["input_recheck"] = journal.recheck()
        if not report["input_recheck"]["unchanged"]:
            report.update(status="failed", error="declared runtime inputs changed", **dict.fromkeys(FLAGS, False))
        report["commands"] = journal.commands
        report["finished_at_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        report["outputs"] = [entry.identity(p) for p in sorted(out.iterdir()) if p.is_file() and not p.is_symlink()]
        build.save(out / "report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("build-report", "seed-file", "output"): parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--mode", choices=MODES, default="positive")
    parser.add_argument("--timeout", type=float, default=50)
    for name, default in (("clang", "clang"), ("linker", "ld.lld"), ("objcopy", "llvm-objcopy"), ("qemu", "qemu-system-aarch64")):
        parser.add_argument("--" + name, default=default)
    args = parser.parse_args()
    def interrupted(number, frame): raise build.BuildError(f"runtime interrupted by signal {number}")
    for number in (signal.SIGTERM, signal.SIGINT): signal.signal(number, interrupted)
    report = run(args); print(json.dumps({"status": report["status"], **{k: report[k] for k in FLAGS}}), flush=True)
    return 0 if report["status"] != "failed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
