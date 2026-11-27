#!/usr/bin/env python3
"""Observe the real source provider and later XNU initialization in QEMU virt.

All breakpoints come from the independently parsed, build-identified kernel.
The negative case flips only one stored POST HMAC byte, then requires actual
panic entry before table/PRNG publication. Guest instructions are never patched.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
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
from arm64_lowering import macho, pacga
from route_a_pacga_probe import run as execution

require = build.require
MODES = ("positive", "negative-post")
FLAGS = ("runtime_post_verified", "negative_post_rejection_verified", "runtime_provider_verified",
         "consumer_vectors_verified", "real_consumer_return_verified", "post_consumer_return_verified",
         "pacga_key_initialization_verified", "pacga_negative_post_unpublished_verified")
CORE_REGISTERS = {**{f"x{i}": (i, 8) for i in range(31)},
                  "sp": (31, 8), "pc": (32, 8), "cpsr": (33, 4)}


def value(number):
    return int(number, 16) if isinstance(number, str) else number


def consumer_callback_offset(layout):
    """Find one complete callback field in the verified compiler ABI record."""
    matches = re.findall(
        r"^[ \t]*([0-9]+)[ \t]+\|[ \t]+crypto_random_kmem_ctx_size_fn_t"
        r"[ \t]+random_kmem_ctx_size_fn[ \t]*$", layout, re.M)
    require(len(matches) == 1, "callback table offset missing or ambiguous")
    offset = int(matches[0])
    require(offset % 8 == 0 and 0 <= offset < 448, "callback table offset outside aligned table slots")
    return offset


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


def select_pacga_runtime(built, strict, kernel_path):
    """A descriptor-bearing kernel must select its exact admitted overlay."""
    descriptors = [section for section in strict["metadata"]["sections"]
                   if section["name"] == "__unixnu_pacga"]
    selected = built.get("pacga_overlay") is not None
    require(len(descriptors) == int(selected), "PACGA descriptor and explicit build selection differ")
    if not selected:
        require(built.get("pacga_runtime") is None, "unselected build has a PACGA runtime receipt")
        return None
    require(isinstance(built["pacga_overlay"], dict), "invalid PACGA overlay receipt")
    actual = pacga.runtime_kernel(kernel_path)
    require(built.get("pacga_runtime") == actual
            and built["pacga_overlay"]["implementation"] == actual["implementation"]
            and built["pacga_overlay"].get("runtime_boot_verified") is False,
            "selected PACGA kernel or implementation differs from its build receipt")
    return actual


def spans_overlap(left, right):
    return left["va"] < right["va"] + right["size"] and right["va"] < left["va"] + left["size"]


def pacga_bootstrap_targets(strict, kernel, state_cells=()):
    returned = call_return(strict, kernel, "_route_a_pacga_bootstrap", "_read_random")
    call = {**returned, "symbol": "PACGA bootstrap read_random call", "va": returned["va"] - 4,
            "file_offset": returned["file_offset"] - 4, "size": 4}
    result = {"call": call, "returned": returned,
              # Only the address and extent are used. No key bytes are requested.
              "key_destination": storage_span(strict, "_route_a_pacga_boot_key", 16),
              "ready": storage_span(strict, "_route_a_pacga_ready", 4)}
    for span in (result["ready"], *state_cells):
        require(not spans_overlap(result["key_destination"], span),
                "PACGA key storage overlaps an observed state cell or table")
    return result


class Remote(entry.Remote):
    def validate_architecture(self):
        self.core_layout_validated = False
        super().validate_architecture()
        self.core_layout_validated = True

    def send(self, command):
        require(time.monotonic() < self.deadline, "provider observation deadline expired before send")
        super().send(command)

    def selected_registers(self, names):
        require(getattr(self, "core_layout_validated", False), "core register XML was not validated")
        require(len(names) == len(set(names)) and all(name in CORE_REGISTERS for name in names),
                "unsupported or duplicate selected core register")
        registers = {}
        for name in names:
            number, size = CORE_REGISTERS[name]
            reply = self.request(f"p{number:x}")
            require(len(reply) == size * 2 and re.fullmatch(r"[0-9a-fA-F]+", reply) is not None,
                    "invalid selected core register reply: " + name)
            registers[name] = int.from_bytes(bytes.fromhex(reply), "little")
        return registers


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
        require(self.permits_memory_read(span["va"], span["size"]),
                "observation request overlaps protected PACGA key storage")
        record = entry.bounded_memory_read(self.remote, span["va"], span["size"],
                                          (span["va"], span["va"] + span["size"]))
        self.report.setdefault("reads", []).append({"label": label, "declaration": span, **record})
        require(record["status"] == "complete", f"incomplete declared read: {label}")
        return bytes.fromhex(record["data_hex"])

    def permits_memory_read(self, address, size):
        require(isinstance(address, int) and isinstance(size, int) and size > 0
                and 0 <= address <= (1 << 64) - size, "invalid observation memory range")
        key = self.targets.get("pacga", {}).get("key_destination")
        return key is None or not spans_overlap(key, {"va": address, "size": size})

    def state(self):
        return {name: int.from_bytes(self.read(span, name), "little") for name, span in self.targets["cells"].items()
                if name != "_kpis"}

    def continue_to(self, label, register_names=()):
        self.paused = False
        stop = self.remote.request("c")
        self.paused = stop.startswith(("T05", "S05"))
        # Stop packets can contain expedited registers. Retain only the signal,
        # then explicitly request the semantic fields this stop needs.
        event = {"label": label, "stop": stop[:3], "stop_reply_chars": len(stop),
                 "register_scope": "selected core registers; no bulk register packet"}
        self.report.setdefault("events", []).append(event)
        require(self.paused and len(stop) <= 4096, "unexpected stop during provider observation")
        registers = self.remote.selected_registers(("pc", "cpsr"))
        require(registers["pc"] in self.installed and registers["cpsr"] & 31 in (4, 5), "unknown breakpoint or wrong EL")
        target = self.installed[registers["pc"]]
        expected = self.kernel[target["file_offset"]:target["file_offset"] + 4]
        actual = self.read({**target, "size": 4}, "stopped instruction")
        require(actual == expected, "stopped instruction differs from identified candidate")
        event["symbol"] = target["symbol"]
        names = (("x0", "x1", "x2", "x7") if registers["pc"] == self.targets["debugger"]["va"]
                 else tuple(register_names))
        registers.update(self.remote.selected_registers(names))
        event["registers"] = {name: hex(number) for name, number in registers.items()}
        return registers

    def register(self, name):
        value = self.remote.selected_registers((name,))[name]
        self.report["events"][-1].setdefault("call_target_registers", {})[name] = hex(value)
        return value

    def expect(self, target, label, register_names=()):
        self.breakpoint(target)
        registers = self.continue_to(label, register_names)
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
        if not self.permits_memory_read(address, limit):
            return {"address": hex(address), "status": "protected-pacga-key-range", "data_hex": ""}
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


def return_from_entry(strict, kernel, registers, target, read_register=None):
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
        require(register < 30, "BLR entry register does not identify the consumer")
        name = f"x{register}"
        operand = registers.get(name)
        if operand is None and read_register is not None:
            operand = read_register(name)
        require(operand == target["va"], "BLR entry register does not identify the consumer")
    return {"symbol": "return from " + target["symbol"], "va": address, "size": 4,
            "file_offset": function["file_offset"] + offset + 4, "caller": function,
            "call_bytes": kernel[function["file_offset"] + offset:function["file_offset"] + offset + 8].hex()}


def observe_pacga_bootstrap(observation, defined, report):
    if "pacga" not in defined:
        return
    target = defined["pacga"]
    registers = observation.expect(target["call"], "actual PACGA read_random call", ("x0", "x1"))
    state = observation.state()
    require(state["_route_a_pacga_ready"] == 0 and state["_prng_ready"] == 1
            and state["_crypto_init"] == 1 and state["_source_corecrypto14_status"] == 0
            and state["_g_crypto_funcs"] == defined["cells"]["_kpis"]["va"],
            "PACGA random-key call precedes complete provider/PRNG publication or repeats initialization")
    require(registers["x0"] == target["key_destination"]["va"] and registers["x1"] == 16,
            "PACGA read_random does not target exactly the declared 128-bit boot key")
    record = {"state_at_random_call": state, "key_destination": target["key_destination"],
              "random_call_observed": True, "random_return_observed": False,
              "key_storage_requested": False, "random_return_gprs_requested": False,
              "bulk_register_packet_requested": False,
              "register_scope_at_return": ["pc", "cpsr"]}
    report["pacga_bootstrap"] = record
    # Do not read any GPR after read_random: caller-saved registers may still
    # contain key material, independently of the key's declared memory cell.
    observation.expect(target["returned"], "actual PACGA read_random return")
    returned_state = observation.state()
    require(returned_state["_route_a_pacga_ready"] == 0,
            "PACGA ready was published before the observed read_random return")
    record.update(random_return_observed=True, state_at_random_return=returned_state)


def require_pacga_unpublished(defined, state):
    if "pacga" in defined:
        require(state["_route_a_pacga_ready"] == 0, "negative POST already published PACGA readiness")


def qualify_pacga_bootstrap(defined, state, report):
    if "pacga" in defined:
        require(report.get("pacga_bootstrap", {}).get("random_call_observed") is True
                and report["pacga_bootstrap"].get("random_return_observed") is True
                and state["_route_a_pacga_ready"] == 1,
                "PACGA initialization sequence or later ready publication was not observed")
        report["pacga_key_initialization_verified"] = True


def observe(remote, strict, kernel, defined, report, mode, callback_offset):
    observation = Observe(remote, strict, kernel, defined, report)
    observation.breakpoint(defined["debugger"])
    try:
        post = observation.expect(defined["post"], "actual POST return", ("x0",))
        report["post_return_w0"] = post["x0"] & 0xffffffff
        if mode == "negative-post":
            require(report["post_return_w0"] != 0, "corrupt HMAC did not fail POST")
            at_return = observation.state(); report["negative_state_at_post_return"] = at_return
            require_pacga_unpublished(defined, at_return)
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
            require_pacga_unpublished(defined, state)
            require(all(state[k] == 0 for k in ("_g_crypto_funcs", "_crypto_init", "_prng_ready",
                                               "_route_a_crypto_consumer_status", "_route_a_crypto_consumer_vectors")),
                    "negative POST published table/PRNG before panic")
            require(panic["format"].get("nul_terminated") is True and "POST" in panic["format"].get("text_utf8", ""),
                    "negative panic format is not the bounded POST failure message")
            report["negative_post_rejection_verified"] = True
            if "pacga" in defined:
                report["pacga_negative_post_unpublished_verified"] = True
            return
        require(report["post_return_w0"] == 0, "real positive POST did not succeed")
        report["runtime_post_verified"] = True
        observe_pacga_bootstrap(observation, defined, report)
        entered = observation.expect(defined["consumer_entry"], "real XNU crypto consumer entry", ("x30",))
        after_consumer = return_from_entry(strict, kernel, entered, defined["consumer_entry"], observation.register)
        report["real_consumer_caller"] = after_consumer
        returned = observation.expect(defined["consumer_return"], "actual kmem ctx-size return", ("x0",))
        state = observation.state(); report["positive_state"] = state
        require(state["_g_crypto_funcs"] == defined["cells"]["_kpis"]["va"] and state["_crypto_init"] == 1
                and state["_prng_ready"] == 1 and state["_source_corecrypto14_status"] == 0, "provider publication not complete")
        qualify_pacga_bootstrap(defined, state, report)
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
    selected_pacga = select_pacga_runtime(built, strict, Path(built["kernel"]["path"]))
    report["pacga_bootstrap_selected"] = selected_pacga is not None
    if selected_pacga is not None:
        report["pacga_runtime_binding"] = selected_pacga
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
    callback_offset = consumer_callback_offset(provider_abi.read_text())
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
    if selected_pacga is not None:
        defined["pacga"] = pacga_bootstrap_targets(strict, kernel, defined["cells"].values())
        defined["cells"]["_route_a_pacga_ready"] = defined["pacga"]["ready"]
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


def finish_launch(process, err, sock, report, trace, serial, strict, image, layout, started, primary):
    """Attempt every teardown step without replacing the observation failure."""
    record, errors = report["qemu"], []

    def attempt(label, function):
        try:
            return function()
        except BaseException as error:
            errors.append((label, error))
            return None

    watched = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    previous_mask = attempt("block-cleanup-signals",
                            lambda: signal.pthread_sigmask(signal.SIG_BLOCK, watched))
    try:
        if process is not None:
            record["cleanup"] = {"group": process.pid, "group_absent": False,
                                 "direct_child_reaped": False}

            def initial_status():
                record["exit_before_termination"] = process.poll()

            attempt("initial-child-status", initial_status)
            # Always clean the owned session, even when the direct QEMU process
            # has already exited. Its descendants may still be alive.
            cleanup = attempt("group-cleanup", lambda: execution.stop_group(process))
            if cleanup is not None:
                record["cleanup"] = cleanup

            def final_status():
                record.update(exit=process.poll(), reaped=process.returncode is not None)

            attempt("final-child-status", final_status)
        for name, handle in (("socket", sock), ("stderr", err)):
            if handle is not None:
                attempt(name + "-close", handle.close)

        def diagnostics():
            report["exception"] = entry.exception_summary(entry.read_text(trace), entry.read_text(serial),
                                                            strict, image, layout)

        attempt("exception-summary", diagnostics)
        record["elapsed_seconds"] = round(time.monotonic() - started, 6)
    finally:
        if previous_mask is not None:
            attempt("restore-cleanup-signals",
                    lambda: signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask))
    record["teardown_errors"] = [dict(phase=label, type=type(error).__name__, error=str(error))
                                 for label, error in errors]
    if errors:
        failure = primary if primary is not None else errors[0][1]
        for label, error in errors:
            if error is not failure:
                failure.add_note(f"QEMU teardown {label}: {type(error).__name__}: {error}")
        if primary is None:
            raise failure


@contextmanager
def defer_spawn_signals():
    """Keep a spawned process handle until launch can clean it in finally."""
    watched = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    previous, pending = {}, []
    primary = None

    def remember(number, _frame):
        if len(pending) < 128:
            pending.append(number)

    try:
        for number in watched:
            # Record first: a signal after installing remember must not leave
            # an untracked handler behind during restoration.
            previous[number] = signal.getsignal(number)
            signal.signal(number, remember)
        yield
    except BaseException as error:
        primary = error
        raise
    finally:
        errors, mask = [], None
        # Only restoration is masked, after the spawn/assignment body ended.
        # The forked QEMU never inherits a newly blocked parent signal mask.
        try:
            mask = signal.pthread_sigmask(signal.SIG_BLOCK, watched)
        except BaseException as error:
            errors.append(error)
        for number, handler in previous.items():
            try:
                signal.signal(number, handler)
            except BaseException as error:
                errors.append(error)
        if mask is not None:
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, mask)
            except BaseException as error:
                errors.append(error)
        if errors:
            failure = primary if primary is not None else errors[0]
            for error in errors:
                if error is not failure:
                    failure.add_note(f"spawn signal restoration: {type(error).__name__}: {error}")
            if primary is None:
                raise failure
        if primary is None:
            for number in pending:
                handler = previous[number]
                if callable(handler):
                    handler(number, None)
                elif handler != signal.SIG_IGN:
                    raise InterruptedError("runtime interrupted by signal " + str(number))


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
    journal.protect(Path(execution.__file__))
    process = err = sock = None
    started = time.monotonic()
    with execution.owned_children():
        try:
            err = (out / "qemu.stderr.log").open("xb")
            sock = socket.socket(socket.AF_UNIX)
            with defer_spawn_signals():
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
            finish_launch(process, err, sock, report, trace, serial, strict, image, layout,
                          started, sys.exc_info()[1])
    require(report["qemu"]["exit_before_termination"] is None and report["qemu"]["reaped"], "QEMU exited unexpectedly")
    require(report["qemu"]["cleanup"].get("group_absent") is True
            and report["qemu"]["cleanup"].get("direct_child_reaped") is True,
            "QEMU owned process group did not finish cleanup")
    require(report["exception"].get("CurrentEL") == 4 and report["exception"].get("CNTFRQ") == 62500000,
            "actual fixture EL/counter differs")


def run(args):
    out = build.fresh(args.output); journal = build.Journal(out)
    report = {"schema": "route-a-corecrypto-runtime-v1", "status": "failed", "mode": args.mode,
              **dict.fromkeys(FLAGS, False), "os_boot_verified": False, "tb371fc_kernel_qualified": False,
              "pacga_bootstrap_selected": False, "pacga_svc_roundtrip_verified": False,
              "userland_execution_observed": False,
              "started_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    try:
        require(args.mode in MODES and 1 <= args.timeout <= 60, "unsupported mode or timeout")
        for path in (Path(__file__), Path(build.__file__), Path(entry.__file__), Path(entry.loader.__file__),
                     Path(entry.loader.platform_link.__file__), Path(entry.loader.platform_link.toolchain.__file__),
                     Path(pacga.__file__), Path(macho.__file__), Path(execution.__file__), build.ROOT / pacga.HEADER,
                     build.ROOT / pacga.PATCH,
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
        if report["pacga_bootstrap_selected"]:
            require(report["pacga_negative_post_unpublished_verified"] if args.mode == "negative-post"
                    else report["pacga_key_initialization_verified"], "requested PACGA bootstrap gate did not finish")
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
