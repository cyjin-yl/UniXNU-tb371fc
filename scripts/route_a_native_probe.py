#!/usr/bin/env python3
"""Execute generated lowering correctness probes on an AArch64 Linux process.

No Apple code is used. Original PAuth words are recorded but never executed.
Each ordinary baseline and lowered function runs in a disposable child process
with a deadline. Code pages are first RW, then RX, never RWX. A native cache-flush
function must be available; absent one, execution fails explicitly.

    python3 scripts/route_a_native_probe.py --emit-payload
    python3 scripts/route_a_native_probe.py --run --timeout 2

Android may not expose __clear_cache. Build the freestanding ELF helper with:

    aarch64-linux-gnu-as -o flush.o scripts/route_a_cache_flush.S
    aarch64-linux-gnu-ld -shared --hash-style=both -z separate-code \
        -z max-page-size=16384 -z noexecstack -soname libroute_a_clear_cache.so \
        -o libroute_a_clear_cache.so flush.o

Then pass --cache-flush-library /absolute/path/libroute_a_clear_cache.so. The
dynamic loader maps the helper normally; generated probes never bootstrap an
unsynchronized executable mapping. The helper has no libc dependencies.

This checks short native instruction sequences under the plain-pointer ABI. It
does not demonstrate Darwin compatibility, authentication security, OS startup,
or application performance. No performance ratio is calculated.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import hashlib
import json
import math
import mmap
import os
import platform
import resource
import select
import signal
import struct
import sys
import time
from typing import Any, Callable

from arm64_lowering.instructions import NOP, RET, describe, lower


RETAA, RETAB = 0xD65F0BFF, 0xD65F0FFF
BRK = 0xD4200000
ABI_CONTRACT = "plain-pointers-with-authentication-removed"

def _words_bytes(words: list[int]) -> bytes:
    return b"".join(struct.pack("<I", word) for word in words)


def _adr(register: int, byte_offset: int) -> int:
    if not 0 <= register < 32 or not -(1 << 20) <= byte_offset < (1 << 20):
        raise ValueError("ADR operand out of range")
    immediate = byte_offset & 0x1FFFFF
    return 0x10000000 | ((immediate & 3) << 29) | ((immediate >> 2) << 5) | register


def _add_x0(immediate: int) -> int:
    if not 0 <= immediate < 4096:
        raise ValueError("ADD immediate out of range")
    return 0x91000000 | (immediate << 10)


def _auth_load(key_b: bool, offset: int, writeback: bool,
               base: int, destination: int) -> int:
    if offset % 8 or not -4096 <= offset <= 4088:
        raise ValueError("LDRA immediate out of range")
    scaled = (offset // 8) & 0x3FF
    return (0xF8200400 | (int(key_b) << 23) | ((scaled >> 9) << 22) |
            ((scaled & 511) << 12) | (int(writeback) << 11) |
            (base << 5) | destination)


def _case(name: str, original: list[int], baseline: list[int],
          arguments: list[dict[str, int | str]], expected_return: int,
          *, data: list[int] | None = None,
          expected_writeback_index: int | None = None) -> dict[str, Any]:
    output = []
    rewrites = []
    for index, word in enumerate(original):
        result = lower(word, plain_pointers=True)
        output.append(word if result is None else result[1])
        if result is not None:
            rewrites.append({"word_index": index, "mnemonic": result[0],
                             "action": describe(word)["action"]})
    # Baselines are independently written ordinary A64 sequences. A difference
    # here is a probe-construction defect, not something to gloss over on device.
    if output != baseline:
        raise ValueError(f"{name}: lowering does not match the ordinary baseline")
    return {
        "name": name,
        "input_words": [f"{word:08x}" for word in original],
        "output_words": [f"{word:08x}" for word in output],
        "baseline_words": [f"{word:08x}" for word in baseline],
        "output_sha256": hashlib.sha256(_words_bytes(output)).hexdigest(),
        "arguments": arguments,
        "data_u64": data or [],
        "expected": {"return": expected_return,
                     "writeback_index": expected_writeback_index},
        "rewrites": rewrites,
    }


def build_payload() -> dict[str, Any]:
    """Build a reproducible JSON payload of synthetic instruction probes."""
    literal = lambda value: {"kind": "literal", "value": value}
    data_arg = lambda index: {"kind": "data", "index": index}
    result_arg = {"kind": "result"}
    cases = []

    register_ops = [0xDAC10020, 0xDAC10420, 0xDAC10820, 0xDAC10C20,
                    0xDAC11020, 0xDAC11420, 0xDAC11820, 0xDAC11C20,
                    0xDAC143E0, 0xDAC147E0]
    cases.append(_case("register_sign_auth_strip", register_ops + [RETAB],
                       [NOP] * len(register_ops) + [RET],
                       [literal(0x12345678), literal(0x42)], 0x12345678))
    zero_ops = [0xDAC123E0, 0xDAC127E0, 0xDAC12BE0, 0xDAC12FE0,
                0xDAC133E0, 0xDAC137E0, 0xDAC13BE0, 0xDAC13FE0]
    cases.append(_case("zero_modifier_sign_auth", zero_ops + [RETAB],
                       [NOP] * len(zero_ops) + [RET],
                       [literal(0x12345678), literal(0)], 0x12345678))

    for name, instruction in (("retaa", RETAA), ("retab", RETAB)):
        cases.append(_case(name, [0xD2800920, instruction], [0xD2800920, RET],
                           [literal(0), literal(0)], 73))  # MOVZ X0, #73

    for name, opcode in (("braa", 0xD71F0801), ("brab", 0xD71F0C01),
                         ("braaz", 0xD61F081F), ("brabz", 0xD61F0C1F)):
        branch = opcode | (9 << 5)
        original = [_adr(9, 12), branch, BRK, _add_x0(7), RETAB]
        baseline = [_adr(9, 12), 0xD61F0120, BRK, _add_x0(7), RET]
        cases.append(_case(name, original, baseline, [literal(35), literal(0)], 42))

    # Save/restore the caller's X29/LR, with 16-byte aligned SP throughout.
    for name, opcode in (("blraa", 0xD73F0801), ("blrab", 0xD73F0C01),
                         ("blraaz", 0xD63F081F), ("blrabz", 0xD63F0C1F)):
        call = opcode | (9 << 5)
        original = [0xA9BF7BFD, 0x910003FD, _adr(9, 16), call,
                    0xA8C17BFD, RETAB, _add_x0(9), RETAB]
        baseline = [0xA9BF7BFD, 0x910003FD, _adr(9, 16), 0xD63F0120,
                    0xA8C17BFD, RET, _add_x0(9), RET]
        cases.append(_case(name, original, baseline, [literal(33), literal(0)], 42))

    # A call through X30 must read the old target before assigning LR=PC+4.
    original = [0xA9BF7BFD, _adr(30, 16), 0xD63F0BDF,
                0xA8C17BFD, RETAB, _add_x0(11), RETAB]
    baseline = [0xA9BF7BFD, _adr(30, 16), 0xD63F03C0,
                0xA8C17BFD, RET, _add_x0(11), RET]
    cases.append(_case("blraaz_x30_target", original, baseline,
                       [literal(31), literal(0)], 42))

    data = [0x1020304050607080, 0x2131415161718191, 0x32425262728292A2]
    for key_b in (False, True):
        prefix = "ldrab" if key_b else "ldraa"
        for suffix, offset, start, expected, ordinary in (
            ("positive", 8, 0, data[1], 0xF9400400),
            ("negative", -8, 1, data[0], 0xF85F8000),
        ):
            cases.append(_case(f"{prefix}_{suffix}",
                               [_auth_load(key_b, offset, False, 0, 0), RETAB],
                               [ordinary, RET], [data_arg(start), literal(0)],
                               expected, data=data))
        for suffix, offset, start, end, ordinary in (
            ("pre_positive", 8, 0, 1, 0xF8408C02),
            ("pre_negative", -8, 1, 0, 0xF85F8C02),
        ):
            # LDR X2,[X0,#offset]!; STR X2,[X1]; STR X0,[X1,#8]; MOV X0,X2
            original = [_auth_load(key_b, offset, True, 0, 2),
                        0xF9000022, 0xF9000420, 0xAA0203E0, RETAB]
            baseline = [ordinary, 0xF9000022, 0xF9000420, 0xAA0203E0, RET]
            cases.append(_case(f"{prefix}_{suffix}", original, baseline,
                               [data_arg(start), result_arg], data[end], data=data,
                               expected_writeback_index=end))
        original = [0xA9BF07E0, _auth_load(key_b, 0, False, 31, 0),
                    0x910043FF, RETAB]
        baseline = [0xA9BF07E0, 0xF94003E0, 0x910043FF, RET]
        cases.append(_case(f"{prefix}_sp_base", original, baseline,
                           [literal(55), literal(99)], 55))

    payload = {
        "schema_version": 1,
        "kind": "route-a-synthetic-native-correctness",
        "architecture": "aarch64-little-endian",
        "abi_contract": ABI_CONTRACT,
        "authentication_preserved": False,
        "performance_measurement": False,
        "original_pauth_words_executed": False,
        "cases": cases,
    }
    payload["payload_sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return payload


def host_facts() -> dict[str, Any]:
    facts = {"machine": platform.machine(), "system": platform.system(),
             "release": platform.release(), "python": platform.python_version(),
             "pointer_bits": ctypes.sizeof(ctypes.c_void_p) * 8,
             "byteorder": sys.byteorder, "uid": os.getuid()}
    try:
        getauxval = ctypes.CDLL(None).getauxval
        getauxval.argtypes = [ctypes.c_ulong]
        getauxval.restype = ctypes.c_ulong
        hwcap = int(getauxval(16))
        facts["hwcap"] = f"0x{hwcap:x}"
        if facts["machine"].lower() in ("aarch64", "arm64"):
            facts.update(paca=bool(hwcap & (1 << 30)), pacg=bool(hwcap & (1 << 31)))
    except (AttributeError, OSError) as exc:
        facts["hwcap_error"] = str(exc)
    return facts


def _resolve_clear_cache(library: str | None) -> tuple[Any, str]:
    candidates = [library] if library else [None, ctypes.util.find_library("gcc_s"),
                                          "libgcc_s.so.1", "libgcc_s.so"]
    seen = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        try:
            handle = ctypes.CDLL(candidate, use_errno=True)
            flush = handle.__clear_cache
            flush.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            flush.restype = None
            return flush, candidate or "process:__clear_cache"
        except (OSError, AttributeError):
            continue
    raise RuntimeError("native __clear_cache unavailable; supply --cache-flush-library")


def _execute_case(case: dict[str, Any], variant: str,
                  cache_flush_library: str | None) -> dict[str, Any]:
    words = [int(word, 16) for word in case[f"{variant}_words"]]
    code = _words_bytes(words)
    flush, flush_source = _resolve_clear_cache(cache_flush_library)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    libc.mprotect.restype = ctypes.c_int
    size = ((len(code) + mmap.PAGESIZE - 1) // mmap.PAGESIZE) * mmap.PAGESIZE
    mapping = mmap.mmap(-1, size, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
                        prot=mmap.PROT_READ | mmap.PROT_WRITE)
    try:
        mapping.write(code)
        address = ctypes.addressof(ctypes.c_char.from_buffer(mapping))
        # Flush while writable (old ARM64 kernels can classify cache maintenance
        # as a write), then change permissions to RX before entering the code.
        flush(address, address + len(code))
        if libc.mprotect(address, size, mmap.PROT_READ | mmap.PROT_EXEC) != 0:
            raise OSError(ctypes.get_errno(), "mprotect RW -> RX failed")
        data_type = ctypes.c_uint64 * max(1, len(case["data_u64"]))
        data = data_type(*case["data_u64"])
        result = (ctypes.c_uint64 * 2)(0, 0)
        arguments = []
        for argument in case["arguments"]:
            if argument["kind"] == "literal":
                arguments.append(argument["value"])
            elif argument["kind"] == "data":
                arguments.append(ctypes.addressof(data) + argument["index"] * 8)
            elif argument["kind"] == "result":
                arguments.append(ctypes.addressof(result))
            else:
                raise ValueError("unknown probe argument kind")
        function = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64,
                                    ctypes.c_uint64)(address)
        actual_return = int(function(*arguments))
        expected = {"return": case["expected"]["return"]}
        actual = {"return": actual_return}
        writeback = case["expected"]["writeback_index"]
        if writeback is not None:
            expected["written_value"] = case["expected"]["return"]
            expected["written_base_offset"] = writeback * 8
            actual["written_value"] = int(result[0])
            actual["written_base_offset"] = int(result[1]) - ctypes.addressof(data)
        return {"status": "passed" if actual == expected else "failed",
                "expected": expected, "actual": actual,
                "cache_flush": flush_source, "mapping_permissions": "RW -> RX",
                "executed_sha256": hashlib.sha256(code).hexdigest()}
    finally:
        mapping.close()


def _run_isolated(operation: Callable[[], dict[str, Any]], timeout: float) -> dict[str, Any]:
    """Contain SIGILL, faults and loops; always reap the disposable child."""
    if not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise ValueError("timeout must be finite, positive and at most 60 seconds")
    read_fd, write_fd = os.pipe()
    try:
        pid = os.fork()
    except BaseException:
        os.close(read_fd)
        os.close(write_fd)
        raise
    if pid == 0:
        os.close(read_fd)
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            result = operation()
        except BaseException as exc:
            result = {"status": "error", "error_type": type(exc).__name__, "error": str(exc)}
        try:
            encoded = json.dumps(result, sort_keys=True).encode()
            while encoded:
                encoded = encoded[os.write(write_fd, encoded):]
        finally:
            os.close(write_fd)
            os._exit(0)

    os.close(write_fd)
    os.set_blocking(read_fd, False)
    deadline = time.monotonic() + timeout
    chunks = []
    status = None
    timed_out = False
    try:
        while status is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                done, child_status = os.waitpid(pid, os.WNOHANG)
                if done:
                    status = child_status
                    break
                timed_out = True
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                _, status = os.waitpid(pid, 0)
                break
            ready, _, _ = select.select([read_fd], [], [], min(remaining, 0.05))
            if ready:
                try:
                    block = os.read(read_fd, 65536)
                    if block:
                        chunks.append(block)
                except BlockingIOError:
                    pass
            done, child_status = os.waitpid(pid, os.WNOHANG)
            if done:
                status = child_status
        while True:
            try:
                block = os.read(read_fd, 65536)
            except BlockingIOError:
                break
            if not block:
                break
            chunks.append(block)
    finally:
        os.close(read_fd)
        if status is None:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)
    if timed_out:
        return {"status": "timeout", "timeout_seconds": timeout}
    if os.WIFSIGNALED(status):
        number = os.WTERMSIG(status)
        return {"status": "signal", "signal": number,
                "signal_name": signal.Signals(number).name}
    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        return {"status": "error", "child_wait_status": status}
    try:
        return json.loads(b"".join(chunks))
    except (ValueError, UnicodeDecodeError) as exc:
        return {"status": "error", "error": f"invalid child result: {exc}"}


def run_probe(*, timeout: float = 2.0,
              cache_flush_library: str | None = None) -> dict[str, Any]:
    payload = build_payload()
    facts = host_facts()
    report = {"schema_version": 1, "kind": payload["kind"],
              "payload_sha256": payload["payload_sha256"], "host": facts,
              "abi_contract": ABI_CONTRACT, "authentication_preserved": False,
              "performance_measurement": False, "original_pauth_words_executed": False,
              "cases": []}
    if cache_flush_library:
        report["cache_flush_library"] = cache_flush_library
        try:
            with open(cache_flush_library, "rb") as handle:
                report["cache_flush_library_sha256"] = hashlib.sha256(handle.read()).hexdigest()
        except OSError as exc:
            report["cache_flush_library_hash_error"] = str(exc)
    if (facts["machine"].lower() not in ("aarch64", "arm64") or
            facts["pointer_bits"] != 64 or facts["byteorder"] != "little" or
            not sys.platform.startswith("linux")):
        report["status"] = "unsupported_host"
        report["reason"] = "requires a little-endian 64-bit AArch64 Linux process"
        return report
    for case in payload["cases"]:
        result = {key: case[key] for key in ("name", "input_words", "output_words",
                                            "baseline_words", "output_sha256", "expected")}
        for variant in ("baseline", "output"):
            key = "baseline" if variant == "baseline" else "lowered"
            result[key] = _run_isolated(
                lambda: _execute_case(case, variant, cache_flush_library), timeout)
        result["status"] = ("passed" if result["baseline"]["status"] == "passed" and
                             result["lowered"]["status"] == "passed" else "failed")
        report["cases"].append(result)
    report["passed"] = sum(case["status"] == "passed" for case in report["cases"])
    report["total"] = len(report["cases"])
    report["status"] = "passed" if report["passed"] == report["total"] else "failed"
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--emit-payload", action="store_true")
    mode.add_argument("--run", action="store_true")
    parser.add_argument("--timeout", type=float, default=2.0, help="per-child deadline, <=60s")
    parser.add_argument("--cache-flush-library", help="library exporting __clear_cache")
    args = parser.parse_args(argv)
    if args.emit_payload:
        result = build_payload()
        exit_code = 0
    else:
        result = run_probe(timeout=args.timeout, cache_flush_library=args.cache_flush_library)
        exit_code = 0 if result["status"] == "passed" else 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
