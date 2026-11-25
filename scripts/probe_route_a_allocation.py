#!/usr/bin/env python3
"""Execute the pinned DarwinBoot allocation C against a host UEFI service model.

The allocator, RunEnd and Boot call sites are extracted from the unchanged and
patched sources. The service model supplies synthetic maps and records calls;
it does not execute firmware, MMU setup, cache instructions or a kernel.
"""
from __future__ import annotations

import argparse
import ctypes
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/route-a-allocation-probe.json"
SOURCE = "DarwinBootPkg/Driver/DarwinBoot.c"
BLOCK = 0x200000
PAGE = 0x1000
WINDOW = 0x10000000
BASE = 0xFFFFFFF007004000
CONVENTIONAL = 7
EFI_ERROR_BIT = 1 << 63


class ProbeError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise ProbeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def read_config():
    return json.loads(CONFIG.read_text())


def verified_sources(root, config):
    result = {}
    for record in config["upstream"]["files"]:
        path = root / record["path"]
        require(path.is_file() and not path.is_symlink(), f"not a regular source: {path}")
        data = path.read_bytes()
        require(len(data) == record["size"] and digest(data) == record["sha256"],
                f"source identity changed: {record['path']}")
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        require(blob == record["git_blob"], f"source blob changed: {record['path']}")
        result[record["path"]] = data
    return result


def prepare_sources(output, config):
    output.mkdir(parents=True, exist_ok=False)
    upstream = config["upstream"]
    for record in upstream["files"]:
        url = (upstream["repository"].replace("https://github.com/", "https://raw.githubusercontent.com/")
               + "/" + upstream["commit"] + "/" + record["path"])
        with urllib.request.urlopen(url, timeout=45) as response:
            data = response.read(record["size"] + 1)
        require(len(data) == record["size"] and digest(data) == record["sha256"], f"bad download: {url}")
        path = output / record["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    verified_sources(output, config)


def apply_patch(sources, directory, config):
    patch = ROOT / config["patch"]["path"]
    require(digest(patch.read_bytes()) == config["patch"]["sha256"], "patch identity changed")
    directory.mkdir(parents=True, exist_ok=False)
    for relative, data in sources.items():
        path = directory / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    for command in (["git", "apply", "--check", str(patch)], ["git", "apply", str(patch)]):
        result = subprocess.run(command, cwd=directory, capture_output=True, text=True)
        require(result.returncode == 0, "patch did not apply exactly: " + result.stderr)
    data = (directory / SOURCE).read_bytes()
    require(digest(data) == config["patch"]["patched_source_sha256"], "unexpected patched source")
    return data.decode()


def between(source, start, end):
    require(source.count(start) == 1 and source.count(end) == 1, "source extraction boundary changed")
    return source[source.index(start):source.index(end)]


def one_line(source, needle):
    lines = [line.strip() for line in source.splitlines() if needle in line]
    require(len(lines) == 1, "call site is absent or ambiguous: " + needle)
    return lines[0]


ADAPTER = r'''
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <wchar.h>
typedef uint8_t UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef size_t UINTN;
typedef int BOOLEAN;
typedef wchar_t CHAR16; /* Only discarded diagnostic strings, not a UEFI ABI claim. */
typedef void VOID;
typedef uint64_t EFI_STATUS;
typedef uint64_t EFI_PHYSICAL_ADDRESS;
#define STATIC static
#define CONST const
#define TRUE 1
#define FALSE 0
#define MAX_UINT64 UINT64_MAX
#define BLOCK_SIZE UINT64_C(0x200000)
#define EFI_PAGE_SIZE UINT64_C(0x1000)
#define EFI_PAGES_TO_SIZE(N) ((UINT64)(N) * EFI_PAGE_SIZE)
#define EFI_SIZE_TO_PAGES(N) (((UINT64)(N) + EFI_PAGE_SIZE - 1) / EFI_PAGE_SIZE)
#define ALIGN_VALUE(N,A) (((N) + (A) - 1) & ~((A) - 1))
#define EFI_SUCCESS UINT64_C(0)
#define EFI_OUT_OF_RESOURCES (UINT64_C(0x8000000000000000) | 9)
#define EFI_INVALID_PARAMETER (UINT64_C(0x8000000000000000) | 2)
#define EFI_ERROR(S) (((S) >> 63) != 0)
#define EfiConventionalMemory 7
#define EfiLoaderCode 1
#define AllocateAddress 2
typedef struct {
    UINT32 Type, Padding;
    UINT64 PhysicalStart, VirtualStart, NumberOfPages, Attribute;
} EFI_MEMORY_DESCRIPTOR;
typedef struct { UINT64 Base, End, Entry; } KERNEL;
typedef struct {
    UINT64 status, address, owned_address, owned_size, attempts;
    UINT64 allocation_start[8], allocation_pages[8];
} RESULT;
typedef struct { UINT64 zero_start, zero_size, cache_start, cache_size, free_start, free_pages; } CALLS;
static EFI_MEMORY_DESCRIPTOR *given_map;
static UINTN given_count;
static UINT64 reject_count;
static RESULT *current_result;
static CALLS current_calls;
static EFI_STATUS GetMap(EFI_MEMORY_DESCRIPTOR **map, UINTN *capacity, UINTN *size,
                         UINTN *key, UINTN *stride) {
    *map = given_map; *capacity = *size = given_count * sizeof(**map);
    *key = 1; *stride = sizeof(**map); return EFI_SUCCESS;
}
static void FreePool(void *pointer) { (void)pointer; }
static void UnicodeSPrint(CHAR16 *line, UINTN size, const CHAR16 *format, ...) {
    (void)size; (void)format; line[0] = 0;
}
static void DiagDraw(const CHAR16 *line, UINTN row) { (void)line; (void)row; }
static EFI_STATUS host_allocate(UINTN type, UINTN memory_type, UINTN pages, UINT64 *start) {
    UINT64 cursor = *start, end;
    UINTN attempt = current_result->attempts++;
    if (attempt < 8) {
        current_result->allocation_start[attempt] = *start;
        current_result->allocation_pages[attempt] = pages;
    }
    if (type != AllocateAddress || memory_type != EfiLoaderCode || !pages ||
        pages > (UINT64_MAX - cursor) / EFI_PAGE_SIZE) return EFI_INVALID_PARAMETER;
    end = cursor + pages * EFI_PAGE_SIZE;
    /* Model only AllocateAddress ownership over the supplied conventional runs. */
    while (cursor < end) {
        UINT64 next = cursor;
        for (UINTN i = 0; i < given_count; ++i) {
            EFI_MEMORY_DESCRIPTOR *d = &given_map[i];
            if (d->Type != EfiConventionalMemory || !d->NumberOfPages ||
                d->NumberOfPages > (UINT64_MAX - d->PhysicalStart) / EFI_PAGE_SIZE) continue;
            UINT64 limit = d->PhysicalStart + d->NumberOfPages * EFI_PAGE_SIZE;
            if (d->PhysicalStart <= cursor && cursor < limit && limit > next) next = limit;
        }
        if (next == cursor) return EFI_OUT_OF_RESOURCES;
        cursor = next;
    }
    if (reject_count) { --reject_count; return EFI_OUT_OF_RESOURCES; }
    return EFI_SUCCESS;
}
static EFI_STATUS host_free(UINT64 start, UINTN pages) {
    current_calls.free_start = start; current_calls.free_pages = pages; return EFI_SUCCESS;
}
static struct {
    EFI_STATUS (*AllocatePages)(UINTN, UINTN, UINTN, UINT64 *);
    EFI_STATUS (*FreePages)(UINT64, UINTN);
} services = {host_allocate, host_free}, *gBS = &services;
static void ZeroMem(void *pointer, UINTN size) {
    current_calls.zero_start = (UINTN)pointer; current_calls.zero_size = size;
    memset(pointer, 0, size);
}
static void DarwinEnter(UINT64 args, UINT64 entry, UINT64 memory, UINT64 size,
                        UINT64 video, UINT64 video_size) {
    (void)args; (void)entry; (void)video; (void)video_size;
    current_calls.cache_start = memory; current_calls.cache_size = size;
}
'''


def host_source(source, window_header, patched):
    run_end = between(source, "STATIC\nUINT64\nRunEnd (", "// Large diagnostic text")
    allocator = between(source, "STATIC\nEFI_STATUS\nAllocateWindow (", "STATIC\nEFI_STATUS\nEFIAPI\nBoot (")
    zero = one_line(source, "ZeroMem ((VOID *)(UINTN)")
    enter = one_line(source, "DarwinEnter (ArgsAddress,")
    free = one_line(source, "{ gBS->FreePages (")
    invoke = ("result->status = AllocateWindow(&kernel, window, &result->address, &result->owned_address, &result->owned_size);"
              if patched else "result->status = AllocateWindow(&kernel, window, &result->address);\n"
              "if (!EFI_ERROR(result->status)) { result->owned_address = result->address; result->owned_size = window; }")
    wrappers = r'''
void probe_allocate(EFI_MEMORY_DESCRIPTOR *map, UINTN count, UINT64 base, UINT64 window,
                    UINT64 reject, RESULT *result) {
    KERNEL kernel = {base, base + 0x100000, base + 0x1000};
    memset(result, 0, sizeof(*result));
    given_map = map; given_count = count; reject_count = reject; current_result = result;
    @INVOKE@
}
void probe_calls(UINT64 AllocationAddress, UINT64 AllocationSize, UINT64 prefix,
                 UINT64 Used, CALLS *result) {
    UINT64 Address = AllocationAddress + prefix;
    UINT64 WindowSize = AllocationSize - prefix;
    UINT64 ArgsAddress = Address + 0x1000;
    UINT64 Video[6] = {0};
    KERNEL Kernel = {0xfffffff007004000ULL, 0, 0xfffffff007005000ULL};
    (void)Address; (void)WindowSize;
    memset(&current_calls, 0, sizeof(current_calls));
    @ZERO@
    @ENTER@
    @FREE@
    *result = current_calls;
}
void probe_release(UINT64 AllocationAddress, UINT64 AllocationSize, UINT64 prefix, CALLS *result) {
    UINT64 Address = AllocationAddress + prefix;
    UINT64 WindowSize = AllocationSize >= prefix ? AllocationSize - prefix : 0;
    (void)Address; (void)WindowSize;
    memset(&current_calls, 0, sizeof(current_calls));
    @FREE@
    *result = current_calls;
}
'''
    for key, value in {"@INVOKE@": invoke, "@ZERO@": zero, "@ENTER@": enter, "@FREE@": free}.items():
        wrappers = wrappers.replace(key, value)
    return ADAPTER + window_header + run_end + allocator + wrappers, {
        "RunEnd_sha256": digest(run_end.encode()), "AllocateWindow_sha256": digest(allocator.encode()),
        "zero_call": zero, "cache_call": enter, "free_call": free,
    }


class Descriptor(ctypes.Structure):
    _fields_ = [("Type", ctypes.c_uint32), ("Padding", ctypes.c_uint32)] + [
        (name, ctypes.c_uint64) for name in ("PhysicalStart", "VirtualStart", "NumberOfPages", "Attribute")]


class Result(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in ("status", "address", "owned_address", "owned_size", "attempts")] + [
        ("allocation_start", ctypes.c_uint64 * 8), ("allocation_pages", ctypes.c_uint64 * 8)]


class Calls(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in ("zero_start", "zero_size", "cache_start", "cache_size", "free_start", "free_pages")]


def build_host(source, header, patched, output, compiler):
    output.mkdir(parents=True, exist_ok=False)
    c_source, extraction = host_source(source, header, patched)
    c_file = output / "allocator.c"
    c_file.write_text(c_source)
    library = output / "allocator.so"
    command = [str(compiler), "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-fPIC", "-shared", str(c_file), "-o", str(library)]
    compiled = subprocess.run(command, capture_output=True)
    (output / "compile.stdout").write_bytes(compiled.stdout)
    (output / "compile.stderr").write_bytes(compiled.stderr)
    require(compiled.returncode == 0, f"host C compile failed: {compiled.stderr.decode(errors='replace')}")
    lib = ctypes.CDLL(str(library))
    lib.probe_allocate.argtypes = [ctypes.POINTER(Descriptor), ctypes.c_size_t, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.POINTER(Result)]
    lib.probe_allocate.restype = None
    lib.probe_calls.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.POINTER(Calls)]
    lib.probe_calls.restype = None
    lib.probe_release.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.POINTER(Calls)]
    lib.probe_release.restype = None
    return lib, {"command": command, "exit_code": compiled.returncode,
                 "generated_c_sha256": digest(c_source.encode()), "library_sha256": digest(library.read_bytes()), **extraction}


def allocate(lib, entries, base=BASE, window=WINDOW, reject=0):
    descriptors = (Descriptor * len(entries))(*[Descriptor(kind, 0, start, 0, size // PAGE, 0) for kind, start, size in entries])
    result = Result()
    lib.probe_allocate(descriptors, len(entries), base, window, reject, ctypes.byref(result))
    return {name: getattr(result, name) for name in ("status", "address", "owned_address", "owned_size", "attempts")} | {
        "allocation_calls": [{"address": result.allocation_start[i], "pages": result.allocation_pages[i]}
                             for i in range(min(result.attempts, 8))]}


def bootstrap_intervals(address, window, used):
    """Source-derived 2 MiB initial mapping with header exactly at physical base."""
    require(0 <= address < address + window <= 1 << 64 and address % PAGE == 0
            and window >= WINDOW and window % BLOCK == 0, "invalid bootstrap inputs")
    require(0 <= used <= window - BLOCK, "payload exceeds loader headroom")
    prefix = address % BLOCK
    mapped_start = address - prefix
    mapped_end = mapped_start + window
    return {"advertised": [address, address + window], "initial_mapping": [mapped_start, mapped_end],
            "required_allocation": [mapped_start, address + window], "zeroed": [mapped_start, address + used],
            "advertised_tail_not_initially_mapped": [mapped_end, address + window],
            "used_end_initially_mapped": address + used <= mapped_end}


def exercise_call_sites(lib, prefix=0x4000, used=0x3000):
    # Only zeroing touches the heap. Cache/free service adapters record arguments.
    payload = prefix + used
    storage = (ctypes.c_uint8 * (payload + 128))(*([0xA5] * (payload + 128)))
    address = ctypes.addressof(storage) + 64
    calls = Calls()
    lib.probe_calls(address, WINDOW + prefix, prefix, used, ctypes.byref(calls))
    data = bytes(storage)
    result = {name: getattr(calls, name) for name, _ in Calls._fields_}
    result.update(host_buffer=address, guards_intact=data[:64] == data[-64:] == bytes([0xA5]) * 64,
                  prefix_zero=data[64:64 + prefix] == bytes(prefix),
                  payload_zero=data[64 + prefix:64 + payload] == bytes(used))
    return result


def run_probe(source_root, output, compiler_name="cc"):
    config = read_config()
    require(ctypes.sizeof(ctypes.c_size_t) == 8 and sys.byteorder == "little", "host requires little-endian LP64")
    output = output.resolve(strict=False)
    source_root = source_root.resolve(strict=True)
    require(not output.exists(), "output must be a new directory")
    require(not output.is_relative_to(source_root) and not output.is_relative_to(ROOT), "output overlaps source or repository")
    compiler = Path(shutil.which(compiler_name) or compiler_name).resolve(strict=True)
    sources = verified_sources(source_root, config)
    protected = {path: digest(path.read_bytes()) for path in
                 (Path(__file__).resolve(), CONFIG, ROOT / config["patch"]["path"], compiler)}
    output.mkdir(parents=True)
    report = {"schema_version": 1, "status": "failed", "host_allocator_contract_verified": False,
              **config["qualification"], "source_revision": config["upstream"]["commit"],
              "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "inputs": {"source_files": config["upstream"]["files"],
                         "protected_files": {str(path): value for path, value in protected.items()}},
              "compiler": {"path": str(compiler), "sha256": digest(compiler.read_bytes())}, "cases": []}
    try:
        patched = apply_patch(sources, output / "patched", config)
        header = sources["DarwinBootPkg/Driver/WindowSize.h"].decode()
        old, old_build = build_host(sources[SOURCE].decode(), header, False, output / "original", compiler)
        new, new_build = build_host(patched, header, True, output / "fixed", compiler)
        report["builds"] = {"original": old_build, "fixed": new_build}
        maps = [
            ("contiguous", [(7, 0x50000000, WINDOW + 0x4000)], 0),
            ("unaligned_free_start", [(7, 0x50004000, WINDOW + BLOCK)], 0),
            ("adjacent_descriptors", [(7, 0x58000000, 0x8004000), (7, 0x50000000, 0x8000000)], 0),
            ("too_short", [(7, 0x50000000, WINDOW + 0x3000)], None),
            ("reserved_gap", [(7, 0x50000000, 0x8000000), (0, 0x58000000, PAGE), (7, 0x58001000, 0x8003000)], None),
            ("allocator_failure", [(7, 0x50000000, WINDOW + 0x4000)], 1),
            ("retry_other_run", [(7, 0x50000000, WINDOW + 0x4000), (7, 0x80000000, WINDOW + 0x4000)], 1),
            ("allocation_at_zero", [(7, 0, WINDOW + 0x4000)], 0),
        ]
        for name, entries, reject in maps:
            before = allocate(old, entries, reject=reject or 0)
            after = allocate(new, entries, reject=reject or 0)
            expected_success = name in {"contiguous", "unaligned_free_start", "adjacent_descriptors", "retry_other_run", "allocation_at_zero"}
            require((after["status"] == 0) == expected_success, f"wrong allocation result: {name}")
            if expected_success:
                require(after["address"] == before["address"], f"kernel address changed: {name}")
                require(after["owned_address"] + 0x4000 == after["address"], f"prefix not owned: {name}")
                require(after["owned_size"] == WINDOW + 0x4000, f"wrong owned size: {name}")
                require(after["allocation_calls"][-1] == {"address": after["owned_address"], "pages": after["owned_size"] // PAGE}, f"wrong AllocatePages pair: {name}")
            else:
                require(after["address"] == after["owned_address"] == after["owned_size"] == 0, f"failure retained allocation: {name}")
            report["cases"].append({"name": name, "map": [list(entry) for entry in entries], "original": before, "fixed": after})
        before_calls = exercise_call_sites(old)
        after_calls = exercise_call_sites(new)
        require(not before_calls["prefix_zero"] and before_calls["payload_zero"], "original prefix omission did not reproduce")
        require(after_calls["prefix_zero"] and after_calls["payload_zero"] and after_calls["guards_intact"], "zeroing range mismatch")
        require(after_calls["cache_start"] == after_calls["free_start"] == after_calls["host_buffer"], "owned base not used at call sites")
        require(after_calls["cache_size"] == WINDOW + 0x4000 == after_calls["free_pages"] * PAGE, "owned size not used at call sites")
        release = Calls()
        new.probe_release(0, WINDOW + 0x4000, 0x4000, ctypes.byref(release))
        require(release.free_start == 0 and release.free_pages * PAGE == WINDOW + 0x4000, "allocation at zero was not freed")
        report["call_sites"] = {"original": before_calls, "fixed": after_calls, "zero_base_free_pages": release.free_pages}
        report["source_derived_intervals"] = bootstrap_intervals(0x50004000, WINDOW, 0x1600000)
        verified_sources(source_root, config)
        require(all(digest(path.read_bytes()) == value for path, value in protected.items()), "protected input changed")
        report["status"] = "host_allocator_contract_verified"
        report["host_allocator_contract_verified"] = True
    except Exception as error:
        report["error"] = str(error)
    finally:
        write_json(output / "report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare-sources")
    prepare.add_argument("--output", type=Path, required=True)
    run = sub.add_parser("run")
    run.add_argument("--sources", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--cc", default="cc")
    args = parser.parse_args()
    if args.command == "prepare-sources":
        prepare_sources(args.output, read_config())
        return 0
    report = run_probe(args.sources, args.output, args.cc)
    print(json.dumps({key: report.get(key) for key in ("status", "error", "host_allocator_contract_verified", "uefi_allocation_verified", "os_boot_verified")}))
    return 0 if report["host_allocator_contract_verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
