#!/usr/bin/env python3
"""Check a real Route A candidate with the pinned production DarwinBoot parser.

The C parser and copy loop are extracted unchanged. Only host scalar/memory
adapters and an isolated heap destination replace UEFI dependencies. No kernel
instruction, firmware allocator, ExitBootServices or DarwinEnter is executed.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from collections import Counter
import ctypes
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
import link_route_a_platform as platform_link

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/route-a-loader-probe.json"
MAX_U64 = (1 << 64) - 1
BLOCK_SIZE = 0x200000
WINDOW_SIZE = 0x10000000
SG_NORELOC = 0x4
LINK_VIRTUAL_BASE = 0xFFFFFFF007004000
GUARD_SIZE = 64
ABI_FIELDS = (
    ("Revision", "Revision"), ("Version", "Version"),
    ("VirtualBase", "virtBase"), ("PhysicalBase", "physBase"),
    ("MemorySize", "memSize"), ("TopOfKernelData", "topOfKernelData"),
    ("Video", "Video"), ("MachineType", "machineType"),
    ("DeviceTree", "deviceTreeP"), ("DeviceTreeLength", "deviceTreeLength"),
    ("CommandLine", "CommandLine"), ("BootFlags", "bootFlags"),
    ("MemorySizeActual", "memSizeActual"),
)
VIDEO_FIELDS = ("v_baseAddr", "v_display", "v_rowBytes", "v_width", "v_height", "v_depth")
ASSYM_FIELDS = {
    "BA_VIRT_BASE": "virtBase", "BA_PHYS_BASE": "physBase",
    "BA_MEM_SIZE": "memSize", "BA_TOP_OF_KERNEL_DATA": "topOfKernelData",
    "BA_BOOT_FLAGS": "bootFlags",
}


class ProbeError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise ProbeError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def blob_sha(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def identity(path):
    return platform_link.identity(Path(path))


def input_path(path):
    logical = Path(path).absolute()
    require(logical.is_file() and not logical.is_symlink(), f"not a regular nonsymlink input: {logical}")
    return logical.resolve(strict=True)


def verify_bytes(data, record, label):
    require(len(data) == record["size"] and sha256(data) == record["sha256"],
            f"pinned bytes differ: {label}")
    if "git_blob" in record:
        require(blob_sha(data) == record["git_blob"], f"pinned Git blob differs: {label}")


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def public_sources(config, root):
    """Read exact public files; no checkout or working-tree assumptions."""
    result = {}
    for component in ("darwinboot", "xnu"):
        for record in config[component]["files"]:
            path = root / component / record["path"]
            current = identity(path)
            data = path.read_bytes()
            verify_bytes(data, record, str(path))
            result[component + "/" + record["path"]] = {
                **current, "git_blob": blob_sha(data), "bytes": data,
            }
    return result


def prepare_sources(output, config):
    """Download only six fixed public source/license files for host CI."""
    output.mkdir(parents=True, exist_ok=False)
    records = []
    for component in ("darwinboot", "xnu"):
        source = config[component]
        require(re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",
                             source["repository"]) is not None, "unapproved source URL")
        require(re.fullmatch(r"[0-9a-f]{40}", source["commit"]) is not None,
                "source commit must be fixed")
        for record in source["files"]:
            relative = Path(record["path"])
            require(not relative.is_absolute() and ".." not in relative.parts, "unsafe source path")
            url = (source["repository"].replace("https://github.com/", "https://raw.githubusercontent.com/")
                   + "/" + source["commit"] + "/" + record["path"])
            with urllib.request.urlopen(url, timeout=45) as response:
                data = response.read(record["size"] + 1)
            verify_bytes(data, record, url)
            path = output / component / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            records.append({"url": url, **identity(path), "git_blob": blob_sha(data)})
    result = {"schema_version": 1, "status": "public_sources_prepared", "sources": records,
              "kernel_compiled": False, "os_boot_verified": False}
    write_json(output / "source-report.json", result)
    return result


def extract(text, start, end, label):
    require(text.count(start) == 1 and text.count(end) == 1,
            f"source extraction boundary absent or ambiguous: {label}")
    first, last = text.index(start), text.index(end)
    require(first < last, f"source extraction boundaries reversed: {label}")
    body = text[first:last]
    return body, {"label": label, "first_line": text.count("\n", 0, first) + 1,
                  "last_line": text.count("\n", 0, last), "size": len(body.encode()),
                  "sha256": sha256(body.encode()), "source_bytes_unchanged": True}


HOST_PREAMBLE = r'''
/* Host scalar/memory adapters only. No UEFI service or kernel callback stub. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
typedef uint8_t UINT8; typedef uint16_t UINT16; typedef uint32_t UINT32;
typedef uint64_t UINT64; typedef size_t UINTN; typedef int BOOLEAN;
typedef int EFI_STATUS; typedef char CHAR8; typedef void VOID;
#define STATIC static
#define CONST const
#define TRUE 1
#define FALSE 0
#define EFI_SUCCESS 0
#define EFI_UNSUPPORTED 3
#define EFI_LOAD_ERROR 1
#define EFI_ERROR(s) ((s) != EFI_SUCCESS)
#define MAX_UINT64 UINT64_MAX
#define WINDOW_SIZE 0x10000000ULL
#define SIZE_2MB 0x200000ULL
#define EFI_PAGE_MASK 4095
#define MAX_SEGMENTS 64
#define MIN(a,b) ((a)<(b)?(a):(b))
#define MAX(a,b) ((a)>(b)?(a):(b))
#define ZeroMem(p,n) memset(p,0,n)
#define CopyMem(a,b,n) memcpy(a,b,n)
#define CompareMem(a,b,n) memcmp(a,b,n)
#define STATIC_ASSERT _Static_assert
#define OFFSET_OF offsetof
_Static_assert(sizeof(void *) == 8 && sizeof(unsigned long) == 8, "LP64 host required");
static UINT32 U32(const void *p) { UINT32 v; memcpy(&v,p,4); return v; }
static UINT64 U64(const void *p) { UINT64 v; memcpy(&v,p,8); return v; }
'''


def make_harness(sources):
    """Use original C declarations, parser functions and the actual copy loop."""
    c = sources["darwinboot/DarwinBootPkg/Driver/DarwinBoot.c"]["bytes"].decode()
    args = sources["darwinboot/DarwinBootPkg/Driver/BootArgs.h"]["bytes"].decode()
    boot = sources["xnu/pexpert/pexpert/arm64/boot.h"]["bytes"].decode()
    copyright_notice = sources["darwinboot/LICENSE"]["bytes"].decode().splitlines()[0]
    excerpts = []
    pieces = ["/* Extracted from fixed DarwinBoot and XNU sources; see source receipts. */\n",
              f"/* {copyright_notice}\n"
              " * The full license is retained in sources/darwinboot/LICENSE. */\n",
              c[:c.index("#include <Uefi.h>")], HOST_PREAMBLE]
    for text, start, end, label in (
        (c, "typedef struct {", "STATIC EFI_HANDLE", "DarwinBoot SEGMENT/KERNEL declarations"),
        (c, "STATIC\nEFI_STATUS\nParseKernelHeader", "STATIC\nBOOLEAN\nAdtNode", "DarwinBoot production parser"),
    ):
        # Two declarations intentionally share the first marker; delimit their
        # complete block by its first declaration and the single mImage marker.
        if label.endswith("declarations"):
            first = c.index(start)
            end_at = c.index(end)
            body = c[first:end_at]
            receipt = {"label": label, "first_line": c.count("\n", 0, first) + 1,
                       "last_line": c.count("\n", 0, end_at), "size": len(body.encode()),
                       "sha256": sha256(body.encode()), "source_bytes_unchanged": True}
        else:
            body, receipt = extract(text, start, end, label)
        pieces.append(body)
        excerpts.append(receipt)
    require(args.count("#include <Base.h>") == 1, "unexpected BootArgs.h include")
    pieces.append(args.replace("#include <Base.h>", "/* Base.h types supplied by the host adapters. */"))
    header, receipt = extract(boot, "#define BOOT_LINE_LENGTH 1024", "#define SOC_DEVICE_TYPE_BUFFER_SIZE",
                              "XNU Boot_Video and boot_args declarations")
    pieces.extend([boot[:boot.index("#ifndef _PEXPERT_ARM64_BOOT_H_")], header])
    excerpts.append(receipt)
    copy, receipt = extract(c, "  ZeroMem ((VOID *)(UINTN)Address, (UINTN)Used);",
                            "  Args = (DARWIN_BOOT_ARGS *)(UINTN)ArgsAddress;",
                            "DarwinBoot production zero/copy block")
    excerpts.append(receipt)
    pieces.append(r'''
int probe_parse(const UINT8 *Data, UINTN Size, KERNEL *Kernel) {
  return ParseKernel(Data, Size, Kernel);
}
int probe_load(const UINT8 *Image, UINTN ImageSize, UINT8 *Destination,
               UINTN Capacity, KERNEL *Result) {
  KERNEL Kernel;
  UINTN Index;
  EFI_STATUS Status = ParseKernel(Image, ImageSize, &Kernel);
  if (EFI_ERROR(Status)) { return Status; }
  UINT64 Used = Kernel.End - Kernel.Base;
  if (Used > Capacity) { return EFI_LOAD_ERROR; }
  UINT64 Address = (UINTN)Destination;
''')
    pieces.extend([copy, "  *Result = Kernel;\n  return EFI_SUCCESS;\n}\n"])
    for kind, type_name, field_index in (("loader", "DARWIN_BOOT_ARGS", 0), ("xnu", "boot_args", 1)):
        pieces.append(f"UINTN probe_{kind}_abi(unsigned field, unsigned size) {{\n  switch (field) {{\n")
        for index, fields in enumerate(ABI_FIELDS):
            name = fields[field_index]
            pieces.append(f"  case {index}: return size ? sizeof((({type_name} *)0)->{name}) : offsetof({type_name}, {name});\n")
        pieces.append(f"  default: return sizeof({type_name});\n  }}\n}}\n")
    pieces.append("UINTN probe_video_abi(unsigned field, unsigned xnu, unsigned size) {\n  switch (field) {\n")
    for index, name in enumerate(VIDEO_FIELDS):
        pieces.append(f"  case {index}: if (xnu) {{ return size ? sizeof(((Boot_Video *)0)->{name}) : offsetof(boot_args, Video) + offsetof(Boot_Video, {name}); }}\n"
                      f"    return size ? sizeof(((DARWIN_BOOT_ARGS *)0)->Video[0]) : offsetof(DARWIN_BOOT_ARGS, Video) + {index} * sizeof(((DARWIN_BOOT_ARGS *)0)->Video[0]);\n")
    pieces.append("  default: return (UINTN)-1;\n  }\n}\n")
    return "".join(pieces), excerpts


class CSegment(ctypes.Structure):
    _fields_ = [("Address", ctypes.c_uint64), ("Size", ctypes.c_uint64),
                ("FileOffset", ctypes.c_uint64), ("FileSize", ctypes.c_uint64),
                ("Protection", ctypes.c_uint32)]


class CKernel(ctypes.Structure):
    _fields_ = [("Segments", CSegment * 64), ("Count", ctypes.c_size_t),
                ("Base", ctypes.c_uint64), ("End", ctypes.c_uint64), ("Entry", ctypes.c_uint64)]


def build_harness(sources, output, compiler, report):
    require(sys.byteorder == "little" and ctypes.sizeof(ctypes.c_void_p) == 8,
            "probe requires a little-endian LP64 host")
    body, excerpts = make_harness(sources)
    source, library = output / "loader-probe.c", output / "loader-probe.so"
    source.write_text(body)
    for relative, record in sources.items():
        target = output / "sources" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(record["bytes"])
    report["production_extractions"] = excerpts
    report["host_adapters"] = ["UEFI scalar typedefs to fixed-width/size_t types",
                               "unaligned reads and ZeroMem/CopyMem/CompareMem to libc memory operations",
                               "original boot argument declarations in an LP64 host translation unit",
                               "Used = Kernel.End - Kernel.Base for kernel-span-only heap zero/copy; production Boot additionally includes boot_args, ADT and supplied sidecars"]
    argv = [str(compiler), "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
            "-shared", "-fPIC", str(source), "-o", str(library)]
    env = {"PATH": os.defpath, "LANG": "C", "LC_ALL": "C", "TMPDIR": str(output)}
    stdout, stderr = output / "compile.stdout", output / "compile.stderr"
    with stdout.open("wb") as out, stderr.open("wb") as err:
        result = subprocess.run(argv, cwd=output, env=env, stdout=out, stderr=err, timeout=60)
    report["host_compile"] = {"argv": argv, "cwd": str(output), "environment": env,
                              "exit_code": result.returncode, "stdout": identity(stdout),
                              "stderr": identity(stderr), "source": identity(source)}
    require(result.returncode == 0, "host C compiler failed; see compile.stderr")
    report["host_compile"]["library"] = identity(library)
    lib = ctypes.CDLL(str(library))
    lib.probe_parse.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(CKernel)]
    lib.probe_parse.restype = ctypes.c_int
    lib.probe_load.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                              ctypes.c_size_t, ctypes.POINTER(CKernel)]
    lib.probe_load.restype = ctypes.c_int
    for name in ("probe_loader_abi", "probe_xnu_abi"):
        getattr(lib, name).argtypes = [ctypes.c_uint, ctypes.c_uint]
        getattr(lib, name).restype = ctypes.c_size_t
    lib.probe_video_abi.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_uint]
    lib.probe_video_abi.restype = ctypes.c_size_t
    return lib


def strict_kernel(data):
    """Additional Route A gates, without changing DarwinBoot's parser policy."""
    info = platform_link.macho(data, 2)
    require(not any(info["symbols"][k] for k in ("strong_undefined", "weak_undefined", "common_external")),
            "kernel still has unresolved or common external symbols")
    command_end = 32 + struct.unpack_from("<I", data, 20)[0]
    cursor, commands, zero_sections = 32, [], []
    dysymtab, symtab = None, None
    # Metadata-only commands used by this non-prelinked MH_EXECUTE. Dynamic
    # fixups, dylib loading, encryption and code-signature handling are outside
    # this probe. An unrecognized command never silently acquires acceptance.
    allowed = {0x19, 2, 0xB, 5, 0x32, 0x1B, 0x2A, 0x26, 0x29}
    raw_segments = []
    while cursor < command_end:
        cmd, length = struct.unpack_from("<II", data, cursor)
        require(cmd in allowed, f"unsupported load command for flat host probe: {cmd:#x}")
        commands.append({"command": cmd, "size": length, "offset": cursor})
        if cmd == 0x19:
            name = data[cursor + 8:cursor + 24].split(b"\0", 1)[0].decode("ascii")
            address, size, fileoff, filesize, maximum, protection, count, flags = struct.unpack_from("<4Q4I", data, cursor + 24)
            require(size <= WINDOW_SIZE and address <= MAX_U64 - size, "segment address overflow or loader size bound")
            # Fixed XNU loader.h defines SG_NORELOC as a relocation annotation,
            # with no alternate copy placement. HIGHVM/protected/fixup-dependent
            # flags and every unknown bit/combination remain unsupported.
            require(flags in {0, SG_NORELOC},
                    f"{name}: unsupported segment flags {flags:#x}; expected 0 or SG_NORELOC=0x4")
            require(not (maximum | protection) & ~7 and not protection & ~maximum,
                    f"{name}: unsupported segment protections maxprot={maximum:#x} initprot={protection:#x} flags={flags:#x}")
            require(not size or (address % 4096 == 0 and size % 4096 == 0), "unaligned nonempty segment")
            require(size or not filesize, "empty segment has file-backed bytes")
            segment = {"name": name, "vmaddr": address, "vmsize": size,
                       "fileoff": fileoff, "filesize": filesize, "initprot": protection,
                       "maxprot": maximum, "flags": flags}
            raw_segments.append(segment)
            for index in range(count):
                at = cursor + 72 + index * 80
                section_name = data[at:at + 16].split(b"\0", 1)[0].decode("ascii")
                owner = data[at + 16:at + 32].split(b"\0", 1)[0].decode("ascii")
                va, amount, offset, alignment, reloff, nreloc, sectflags = struct.unpack_from("<2Q5I", data, at + 32)
                require(owner == name, "section names a different owning segment")
                require(address <= va <= address + size and amount <= address + size - va,
                        "section memory lies outside its segment")
                require(nreloc == 0, f"{name},{section_name}: section has unresolved relocations (nreloc={nreloc}, flags={flags:#x})")
                require(alignment < 64 and (not amount or va % (1 << alignment) == 0),
                        "section address violates its declared alignment")
                if (sectflags & 0xFF) in {1, 0xC, 0x12}:
                    if amount:
                        zero_sections.append({"segment": name, "section": section_name, "vmaddr": va, "size": amount})
                elif amount:
                    require(fileoff <= offset <= fileoff + filesize and amount <= fileoff + filesize - offset,
                            "section file bytes lie outside their segment")
                    require(va - address == offset - fileoff, "section file/virtual mapping disagrees")
        elif cmd == 0xB:
            require(length == 80 and dysymtab is None, "invalid or duplicate LC_DYSYMTAB")
            dysymtab = struct.unpack_from("<18I", data, cursor + 8)
        elif cmd == 2:
            symtab = struct.unpack_from("<4I", data, cursor + 8)
        elif cmd in {0x26, 0x29}:
            require(length == 16, "invalid linkedit data command")
            offset, amount = struct.unpack_from("<II", data, cursor + 8)
            require(offset <= len(data) and amount <= len(data) - offset, "linkedit data outside file")
            if cmd == 0x29:
                require(amount == 0, "nonempty data-in-code requires a separately audited entry/code boundary")
        elif cmd == 0x1B:
            require(length == 24, "invalid LC_UUID size")
        elif cmd == 0x2A:
            require(length == 16, "invalid LC_SOURCE_VERSION size")
        cursor += length
    segments = [segment for segment in raw_segments if segment["vmsize"]]
    require(0 < len(segments) <= 64, "unsupported loaded segment count")
    require(len({s["name"] for s in raw_segments}) == len(raw_segments), "duplicate segment names")
    ordered = sorted(segments, key=lambda segment: segment["vmaddr"])
    for before, after in zip(ordered, ordered[1:]):
        require(before["vmaddr"] + before["vmsize"] <= after["vmaddr"], "overlapping virtual segments")
    file_ranges = sorted((segment["fileoff"], segment["fileoff"] + segment["filesize"])
                         for segment in segments if segment["filesize"])
    for before, after in zip(file_ranges, file_ranges[1:]):
        require(before[1] <= after[0], "overlapping file-backed segments")
    contract = info["load_contract"]
    require(contract["memory_span"] <= WINDOW_SIZE - BLOCK_SIZE, "kernel exceeds production loader's 254 MiB span bound")
    require(contract["virtual_base"] <= MAX_U64 - WINDOW_SIZE, "virtual window overflows")
    headers = [s for s in segments if s["fileoff"] == 0 and s["filesize"] >= command_end]
    require(len(headers) == 1 and headers[0]["vmaddr"] == contract["virtual_base"],
            "Mach-O header is not loaded at the kernel virtual base")
    entry_sections = [s for s in info["sections"] if s["addr"] <= info["entry"] < s["addr"] + s["size"]
                      and s["flags"] & 0x80000000 and (s["flags"] & 0xFF) == 0]
    require(len(entry_sections) == 1 and info["entry"] + 4 <= entry_sections[0]["addr"] + entry_sections[0]["size"],
            "entry is not a complete instruction in one pure-instruction section")
    relocations = audit_local_relocations(data, info, raw_segments, dysymtab, symtab)
    return {"metadata": info, "segments": segments, "ignored_empty_segments": [s for s in raw_segments if not s["vmsize"]],
            "commands": commands, "zero_sections": zero_sections,
            "local_relocations": relocations,
            "segment_annotations": [{k: s[k] for k in ("name", "vmsize", "filesize", "flags", "maxprot", "initprot")}
                                    for s in raw_segments]}


def audit_local_relocations(data, info, segments, fields, symtab, *, virtual_slide=0):
    """Validate every supported local pointer at its fixed linked virtual VA.

    Physical placement is not a virtual slide. No pointer or relocation record
    is rewritten. This does not establish a running kernel's chosen slide.
    """
    require(virtual_slide == 0, "only zero virtual slide is supported")
    base = info["load_contract"]["virtual_base"]
    require(base == LINK_VIRTUAL_BASE and segments[0]["vmaddr"] == base and segments[0]["fileoff"] == 0,
            "fixed virtual mapping requires the first segment/header at the linked iOS ARM64 base")
    require(not info["flags"] & (0x20 | 0x80000000),
            "MH_SPLIT_SEGS or MH_DYLIB_IN_CACHE has different relocation/slide semantics")
    require(not any(s["name"] == "__thread_starts" and s["size"] for s in info["sections"]),
            "nonempty __thread_starts requires a separate threaded fixup contract")
    names = ("ilocalsym", "nlocalsym", "iextdefsym", "nextdefsym", "iundefsym", "nundefsym",
             "tocoff", "ntoc", "modtaboff", "nmodtab", "extrefsymoff", "nextrefsyms",
             "indirectsymoff", "nindirectsyms", "extreloff", "nextrel", "locreloff", "nlocrel")
    command_present = fields is not None
    if fields is None:
        fields = (0,) * 18
    else:
        require(fields[5] == fields[15] == 0,
                f"unsupported dynamic undefined/external relocations: nundefsym={fields[5]}, nextrel={fields[15]}")
        require(all(value == 0 for value in fields[6:16]),
                "dynamic module/reference/indirect/external tables are outside this fixed local-pointer contract")
        require(fields[0] == 0 and fields[2] == fields[1] and fields[4] == fields[2] + fields[3]
                and fields[4] == symtab[1], "dynamic symbol groups do not partition the actual nlist table")
    offset, count = fields[16:18]
    amount = count * 8
    require(offset <= len(data) and amount <= len(data) - offset, "local relocation table lies outside file")
    loaded = [s for s in segments if s["vmsize"]]
    if count:
        owner = [s for s in loaded if s["fileoff"] <= offset and offset + amount <= s["fileoff"] + s["filesize"]]
        require(len(owner) == 1 and owner[0]["name"] == "__LINKEDIT",
                "local relocation table is not entirely in one __LINKEDIT file range")
        for start, size in ((symtab[0], symtab[1] * 16), (symtab[2], symtab[3])):
            require(not size or offset + amount <= start or start + size <= offset,
                    "local relocation table overlaps the symbol or string table")
    elif offset:
        require(offset <= len(data), "empty local relocation offset lies outside file")
    by_name = {s["name"]: s for s in segments}
    locations, boundaries, samples = [], [], []
    target_sections, location_segments, target_segments, alignments = Counter(), Counter(), Counter(), Counter()
    bindings = hashlib.sha256()
    for index in range(count):
        address, bits = struct.unpack_from("<iI", data, offset + index * 8)
        symbolnum, pcrel, length, external, kind = (bits & 0xFFFFFF, (bits >> 24) & 1,
                                                   (bits >> 25) & 3, (bits >> 27) & 1, bits >> 28)
        require(address >= 0, f"local relocation {index}: negative/scattered r_address is unsupported")
        require((kind, length, pcrel, external) == (0, 3, 0, 0),
                f"local relocation {index}: unsupported type/length/pcrel/extern {(kind, length, pcrel, external)}")
        require(1 <= symbolnum <= len(info["sections"]),
                f"local relocation {index}: missing real target section ordinal {symbolnum}")
        location = base + address
        require(location <= MAX_U64 - 8, f"local relocation {index}: storage address overflow")
        owners = [s for s in loaded if s["vmaddr"] <= location and location + 8 <= s["vmaddr"] + s["filesize"]]
        require(len(owners) == 1, f"local relocation {index}: complete 8-byte storage is not uniquely file-backed")
        owner = owners[0]
        source_offset = owner["fileoff"] + location - owner["vmaddr"]
        value = struct.unpack_from("<Q", data, source_offset)[0]
        section = info["sections"][symbolnum - 1]
        target_owner = by_name[section["segment"]]
        require(target_owner["vmsize"] and target_owner["vmaddr"] <= value < target_owner["vmaddr"] + target_owner["vmsize"],
                f"local relocation {index}: target is not inside its loaded parent segment")
        inside = section["size"] > 0 and section["addr"] <= value < section["addr"] + section["size"]
        boundary = section["size"] == 0 and value == section["addr"]
        require(inside or boundary,
                f"local relocation {index}: target is outside its declared section or exact empty boundary")
        require(not (owner["flags"] | target_owner["flags"]) & SG_NORELOC,
                f"local relocation {index}: SG_NORELOC contradicts actual storage/target membership")
        target_kind = "empty_section_boundary" if boundary else "within_declared_section"
        key = f"{symbolnum}:{section['segment']},{section['name']}"
        target_sections[key] += 1
        location_segments[owner["name"]] += 1
        target_segments[target_owner["name"]] += 1
        alignments[str(location % 8)] += 1
        locations.append(location)
        # Fixed-width canonical tuples cover every binding without publishing a
        # 100k-row pointer dump. The raw table also has its own full SHA-256.
        bindings.update(struct.pack("<IQQQIB", index, location, source_offset, value, symbolnum, int(boundary)))
        if boundary or len(samples) < 5:
            record = {"index": index, "r_address": address, "storage_va": location,
                      "storage_file_offset": source_offset, "target_va": value,
                      "target_section_ordinal": symbolnum, "target_section": key, "target_kind": target_kind}
            if boundary:
                record["storage_symbols"] = [s for s in info["symbols"]["records"]
                                             if s["value"] == location and s["n_type"] & 0xE == 0xE]
                record["boundary_implies_dereferenceable_object"] = False
                boundaries.append(record)
            else:
                samples.append(record)
    ordered = sorted(locations)
    require(all(after >= before + 8 for before, after in zip(ordered, ordered[1:])),
            "local relocation storage locations duplicate or overlap")
    return {"scope": "all local unsigned64 records at the fixed linked virtual mapping",
            "virtual_slide": 0, "relocation_base": base, "load_command_present": command_present,
            "dysymtab": dict(zip(names, fields)),
            "record_count": count, "records_checked": count, "records_skipped": 0,
            "table": {"offset": offset, "size": amount, "sha256": sha256(data[offset:offset + amount])},
            "binding_sha256": bindings.hexdigest(),
            "binding_encoding": "little-endian <IQQQIB per original record order: index, storage VA, storage file offset, target VA, section ordinal, empty-boundary flag",
            "record_class": {"r_type": 0, "name": "ARM64_RELOC_UNSIGNED", "r_length": 3, "r_pcrel": 0, "r_extern": 0},
            "location_alignment_mod8": dict(sorted(alignments.items())),
            "location_segment_counts": dict(sorted(location_segments.items())),
            "target_segment_counts": dict(sorted(target_segments.items())),
            "target_section_counts": dict(sorted(target_sections.items())),
            "empty_section_boundary_records": boundaries, "sample_records": samples,
            "duplicate_or_overlapping_storage_count": 0, "sg_noreloc_membership_conflicts": 0,
            "relocation_writes_performed": 0, "physical_placement_is_virtual_slide": False,
            "runtime_kernel_slide_verified": False, "full_loader_fixup_closure_verified": False,
            "cpu_unaligned_access_verified": False, "general_relocation_support": False}


def c_geometry(kernel):
    require(kernel.Count <= 64, "production parser returned an invalid count")
    return {"base": kernel.Base, "end": kernel.End, "entry": kernel.Entry,
            "segments": [{"vmaddr": s.Address, "vmsize": s.Size, "fileoff": s.FileOffset,
                           "filesize": s.FileSize, "initprot": s.Protection}
                          for s in kernel.Segments[:kernel.Count]]}


def verify_load(lib, data, strict, destination):
    info = strict["metadata"]
    base, span = info["load_contract"]["virtual_base"], info["load_contract"]["memory_span"]
    image = ctypes.create_string_buffer(data)
    parsed = CKernel()
    status = lib.probe_parse(image, len(data), ctypes.byref(parsed))
    require(status == 0, f"production DarwinBoot ParseKernel rejected the candidate: {status}")
    expected = {"base": base, "end": base + span, "entry": info["entry"],
                "segments": [{k: s[k] for k in ("vmaddr", "vmsize", "fileoff", "filesize", "initprot")}
                             for s in strict["segments"]]}
    require(c_geometry(parsed) == expected, "production C parser and independent metadata disagree")
    memory = ctypes.create_string_buffer(span + 2 * GUARD_SIZE)
    ctypes.memset(memory, 0xA5, len(memory))
    loaded = CKernel()
    status = lib.probe_load(image, len(data), ctypes.addressof(memory) + GUARD_SIZE, span, ctypes.byref(loaded))
    require(status == 0 and c_geometry(loaded) == expected, "production copy wrapper failed or changed geometry")
    raw = memory.raw
    require(raw[:GUARD_SIZE] == b"\xa5" * GUARD_SIZE and raw[-GUARD_SIZE:] == b"\xa5" * GUARD_SIZE,
            "production copy crossed the destination guards")
    result = raw[GUARD_SIZE:-GUARD_SIZE]
    copied, tails, gaps = [], [], []
    ordered = sorted(strict["segments"], key=lambda s: s["vmaddr"])
    end = 0
    for segment in ordered:
        at, size, count, fileoff = (segment["vmaddr"] - base, segment["vmsize"], segment["filesize"], segment["fileoff"])
        require(result[at:at + count] == data[fileoff:fileoff + count], "copied segment bytes differ")
        copied.append({"segment": segment["name"], "source_offset": fileoff, "destination_offset": at,
                       "size": count, "sha256": sha256(result[at:at + count])})
        require(not any(result[at + count:at + size]), "segment zero-fill tail contains data")
        if size > count:
            tails.append({"segment": segment["name"], "offset": at + count, "size": size - count})
        require(not any(result[end:at]), "inter-segment gap contains data")
        if at > end:
            gaps.append({"offset": end, "size": at - end})
        end = at + size
    for section in strict["zero_sections"]:
        at = section["vmaddr"] - base
        require(not any(result[at:at + section["size"]]), "declared zero-fill section contains nonzero data")
    destination.write_bytes(result)
    entry = info["entry"] - base
    return {"production_parser_exit_code": status, "production_geometry": expected,
            "independent_geometry_matches": True, "destination_guards_unchanged": True,
            "copied_segments": copied, "zero_fill_tails": tails, "zeroed_gaps": gaps,
            "declared_zero_sections_checked": strict["zero_sections"], "image": identity(destination),
            "entry_destination_offset": entry, "entry_first_16_bytes": result[entry:entry + 16].hex(),
            "kernel_bytes_executed": False, "heap_materialization_only": True}


def check_abi(lib, assym=None):
    fields = []
    for index, (loader, xnu) in enumerate(ABI_FIELDS):
        left = [lib.probe_loader_abi(index, mode) for mode in (0, 1)]
        right = [lib.probe_xnu_abi(index, mode) for mode in (0, 1)]
        require(left == right, f"loader/XNU boot_args ABI mismatch: {loader}/{xnu}")
        fields.append({"loader_field": loader, "xnu_field": xnu, "offset": left[0], "size": left[1]})
    size = lib.probe_xnu_abi(len(ABI_FIELDS), 0)
    require(size == lib.probe_loader_abi(len(ABI_FIELDS), 0) == 0x480, "boot_args structure size mismatch")
    video_fields = []
    for index, name in enumerate(VIDEO_FIELDS):
        left = [lib.probe_video_abi(index, 0, mode) for mode in (0, 1)]
        right = [lib.probe_video_abi(index, 1, mode) for mode in (0, 1)]
        require(left == right, f"loader/XNU Boot_Video member mismatch: {name}")
        video_fields.append({"loader_field": f"Video[{index}]", "xnu_field": f"Video.{name}",
                             "offset": left[0], "size": left[1]})
    definitions = {}
    if assym is not None:
        for name, field in ASSYM_FIELDS.items():
            expected = next(row["offset"] for row in fields if row["xnu_field"] == field)
            for spelling in (name, name + "_NUM"):
                matches = re.findall(r"^#define\s+" + spelling + r"\s+([0-9]+)\s*$", assym, re.MULTILINE)
                require(len(matches) == 1 and int(matches[0]) == expected,
                        f"actual target assym offset differs or is ambiguous: {spelling}")
                definitions[spelling] = expected
    return {"fields": fields, "video_fields": video_fields, "size": size, "host_lp64_layout_matches": True,
            "actual_target_assym_checked": assym is not None, "assym_offsets": definitions,
            "boot_args_instance_generated": False}


def check_entry_symbols(strict, config, data):
    info = strict["metadata"]
    records = info["symbols"]["records"]
    result = {}
    for label, key in (("entry", "required_entry_symbol"), ("early_cpu", "early_cpu_symbol")):
        found = [record for record in records if record["name"] == config["candidate"][key]]
        require(len(found) == 1 and found[0]["n_type"] == 0xF and found[0]["n_sect"] > 0
                and not found[0]["n_desc"] & 0x80,
                f"entry contract symbol absent or ambiguous: {config['candidate'][key]}")
        symbol = found[0]
        section = info["sections"][symbol["n_sect"] - 1]
        require(section["flags"] & 0x80000000 and (section["flags"] & 0xFF) == 0
                and section["addr"] <= symbol["value"] and symbol["value"] + 4 <= section["addr"] + section["size"],
                "entry contract symbol section does not contain a complete pure instruction")
        owners = [s for s in strict["segments"] if s["initprot"] & 4 and s["vmaddr"] <= symbol["value"] < s["vmaddr"] + s["filesize"]]
        require(len(owners) == 1 and symbol["value"] % 4 == 0,
                "entry contract symbol is not aligned file-backed executable memory")
        require(symbol["value"] + 4 <= owners[0]["vmaddr"] + owners[0]["filesize"],
                "entry contract symbol extends beyond file-backed executable memory")
        result[label] = symbol
    require(result["entry"]["value"] == info["entry"], "LC_UNIXTHREAD does not select the actual __start symbol")
    owner = next(s for s in strict["segments"] if s["initprot"] & 4 and
                 s["vmaddr"] <= info["entry"] < s["vmaddr"] + s["filesize"])
    offset = owner["fileoff"] + info["entry"] - owner["vmaddr"]
    instruction = struct.unpack_from("<I", data, offset)[0]
    require(instruction & 0xFC000000 == 0x14000000,
            "fixed ordinary-arm64 entry is not an immediate B trampoline")
    immediate = instruction & 0x3FFFFFF
    if immediate & (1 << 25):
        immediate -= 1 << 26
    target = info["entry"] + immediate * 4
    require(target == result["early_cpu"]["value"],
            "actual __start branch does not reach _start_first_cpu")
    result["trampoline"] = {"file_offset": offset, "instruction_word": instruction,
                             "instruction_hex": f"{instruction:08x}", "decoded_target": target,
                             "scope": "one direct B instruction; early CPU body not control-flow verified"}
    result["entry_executed"] = False
    return result


def recheck(records):
    changes = []
    for before in records:
        try:
            after = (platform_link.tool_identity(Path(before["path"])) if before.get("kind") == "tool"
                     else identity(Path(before["path"])))
            if after != before:
                changes.append({"before": before, "after": after})
        except (OSError, platform_link.LinkError) as exc:
            changes.append({"before": before, "error": str(exc)})
    return {"checked_file_count": len(records), "unchanged": not changes, "changes": changes,
            "scope": "declared files only; host system headers and libraries are not a frozen toolchain"}


def run_probe(args, config):
    output = args.output.resolve()
    kernel_path, link_path, assym_path = (input_path(path) for path in (args.kernel, args.link_report, args.assym))
    for input_root in (args.sources.resolve(), args.xnu_work.resolve(), kernel_path.parent, link_path.parent, assym_path.parent):
        require(output != input_root and input_root not in output.parents,
                "output must be outside every source/build/input directory")
    output.mkdir(parents=True, exist_ok=False)
    report = {"schema_version": 1, "status": "incomplete", "scope": config["scope"],
              "output": str(output), "started_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              **config["qualification"], "host_loader_probe_verified": False,
              "kernel_segment_bytes_verified": False, "boot_args_abi_verified": False}
    records = []
    try:
        sources = public_sources(config, args.sources.resolve())
        boot_header = input_path(args.xnu_work.resolve() / config["xnu"]["files"][0]["path"])
        start_source = input_path(args.xnu_work.resolve() / config["prepared_xnu"]["start_source"]["path"])
        source_paths = [Path(record["path"]) for record in sources.values()]
        compiler_path = shutil.which(args.cc)
        require(compiler_path is not None, "host compiler is unavailable")
        compiler = Path(compiler_path).absolute()
        paths = [kernel_path, link_path, boot_header, start_source,
                 assym_path, Path(__file__).resolve(), Path(platform_link.__file__).resolve(),
                 Path(platform_link.toolchain.__file__).resolve(), CONFIG, *source_paths]
        for path in paths:
            require(output != path and output not in path.parents, "output contains a protected input")
        with ExitStack() as stack:
            for path in sorted(set(paths)):
                require(not path.is_symlink(), f"protected input is a symlink: {path}")
                handle = stack.enter_context(path.open("rb"))
                fcntl.flock(handle, fcntl.LOCK_SH)
                records.append(identity(path))
            records.append(platform_link.tool_identity(compiler))
            report["protected_inputs"] = records
            report["source_provenance"] = config
            require(config["local_relocation_contract"]["virtual_slide"] == 0
                    and int(config["local_relocation_contract"]["linked_virtual_base"], 0) == LINK_VIRTUAL_BASE,
                    "configuration does not describe the supported fixed virtual mapping")
            for source in sources.values():
                now = identity(Path(source["path"]))
                require(now["sha256"] == sha256(source["bytes"]) and now["size"] == len(source["bytes"]),
                        "public source changed before its protection receipt")
            verify_bytes(boot_header.read_bytes(), config["xnu"]["files"][0], "actual prepared boot.h")
            verify_bytes(start_source.read_bytes(), config["prepared_xnu"]["start_source"], "actual prepared start.s")
            verify_bytes(assym_path.read_bytes(), config["prepared_xnu"]["assym"], "actual generated assym.s")
            link_bytes = link_path.read_bytes()
            require(sha256(link_bytes) == config["candidate"]["link_report_sha256"], "link report is not the pinned successful result")
            link = json.loads(link_bytes)
            require(link["status"] == "platform_link_compatible" and link["platform_link_compatible"] is True
                    and link["baseline_reproduced"] is True and link["kernel_callback_linked"] is True
                    and link["protected_inputs_recheck"]["unchanged"] is True,
                    "input link report lacks the required successful gates")
            data = kernel_path.read_bytes()
            verify_bytes(data, config["candidate"], "actual platform candidate")
            require(link["candidate"]["sha256"] == sha256(data) and link["candidate"]["size"] == len(data),
                    "candidate is not bound by the link report")
            report["kernel"] = identity(kernel_path)
            strict = strict_kernel(data)
            require(strict["metadata"]["load_contract"] == link["candidate"]["load_contract"],
                    "current load contract differs from the successful link receipt")
            report["load_commands"] = strict["commands"]
            report["ignored_empty_segments"] = strict["ignored_empty_segments"]
            report["segment_flags"] = {"source_reference": config["segment_flags_reference"],
                                        "observed": strict["segment_annotations"],
                                        "annotation_is_loader_fixup_proof": False}
            report["entry_symbols"] = check_entry_symbols(strict, config, data)
            lib = build_harness(sources, output, compiler, report)
            report["byte_load"] = verify_load(lib, data, strict, output / "kernel.load.bin")
            report["local_relocations"] = {**strict["local_relocations"],
                                            "source_contract": config["local_relocation_contract"],
                                            "copied_pointer_storage_bytes_unchanged": True}
            report["boot_args_abi"] = check_abi(lib, assym_path.read_text())
            contract = strict["metadata"]["load_contract"]
            report["load_contract"] = {**contract,
                "virtual_slide": 0, "runtime_kernel_slide_verified": False,
                "physical_base": None, "board_adt": None, "uefi_window_size": None,
                "physical_allocation_rule": "AllocateAddress in a real EfiConventionalMemory run; physical base modulo 2 MiB equals virtual base modulo 2 MiB",
                "boot_args_physical_rule": "align_up(physical_base + memory_span, 16384)",
                "device_tree_physical_rule": "boot_args_physical + 4096",
                "device_tree_pointer_rule": "virtual_base + device_tree_physical - physical_base",
                "top_of_kernel_data_rule": "physical_base + Used, including actual ADT and all supplied sidecars",
                "entry_rule": "x0 = boot_args physical address; branch to physical_base + entry_offset at EL1",
                "loader_initial_window_bytes": WINDOW_SIZE,
                "loader_kernel_span_limit": WINDOW_SIZE - BLOCK_SIZE,
                "window_available_on_device": False,
                "source_basis": "fixed DarwinBoot.c AllocateWindow/Boot and Entry.S; no allocation or EL1 transition executed"}
            report["host_loader_probe_verified"] = True
            report["kernel_segment_bytes_verified"] = True
            report["boot_args_abi_verified"] = True
            report["status"] = "host_loader_contract_verified"
    except (ProbeError, platform_link.LinkError, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        report["status"] = "failed"
        report["error"] = str(exc)
    finally:
        report["protected_inputs_recheck"] = recheck(records)
        if not report["protected_inputs_recheck"]["unchanged"]:
            report["status"] = "failed"
            report["error"] = "protected inputs changed during the loader probe"
        if report["status"] == "failed":
            report["host_loader_probe_verified"] = False
            report["kernel_segment_bytes_verified"] = False
            report["boot_args_abi_verified"] = False
        report["finished_at_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        write_json(output / "report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare-sources", help="download only the pinned public loader and ABI sources")
    prepare.add_argument("--output", type=Path, required=True)
    run = commands.add_parser("run", help="check the fixed real platform candidate; never enter the kernel")
    run.add_argument("--sources", type=Path, required=True)
    run.add_argument("--kernel", type=Path, required=True)
    run.add_argument("--link-report", type=Path, required=True)
    run.add_argument("--xnu-work", type=Path, required=True)
    run.add_argument("--assym", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--cc", default="cc")
    args = parser.parse_args()
    config = json.loads(CONFIG.read_text())
    try:
        result = prepare_sources(args.output.resolve(), config) if args.command == "prepare-sources" else run_probe(args, config)
    except (OSError, ProbeError, platform_link.LinkError, ValueError) as exc:
        parser.exit(1, f"loader probe: {exc}\n")
    print(json.dumps({key: result.get(key) for key in ("status", "error", "host_loader_probe_verified", "kernel_segment_bytes_verified", "boot_args_abi_verified", "os_boot_verified")}, sort_keys=True))
    return 1 if result["status"] == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
