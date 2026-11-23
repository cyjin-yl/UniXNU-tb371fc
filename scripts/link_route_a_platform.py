#!/usr/bin/env python3
"""Link two public platform archives in an isolated compatibility experiment.

This does not select a crypto/pthread provider, change the upstream build
recipe, or qualify a device kernel. A recovered, reviewable link command is
required; this program never invents a command or invokes make to obtain one.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import prepare_route_a_toolchain as toolchain

KERNEL_RELATIVE = Path("build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837")
KERNEL_NAME = "mach.development.bcm2837.unstripped"
KERNEL_SHA256 = "a58cdeedb9b7a4c152867c3487f28658a3799b0158f5046bbad6d2d58e741469"
KERNEL_SOURCE_VERSION = "12377.121.6"
CPU_OBJECT_RELATIVE = KERNEL_RELATIVE / "osfmk/DEVELOPMENT/cpu.o"
CPU_SOURCE_RELATIVE = Path(".cache/xnu-work/osfmk/arm64/cpu.c")
CPU_OBJECT_SHA256 = "25b913d235ed38f7d4e1910d54d79eaebdbc83003c501939822e288246ed12e4"
CPU_SOURCE_SHA256 = "6ea14e16fab1d5a16cf3483e630863b830e07190db35d1180850f29a27d9f968"
CPU_RECIPE_SHA256 = "bfd7ad809f8b5704f8815a4f9214cba8de8a58c949825a1d8a0bf48fb22a0002"
CALLBACK_PATCH_SHA256 = "e241b720a828d307daba0cd57fc956515641a19867e723a58d54295a98fdb760"
CALLBACK_SOURCE_SHA256 = "7b8eb68b50971168a7bc3d8ec05b8c76dbc9ee0b77e5f280b02d0c34a8c89bfc"
CALLBACK_SYMBOL = "_arm64_platform_sleep_hook"
CALLBACK_PROVENANCE = {
    "repository": "https://github.com/UniXNU/UniXNU-sheng",
    "commit": "c8f92b208068eeaa4cd2b0f592671f04ee70076e",
    "path": "patches/xnu-12377/sheng-platform-sleep.patch",
    "git_blob": "8517a5278e7fa5446a569aa111344b0c40140ce5",
    "selected_hunks": ["cpu.c:hook-definition", "cpu.c:boot-cpu-dispatch-and-resume",
                       "cpu.c:secondary-cpu-dispatch"],
}
COMPONENTS = ("ArmDTPlatform", "ArmCpu")
SCOPE = "isolated-platform-link-compatibility"
FLAGS_SHA256 = "122039d9686275166f9772c52c4d494adfe02e6e417c069639dee0f9c297435f"
ARCHIVES_SHA256 = "661b58d3de53186c66285cda06e9caf3236ff1b7eab6858b612b09f3cec6a196"
FILELIST_SHA256 = "ef6d270d22291a6e43c8d91b8811a505d25ed1465e4c0dba9174f3d19eaa556d"
FILELIST_OBJECT_COUNT = 1067
BUILD_REPORT_SHA256 = "34c40f71b43000dff0cc39b97264fc93ef1fd3b3027735c4a710817863b71044"
CLANG_SHA256 = "85d220e32bd83d75de788c8beab0bea646a4684e1112f7c06266ca71e651bb04"
MAKE_PINS = {
    "MakeInc.kernel": "baed9a0526bae3e475c38fbdd12444f5e6d0496adaf60d5270c7ed871d4ff5f8",
    "MakeInc.def": "fdd3528c4d0d3073ea7c225d8a34fb609a15df57327eb5cf97e2f059c4e86899",
}
# Order comes from the retained non-PRE_LTO rule's prerequisites, not a glob.
EXTRA_OBJECTS = {
    "lastkerneldataconst.o": "11de7c292f3f472005cff2e882835b61b555136933fee1d483cff1e4049b536d",
    "lastkernelconstructor.o": "90d6d8051a3afe895610e32f3b4e998c4b6678d7aa7feb895f13e9cd3f10e63e",
    "nonlto.o": "0015456fe1265aa457ff0257b5e8ea327bdf377df5d3b3e7fa58c6ad34c557ba",
    "version.o": "b6bfbc21337d2f6102cc1719bd95eaa897e6b366ca46782143f77e5dcbe7ef7b",
}


class LinkError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise LinkError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def identity(path: Path) -> dict:
    require(path.is_file() and not path.is_symlink(), f"not a regular input file: {path}")
    return {"path": str(path.resolve()), "size": path.stat().st_size,
            "sha256": toolchain.sha256_file(path)}


def tool_identity(path: Path) -> dict:
    """Bind the invoked name as well as its final executable bytes.

    Resolving first would lose a symlink alias: its old target can remain
    unchanged while a later invocation follows the alias somewhere else.
    """
    require(path.is_absolute() and path.is_file(), f"missing absolute tool file: {path}")
    logical, resolved = path.absolute(), path.resolve(strict=True)
    return {"kind": "tool", "path": str(logical), "realpath": str(resolved),
            "symlink_target": os.readlink(logical) if logical.is_symlink() else None,
            "size": resolved.stat().st_size, "sha256": toolchain.sha256_file(logical)}


def verify_identity(record: dict) -> Path:
    require(isinstance(record, dict) and isinstance(record.get("path"), str), "missing input identity")
    path = Path(record["path"])
    require(path.is_absolute(), f"input identity is not absolute: {path}")
    current = identity(path)
    require(current["sha256"] == record.get("sha256"), f"input digest changed: {path}")
    if "size" in record:
        require(current["size"] == record["size"], f"input size changed: {path}")
    return path.resolve()


def _range(offset, size, length, label):
    require(offset >= 0 and size >= 0 and offset <= length and size <= length - offset,
            f"{label} outside its input")


def macho(data: bytes, expected_type: int) -> dict:
    """Read ordinary ARM64 symbol/section metadata, without an ISA claim."""
    require(len(data) >= 32, "truncated Mach-O header")
    magic, cpu, subtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from("<8I", data)
    require((magic, cpu, subtype, filetype) == (0xFEEDFACF, 0x0100000C, 0, expected_type),
            "expected a thin ordinary-arm64 Mach-O with the specified file type")
    _range(32, sizeofcmds, len(data), "load commands")
    require(ncmds <= sizeofcmds // 8, "invalid Mach-O command count")
    end, cursor, symtab, entry = 32 + sizeofcmds, 32, None, None
    sections, segments, versions = [], [], []
    for _ in range(ncmds):
        _range(cursor, 8, end, "load command")
        command, length = struct.unpack_from("<2I", data, cursor)
        require(length >= 8 and length % 8 == 0, "invalid load command size")
        _range(cursor, length, end, "load command")
        if command == 0x19:
            require(length >= 72, "truncated LC_SEGMENT_64")
            name = data[cursor + 8:cursor + 24].split(b"\0", 1)[0].decode("ascii")
            vmaddr, vmsize, fileoff, filesize, maxprot, initprot, count, segflags = struct.unpack_from(
                "<4Q4I", data, cursor + 24)
            require(length == 72 + 80 * count, "segment section count mismatch")
            _range(fileoff, filesize, len(data), "segment bytes")
            require(filesize <= vmsize, "segment file span exceeds memory span")
            segments.append({"name": name, "vmaddr": vmaddr, "vmsize": vmsize,
                             "fileoff": fileoff, "filesize": filesize, "initprot": initprot})
            for i in range(count):
                at = cursor + 72 + 80 * i
                sectname = data[at:at + 16].split(b"\0", 1)[0].decode("ascii")
                segname = data[at + 16:at + 32].split(b"\0", 1)[0].decode("ascii")
                addr, size, offset, align, reloff, nreloc, sectflags = struct.unpack_from("<2Q5I", data, at + 32)
                if (sectflags & 0xFF) not in {1, 0xC, 0x12}:
                    _range(offset, size, len(data), "section bytes")
                sections.append({"index": len(sections) + 1, "name": sectname, "segment": segname,
                                 "addr": addr, "size": size, "offset": offset, "flags": sectflags})
        elif command == 2:
            require(length == 24 and symtab is None, "invalid or duplicate LC_SYMTAB")
            symtab = struct.unpack_from("<4I", data, cursor + 8)
        elif command == 5:
            require(length == 288 and entry is None, "invalid or duplicate LC_UNIXTHREAD")
            require(struct.unpack_from("<2I", data, cursor + 8) == (6, 68), "unsupported thread state")
            entry = struct.unpack_from("<Q", data, cursor + 272)[0]
        elif command == 0x32:
            require(length >= 24, "truncated LC_BUILD_VERSION")
            platform, minimum, sdk, count = struct.unpack_from("<4I", data, cursor + 8)
            require(length == 24 + count * 8, "LC_BUILD_VERSION tool count/size mismatch")
            versions.append({"platform": platform, "minos": minimum, "sdk": sdk})
        elif command in {0x24, 0x25, 0x2F, 0x30}:
            raise LinkError("legacy deployment command is outside the recorded iOS 27 target")
        cursor += length
    require(cursor == end and symtab is not None, "incomplete Mach-O commands or symbol table")
    require(len(versions) == 1 and versions[0]["platform"] == 2 and versions[0]["minos"] == 27 << 16,
            "expected exactly one LC_BUILD_VERSION for iOS 27.0")
    symoff, nsyms, stroff, strsize = symtab
    _range(symoff, nsyms * 16, len(data), "nlist table")
    _range(stroff, strsize, len(data), "string table")
    strings, records = data[stroff:stroff + strsize], []
    categories = {key: [] for key in ("defined_external", "strong_undefined", "weak_undefined",
                                     "common_external", "unsupported_external")}
    for i in range(nsyms):
        strx, n_type, n_sect, n_desc, value = struct.unpack_from("<IBBHQ", data, symoff + i * 16)
        if n_type & 0xE0:
            continue
        require(strx < strsize, "symbol string index outside string table")
        stop = strings.find(b"\0", strx)
        require(stop >= 0, "unterminated symbol string")
        name = strings[strx:stop].decode("utf-8", "strict")
        require(n_sect <= len(sections), "symbol section index outside image")
        record = {"name": name, "n_type": n_type, "n_sect": n_sect,
                  "n_desc": n_desc, "value": value}
        records.append(record)
        if not n_type & 1:
            continue
        kind = n_type & 0xE
        if kind in {2, 0xE}:
            category = "defined_external"
        elif kind == 0 and value:
            category = "common_external"
        elif kind == 0:
            category = "weak_undefined" if n_desc & 0x40 else "strong_undefined"
        else:
            category = "unsupported_external"
        categories[category].append(record)
    require(not categories["unsupported_external"], "unsupported external symbol semantics")
    result = {"cpu_type": cpu, "cpu_subtype": subtype, "file_type": filetype,
              "flags": flags, "entry": entry, "segments": segments, "sections": sections,
              "build_version": versions[0],
              "symbols": {"records": records, **categories}}
    if expected_type == 2:
        require(entry is not None, "linked kernel lacks LC_UNIXTHREAD")
        executable = [s for s in segments if s["initprot"] & 4 and
                      s["vmaddr"] <= entry < s["vmaddr"] + s["filesize"]]
        require(len(executable) == 1 and entry % 4 == 0, "entry is not uniquely file-backed executable memory")
        nonempty = [s for s in segments if s["vmsize"]]
        base = min(s["vmaddr"] for s in nonempty)
        result["load_contract"] = {"virtual_base": base, "entry_offset": entry - base,
                                   "required_physical_base_low_21_bits": base & 0x1FFFFF,
                                   "memory_span": max(s["vmaddr"] + s["vmsize"] for s in nonempty) - base}
    return result


def archive_members(data: bytes) -> list[dict]:
    """Read regular BSD/GNU ar members; refuse thin or unresolved names."""
    require(data.startswith(b"!<arch>\n"), "expected a regular archive, not a thin archive")
    cursor, names, members = 8, None, []
    while cursor < len(data):
        _range(cursor, 60, len(data), "archive member header")
        header = data[cursor:cursor + 60]
        require(header[58:] == b"`\n", "invalid archive member trailer")
        try:
            size = int(header[48:58].decode("ascii").strip())
        except (ValueError, UnicodeError) as exc:
            raise LinkError("invalid archive member size") from exc
        at = cursor + 60
        _range(at, size, len(data), "archive member")
        rawname, payload = header[:16].decode("ascii").strip(), data[at:at + size]
        if rawname == "//":
            names = payload
        elif rawname in {"/", "/SYM64/"}:
            pass
        else:
            if rawname.startswith("#1/"):
                try:
                    namelen = int(rawname[3:])
                except ValueError as exc:
                    raise LinkError("invalid BSD archive member name") from exc
                _range(0, namelen, len(payload), "BSD member name")
                name, payload = payload[:namelen].rstrip(b"\0").decode("utf-8"), payload[namelen:]
            elif rawname.startswith("/"):
                require(names is not None and rawname[1:].isdigit(), "unresolved GNU archive name")
                offset = int(rawname[1:])
                require(offset < len(names), "GNU archive name offset outside table")
                stop = names.find(b"/\n", offset)
                require(stop >= 0, "unterminated GNU archive name")
                name = names[offset:stop].decode("utf-8")
            else:
                name = rawname.removesuffix("/")
            if not name.startswith("__.SYMDEF"):
                require(name and "/" not in name and name not in {".", ".."}, "nonlocal archive member name")
                members.append({"name": name, "sha256": sha256(payload), "size": len(payload), "data": payload})
        cursor = at + size + (size & 1)
        require(cursor <= len(data), "missing archive alignment padding")
    require(members and len({m["name"] for m in members}) == len(members), "empty archive or duplicate members")
    return members


def verify_platform(report_path: Path, candidate: Path) -> tuple[dict, list[dict]]:
    report = json.loads(report_path.read_text())
    require(report.get("status") == "archives_built" and
            report.get("scope") == "public-platform-archives-against-generic-kernel",
            "platform report does not describe completed independent archives")
    require(verify_identity(report["kernel"]) == candidate.resolve(), "platform archives target a different kernel")
    components = report.get("components", [])
    require(len(components) == 2 and {c.get("name") for c in components} == set(COMPONENTS),
            "exactly ArmDTPlatform and ArmCpu are required")
    records = []
    for name in COMPONENTS:
        component = next(c for c in components if c["name"] == name)
        require(component.get("status") == "archive_built", f"archive was not built: {name}")
        obj, archive = verify_identity(component["object"]), verify_identity(component["archive"])
        parsed = macho(obj.read_bytes(), 1)
        require(not parsed["symbols"]["common_external"], "common symbols need a separately reviewed link contract")
        members = archive_members(archive.read_bytes())
        require(len(members) == 1 and members[0]["name"] == f"{name}.o" and
                members[0]["sha256"] == component["object"]["sha256"],
                f"archive does not contain exactly the recorded object: {name}")
        declared = component["archive"].get("members", [])
        require(len(declared) == 1 and declared[0].get("name") == members[0]["name"] and
                declared[0].get("sha256") == members[0]["sha256"] and
                Path(declared[0]["object_path"]).resolve() == obj,
                f"archive member report mismatch: {name}")
        symbols_path = verify_identity(component["object"]["symbols"])
        supplied_symbols = json.loads(symbols_path.read_text())
        require(supplied_symbols.get("records") == parsed["symbols"]["records"],
                f"recorded symbol metadata differs from object: {name}")
        records.append({"name": name, "object": identity(obj), "archive": identity(archive),
                        "symbol_report": identity(symbols_path),
                        "member": {k: v for k, v in members[0].items() if k != "data"},
                        "macho": parsed})
    return report, records


def symbol_closure(kernel_inputs: list[dict], components: list[dict]) -> dict:
    """Conservative inventory. The actual linker remains authoritative."""
    definitions = {}
    for source in [*kernel_inputs, *components]:
        for symbol in source["macho"]["symbols"]["defined_external"]:
            definitions.setdefault(symbol["name"], []).append(
                {"source": source.get("name", source.get("path")), "weak": bool(symbol["n_desc"] & 0x80)})
    duplicates = {name: rows for name, rows in definitions.items() if sum(not row["weak"] for row in rows) > 1}
    missing, weak = [], []
    for component in components:
        symbols = component["macho"]["symbols"]
        for category, destination in (("strong_undefined", missing), ("weak_undefined", weak)):
            for symbol in symbols[category]:
                if symbol["name"] not in definitions:
                    destination.append({"component": component["name"], "symbol": symbol["name"]})
    return {"unresolved_platform_strong": missing, "unresolved_platform_weak": weak,
            "duplicate_strong_definitions": duplicates,
            "inventory_is_link_success": False,
            "unextracted_baseline_archive_members_included": False}


def parse_link_map(text: str) -> tuple[dict, list[dict]]:
    objects, symbols = {}, []
    for line in text.splitlines():
        if line.startswith("# Dead Stripped Symbols:"):
            break
        obj = re.fullmatch(r"\[\s*(\d+)\]\s+(.+)", line)
        if obj:
            require(int(obj[1]) not in objects, "duplicate object index in link map")
            objects[int(obj[1])] = obj[2]
        sym = re.fullmatch(r"(0x[0-9A-Fa-f]+)\s+(0x[0-9A-Fa-f]+)\s+\[\s*(\d+)\]\s+(.+)", line)
        if sym:
            symbols.append({"address": int(sym[1], 16), "size": int(sym[2], 16),
                            "object_index": int(sym[3]), "name": sym[4]})
    require(objects and symbols, "link map has no recognized allocated members/symbols")
    return objects, symbols


def verify_link_map(text: str, components: list[dict], linked: dict, data: bytes) -> dict:
    """Require actual member allocation and its initialization in the new image."""
    objects, symbols = parse_link_map(text)
    init_sections = [s for s in linked["sections"] if s["name"] == "__mod_init_func"]
    require(init_sections and all(s["size"] % 8 == 0 for s in init_sections), "missing or malformed constructor table")
    init_pointers = set()
    for section in init_sections:
        _range(section["offset"], section["size"], len(data), "constructor table")
        init_pointers.update(value[0] for value in struct.iter_unpack(
            "<Q", data[section["offset"]:section["offset"] + section["size"]]))
    evidence = []
    for component in components:
        expected = f"{component['archive']['path']}({component['member']['name']})"
        indexes = [index for index, path in objects.items() if path == expected]
        require(len(indexes) == 1, f"map does not identify the actual archive member: {component['name']}")
        allocated = [s for s in symbols if s["object_index"] == indexes[0] and s["size"] > 0]
        require(allocated, f"archive member contributed no allocated symbols: {component['name']}")
        constructors = [s for s in allocated if s["address"] in init_pointers]
        require(constructors, f"archive member has no retained constructor: {component['name']}")
        metas = [s for s in allocated if "gMetaClass" in s["name"] and component["name"] in s["name"]]
        require(metas, f"archive member has no retained metaclass: {component['name']}")
        marker = "_armdt_platform_configured" if component["name"] == "ArmDTPlatform" else "_armcpu_registered"
        require(any(s["name"] == marker for s in allocated), f"missing actual platform observation symbol: {marker}")
        evidence.append({"component": component["name"], "map_member": expected,
                         "object_index": indexes[0], "allocated_symbol_count": len(allocated),
                         "constructor_symbols": constructors, "metaclass_symbols": metas,
                         "observation_symbol": marker})
    return {"components": evidence, "constructor_pointer_count": len(init_pointers),
            "runtime_driver_matching_verified": False}


def apply_cpu_patch(before: bytes, patch: bytes) -> bytes:
    """Reproduce exactly three single-file unified hunks without invoking git."""
    lines = patch.decode("utf-8").splitlines(keepends=True)
    source = before.decode("utf-8").splitlines(keepends=True)
    old_header = "--- a/osfmk/arm64/cpu.c\n"
    new_header = "+++ b/osfmk/arm64/cpu.c\n"
    require(lines.count(old_header) == 1 and lines.count(new_header) == 1,
            "callback patch must name only osfmk/arm64/cpu.c")
    cursor = lines.index(old_header)
    require(cursor + 1 < len(lines) and lines[cursor + 1] == new_header, "malformed callback patch headers")
    for line in lines[:cursor]:
        require(line == "\n" or line.startswith("# ") or
                line == "diff --git a/osfmk/arm64/cpu.c b/osfmk/arm64/cpu.c\n" or
                re.fullmatch(r"index [0-9a-f]+\.\.[0-9a-f]+(?: 100644)?\n", line),
                "callback patch has unreviewed metadata or another file")
    cursor += 2
    old_cursor, previous_header_end, result, hunks = 0, 0, [], 0
    while cursor < len(lines):
        match = re.fullmatch(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n", lines[cursor])
        require(match is not None, "invalid callback hunk header")
        old_start, old_count = int(match[1]), int(match[2] or 1)
        new_start, new_count = int(match[3]), int(match[4] or 1)
        require(old_start >= 1 and new_start >= 1 and old_count > 0, "unsupported callback hunk range")
        header_start = old_start - 1
        require(header_start >= previous_header_end, "overlapping callback hunk headers")
        cursor += 1
        removed, added = [], []
        while cursor < len(lines) and not lines[cursor].startswith("@@ "):
            line = lines[cursor]
            require(line.startswith((" ", "+", "-")), "invalid callback hunk body or extra file")
            require(not line.startswith(("--- ", "+++ ")), "callback patch contains another file")
            if line[0] in " -":
                removed.append(line[1:])
            if line[0] in " +":
                added.append(line[1:])
            cursor += 1
        require(len(removed) == old_count and len(added) == new_count, "callback hunk line count mismatch")
        # The retained generic patch set has removed 32 earlier source lines
        # before the last two upstream hunks. Locate each complete old context
        # uniquely, without dropping context lines or applying fuzzy matches.
        matches = [i for i in range(len(source) - old_count + 1) if source[i:i + old_count] == removed]
        require(len(matches) == 1, "callback patch context is absent or ambiguous in original cpu.c")
        start = matches[0]
        require(old_cursor <= start, "callback contexts overlap or change order")
        result.extend(source[old_cursor:start])
        require(len(result) == new_start - 1 + start - header_start, "callback hunk new-file position mismatch")
        result.extend(added)
        old_cursor = start + old_count
        previous_header_end = header_start + old_count
        hunks += 1
    require(hunks == 3, "callback patch must contain exactly the three selected cpu.c hunks")
    result.extend(source[old_cursor:])
    return "".join(result).encode("utf-8")


def hook_definition(parsed: dict) -> dict:
    definitions = [s for s in parsed["symbols"]["defined_external"] if s["name"] == CALLBACK_SYMBOL]
    require(len(definitions) == 1 and not definitions[0]["n_desc"] & 0x80,
            "replacement must provide one strong platform-sleep hook definition")
    symbol = definitions[0]
    require((symbol["n_type"] & 0xE) == 0xE and symbol["n_sect"] > 0, "callback is not a section-backed variable")
    section = parsed["sections"][symbol["n_sect"] - 1]
    require(symbol["value"] % 8 == 0 and not (section["flags"] & 0x80000400) and
            (section["flags"] & 0xFF) in {0, 1, 0xC, 0x12} and
            section["addr"] <= symbol["value"] and symbol["value"] + 8 <= section["addr"] + section["size"],
            "callback definition is not backed by ordinary pointer-sized data storage")
    return {"symbol": symbol, "section": section}


def callback_producer():
    # Deferred: ordinary archive-only replay keeps its original dependencies.
    # The producer imports no linker module, so this does not create a cycle.
    try:
        import build_route_a_kernel_callback
    except ImportError as exc:
        raise LinkError("callback verification requires the recorded callback producer and its support modules") from exc
    return build_route_a_kernel_callback


def callback_recheck(report: dict, required: list[dict]):
    checks, summary = report.get("protected_input_rechecks"), report.get("protected_inputs_recheck", {})
    require(report.get("protected_inputs_unchanged") is True and isinstance(checks, list) and checks and
            summary.get("unchanged") is True and summary.get("checked_file_count") == len(checks) and
            summary.get("changes") == [], "callback build has no complete unchanged-input receipt")
    for item in checks:
        require(item.get("unchanged") is True and re.fullmatch(r"[0-9a-f]{64}", item.get("expected_sha256", "")) and
                item.get("expected_sha256") == item.get("actual_sha256"), "callback build recorded a changed input")
    observed = {(item["path"], item["expected_sha256"]) for item in checks}
    require(all((item["path"], item["sha256"]) in observed for item in required),
            "callback unchanged-input receipt omits a required source/recipe/driver/tool input")


def callback_codegen(producer, report: dict, raw: bytes, after: dict) -> tuple[dict, list[dict]]:
    """Recompute the producer's bounded code proof from the actual object."""
    evidence_path = verify_identity(report["callback_evidence"])
    observed = json.loads(evidence_path.read_text())
    require(observed.get("passed") is True and observed.get("object_sha256") == sha256(raw) and
            observed.get("source_sha256") == after["sha256"], "callback generated-code evidence is not a passing bound result")
    try:
        _, symbols, sections, relocations = producer.object_layout(raw)
        decoder, decoder_id = producer.decoder_identity()
        recomputed = producer.callback_evidence(raw, symbols, sections, relocations, decoder)
    except (ImportError, RuntimeError, OSError, ValueError, KeyError, TypeError, struct.error) as exc:
        raise LinkError(f"callback generated-code verification failed: {exc}") from exc
    require(all(observed.get(key) == value for key, value in recomputed.items()),
            "callback generated-code evidence differs from the actual bounded object sequences")
    require(recomputed.get("passed") is True and len(recomputed.get("dispatch_calls", [])) == 2 and
            sorted(call.get("argument_value") for call in recomputed["dispatch_calls"]) == [0, 1] and
            all(call.get("instruction") == "blr" for call in recomputed["dispatch_calls"]),
            "callback object lacks the two verified TRUE/FALSE dispatch calls")
    resume = recomputed.get("resume_call", {})
    require(resume.get("symbol") == "_arm_init_cpu" and resume.get("instruction") == "bl" and
            resume.get("second_argument") == 0 and resume.get("after_boot_dispatch") is True,
            "callback object lacks the verified post-boot-dispatch resume call")
    require(all(recomputed.get(key) is False for key in (
        "full_control_flow_proven", "full_instruction_set_audited", "runtime_path_execution_verified", "sleep_resume_verified")),
        "callback bounded evidence overstates runtime or ISA qualification")
    inputs = [identity(evidence_path)]
    recorded_decoder = report["decoder"]
    require(decoder_id["version"] == recorded_decoder["version"] == "5.0.6" and
            decoder_id["core_version"] == recorded_decoder["core_version"], "callback decoder identity changed")
    for key in ("module", "native_library", "python"):
        recorded, actual = recorded_decoder[key], decoder_id[key]
        original = tool_identity(Path(recorded["path"]))
        current = tool_identity(Path(actual["path"]))
        require(original["sha256"] == recorded["sha256"] == current["sha256"] == actual["sha256"],
                f"callback decoder input differs: {key}")
        inputs.extend((original, current))
    disassembly = verify_identity(report["disassembly"])
    require(observed.get("disassembly") == report["disassembly"], "callback evidence names a different disassembly artifact")
    inputs.append(identity(disassembly))
    return {"passed": True, "recomputed_from_replacement_object": True,
            "scope": recomputed["scope"], "function": recomputed["function"],
            "dispatch_calls": recomputed["dispatch_calls"], "resume_call": resume,
            "runtime_path_execution_verified": False}, inputs


def verify_callback(report_path: Path, candidate: Path, kernel: Path, prefix: Path) -> tuple[dict, list[dict]]:
    report = json.loads(report_path.read_text())
    require(report.get("schema_version") == 1 and report.get("status") == "kernel_callback_built" and
            report.get("kernel_callback_built") is True and
            report.get("scope") == "arm64-platform-sleep-cpu-replacement", "callback object has not been independently built")
    provenance = report.get("provenance", {})
    require(all(provenance.get(key) == value for key, value in CALLBACK_PROVENANCE.items()),
            "callback patch provenance differs from the selected real XNU cpu.c wiring")
    require(verify_identity(report["kernel"]) == candidate.resolve(), "callback targets a different kernel")
    original = verify_identity(report["original_object"])
    replacement = verify_identity(report["replacement_object"])
    before = verify_identity(report["source"]["before"])
    after = verify_identity(report["source"]["after"])
    original_recipe = verify_identity(report["compile_record"]["original"])
    replay_recipe = verify_identity(report["compile_record"]["replay"])
    patch_path = verify_identity(report["patch"])
    require(report["patch"]["sha256"] == CALLBACK_PATCH_SHA256 and
            report["source"]["after"]["sha256"] == CALLBACK_SOURCE_SHA256,
            "callback patch or result source differs from the pinned three-hunk selection")
    require(original == kernel / CPU_OBJECT_RELATIVE and report["original_object"]["sha256"] == CPU_OBJECT_SHA256,
            "callback original object is not the pinned kernel cpu.o")
    require(before == kernel / CPU_SOURCE_RELATIVE and report["source"]["before"]["sha256"] == CPU_SOURCE_SHA256,
            "callback original source is not the pinned kernel cpu.c")
    require(original_recipe == original.with_name("cpu.o.json") and
            report["compile_record"]["original"]["sha256"] == CPU_RECIPE_SHA256,
            "callback original compilation record differs from the kernel's cpu.o recipe")
    require(not replacement.is_relative_to(kernel) and not after.is_relative_to(kernel) and
            replacement != original and after != before, "callback outputs overlap the protected kernel tree")
    require(apply_cpu_patch(before.read_bytes(), patch_path.read_bytes()) == after.read_bytes(),
            "callback patched source does not equal the three recorded cpu.c hunks")
    input_paths = [report_path, original, replacement, before, after, original_recipe, replay_recipe, patch_path]
    for key in ("driver", "config", "callback_evidence"):
        input_paths.append(verify_identity(report[key]))
    producer = callback_producer()
    imported_driver = identity(Path(producer.__file__).resolve())
    require(imported_driver["sha256"] == report["driver"]["sha256"],
            "callback replay verifier differs from the driver that produced the object")
    input_paths.append(Path(imported_driver["path"]))
    config = json.loads(Path(report["config"]["path"]).read_text())
    require(config.get("scope") == report["scope"] and config.get("schema_version") == 1 and
            config.get("patch", {}).get("sha256") == CALLBACK_PATCH_SHA256 and
            config.get("patch", {}).get("result_source_sha256") == CALLBACK_SOURCE_SHA256 and
            all(config.get("provenance", {}).get(key) == value for key, value in CALLBACK_PROVENANCE.items()),
            "callback configuration differs from the selected source/provenance contract")
    support = report.get("support_files", [])
    expected_support = {"scripts/build_route_a_platform.py": Path(producer.platform.__file__).resolve(),
                        "scripts/prepare_route_a_toolchain.py": Path(toolchain.__file__).resolve()}
    specs = config.get("support_files", [])
    require(len(specs) == len(expected_support) and {item["path"] for item in specs} == set(expected_support),
            "callback configuration has unexpected replay support modules")
    for spec in specs:
        imported = identity(expected_support[spec["path"]])
        recorded = [item for item in support if Path(item["path"]).name == Path(spec["path"]).name]
        require(len(recorded) == 1 and recorded[0]["sha256"] == imported["sha256"] == spec["sha256"],
                "callback replay support differs from the recorded compiler contract")
        input_paths.extend((verify_identity(recorded[0]), Path(imported["path"])))
    compiler_record = report["compiler"]
    compiler = Path(compiler_record["path"])
    compiler_id = tool_identity(compiler)
    require(compiler_id["sha256"] == compiler_record.get("sha256") == CLANG_SHA256 and
            compiler.resolve() == (prefix / "llvm/bin/clang").resolve(), "callback compiler is not the verified kernel compiler")
    old_command = json.loads(original_recipe.read_text().strip().rstrip(","))
    new_command = json.loads(replay_recipe.read_text())
    cwd = Path(old_command["directory"])
    require(cwd.is_absolute() and cwd == original.parent and old_command["file"] == str(before),
            "callback original source/cwd disagrees with the fixed recipe")
    require(new_command.get("directory") == str(replacement.parent) and new_command.get("file") == str(after),
            "callback replay source/cwd is not the recorded isolated compilation")
    replay_output = Path(new_command["output"])
    require((replay_output if replay_output.is_absolute() else replacement.parent / replay_output).resolve() == replacement,
            "callback compilation output is not the recorded replacement")
    argv = new_command.get("arguments")
    require(isinstance(argv, list) and argv and all(isinstance(a, str) and a and "\0" not in a for a in argv),
            "invalid callback compiler argv")
    require(Path(argv[0]).resolve() == compiler.resolve() and argv.count(str(after)) == 1 and argv.count("-c") == 1 and
            argv.count("-o") == 1 and [a for a in argv if a.startswith("-mcpu")] == ["-mcpu=generic"],
            "callback replay does not use the expected compiler/source/compile-only CPU contract")
    at = argv.index("-o")
    require(at + 1 < len(argv), "callback replay has no output after -o")
    arg_output = Path(argv[at + 1])
    require((arg_output if arg_output.is_absolute() else replacement.parent / arg_output).resolve() == replacement,
            "callback replay argv writes a different object")
    try:
        expected_argv, changes = producer.replay_recipe(old_command, kernel, after, replacement.parent)
    except (RuntimeError, ValueError, KeyError, TypeError, OSError) as exc:
        raise LinkError(f"callback original recipe cannot be replayed safely: {exc}") from exc
    require(argv == expected_argv and report.get("recipe_changes") == changes,
            "callback replay argv/changes differ from exact reconstruction of the original C recipe")
    compiled = report.get("compile", {})
    require(compiled.get("status") == "completed" and compiled.get("exit_code") == 0 and
            compiled.get("label") == "cpu-compile" and compiled.get("argv") == argv and
            compiled.get("cwd") == str(replacement.parent), "callback has no matching successful compiler execution")
    for key in ("stdout", "stderr"):
        log = Path(compiled[key])
        require(identity(log)["sha256"] == compiled.get(key + "_sha256"), "callback compilation log digest changed")
        input_paths.append(log)
    callback_recheck(report, [report["kernel"], report["original_object"], report["source"]["before"],
                             report["source"]["after"], report["compile_record"]["original"],
                             report["driver"], report["config"], report["patch"], report["compiler"], *support])
    old_macho, new_macho = macho(original.read_bytes(), 1), macho(replacement.read_bytes(), 1)
    require(not old_macho["symbols"]["common_external"] and not new_macho["symbols"]["common_external"],
            "callback common symbols require a different link contract")
    old_definitions = {s["name"] for s in old_macho["symbols"]["defined_external"]}
    new_definitions = {s["name"] for s in new_macho["symbols"]["defined_external"]}
    require(CALLBACK_SYMBOL not in old_definitions and new_definitions == old_definitions | {CALLBACK_SYMBOL},
            "callback replacement changes external definitions beyond the sleep hook")
    old_kinds = {s["name"]: (s["n_type"], s["n_desc"] & 0x80)
                 for s in old_macho["symbols"]["defined_external"]}
    new_kinds = {s["name"]: (s["n_type"], s["n_desc"] & 0x80)
                 for s in new_macho["symbols"]["defined_external"] if s["name"] != CALLBACK_SYMBOL}
    require(old_kinds == new_kinds, "callback replacement changes existing definition type or weak/strong binding")
    require("_ml_arm_sleep" in old_definitions, "original cpu.o does not define ml_arm_sleep")
    hook = hook_definition(new_macho)
    symbols_path = verify_identity(report["replacement_object"]["symbols"])
    require(json.loads(symbols_path.read_text()).get("records") == new_macho["symbols"]["records"],
            "callback symbol report differs from replacement bytes")
    input_paths.append(symbols_path)
    generated, generated_inputs = callback_codegen(producer, report, replacement.read_bytes(), report["source"]["after"])
    evidence = {"report": identity(report_path), "provenance": provenance,
                "original_object": identity(original), "replacement_object": identity(replacement),
                "source": {"before": identity(before), "after": identity(after)},
                "compile_record": {"original": identity(original_recipe), "replay": identity(replay_recipe)},
                "driver": report["driver"], "config": report["config"], "patch": report["patch"],
                "compiler": compiler_id, "callback_evidence": report["callback_evidence"],
                "recipe_reconstruction_verified": True, "recipe_changes": changes,
                "producer_protected_inputs_recheck": report["protected_inputs_recheck"],
                "generated_code_verification": generated, "hook_definition": hook,
                "runtime_path_execution_verified": False}
    return {"name": "kernel cpu callback", "macho": new_macho, "original_macho": old_macho,
            "evidence": evidence}, [*[identity(path) for path in input_paths], compiler_id, *generated_inputs]


def callback_kernel_symbols(kernel_metadata: dict, callback: dict | None) -> list[dict]:
    if callback is None:
        return [{"name": "original generic kernel", "macho": kernel_metadata}]
    # A strong definition in the successful original link came from this
    # object. A weak definition may have lost to another object's strong
    # definition: keep that baseline observation, since the new weak copy
    # cannot introduce a duplicate-strong claim. Unsupported aliases fail in
    # macho(); this inventory is not proof of actual symbol resolution.
    removed = {s["name"] for s in callback["original_macho"]["symbols"]["defined_external"]
               if not (s["n_desc"] & 0x80)}
    remaining = [s for s in kernel_metadata["symbols"]["defined_external"] if s["name"] not in removed]
    adjusted = {**kernel_metadata, "symbols": {**kernel_metadata["symbols"], "defined_external": remaining}}
    return [{"name": "original kernel excluding replaced cpu definitions", "macho": adjusted}, callback]


def replace_cpu_filelist(recipe: dict, original_filelist: Path, destination: Path, callback: dict) -> dict:
    require(destination.parent == original_filelist.parent and destination != original_filelist and not destination.exists(),
            "replacement filelist must be a fresh sibling of the preserved baseline filelist")
    original_path = Path(callback["evidence"]["original_object"]["path"])
    replacement_path = Path(callback["evidence"]["replacement_object"]["path"])
    require(replacement_path.is_absolute() and not any(c in str(replacement_path) for c in (",", "\n", "\0")),
            "invalid replacement object path")
    raw = original_filelist.read_bytes()
    require(sha256(raw) == FILELIST_SHA256, "baseline filelist changed before cpu replacement")
    lines = raw.decode("utf-8").splitlines(keepends=True)
    cwd = Path(recipe["cwd"])
    matches = []
    for index, line in enumerate(lines):
        require(line.endswith("\n") and line[:-1] == line[:-1].strip(), "unsupported filelist line form")
        entry = Path(line[:-1])
        if (entry if entry.is_absolute() else cwd / entry).resolve() == original_path:
            matches.append(index)
    require(len(matches) == 1, "original cpu.o must occur exactly once in the retained filelist")
    changed = list(lines)
    index = matches[0]
    changed[index] = str(replacement_path) + "\n"
    require(changed[index] != lines[index], "callback replacement does not change the object")
    with destination.open("xb") as stream:
        stream.write("".join(changed).encode("utf-8"))
    return {"original_filelist": identity(original_filelist), "platform_filelist": identity(destination),
            "line_index": index, "original_entry": lines[index].rstrip("\n"),
            "replacement_entry": str(replacement_path), "replacement_count": 1,
            "unchanged_original_linked_object_count": recipe["linked_object_count"] - 1}


def verify_callback_link_map(text: str, callback: dict, linked: dict) -> dict:
    objects, symbols = parse_link_map(text)
    original = callback["evidence"]["original_object"]["path"]
    replacement = callback["evidence"]["replacement_object"]["path"]
    require(original not in objects.values(), "original cpu.o still appears in platform link map")
    indexes = [index for index, path in objects.items() if path == replacement]
    require(len(indexes) == 1, "platform link map does not identify the actual replacement cpu.o")
    selected = [s for s in symbols if s["object_index"] == indexes[0] and s["size"] > 0]
    hook_rows = [s for s in selected if s["name"] == CALLBACK_SYMBOL and s["size"] >= 8]
    sleep_rows = [s for s in selected if s["name"] == "_ml_arm_sleep"]
    require(len(hook_rows) == 1 and len(sleep_rows) == 1, "replacement hook/ml_arm_sleep were not retained from the actual object")
    definition = hook_definition(linked)
    require(definition["symbol"]["value"] == hook_rows[0]["address"], "linked callback symbol disagrees with its map address")
    sleep_definitions = [s for s in linked["symbols"]["defined_external"] if s["name"] == "_ml_arm_sleep"]
    require(len(sleep_definitions) == 1 and sleep_definitions[0]["n_sect"] > 0 and
            sleep_definitions[0]["value"] == sleep_rows[0]["address"] and
            linked["sections"][sleep_definitions[0]["n_sect"] - 1]["flags"] & 0x80000400,
            "linked ml_arm_sleep is not the mapped instruction-section definition")
    return {"map_object": replacement, "object_index": indexes[0], "hook_symbol": hook_rows[0],
            "ml_arm_sleep_symbol": sleep_rows[0], "definition": definition,
            "runtime_path_execution_verified": False}


def pinned(path: Path, expected: str) -> dict:
    record = identity(path)
    require(record["sha256"] == expected, f"retained link input differs from its fixed baseline: {path}")
    return record


def recover_recipe(kernel: Path, prefix: Path) -> tuple[dict, list[dict]]:
    """Expand only the observed non-LTO rule; do not run make or a shell.

    The flags file omits -filelist, extra prerequisites, -o and
    LD_KERNEL_ARCHIVES. Each missing part is available in retained inputs or
    the fixed Make rule. Byte-identical baseline replay is mandatory below.
    """
    cwd = kernel / KERNEL_RELATIVE
    inputs = []
    for name, expected in MAKE_PINS.items():
        inputs.append(pinned(kernel / ".cache/xnu-work/makedefs" / name, expected))
    flags_path = cwd / ".LDFLAGS"
    archives_path = cwd / "mach.development.bcm2837.link/mach.development.bcm2837.linkarchives"
    filelist = cwd / "link.filelist"
    inputs.extend((pinned(flags_path, FLAGS_SHA256), pinned(archives_path, ARCHIVES_SHA256),
                   pinned(filelist, FILELIST_SHA256)))
    raw = flags_path.read_bytes()
    require(raw.endswith(b"\n\0") and b"\0" not in raw[:-1], "unexpected retained flags terminator")
    flags = shlex.split(raw[:-2].decode("utf-8"))
    sdk = kernel / ".cache/fakeroot/usr/local/lib/kernel"
    libcc = sdk / "libcc_kext.a"
    driver = prefix / "CommandLineTools/usr/bin/clang++"
    require(flags[0] == str(driver) and flags[-1] == str(libcc), "retained compiler/runtime-library layout changed")
    archives = shlex.split(archives_path.read_text())
    require(archives == [f"-L{sdk}", f"-L{sdk / 'platform'}", "-lfirehose_kernel"],
            "retained archive selection is not the reviewed baseline")
    require(not any(token.startswith("@") or "\0" in token for token in [*flags, *archives]), "unsafe argument encoding")
    # The digest pins the complete read-only flag grammar above. These checks
    # document the side-effect boundary rather than accepting arbitrary -Wl.
    require(not any(token in {"-o", "-Xlinker", "-filelist"} or token.startswith(
        ("-Wl,-o,", "-Wl,-map,", "-Wl,-dependency_info,", "-Wl,-object_path_lto,",
         "-Wl,-undefined,", "-Wl,-U,", "-Wl,-force_load,", "-save-temps")) for token in flags[1:]),
        "retained flags contain unreviewed outputs or altered resolution semantics")
    require(not any((cwd / name).exists() for name in ("ltolink.filelist", "nonltolink.filelist", "justlto.o")),
            "a PRE_LTO artifact exists; this non-LTO reconstruction is not applicable")
    objects = []
    for line in filelist.read_text().splitlines():
        require(line == line.strip() and line and "\0" not in line and "," not in line,
                "unsupported filelist entry")
        path = Path(line) if Path(line).is_absolute() else cwd / line
        path = path.resolve()
        require(path.is_relative_to(kernel) and path.suffix in {".o", ".cpo"}, "filelist input escapes kernel or is not an object")
        objects.append(path)
    require(len(objects) == FILELIST_OBJECT_COUNT and len(set(objects)) == len(objects),
            "linked object set differs from the retained filelist")
    extra = []
    for name, expected in EXTRA_OBJECTS.items():
        path = cwd / name
        inputs.append(pinned(path, expected))
        extra.append(path)
    require(not set(objects).intersection(extra), "extra object occurs twice in link inputs")
    for path in objects:
        inputs.append(identity(path))
    for path in [*objects, *extra]:
        with path.open("rb") as stream:
            header = stream.read(16)
        require(header == struct.pack("<4I", 0xFEEDFACF, 0x0100000C, 0, 1),
                f"linked input is not a plain-arm64 object (LTO is not accepted): {path}")
    # Resolve the only -l input in the static baseline's exact search order.
    libraries = [sdk / "libfirehose_kernel.a", sdk / "platform/libfirehose_kernel.a"]
    found = [path for path in libraries if path.is_file()]
    require(found, "retained firehose archive is absent")
    inputs.extend(identity(path) for path in [libcc, *found])
    for name in ("all-kpi.exp", "all-alias.exp", "symbolsets.plist"):
        inputs.append(identity(cwd / name))
    return {"mode": "reconstructed_from_retained_flags_and_pinned_make_recipe",
            "captured_final_argv": False, "make_rule": "makedefs/MakeInc.kernel:239 (non-PRE_LTO)",
            "cwd": str(cwd), "driver_and_flags": flags[:-1], "runtime_libraries": flags[-1:],
            "archive_arguments": archives, "filelist": str(filelist),
            "extra_objects": [str(path) for path in extra], "linked_object_count": len(objects) + len(extra),
            "resolved_firehose_archive": str(found[0]), "byte_identical_baseline_required": True}, inputs


def link_command(recipe: dict, filelist: Path, output: Path, mapfile: Path,
                 components=()) -> list[str]:
    require(output.parent == mapfile.parent and output.parent == filelist.parent.parent,
            "link outputs/filelist must be inside the same isolated directory")
    for path in (filelist, output, mapfile):
        require(path.is_absolute() and not any(c in str(path) for c in (",", "\n", "\0")), "unsupported output path")
    require(not output.exists() and not mapfile.exists(), "refuse to overwrite an earlier link attempt")
    command = [*recipe["driver_and_flags"], "-filelist", str(filelist), *recipe["extra_objects"],
               "-o", str(output), *recipe["runtime_libraries"], *recipe["archive_arguments"],
               f"-Wl,-map,{mapfile}"]
    for component in components:
        archive = component["archive"]["path"]
        require(not any(c in archive for c in (",", "\n", "\0")), "unsupported archive path")
        command.append(f"-Wl,-force_load,{archive}")
    return command


def check_unchanged(inputs: list[dict]) -> dict:
    changes = []
    for record in inputs:
        path = Path(record["path"])
        try:
            actual = tool_identity(path) if record.get("kind") == "tool" else identity(path)
        except (LinkError, OSError) as exc:
            changes.append({"path": str(path), "error": str(exc)})
            continue
        if actual != record:
            changes.append({"path": str(path), "before": record, "after": actual})
    return {"checked_file_count": len(inputs), "unchanged": not changes, "changes": changes}


def execute(argv: list[str], *, cwd: Path, env: dict, output: Path, label: str, report: dict) -> dict:
    stdout, stderr = output / f"{label}.stdout", output / f"{label}.stderr"
    item = {"label": label, "argv": argv, "cwd": str(cwd), "status": "running"}
    report["commands"].append(item)
    toolchain.save_json(output / "report.json", report)
    try:
        with stdout.open("xb") as out, stderr.open("xb") as err:
            process = subprocess.run(argv, cwd=cwd, env=env, stdout=out, stderr=err, timeout=600)
        item.update(status="completed", exit_code=process.returncode)
    except (OSError, subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
        item.update(status="failed", error=str(exc))
        raise
    finally:
        for key, path in (("stdout", stdout), ("stderr", stderr)):
            if path.is_file():
                item[key] = identity(path)
                if item.get("exit_code", 1):
                    with path.open("rb") as stream:
                        stream.seek(max(0, path.stat().st_size - 12000))
                        item[key + "_tail"] = stream.read().decode("utf-8", "replace")
        toolchain.save_json(output / "report.json", report)
    return item


def tool_inputs(toolwork: Path, build_report: dict) -> tuple[Path, list[dict], dict]:
    identities = [identity(toolwork / name) for name in ("identity.json", "state.json", "host-tools-state.json")]
    installation, state, host = [json.loads(Path(item["path"]).read_text()) for item in identities]
    require(state.get("status") == "clang_verified" and host.get("status") == "host_tools_built" and
            host.get("combined_toolchain_verified") is True, "combined compiler/host tools are not verified")
    prefix = Path(installation["prefix"]).resolve()
    clang = prefix / "llvm/bin/clang"
    clang_id = tool_identity(clang)
    require(clang_id["sha256"] == CLANG_SHA256 == state["verification"]["compiler"]["sha256"] ==
            build_report["compiler"]["sha256"], "compiler differs from successful kernel build")
    identities.append(clang_id)
    for item in host["outputs"]:
        path = Path(item["path"])
        current = tool_identity(path)
        require(current["sha256"] == item["sha256"], f"host tool changed: {path}")
        identities.append(current)
    # The successful build's generic CPU environment is authoritative, not
    # the older installation report's pre-generic defaults.
    original = build_report["environment"]
    expected = toolchain.toolchain_environment(prefix, Path(build_report["environment"]["UNIXNU_SDKROOT"]))
    for key in ("CROSS_CLANG", "DARWIN_TRIPLE", "CROSS_EXTRA_FLAGS"):
        require(original[key] == expected[key], f"successful build/toolchain environment mismatch: {key}")
    env = {key: value for key, value in original.items() if key in {
        "PATH", "LC_ALL", "ZERO_AR_DATE", "CROSS_CLANG", "CROSS_EXTRA_FLAGS", "DARWIN_TRIPLE",
        "CLT_PREFIX", "XCTOOLCHAIN_PREFIX", "XNU_CLANG_DROP_FLAGS", "UNIXNU_TOOLCHAIN"}}
    require(env.get("CROSS_EXTRA_FLAGS", "").startswith("-mcpu=generic "), "generic CPU selection is missing")
    # The upstream builder passes this value to make, which exports it to ld.
    # ld64 Options.cpp reads RC_ProjectSourceVersion for LC_SOURCE_VERSION;
    # it is not present in the retained command-line-only .LDFLAGS file.
    require(original.get("UNIXNU_XNU_VERSION") == KERNEL_SOURCE_VERSION,
            "successful build source version differs from the fixed XNU baseline")
    env["RC_ProjectSourceVersion"] = original["UNIXNU_XNU_VERSION"]
    env.update(LC_ALL="C", ZERO_AR_DATE="1")
    return prefix, identities, env


def run(args) -> dict:
    kernel, toolwork, platform = args.kernel_dir.resolve(), args.toolchain_work.resolve(), args.platform_report.resolve()
    require(kernel.is_dir() and toolwork.is_dir() and platform.is_file(), "missing kernel/toolchain/platform inputs")
    callback_path = getattr(args, "kernel_callback_report", None)
    if callback_path is not None:
        callback_path = callback_path.resolve()
        require(callback_path.is_file(), "missing kernel callback report")
    output = args.output
    require(not output.is_symlink() and not output.exists(), "output must be unused; retain earlier attempts")
    output = output.resolve()
    # The installation can live outside toolwork. Read its location before
    # creating anything, then require this same identity again under locks.
    installation_hint = identity(toolwork / "identity.json")
    prefix_value = json.loads(Path(installation_hint["path"]).read_text()).get("prefix")
    require(isinstance(prefix_value, str) and Path(prefix_value).is_absolute(), "invalid tool installation prefix")
    prefix_hint = Path(prefix_value).resolve()
    require(prefix_hint.is_dir(), "tool installation prefix is absent")
    protected_roots = [kernel, toolwork, prefix_hint, platform.parent, Path(__file__).resolve().parents[1]]
    if callback_path is not None:
        protected_roots.append(callback_path.parent)
    for protected in protected_roots:
        require(not output.is_relative_to(protected) and not protected.is_relative_to(output), "output overlaps protected inputs")
    output.mkdir(parents=True, exist_ok=False)
    report = {"schema_version": 1, "status": "validating", "scope": SCOPE, "output": str(output),
              "driver": identity(Path(__file__).resolve()), "commands": [], "baseline_reproduced": False,
              "platform_link_compatible": False, "complete_board_archive_closure": False,
              "crypto_provider_selected": False, "pthread_provider_selected": False,
              "kernel_callback_requested": callback_path is not None, "kernel_callback_linked": False,
              "sleep_runtime_verified": False,
              "runtime_driver_matching_verified": False, "full_instruction_set_audited": False,
              "tb371fc_kernel_qualified": False, "os_boot_verified": False}
    toolchain.save_json(output / "report.json", report)
    try:
        with ExitStack() as locks:
            for path in (kernel / ".route-a/build.lock", toolwork / "build.lock", toolwork / "host-tools.lock"):
                handle = locks.enter_context(path.open("rb"))
                try:
                    fcntl.flock(handle, fcntl.LOCK_SH | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise LinkError(f"input build or installation is active: {path}") from exc
            protected_inputs = []
            try:
                verify_identity(installation_hint)
                candidate = kernel / KERNEL_RELATIVE / KERNEL_NAME
                original = pinned(candidate, KERNEL_SHA256)
                noctf = pinned(candidate.with_name(KERNEL_NAME + ".noctf"), KERNEL_SHA256)
                built_id = pinned(kernel / ".route-a/build-report.json", BUILD_REPORT_SHA256)
                protected_inputs.extend((original, noctf, built_id, identity(platform)))
                built = json.loads(Path(built_id["path"]).read_text())
                require(built.get("status") == "builder_completed" and built.get("exit_code") == 0,
                        "generic kernel build is not complete")
                platform_report, components = verify_platform(platform, candidate)
                for component in components:
                    protected_inputs.extend((component["object"], component["archive"], component["symbol_report"]))
                prefix, tools, env = tool_inputs(toolwork, built)
                require(prefix == prefix_hint, "tool installation prefix changed after output validation")
                require(not output.is_relative_to(prefix) and not prefix.is_relative_to(output), "output overlaps tool installation")
                (output / "tmp").mkdir()
                env["TMPDIR"] = str(output / "tmp")
                protected_inputs.extend(tools)
                callback = None
                if callback_path is not None:
                    callback, callback_inputs = verify_callback(callback_path, candidate, kernel, prefix)
                    protected_inputs.extend(callback_inputs)
                    report["kernel_callback"] = callback["evidence"]
                recipe, linked_inputs = recover_recipe(kernel, prefix)
                protected_inputs.extend(linked_inputs)
                # Deduplicate identical identities without omitting any path.
                unique = {}
                for item in protected_inputs:
                    require(item["path"] not in unique or unique[item["path"]] == item, "input changed during preflight")
                    unique[item["path"]] = item
                protected_inputs = list(unique.values())
                inputs_dir = output / "inputs"
                inputs_dir.mkdir()
                toolchain.save_json(inputs_dir / "protected-inputs.json", protected_inputs)
                toolchain.save_json(inputs_dir / "link-reconstruction.json", recipe)
                filelist = inputs_dir / "link.filelist"
                filelist.write_bytes(Path(recipe["filelist"]).read_bytes())
                report.update(source_provenance=identity(inputs_dir / "link-reconstruction.json"),
                              protected_input_inventory=identity(inputs_dir / "protected-inputs.json"),
                              original_kernel=original, platform_report=identity(platform), environment=env,
                              linked_original_object_count=recipe["linked_object_count"])
                kernel_metadata = macho(candidate.read_bytes(), 2)
                closure = symbol_closure(callback_kernel_symbols(kernel_metadata, callback), components)
                if callback is not None:
                    closure["cpu_replacement"] = {
                        "original_object": callback["evidence"]["original_object"],
                        "replacement_object": callback["evidence"]["replacement_object"],
                        "original_strong_definition_names_removed": sorted(
                            s["name"] for s in callback["original_macho"]["symbols"]["defined_external"]
                            if not (s["n_desc"] & 0x80)),
                        "weak_definition_winner_inferred": False}
                toolchain.save_json(output / "symbol-closure.json", closure)
                report["symbol_closure"] = identity(output / "symbol-closure.json")
                require(not closure["duplicate_strong_definitions"], "duplicate strong platform/kernel definitions")
                # A new reference can legitimately extract a previously unused
                # member of a baseline archive. Keep the name-set observation;
                # only the real link can establish that resolution succeeds.
                # ld64 computeContentUUID hashes the output leaf (including
                # its preceding slash). Preserve that input in a new directory.
                baseline = output / (KERNEL_NAME + ".noctf")
                baseline_map = output / "baseline.map"
                report["status"] = "replaying_baseline"
                result = execute(link_command(recipe, filelist, baseline, baseline_map), cwd=Path(recipe["cwd"]),
                                 env=env, output=output, label="baseline-link", report=report)
                require(result["exit_code"] == 0 and baseline.is_file(), "baseline replay linker failed; platform link not attempted")
                report["baseline"] = identity(baseline)
                require(report["baseline"]["sha256"] == KERNEL_SHA256,
                        "baseline replay differs byte-for-byte from the successful kernel; platform link not attempted")
                report["baseline_reproduced"] = True
                require(check_unchanged(protected_inputs)["unchanged"], "inputs changed during baseline replay")
                platform_filelist = filelist
                if callback is not None:
                    platform_filelist = inputs_dir / "platform-link.filelist"
                    report["kernel_callback"]["filelist_replacement"] = replace_cpu_filelist(
                        recipe, filelist, platform_filelist, callback)
                destination = output / "mach.platform-link-probe.unstripped.noctf"
                mapfile = output / "platform.map"
                report["status"] = "linking_platform"
                result = execute(link_command(recipe, platform_filelist, destination, mapfile, components), cwd=Path(recipe["cwd"]),
                                 env=env, output=output, label="platform-link", report=report)
                require(result["exit_code"] == 0 and destination.is_file(), "platform compatibility link failed")
                data = destination.read_bytes()
                linked = macho(data, 2)
                require(not linked["symbols"]["strong_undefined"] and not linked["symbols"]["common_external"],
                        "linked image retains strong undefined/common symbols")
                members = verify_link_map(mapfile.read_text(), components, linked, data)
                if callback is not None:
                    report["kernel_callback"]["actual_member_evidence"] = verify_callback_link_map(
                        mapfile.read_text(), callback, linked)
                    report["kernel_callback_linked"] = True
                report.update(status="platform_link_compatible", platform_link_compatible=True,
                              candidate={**identity(destination), "load_contract": linked["load_contract"],
                                         "entry": linked["entry"], "file_type": linked["file_type"],
                                         "cpu_subtype": linked["cpu_subtype"],
                                         "build_version": linked["build_version"],
                                         "strong_undefined": linked["symbols"]["strong_undefined"],
                                         "weak_undefined": linked["symbols"]["weak_undefined"]},
                              link_map=identity(mapfile), actual_member_evidence=members)
            finally:
                recheck = check_unchanged(protected_inputs)
                report["protected_inputs_recheck"] = recheck
                if not recheck["unchanged"]:
                    report["platform_link_compatible"] = False
                    report["kernel_callback_linked"] = False
                    raise LinkError("protected inputs changed during the compatibility experiment")
    except (LinkError, OSError, ValueError, KeyError, TypeError, struct.error, subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
        report.update(failed_stage=report["status"], status="failed", error=str(exc), error_type=type(exc).__name__)
        report["platform_link_compatible"] = False
        report["kernel_callback_linked"] = False
    finally:
        report["finished_at_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        toolchain.save_json(output / "report.json", report)
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-dir", type=Path, required=True)
    parser.add_argument("--toolchain-work", type=Path, required=True)
    parser.add_argument("--platform-report", type=Path, required=True)
    parser.add_argument("--kernel-callback-report", type=Path,
                        help="optional independent, source-bound cpu.o callback replacement report")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = run(args)
    except (LinkError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"status": report["status"], "report": str(Path(report["output"]) / "report.json"),
                      "error": report.get("error")}, indent=2))
    return 0 if report["status"] == "platform_link_compatible" else 2


if __name__ == "__main__":
    raise SystemExit(main())
