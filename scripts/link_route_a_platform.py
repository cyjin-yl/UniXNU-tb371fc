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


def verify_link_map(text: str, components: list[dict], linked: dict, data: bytes) -> dict:
    """Require actual member allocation and its initialization in the new image."""
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
            actual = identity(path)
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
    clang_id = identity(clang.resolve())
    require(clang_id["sha256"] == CLANG_SHA256 == state["verification"]["compiler"]["sha256"] ==
            build_report["compiler"]["sha256"], "compiler differs from successful kernel build")
    identities.append(clang_id)
    for item in host["outputs"]:
        path = Path(item["path"])
        require(toolchain.sha256_file(path) == item["sha256"], f"host tool changed: {path}")
        identities.append(identity(path.resolve()))
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
    env.update(LC_ALL="C", ZERO_AR_DATE="1")
    return prefix, identities, env


def run(args) -> dict:
    kernel, toolwork, platform = args.kernel_dir.resolve(), args.toolchain_work.resolve(), args.platform_report.resolve()
    require(kernel.is_dir() and toolwork.is_dir() and platform.is_file(), "missing kernel/toolchain/platform inputs")
    output = args.output
    require(not output.is_symlink() and not output.exists(), "output must be unused; retain earlier attempts")
    output = output.resolve()
    for protected in (kernel, toolwork, platform.parent, Path(__file__).resolve().parents[1]):
        require(not output.is_relative_to(protected) and not protected.is_relative_to(output), "output overlaps protected inputs")
    output.mkdir(parents=True, exist_ok=False)
    report = {"schema_version": 1, "status": "validating", "scope": SCOPE, "output": str(output),
              "driver": identity(Path(__file__).resolve()), "commands": [], "baseline_reproduced": False,
              "platform_link_compatible": False, "complete_board_archive_closure": False,
              "crypto_provider_selected": False, "pthread_provider_selected": False,
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
                require(not output.is_relative_to(prefix) and not prefix.is_relative_to(output), "output overlaps tool installation")
                (output / "tmp").mkdir()
                env["TMPDIR"] = str(output / "tmp")
                protected_inputs.extend(tools)
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
                closure = symbol_closure([{"name": "original generic kernel", "macho": kernel_metadata}], components)
                toolchain.save_json(output / "symbol-closure.json", closure)
                report["symbol_closure"] = identity(output / "symbol-closure.json")
                require(not closure["duplicate_strong_definitions"], "duplicate strong platform/kernel definitions")
                # A new reference can legitimately extract a previously unused
                # member of a baseline archive. Keep the name-set observation;
                # only the real link can establish that resolution succeeds.
                baseline = output / "baseline.unstripped.noctf"
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
                destination = output / "mach.platform-link-probe.unstripped.noctf"
                mapfile = output / "platform.map"
                report["status"] = "linking_platform"
                result = execute(link_command(recipe, filelist, destination, mapfile, components), cwd=Path(recipe["cwd"]),
                                 env=env, output=output, label="platform-link", report=report)
                require(result["exit_code"] == 0 and destination.is_file(), "platform compatibility link failed")
                data = destination.read_bytes()
                linked = macho(data, 2)
                require(not linked["symbols"]["strong_undefined"] and not linked["symbols"]["common_external"],
                        "linked image retains strong undefined/common symbols")
                members = verify_link_map(mapfile.read_text(), components, linked, data)
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
                    raise LinkError("protected inputs changed during the compatibility experiment")
    except (LinkError, OSError, ValueError, KeyError, TypeError, struct.error, subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
        report.update(failed_stage=report["status"], status="failed", error=str(exc), error_type=type(exc).__name__)
        report["platform_link_compatible"] = False
    finally:
        report["finished_at_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        toolchain.save_json(output / "report.json", report)
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-dir", type=Path, required=True)
    parser.add_argument("--toolchain-work", type=Path, required=True)
    parser.add_argument("--platform-report", type=Path, required=True)
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
