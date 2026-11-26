"""Bind the explicit syscall-38 fixture model to compiled XNU artifacts.

The actual table entry and its complete 24-byte target are checked. This does
not execute XNU's exception entry, MAC filters or error-return path.
"""
from __future__ import annotations

import json
from pathlib import Path
import struct

from audit_route_a_nontpro import file_identity, load_commands, require, sha256

CROSSARCH_WORDS = (0xb9400029, 0x528002c8, 0x7100013f, 0x528005a9, 0x1a880120, 0xd65f03c0)
SOURCE_PINS = {
    "bsd/sys/sysent.h": "715e6d3de51faeed3edf30db6b872b8b2716b0c676fd1a7faf0bbfd2a980f07c",
    "bsd/kern/syscalls.master": "0e22c8fa035bcdbd826e64afd9bf0bb85c4d2a6e8e43e503f278fdc5aab668d2",
    "bsd/kern/kern_crossarch.c": "07bfe90e3036a36bb0dcfb978dc0f11b218981b7a67d4834ac150b2f5c271a91",
    "bsd/dev/arm/systemcalls.c": "7eb44232e6da37c8e6f5d2317ed5cf1d55d02032410b0ddf7007e4ca7b495df4",
    "osfmk/arm64/sleh.c": "4eeb208fb2510bfdc0338d1a1d7d2d702fe9eb65d332eea388720ef6574375d1",
    "osfmk/mach/arm/thread_status.h": "60434026c659eebe0137ad2dd6536637e7330cf355958f580afe95bc34a82e95",
    "osfmk/arm64/proc_reg.h": "5bdb14d2cc33dfa5d771f81794dea0a961801331be519904c02fdc6141f57ab5",
    "bsd/sys/errno.h": "b16e5eb195f153793b14c3826e6b04db945e9ed6a37c5a9046196555bded6906",
}


class SelectedMachO:
    """Bounded seek reader for selected ordinary-arm64 N_SECT symbols.

    It deliberately does not claim whole Mach-O validation or a full ISA scan.
    """
    def __init__(self, path, required, file_type):
        self.path = Path(path)
        self.file_type = file_type
        self.identity = file_identity(self.path)
        self.length = self.identity["size"]
        require(32 <= self.length <= 1 << 30, "unsupported Mach-O input size")
        header = self.read(0, 32)
        magic, cpu, subtype, kind, count, size, _, reserved = struct.unpack("<8I", header)
        require((magic, cpu, subtype, kind, reserved) == (0xfeedfacf, 0x100000c, 0, file_type, 0),
                "expected plain ARM64 Mach-O of the requested kind")
        require(8 <= size <= 1 << 20, "unbounded load-command block")
        raw = header + self.read(32, size)
        self.sections, self.segments, symtab = [], [], []
        for command, at, length in load_commands(raw):
            if command == 0x19:
                require(length >= 72, "short segment command")
                name = raw[at + 8:at + 24].split(b"\0", 1)[0].decode("ascii")
                address, vm_size, offset, file_size, maxprot, initprot, nsects, flags = struct.unpack_from("<4Q4I", raw, at + 24)
                require(length == 72 + 80 * nsects and address + vm_size <= 1 << 64 and
                        offset + file_size <= self.length and initprot & ~maxprot == 0,
                        "invalid selected-image segment geometry")
                require(file_type != 2 or file_size <= vm_size, "linked file extent exceeds virtual segment")
                segment = {"name": name, "address": address, "vm_size": vm_size,
                           "offset": offset, "file_size": file_size, "initprot": initprot}
                self.segments.append(segment)
                for i in range(nsects):
                    values = struct.unpack_from("<16s16sQQ8I", raw, at + 72 + i * 80)
                    section_name, owner_name = [v.split(b"\0", 1)[0].decode("ascii") for v in values[:2]]
                    va, size, off, align, reloc, nreloc, sec_flags = values[2:9]
                    zero = sec_flags & 0xff in (1, 0xc, 0x12)
                    require(address <= va <= address + vm_size and size <= address + vm_size - va,
                            "section leaves declared segment")
                    require(zero or off + size <= self.length, "file-backed section leaves input")
                    if file_type == 2:
                        require(owner_name == name, "linked section names the wrong segment")
                        if not zero:
                            require(offset <= off <= offset + file_size and size <= offset + file_size - off and
                                    va + size <= address + file_size and off == offset + va - address,
                                    "linked section does not match its loaded segment mapping")
                    require(reloc + nreloc * 8 <= self.length, "section relocations leave input")
                    self.sections.append({"segment": owner_name, "name": section_name, "address": va,
                                          "size": size, "offset": off, "flags": sec_flags, "zero": zero,
                                          "reloff": reloc, "nreloc": nreloc, "owner": segment})
            elif command == 2:
                require(length == 24, "bad LC_SYMTAB length")
                symtab.append(struct.unpack_from("<4I", raw, at + 8))
        if file_type == 2:
            intervals = sorted((s["address"], s["address"] + s["vm_size"])
                               for s in self.segments if s["vm_size"])
            require(all(a[1] <= b[0] for a, b in zip(intervals, intervals[1:])),
                    "linked virtual segments overlap")
        require(len(symtab) == 1 and self.sections, "missing or duplicate symbol metadata")
        offset, count, strings, length = symtab[0]
        require(count <= 1 << 20 and length <= 16 << 20, "symbol metadata exceeds bound")
        self.names = self.read(strings, length)
        self.rows = self.read(offset, count * 16)
        self.symbols = {}
        wanted = {name.encode("ascii") for name in required}
        for i in range(count):
            string, typ, section, desc, value = struct.unpack_from("<IBBHQ", self.rows, i * 16)
            require(string < length, "bad nlist string offset")
            end = self.names.find(b"\0", string)
            require(end >= string, "unterminated nlist name")
            name = self.names[string:end]
            if name not in wanted or typ & 0xe0 or typ & 0x0e != 0x0e:
                continue
            text = name.decode("ascii")
            require(text not in self.symbols and 1 <= section <= len(self.sections) and not desc & 0xc0,
                    "ambiguous, weak or invalid selected N_SECT symbol")
            owner = self.sections[section - 1]
            require(owner["address"] <= value < owner["address"] + owner["size"], "selected symbol leaves section")
            self.symbols[text] = {"name": text, "value": value, "section": section, "index": i}
        require(set(self.symbols) == set(required), "required compiled symbol missing")

    def read(self, offset, size):
        require(type(offset) is int and type(size) is int and 0 <= offset <= self.length and
                0 <= size <= self.length - offset and size <= 32 << 20, "unbounded file read")
        with self.path.open("rb") as stream:
            stream.seek(offset)
            result = stream.read(size)
        require(len(result) == size, "input truncated during selected read")
        return result

    def symbol_data(self, name, size, displacement=0, executable=False):
        symbol = self.symbols[name]
        section = self.sections[symbol["section"] - 1]
        address = symbol["value"] + displacement
        require(displacement >= 0 and size > 0 and not section["zero"] and
                section["address"] <= address and address + size <= section["address"] + section["size"],
                "selected symbol bytes leave their file-backed section")
        if executable:
            require(section["flags"] & 0x80000000 and address % 4 == 0 and size % 4 == 0,
                    "selected function is not complete aligned pure instructions")
            require(self.file_type != 2 or section["owner"]["initprot"] & 4,
                    "selected linked function is not executable")
        return self.read(section["offset"] + address - section["address"], size)

    def relocation_symbol(self, name, displacement):
        symbol = self.symbols[name]
        section = self.sections[symbol["section"] - 1]
        wanted = symbol["value"] - section["address"] + displacement
        matches = []
        records = self.read(section["reloff"], section["nreloc"] * 8)
        for i in range(section["nreloc"]):
            address, bits = struct.unpack_from("<II", records, i * 8)
            require(not address & 0x80000000, "scattered ARM64 object relocation unsupported")
            length = 1 << ((bits >> 25) & 3)
            if address < wanted + 8 and wanted < address + length:
                require(address == wanted and length == 8 and bits >> 28 == 0 and
                        bits & (1 << 27) and not bits & (1 << 24), "wrong selected pointer relocation")
                index = bits & 0xffffff
                require(index * 16 + 16 <= len(self.rows), "relocation nlist index out of bounds")
                name_offset = struct.unpack_from("<I", self.rows, index * 16)[0]
                end = self.names.find(b"\0", name_offset)
                require(name_offset < len(self.names) and end >= name_offset, "bad relocation target name")
                matches.append(self.names[name_offset:end].decode("ascii"))
        require(len(matches) == 1, "missing or overlapping selected pointer relocation")
        require(self.symbol_data(name, 8, displacement) == bytes(8), "selected pointer has a nonzero addend")
        return matches[0]

    def recheck(self):
        return file_identity(self.path) == self.identity


def compiler_recipe(path):
    raw = Path(path).read_bytes()
    text = raw.decode("utf-8")
    record, end = json.JSONDecoder().raw_decode(text)
    require(text[end:].strip() in ("", ","), "unexpected clang -MJ trailing data")
    require(isinstance(record, dict) and isinstance(record.get("arguments"), list) and
            all(isinstance(a, str) for a in record["arguments"]) and
            isinstance(record.get("file"), str) and isinstance(record.get("directory"), str),
            "invalid compiler recipe")
    source = Path(record["file"])
    if not source.is_absolute():
        source = Path(record["directory"]) / source
    definitions = {}
    arguments = record["arguments"]
    i = 0
    while i < len(arguments):
        argument = arguments[i]
        i += 1
        if argument in ("-D", "-U"):
            require(i < len(arguments), "missing compiler macro argument")
            definition = arguments[i]
            i += 1
        elif argument.startswith(("-D", "-U")):
            definition = argument[2:]
        else:
            continue
        require(definition and not definition.startswith("-") and chr(0) not in definition,
                "invalid compiler macro argument")
        key, separator, value = definition.partition("=")
        if argument.startswith("-U"):
            require(not separator, "invalid compiler macro undefinition")
            definitions.pop(key, None)
        else:
            require(key not in definitions or definitions[key] == (value if separator else "1"),
                    "contradictory macro definitions")
            definitions[key] = value if separator else "1"
    return {"identity": file_identity(path), "source_path": str(source),
            "source": file_identity(source), "definitions": definitions}


def compiled_sysent_layout(obj):
    count = struct.unpack("<I", obj.symbol_data("_nsysent", 4))[0]
    symbol = obj.symbols["_sysent"]
    section = obj.sections[symbol["section"] - 1]
    require(symbol["value"] == section["address"] and count > 38, "unexpected object sysent extent")
    require(section["size"] == count * 24, "compiled sysent layout is not the declared 24-byte layout")
    return count, 24


def bind_syscall38(kernel, objects, prepared, filelist):
    objects, prepared, filelist = Path(objects), Path(prepared), Path(filelist)
    source_identities = {}
    for name, expected in SOURCE_PINS.items():
        path = prepared / name
        record = file_identity(path)
        require(record["sha256"] == expected, "source contract changed: " + name)
        source_identities[str(path)] = record
    object_paths = {name: objects / (name + ".o") for name in ("init_sysent", "kern_crossarch", "systemcalls")}
    tracked = dict(source_identities)
    tracked[str(filelist)] = file_identity(filelist)
    tracked.update({str(path): file_identity(path) for path in object_paths.values()})
    lines = filelist.read_text().splitlines()
    for path in object_paths.values():
        require(lines.count(str(path)) == 1, "compiled object is not unique in declared link filelist")
    recipes = {name: compiler_recipe(str(path) + ".json") for name, path in object_paths.items()}
    for name, record in recipes.items():
        tracked[str(object_paths[name]) + ".json"] = record["identity"]
        tracked[record["source_path"]] = record["source"]
    require(recipes["init_sysent"]["definitions"].get("CONFIG_REQUIRES_U32_MUNGING") == "1",
            "sysent compile configuration does not declare U32 munging")
    require(recipes["kern_crossarch"]["source"]["sha256"] == SOURCE_PINS["bsd/kern/kern_crossarch.c"] and
            recipes["systemcalls"]["source"]["sha256"] == SOURCE_PINS["bsd/dev/arm/systemcalls.c"],
            "compiler source identity differs from contract")
    generated = Path(recipes["init_sysent"]["source_path"]).read_text()
    require("/* 38 = sys_crossarch_trap */" in generated, "generated syscall table lacks crossarch slot")
    table_obj = SelectedMachO(object_paths["init_sysent"], ("_sysent", "_nsysent"), 1)
    call_obj = SelectedMachO(object_paths["kern_crossarch"], ("_sys_crossarch_trap",), 1)
    require(table_obj.identity == tracked[str(table_obj.path)] and call_obj.identity == tracked[str(call_obj.path)],
            "compiled object changed before selected-symbol analysis")
    count, stride = compiled_sysent_layout(table_obj)
    obj_entry = table_obj.symbol_data("_sysent", stride, 38 * stride)
    require(table_obj.relocation_symbol("_sysent", 38 * stride) == "_sys_crossarch_trap",
            "object syscall-38 pointer targets a different function")
    require(table_obj.relocation_symbol("_sysent", 38 * stride + 8) == "_munge_w",
            "object syscall-38 munger targets a different function")
    require(struct.unpack_from("<ihH", obj_entry, 16) == (1, 1, 4), "object syscall-38 ABI fields changed")
    object_body = call_obj.symbol_data("_sys_crossarch_trap", 24, executable=True)
    require(struct.unpack("<6I", object_body) == CROSSARCH_WORDS, "compiled crossarch function changed")
    call_section = call_obj.sections[call_obj.symbols["_sys_crossarch_trap"]["section"] - 1]
    require(call_section["size"] == 24, "crossarch object text is not the complete checked function")
    linked = SelectedMachO(kernel, ("_sysent", "_nsysent", "_sys_crossarch_trap", "_munge_w"), 2)
    tracked[str(linked.path)] = linked.identity
    require(struct.unpack("<I", linked.symbol_data("_nsysent", 4))[0] == count, "linked syscall count changed")
    entry = linked.symbol_data("_sysent", stride, 38 * stride)
    call, munger, return_type, nargs, arg_bytes = struct.unpack("<QQihH", entry)
    require(call == linked.symbols["_sys_crossarch_trap"]["value"] and
            munger == linked.symbols["_munge_w"]["value"] and entry[16:] == obj_entry[16:],
            "final syscall-38 table differs from its compiled object")
    target_section = linked.sections[linked.symbols["_sys_crossarch_trap"]["section"] - 1]
    require(target_section["owner"]["initprot"] & 4, "final crossarch target is not executable")
    body = linked.symbol_data("_sys_crossarch_trap", 24, executable=True)
    require(body == object_body, "final crossarch instructions differ from compiled function")
    checks = {p: file_identity(p) == value for p, value in tracked.items()}
    require(all(checks.values()), "syscall binding input changed while reading")
    return {"schema": "route-a-syscall38-binding-v1", "kernel": linked.identity,
            "sources": source_identities, "recipes": recipes,
            "objects": {name: tracked[str(path)] for name, path in object_paths.items()},
            "inputs": tracked,
            "link_filelist": tracked[str(filelist)], "compiled_sysent_count": count,
            "compiled_sysent_stride": stride,
            "table": {"address": hex(linked.symbols["_sysent"]["value"] + 38 * stride),
                      "raw_hex": entry.hex(), "function": hex(call), "munger": hex(munger),
                      "return_type": return_type, "argument_count": nargs, "argument_bytes32": arg_bytes},
            "function": {"symbol": "_sys_crossarch_trap", "address": hex(call),
                         "bytes": len(body), "sha256": sha256(body),
                         "namespace_zero_return": 45, "other_namespace_return": 22,
                         "contains_memory_store": False},
            "syscall38_static_target_verified": True, "input_recheck": checks,
            "explicit_debug_syscall_rejection_define": recipes["systemcalls"]["definitions"].get(
                "CONFIG_DEBUG_SYSCALL_REJECTION"),
            "dispatch_conditions": ["64-bit direct positive-X16 syscall",
                                    "normal process/thread syscall filter permits the call",
                                    "no debugger/DTrace table replacement",
                                    "valid user and saved-state buffers"],
            "actual_xnu_dispatch_verified": False, "error_return_machine_path_verified": False,
            "runtime_filter_state_verified": False}


def main():
    import argparse
    import sys
    from audit_route_a_nontpro import AuditError
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--objects", type=Path, required=True)
    parser.add_argument("--prepared", type=Path, required=True)
    parser.add_argument("--filelist", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    require(not args.report.exists(), "refusing to overwrite a binding report")
    try:
        report = bind_syscall38(args.kernel, args.objects, args.prepared, args.filelist)
        status = 0
    except (AuditError, OSError, ValueError) as error:
        report = {"schema": "route-a-syscall38-binding-v1", "syscall38_static_target_verified": False,
                  "actual_xnu_dispatch_verified": False, "error": {"type": type(error).__name__, "message": str(error)}}
        status = 2
    report["tool"] = file_identity(__file__)
    with args.report.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"report": str(args.report), "syscall38_static_target_verified":
                      report["syscall38_static_target_verified"], "actual_xnu_dispatch_verified": False}))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
