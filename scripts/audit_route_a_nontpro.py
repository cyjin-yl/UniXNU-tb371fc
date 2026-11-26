#!/usr/bin/env python3
"""Exact-input startup and hazard ledger for the 24A446 dyld pair.

The ledger covers every candidate TCHANGE and tracked Apple register access.
Enumeration, byte equality and the finite EL0 fixture are separate evidence.
An unresolved incoming edge, state writer or callee never becomes a proof.
"""
from __future__ import annotations

import argparse
import bisect
from collections import Counter
import hashlib
import json
from pathlib import Path
import stat
import struct
import sys

from arm64_lowering.macho import parse_macho
from arm64_lowering.pipeline import verify_code_pages
from audit_route_a_tpro import (AuditError, SOURCE_BYTES, SOURCE_SHA256,
                               TRACKED_REGISTERS, direct_branch,
                               system_register, read_at_va)

CACHE_MAIN_SHA256 = "1b4343ca04f08d0ad7e532c8a2f7e1af2b65ada4c92ccfeb14a7c021e2c2a7d4"
CACHE_TEXT_MEMBER_SHA256 = "6333aab2afec45e47dd2bda796b65d7047c72e835f4af75c223a2666120ce004"
DYLD_UUID = "d3f59b02ee07371bb0913f150a078ed8"
TRANSITIONS = {0xd5900040: "tchangef", 0xd5940000: "tchangeb"}
FRAGMENTS = {
    "entry": (0x5a90, 0x5aa4),
    "apple_vector": (0x6e38, 0x6e78),
    "apple_lookup": (0x6e78, 0x6f20),
    "memory_manager_constructor": (0x713c, 0x7208),
    "default_tpro_stack": (0x21264, 0x212f0),
    "protected_stack_constructor": (0x3cb2c, 0x3cb68),
    "crossarch_wrapper": (0xa99c, 0xa9d0),
    "crossarch_stub": (0xa9d0, 0xa9dc),
}
MAX_U64 = (1 << 64) - 1


def require(condition, message):
    if not condition:
        raise AuditError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def file_identity(path):
    path = Path(path)
    before = path.stat()
    require(stat.S_ISREG(before.st_mode), "input is not a regular file")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    after = path.stat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            "input changed while hashing")
    return {"name": path.name, "size": after.st_size, "sha256": digest.hexdigest()}


def load_commands(data):
    require(len(data) >= 32, "short Mach-O header")
    count, size = struct.unpack_from("<II", data, 16)
    require(count <= size // 8 and 32 + size <= len(data), "bad command bounds")
    at, end, result = 32, 32 + size, []
    for _ in range(count):
        require(at + 8 <= end, "truncated command")
        command, length = struct.unpack_from("<II", data, at)
        require(length >= 8 and length % 8 == 0 and at + length <= end, "bad command size")
        result.append((command, at, length))
        at += length
    require(at == end, "unconsumed command bytes")
    return result


def command_uuid(data):
    values = [data[a + 8:a + 24].hex() for c, a, n in load_commands(data) if c == 0x1b and n == 24]
    require(len(values) == 1, "missing or duplicate LC_UUID")
    return values[0]


def unixthread_entry(data):
    values = []
    for command, at, length in load_commands(data):
        if command == 5:
            require(length == 288, "unexpected LC_UNIXTHREAD length")
            flavor, count = struct.unpack_from("<II", data, at + 8)
            require((flavor, count) == (6, 68), "unexpected ARM_THREAD_STATE64")
            values.append(struct.unpack_from("<Q", data, at + 16 + 32 * 8)[0])
    require(len(values) == 1, "missing or duplicate LC_UNIXTHREAD")
    return values[0]


def symbols(data, image):
    commands = [(a, n) for c, a, n in load_commands(data) if c == 2]
    require(len(commands) == 1 and commands[0][1] == 24, "unsupported LC_SYMTAB")
    offset, count, strings, length = struct.unpack_from("<4I", data, commands[0][0] + 8)
    require(offset + count * 16 <= len(data) and strings + length <= len(data),
            "symbol table leaves input")
    result = []
    for i in range(count):
        name, kind, section, description, address = struct.unpack_from("<IBBHQ", data, offset + 16 * i)
        require(name < length, "bad symbol string offset")
        end = data.find(b"\0", strings + name, strings + length)
        require(end >= 0, "unterminated symbol name")
        if kind & 0xe0 or kind & 0x0e != 0x0e:
            continue
        require(1 <= section <= len(image.sections), "bad N_SECT ordinal")
        owner = image.sections[section - 1]
        require(owner.addr <= address <= owner.addr + owner.size, "symbol leaves section")
        result.append({"name": data[strings + name:end].decode("utf-8"),
                       "address": address, "section": section, "description": description})
    return result


def function_starts(data, image):
    commands = [(a, n) for c, a, n in load_commands(data) if c == 0x26]
    require(len(commands) == 1 and commands[0][1] == 16, "unsupported LC_FUNCTION_STARTS")
    offset, length = struct.unpack_from("<II", data, commands[0][0] + 8)
    require(offset + length <= len(data), "function starts leave input")
    address = next(s.vmaddr for s in image.segments if s.name == "__TEXT")
    result, at, limit, terminated = [], offset, offset + length, False
    while at < limit:
        value, shift = 0, 0
        while True:
            require(at < limit and shift <= 63, "truncated or overflowing function-start ULEB")
            byte = data[at]
            at += 1
            require(shift < 63 or byte <= 1, "overflowing function-start ULEB")
            value |= (byte & 0x7f) << shift
            if byte < 0x80:
                break
            shift += 7
        if value == 0:
            terminated = True
            break
        require(address + value <= MAX_U64, "function address overflow")
        address += value
        require(address % 4 == 0, "unaligned function start")
        require(any(r.vmaddr <= address < r.vmaddr + r.size for r in image.candidate_ranges),
                "function start is outside instruction candidates")
        result.append(address)
    require(terminated and not any(data[at:limit]), "missing terminator or nonzero function-start padding")
    require(result and len(set(result)) == len(result), "empty or duplicate function starts")
    return result


def section_coordinate(sections, address, size=1):
    """A unique (segment, section, offset), never a nearest-symbol guess."""
    require(type(address) is int and type(size) is int and size > 0 and
            0 <= address <= MAX_U64 and size <= MAX_U64 + 1 - address,
            "invalid section read interval")
    matches = []
    for section in sections:
        if isinstance(section, dict):
            segment, name, begin, length = (section[k] for k in ("segment", "name", "addr", "size"))
        else:
            segment, name, begin, length = section.segment, section.name, section.addr, section.size
        if begin <= address and address + size <= begin + length:
            matches.append((segment, name, address - begin))
    require(len(matches) == 1, "address does not belong to exactly one section")
    return matches[0]


def adrp_store_target(words, address):
    """Decode exactly ADRP X8; STR X19,[X8,#scaled-imm12]."""
    page, store = words
    require(page & 0x9f00001f == 0x90000008 and store & 0xffc003ff == 0xf9000113,
            "global-store instruction shape changed")
    immediate = ((page >> 5) & 0x7ffff) << 2 | ((page >> 29) & 3)
    if immediate & (1 << 20):
        immediate -= 1 << 21
    target = (address & ~4095) + (immediate << 12) + ((store >> 10) & 4095) * 8
    require(0 <= target <= MAX_U64 - 7, "global-store target overflows")
    return target


class Standalone:
    def __init__(self, path):
        self.path = Path(path)
        self.identity = file_identity(self.path)
        require((self.identity["size"], self.identity["sha256"]) == (SOURCE_BYTES, SOURCE_SHA256),
                "this audit only accepts the pinned original 24A446 standalone dyld")
        self.data = self.path.read_bytes()
        require(sha256(self.data) == SOURCE_SHA256, "standalone changed after hashing")
        self.image = parse_macho(self.data)
        require(not self.image.blockers, "blocked Mach-O: " + "; ".join(self.image.blockers))
        require(self.image.code_signature is not None, "standalone has no code signature")
        self.code_pages = verify_code_pages(self.data, self.image.code_signature)
        require(command_uuid(self.data) == DYLD_UUID, "standalone UUID changed")
        self.entry = unixthread_entry(self.data)
        require(self.entry == FRAGMENTS["entry"][0], "unexpected dyld entry")
        self.symbols = symbols(self.data, self.image)
        self.starts = function_starts(self.data, self.image)
        ranges = sorted((r.vmaddr, r.vmaddr + r.size) for r in self.image.candidate_ranges)
        require(all(a[1] <= b[0] for a, b in zip(ranges, ranges[1:])), "duplicate candidate address range")
        self.text = next(s for s in self.image.sections if s.segment == "__TEXT" and s.name == "__text")
        require(self.text.addr == 0x1000 and self.text.size == 650660, "unexpected __text geometry")

    def read(self, address, size):
        return read_at_va(self.data, self.image, address, size)

    def iter_words(self):
        for region in self.image.candidate_ranges:
            for displacement in range(0, region.size, 4):
                yield region.vmaddr + displacement, struct.unpack_from(
                    "<I", self.data, region.offset + displacement)[0]

    def flat_image(self):
        """A private fixture load image. Original instruction bytes are preserved."""
        allocated = [s for s in self.image.segments if s.name != "__LINKEDIT" and s.vmsize]
        require(all(s.vmaddr < 2 << 20 and s.vmaddr + s.vmsize <= 2 << 20 for s in allocated),
                "unexpected fixture load extent")
        result = bytearray(max(s.vmaddr + s.vmsize for s in allocated))
        for s in allocated:
            require(s.filesize <= s.vmsize, "file-backed extent exceeds VM extent")
            result[s.vmaddr:s.vmaddr + s.filesize] = self.data[s.fileoff:s.fileoff + s.filesize]
        return bytes(result)

    def recheck(self):
        return file_identity(self.path) == self.identity


class Cached:
    def __init__(self, main, standalone):
        from route_a_zeta.zeta_dyld_cache import Cache, Image
        self.main = Path(main)
        self.identities = {str(self.main): file_identity(self.main)}
        require(self.identities[str(self.main)]["sha256"] == CACHE_MAIN_SHA256, "unknown cache main input")
        self.cache = Cache(self.main)
        selected = [(i, address, name) for i, (address, name) in enumerate(self.cache.images)
                    if name == "/usr/lib/dyld"]
        require(len(selected) == 1, "cache must contain exactly one /usr/lib/dyld")
        self.index, self.base, name = selected[0]
        self.image = Image(self.cache, self.base, name)
        header = self.cache.read(self.base, 32)
        commands_size = struct.unpack_from("<I", header, 20)[0]
        require(commands_size <= 1 << 20, "oversized cached Mach-O commands")
        self.header = self.cache.read(self.base, 32 + commands_size)
        require(command_uuid(self.header) == DYLD_UUID, "cached dyld UUID mismatch")
        text = [s for s in self.image.instruction_sections() if s["segment"] == "__TEXT" and s["name"] == "__text"]
        require(len(text) == 1, "unexpected cached instruction sections")
        self.text = text[0]
        require(self.text["addr"] - self.base == standalone.text.addr and
                self.text["size"] == standalone.text.size, "cached text geometry differs")
        member = self.cache.files[self.text["file"]].path
        self.identities[str(member)] = file_identity(member)
        require(self.identities[str(member)]["sha256"] == CACHE_TEXT_MEMBER_SHA256,
                "unknown cached dyld code member")
        self.bytes = self.cache.read(self.text["addr"], self.text["size"])

    def read_relative(self, address, length):
        require(0 <= address <= MAX_U64 - self.base, "cached relative address overflows")
        return self.cache.read(self.base + address, length)

    def recheck(self):
        return all(file_identity(p) == record for p, record in self.identities.items())


def classify_symbol(names):
    if any("withReadOnlyTPROMemory" in n or "withReadOnlyMemoryInternal" in n for n in names):
        return "memory_manager_readonly_block"
    if any("ReadOnlyCallback" in n for n in names):
        return "readonly_callback"
    if "start" in names:
        return "startup"
    if any("MemoryManager4init" in n for n in names):
        return "memory_manager_initialization"
    if any("mapSplitCachePrivate" in n for n in names):
        return "private_cache_mapping"
    return "api_or_runtime_state"


def hazard_ledger(source, cached):
    names = {}
    for symbol in source.symbols:
        names.setdefault(symbol["address"], []).append(symbol["name"])
    word_items = source.iter_words if hasattr(source, "iter_words") else source.words.items
    branches = []
    for address, word in word_items():
        edge = direct_branch(word, address)
        if edge is not None:
            branches.append((address, edge["target"], edge["kind"]))
    hazards, groups = [], {}
    text_end = source.text.addr + source.text.size
    for address, word in word_items():
        register = system_register(word)
        if word not in TRANSITIONS and not (register and register["system_register"] in TRACKED_REGISTERS):
            continue
        owner = bisect.bisect_right(source.starts, address) - 1
        require(owner >= 0, "hazard precedes first real function start")
        begin = source.starts[owner]
        end = source.starts[owner + 1] if owner + 1 < len(source.starts) else text_end
        require(begin <= address < end and address < text_end, "hazard function interval mismatch")
        cached_word = struct.unpack("<I", cached.read_relative(address, 4))[0] if cached else None
        if cached:
            require(cached_word == word, "cached tracked hazard differs from standalone")
        item = {"address": hex(address), "word": f"0x{word:08x}", "function_start": hex(begin),
                "kind": TRANSITIONS[word] if word in TRANSITIONS else register["kind"],
                "system_register": register["system_register"] if register else None,
                "cached_address": hex(cached.base + address) if cached else None,
                "state_contract": None, "closed": False}
        hazards.append(item)
        if begin not in groups:
            predecessors = [{"address": hex(a), "target": hex(target), "kind": kind}
                            for a, target, kind in branches if not begin <= a < end and begin <= target < end]
            groups[begin] = {"function_start": hex(begin), "function_end": hex(end),
                             "symbols": names.get(begin, []), "family": classify_symbol(names.get(begin, [])),
                             "standalone_bytes_sha256": sha256(source.read(begin, end - begin)),
                             "cached_bytes_sha256": sha256(cached.read_relative(begin, end - begin)) if cached else None,
                             "direct_incoming_edges": predecessors,
                             "indirect_incoming_edges_complete": False,
                             "state_writers_complete": False, "callee_contracts_complete": False,
                             "hazards": [], "closed": False}
        groups[begin]["hazards"].append(hex(address))
    transitions = Counter(item["kind"] for item in hazards if item["kind"] in ("tchangef", "tchangeb"))
    require(dict(transitions) == {"tchangef": 116, "tchangeb": 120}, "transition coverage differs from pinned input")
    return {"tchange_count": sum(transitions.values()), "tchange_counts": dict(transitions),
            "tracked_register_count": len(hazards) - sum(transitions.values()),
            "function_group_count": len(groups), "hazards": hazards, "groups": list(groups.values()),
            "enumeration_complete_for_candidate_ranges": True,
            "all_sites_dispatch_verified": False}


def entry_contract(source, cached):
    words = struct.unpack("<5I", source.read(source.entry, 20))
    require(words == (0x910003e0, 0x927cec1f, 0xd280001d, 0xd280001e, 0x17fff850),
            "entry no longer preserves initial SP in X0 before alignment and branches to start")
    syscall_words = struct.unpack("<3I", source.read(0xa9d0, 12))
    require(syscall_words == (0xd28004d0, 0xd4001001, 0xd65f03c0), "syscall selector or SVC changed")
    require(sha256(source.read(0xa99c, 52)) ==
            "8ec7f497c6b92b8122106cf58133365625d6722b2800e656035977214db909b6",
            "query wrapper bytes changed")
    target = adrp_store_target(struct.unpack("<2I", source.read(0x3c64, 8)), 0x3c64)
    coordinate = section_coordinate(source.image.sections, target, 8)
    require(coordinate == ("__DATA_DIRTY", "__common", 0x20), "startup global store changes section field")
    result = {"lc_unixthread_pc": hex(source.entry), "initial_sp_preserved_in_x0": True,
              "start_branch": hex(direct_branch(words[-1], source.entry + 16)["target"]),
              "syscall": {"svc_immediate": "0x80", "x16_raw": "0x26", "x16_signed": 38,
                          "namespace_x0": "0x0", "actual_xnu_dispatch_verified": False},
              "standalone_global_store": {"address": hex(target), "coordinate": list(coordinate)},
              "cached_entry_bytes_equal": False, "cache_handoff_verified": False,
              "alternate_predecessors_closed": False,
              "fragments": {name: {"start": hex(a), "end": hex(b), "sha256": sha256(source.read(a, b - a))}
                            for name, (a, b) in FRAGMENTS.items()}}
    if cached:
        require(cached.read_relative(source.entry, 20) == source.read(source.entry, 20), "cached entry bytes differ")
        cached_target = adrp_store_target(struct.unpack("<2I", cached.read_relative(0x3c64, 8)), cached.base + 0x3c64)
        cached_coordinate = section_coordinate(cached.image.sections, cached_target, 8)
        require(cached_coordinate == coordinate, "cached startup write does not target corresponding section field")
        result.update(cached_entry_bytes_equal=True,
                      cached_global_store={"address": hex(cached_target), "coordinate": list(cached_coordinate)},
                      global_store_section_coordinate_equal=True)
    return result


def audit(source, cached=None):
    result = {"schema": "route-a-nontpro-startup-v1", "standalone": source.identity,
              "uuid": DYLD_UUID, "entry": entry_contract(source, cached),
              "ledger": hazard_ledger(source, cached), "source_code_pages": source.code_pages,
              "a01_verified": False, "runtime_dispatch_verified": False,
              "darwin_process_started": False, "os_boot_verified": False,
              "tb371fc_verified": False,
              "open_obligations": ["complete apple-vector publication and provenance",
                                   "disabled-state propagation and all relevant writers",
                                   "all incoming edges and callback contracts",
                                   "commpage contents and ordinary VM-protection fallback",
                                   "standalone-to-cache handoff"]}
    if cached:
        result["cache"] = {"main": cached.identities[str(cached.main)], "image_index": cached.index,
                           "dyld_base": hex(cached.base), "uuid": DYLD_UUID,
                           "identities": list(cached.identities.values()),
                           "inspected_image_only": True, "whole_cache_verified": False}
    result["inputs_unchanged"] = source.recheck() and (cached.recheck() if cached else True)
    require(result["inputs_unchanged"], "inputs changed during audit")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    require(not args.report.exists(), "refusing to overwrite a report")
    source = Standalone(args.input)
    cached = Cached(args.cache, source) if args.cache else None
    report = audit(source, cached)
    with args.report.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"report": str(args.report), "tchange_count": report["ledger"]["tchange_count"],
                      "a01_verified": False}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuditError, OSError, ValueError) as error:
        print(f"A01 audit failed: {error}", file=sys.stderr)
        raise SystemExit(2)
