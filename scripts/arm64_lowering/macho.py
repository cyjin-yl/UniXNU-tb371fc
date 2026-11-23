"""Bounds-checked Mach-O geometry for the arm64 lowering experiments.

Candidate ranges describe *where instructions may occur*, not proof that a word
is reachable code.  CFG/decoder evidence is still required before rewriting.
This module never modifies an input or claims that signatures remain valid.

Format references: Apple OSS xnu EXTERNAL_HEADERS/mach-o/loader.h,
osfmk/mach/machine.h and cctools include/mach-o/fat.h.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import struct
from typing import Any


CPU_TYPE_ARM64 = 0x0100000C
CPU_SUBTYPE_MASK = 0xFF000000
CPU_SUBTYPE_ARM64E = 2
MH_MAGIC_64 = 0xFEEDFACF
MH_FILESET = 0xC
LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D
LC_DATA_IN_CODE = 0x29
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_REQ_DYLD = 0x80000000
S_ATTR_PURE_INSTRUCTIONS = 0x80000000
S_ATTR_SOME_INSTRUCTIONS = 0x400
S_ATTR_DEBUG = 0x02000000
INSTRUCTIONS = S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
ZERO_FILL_TYPES = {1, 0xC, 0x12}
USER_FILE_TYPES = {2, 6, 7, 8}
UINT64_LIMIT = 1 << 64

# Recognized semantics, not merely a masked command number.  New required
# commands are blocked until their effect on the image is understood.
KNOWN_REQUIRED = {
    0x80000018,  # LC_LOAD_WEAK_DYLIB
    0x8000001C,  # LC_RPATH
    0x8000001F,  # LC_REEXPORT_DYLIB
    0x80000022,  # LC_DYLD_INFO_ONLY
    0x80000023,  # LC_LOAD_UPWARD_DYLIB
    0x80000028,  # LC_MAIN
    0x80000033,  # LC_DYLD_EXPORTS_TRIE
    LC_DYLD_CHAINED_FIXUPS,
}
LINKEDIT_COMMANDS = {
    LC_CODE_SIGNATURE, 0x1E, 0x26, LC_DATA_IN_CODE, 0x2B, 0x2E,
    0x80000033, LC_DYLD_CHAINED_FIXUPS,
}
DYLIB_COMMANDS = {0xC, 0xD, 0x80000018, 0x8000001F, 0x20, 0x80000023}


class MachOError(ValueError):
    """Invalid or unsafe Mach-O geometry; no candidate scan is returned."""


class UnsupportedMachO(MachOError):
    """A recognized container/architecture needs a separate parser."""

    def __init__(self, message: str, format: str):
        super().__init__(message)
        self.format = format


@dataclass(frozen=True)
class CodeRange:
    offset: int
    size: int
    vmaddr: int
    segment: str
    section: str
    pure_instructions: bool

    @property
    def end(self) -> int:
        return self.offset + self.size


@dataclass(frozen=True)
class Section:
    name: str
    segment: str
    addr: int
    size: int
    offset: int
    flags: int
    align: int
    reloff: int
    nreloc: int

    @property
    def zero_fill(self) -> bool:
        return (self.flags & 0xFF) in ZERO_FILL_TYPES


@dataclass
class Segment:
    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int
    maxprot: int
    initprot: int
    flags: int
    sections: list[Section] = field(default_factory=list)


@dataclass
class MachOImage:
    cpu_type: int
    subtype_raw: int
    subtype_base: int
    subtype_features: int
    file_type: int
    flags: int
    ncmds: int
    sizeofcmds: int
    segments: list[Segment]
    data_in_code: list[tuple[int, int, int]]
    candidate_ranges: list[CodeRange]
    excluded_data_ranges: list[tuple[int, int]]
    code_signature: dict[str, int] | None
    chained_fixups: dict[str, int] | None
    encryption: dict[str, int] | None
    blockers: list[str]
    warnings: list[str]
    format: str = "thin64"

    @property
    def can_scan_candidates(self) -> bool:
        return not self.blockers

    @property
    def sections(self) -> list[Section]:
        return [section for segment in self.segments for section in segment.sections]

    @property
    def is_arm64e(self) -> bool:
        return self.subtype_base == CPU_SUBTYPE_ARM64E

    def is_candidate(self, offset: int, size: int = 4) -> bool:
        """Whether a whole proposed instruction lies inside an allowed range."""
        if size <= 0 or offset < 0 or not self.can_scan_candidates:
            return False
        return any(r.offset <= offset and offset + size <= r.end for r in self.candidate_ranges)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["can_scan_candidates"] = self.can_scan_candidates
        result["is_arm64e"] = self.is_arm64e
        result["ptrauth_abi_version"] = (self.subtype_raw >> 24) & 0xF
        result["candidate_bytes"] = sum(r.size for r in self.candidate_ranges)
        result["candidate_ranges_are_code_proof"] = False
        return result

    def to_zeta_info(self) -> dict[str, Any]:
        """Geometry adapter for zeta's CFG proof, never a conversion approval.

        The original DIC kinds and byte lengths are preserved.  Callers must
        additionally test every proposed four-byte edit with ``is_candidate``;
        this rejects instructions partially overlapped by an unaligned DIC.
        """
        if self.blockers:
            raise MachOError("cannot export blocked image: " + "; ".join(self.blockers))
        return {
            "subtype": self.subtype_raw,
            "filetype": self.file_type,
            "segments": [
                {
                    "name": segment.name, "vmaddr": segment.vmaddr,
                    "fileoff": segment.fileoff, "filesize": segment.filesize,
                    "initprot": segment.initprot,
                    "sections": [
                        {"name": section.name, "addr": section.addr,
                         "size": section.size, "offset": section.offset,
                         "flags": section.flags}
                        for section in segment.sections
                    ],
                }
                for segment in self.segments
            ],
            "dice": list(self.data_in_code),
            "signature": None if self.code_signature is None else (
                self.code_signature["offset"], self.code_signature["size"]
            ),
        }


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise MachOError(message)


def _range(start: int, size: int, limit: int, label: str) -> None:
    _require(0 <= start <= limit and 0 <= size <= limit - start,
             f"{label} leaves its containing range")


def _vm_range(start: int, size: int, label: str) -> None:
    _range(start, size, UINT64_LIMIT, label)


def _name(raw: bytes) -> str:
    # ASCII is conventional, but an unusual name must not crash the parser or
    # be silently discarded while looking for code.
    return bytes(raw).split(b"\0", 1)[0].decode("utf-8", "backslashreplace")


def _overlap(a: int, an: int, b: int, bn: int) -> bool:
    return an > 0 and bn > 0 and a < b + bn and b < a + an


def _disjoint(ranges: list[tuple[int, int, str]], label: str) -> None:
    nonempty = sorted((start, start + size, name) for start, size, name in ranges if size)
    for previous, current in zip(nonempty, nonempty[1:]):
        _require(previous[1] <= current[0],
                 f"overlapping {label}: {previous[2]} and {current[2]}")


def _merge(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if start == end:
            continue
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def _command_string(data: Any, at: int, size: int, minimum: int) -> None:
    _require(size >= minimum, "truncated string load command")
    relative = struct.unpack_from("<I", data, at + 8)[0]
    _require(minimum <= relative < size, "load command string offset is invalid")
    _require(b"\0" in data[at + relative:at + size], "unterminated load command string")


def parse_macho(data: Any) -> MachOImage:
    """Parse an unmodified thin little-endian ARM64 Mach-O, fail on bad bounds.

    Known unsupported containers raise :class:`UnsupportedMachO`.  Encrypted
    images and images with unknown required commands produce metadata with
    blockers and *no* candidate ranges.  No chained pointers or signatures are
    modified by this structural parser.
    """
    length = len(data)
    if bytes(data[:7]) == b"dyld_v1" or bytes(data[:6]) == b"dyld_v":
        raise UnsupportedMachO("dyld shared cache requires cache/subcache parsing", "dyld-cache")
    _require(length >= 4, "truncated file magic")
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic in {0xBEBAFECA, 0xCAFEBABE, 0xBFBAFECA, 0xCAFEBABF}:
        fmt = "fat64" if magic in {0xBFBAFECA, 0xCAFEBABF} else "fat32"
        raise UnsupportedMachO("fat container requires explicit slice selection", fmt)
    if magic in {0xFEEDFACE, 0xCEFAEDFE, 0xCFFAEDFE}:
        raise UnsupportedMachO("only little-endian 64-bit Mach-O is supported", "macho-other")
    _require(magic == MH_MAGIC_64, "not a Mach-O file")
    _require(length >= 32, "truncated Mach-O header")
    _, cpu, subtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from("<8I", data, 0)
    if filetype == MH_FILESET:
        raise UnsupportedMachO("MH_FILESET requires member/address ownership parsing", "fileset")
    if cpu != CPU_TYPE_ARM64:
        raise UnsupportedMachO(f"unsupported CPU type {cpu:#x}", "thin64-other-cpu")
    _range(32, sizeofcmds, length, "load commands")
    _require(sizeofcmds % 8 == 0, "unaligned load command area")
    _require(ncmds <= sizeofcmds // 8, "load command count exceeds command area")

    blockers: list[str] = []
    warnings: list[str] = []
    if filetype not in USER_FILE_TYPES:
        blockers.append(f"unsupported_userland_filetype:{filetype:#x}")
    if reserved:
        blockers.append("nonzero_reserved_header_field")
    if flags & 0x80000000:  # MH_DYLIB_IN_CACHE uses shared-cache address ownership.
        blockers.append("shared_cache_image_requires_cache_mapping")
    segments: list[Segment] = []
    dice: list[tuple[int, int, int]] = []
    metadata: dict[int, dict[str, int]] = {}
    encryption: dict[str, int] | None = None
    command_end = 32 + sizeofcmds
    at = 32
    for index in range(ncmds):
        _range(at, 8, command_end, f"load command {index}")
        command, size = struct.unpack_from("<II", data, at)
        _require(size >= 8 and size % 8 == 0, f"bad load command {index} size/alignment")
        _range(at, size, command_end, f"load command {index}")
        if command & LC_REQ_DYLD and command not in KNOWN_REQUIRED:
            blockers.append(f"unknown_required_load_command:{command:#x}")
        if command == LC_SEGMENT_64:
            _require(size >= 72, "truncated LC_SEGMENT_64")
            values = struct.unpack_from("<4Q4I", data, at + 24)
            vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, segflags = values
            _require(size == 72 + 80 * nsects, "LC_SEGMENT_64 section count/size mismatch")
            name = _name(data[at + 8:at + 24])
            _vm_range(vmaddr, vmsize, f"segment {name} VM")
            _range(fileoff, filesize, length, f"segment {name} file")
            _require(filesize <= vmsize, f"segment {name} file size exceeds VM size")
            _require((initprot & ~maxprot) == 0, f"segment {name} initial protection exceeds maximum")
            if (initprot | maxprot) & ~7:
                blockers.append(f"unsupported_segment_protection:{name}")
            if segflags & 1:  # SG_HIGHVM changes the file-to-VM translation.
                blockers.append(f"unsupported_highvm_segment:{name}")
            if segflags & 8:  # SG_PROTECTED_VERSION_1 can protect executable bytes.
                blockers.append(f"protected_segment:{name}")
            segment = Segment(name, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, segflags)
            for section_index in range(nsects):
                pos = at + 72 + 80 * section_index
                sectname = _name(data[pos:pos + 16])
                segname = _name(data[pos + 16:pos + 32])
                addr, sectsize, offset, align, reloff, nreloc, sectflags, _, _, _ = struct.unpack_from("<2Q8I", data, pos + 32)
                label = f"section {name},{sectname}"
                _require(segname == name, f"{label} segment name mismatch")
                _vm_range(addr, sectsize, label + " VM")
                _require(vmaddr <= addr and sectsize <= vmaddr + vmsize - addr,
                         f"{label} leaves segment VM range")
                _require(align <= 63, f"{label} has invalid alignment exponent")
                if sectsize:
                    _require(addr % (1 << align) == 0, f"{label} violates declared VM alignment")
                section = Section(sectname, segname, addr, sectsize, offset, sectflags, align, reloff, nreloc)
                if not section.zero_fill and sectsize:
                    _range(offset, sectsize, length, label + " file")
                    _require(fileoff <= offset and sectsize <= fileoff + filesize - offset,
                             f"{label} leaves segment file range")
                    _require(offset >= command_end, f"{label} overlaps header/load commands")
                    if not segflags & 1:
                        _require(addr - vmaddr == offset - fileoff,
                                 f"{label} file/VM mapping is inconsistent")
                if nreloc:
                    _range(reloff, nreloc * 8, length, label + " relocations")
                if sectflags & INSTRUCTIONS:
                    _require(not section.zero_fill, f"{label} is zero-fill instruction data")
                    _require(initprot & 4, f"{label} is not executable")
                    _require(not sectflags & S_ATTR_DEBUG, f"{label} is debug instruction data")
                    _require(addr % 4 == offset % 4 == sectsize % 4 == 0,
                             f"{label} has unaligned instruction geometry")
                    if not sectflags & S_ATTR_PURE_INSTRUCTIONS:
                        warnings.append(f"mixed_instruction_section:{name},{sectname}")
                segment.sections.append(section)
            _disjoint([(s.addr, s.size, s.name) for s in segment.sections], "section VM ranges")
            _disjoint([(s.offset, s.size, s.name) for s in segment.sections if not s.zero_fill], "section file ranges")
            segments.append(segment)
        elif command in LINKEDIT_COMMANDS:
            _require(size == 16, f"bad linkedit command {command:#x} size")
            _require(command not in metadata, f"duplicate linkedit command {command:#x}")
            offset, region_size = struct.unpack_from("<2I", data, at + 8)
            _range(offset, region_size, length, f"linkedit command {command:#x}")
            if region_size:
                _require(offset >= command_end, "linkedit data overlaps header/load commands")
            metadata[command] = {"offset": offset, "size": region_size, "command_offset": at}
            if command == LC_DATA_IN_CODE:
                _require(region_size % 8 == 0, "data-in-code table has partial entry")
                for pos in range(offset, offset + region_size, 8):
                    entry = struct.unpack_from("<IHH", data, pos)
                    _range(entry[0], entry[1], length, "data-in-code entry")
                    if entry[1]:
                        _require(entry[0] >= command_end, "data-in-code entry overlaps header/load commands")
                        dice.append(entry)
        elif command in {0x21, 0x2C}:
            expected = 24 if command == 0x2C else 24  # 64-bit commands are padded to eight bytes.
            _require(size == expected, "bad encryption load command size")
            _require(encryption is None, "duplicate encryption load command")
            offset, region_size, cryptid = struct.unpack_from("<3I", data, at + 8)
            _range(offset, region_size, length, "encrypted region")
            encryption = {"offset": offset, "size": region_size, "cryptid": cryptid}
            if cryptid:
                blockers.append(f"encrypted_image:cryptid={cryptid}")
        elif command in DYLIB_COMMANDS:
            _command_string(data, at, size, 24)
        elif command in {0xE, 0xF, 0x27, 0x8000001C}:
            _command_string(data, at, size, 12)
        elif command in {0x22, 0x80000022}:
            _require(size == 48, "bad dyld-info command size")
            regions = struct.unpack_from("<10I", data, at + 8)
            for region_index in range(0, 10, 2):
                _range(regions[region_index], regions[region_index + 1], length, "dyld-info region")
        elif command == 0x2:  # LC_SYMTAB, consumed by the downstream CFG roots.
            _require(size == 24, "bad LC_SYMTAB command size")
            symoff, nsyms, stroff, strsize = struct.unpack_from("<4I", data, at + 8)
            _range(symoff, nsyms * 16, length, "64-bit symbol table")
            _range(stroff, strsize, length, "symbol string table")
        elif command == 0xB:  # LC_DYSYMTAB
            _require(size == 80, "bad LC_DYSYMTAB command size")
            values = struct.unpack_from("<18I", data, at + 8)
            for start_index, record_size in ((6, 8), (8, 56), (10, 4), (12, 4), (14, 8), (16, 8)):
                _range(values[start_index], values[start_index + 1] * record_size,
                       length, "dynamic symbol table region")
        elif command == 0x80000028:
            _require(size == 24, "bad LC_MAIN command size")
        elif command == 0x1B:
            _require(size == 24, "bad LC_UUID command size")
        elif command == 0x32:
            _require(size >= 24, "truncated LC_BUILD_VERSION")
            ntools = struct.unpack_from("<I", data, at + 20)[0]
            _require(size == 24 + 8 * ntools, "LC_BUILD_VERSION tool count/size mismatch")
        at += size
    _require(at == command_end, "load command count/sizeofcmds mismatch")
    _require(bool(segments), "Mach-O has no segments")
    _disjoint([(s.fileoff, s.filesize, s.name) for s in segments], "segment file ranges")
    _disjoint([(s.vmaddr, s.vmsize, s.name) for s in segments], "segment VM ranges")

    instruction_sections = [s for seg in segments for s in seg.sections if s.flags & INSTRUCTIONS and s.size]
    for command, region in metadata.items():
        for section in instruction_sections:
            _require(not _overlap(region["offset"], region["size"], section.offset, section.size),
                     f"linkedit command {command:#x} overlaps instruction section")
    dice.sort()
    for offset, size, _ in dice:
        _require(any(s.offset <= offset and offset + size <= s.offset + s.size for s in instruction_sections),
                 "data-in-code entry is not contained in an instruction section")
    excluded = _merge([(offset, offset + size) for offset, size, _ in dice])
    candidates: list[CodeRange] = []
    for section in instruction_sections:
        # Expand intersections outwards to whole AArch64 words.  DIC bytes can
        # be unaligned even when the containing instruction section is aligned.
        cuts = _merge([
            (max(section.offset, start // 4 * 4), min(section.offset + section.size, (end + 3) // 4 * 4))
            for start, end in excluded
            if _overlap(start, end - start, section.offset, section.size)
        ])
        cursor = section.offset
        for start, end in cuts + [(section.offset + section.size, section.offset + section.size)]:
            if cursor < start:
                candidates.append(CodeRange(cursor, start - cursor,
                                            section.addr + cursor - section.offset,
                                            section.segment, section.name,
                                            bool(section.flags & S_ATTR_PURE_INSTRUCTIONS)))
            cursor = max(cursor, end)
    if blockers:
        candidates = []
    candidates.sort(key=lambda r: r.offset)
    return MachOImage(cpu, subtype, subtype & ~CPU_SUBTYPE_MASK, subtype & CPU_SUBTYPE_MASK,
                      filetype, flags, ncmds, sizeofcmds, segments, dice, candidates,
                      [(start, end - start) for start, end in excluded],
                      metadata.get(LC_CODE_SIGNATURE), metadata.get(LC_DYLD_CHAINED_FIXUPS),
                      encryption, blockers, warnings)
