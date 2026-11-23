#!/usr/bin/env python3
"""Read-only, exact-source TPRO inventory for the 24A446 standalone dyld.

This is an evidence collector, not an instruction rewriter or an A77 verifier.
It intentionally emits false whole-program/runtime verification flags.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import sys

from arm64_lowering.macho import MachOError, parse_macho
from arm64_lowering.pipeline import verify_code_pages

SOURCE_SHA256 = "ab9887ed96c9c08ad68d4c6a5c27e8289fb0c9e55ec3e134547292a1ec579608"
SOURCE_BYTES = 1447088
FEATURE_KEYS = ("dyld_hw_tpro", "dyld_hw_tpro_pagers")
TRACKED_REGISTERS = {"s3_6_c15_c1_5", "s3_3_c4_c0_3"}
STRINGS = {0xA5E9C: b"dyld_hw_tpro=1\0", 0xA62F7: b"dyld_hw_tpro\0"}
INSPECTION_RANGES = (
    ("start", 0x3BE0, 0x5A90),
    ("MemoryManager constructor", 0x713C, 0x7208),
    ("defaultTproStack", 0x21264, 0x212F0),
    ("ProtectedStack constructor", 0x3CB2C, 0x3CB68),
)
EXPECTED_TCHANGE_WORDS = {0xD5900040: 116, 0xD5940000: 120}


class AuditError(ValueError):
    pass


def sign_extend(value: int, bits: int) -> int:
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def direct_branch(word: int, pc: int) -> dict | None:
    """Bit-decode only fixed-width direct A64 branch classes.

    Results are static instruction candidates. They do not establish reachable
    edges, call/return matching, indirect targets, or branch feasibility.
    """
    if word & 0x7C000000 == 0x14000000:
        return {"kind": "bl" if word >> 31 else "b",
                "target": pc + (sign_extend(word & 0x03FFFFFF, 26) << 2)}
    if word & 0xFF000010 == 0x54000000:
        return {"kind": "b.cond", "condition": word & 15,
                "target": pc + (sign_extend((word >> 5) & 0x7FFFF, 19) << 2)}
    if word & 0x7E000000 == 0x34000000:
        return {"kind": "cbnz" if word & (1 << 24) else "cbz",
                "register": word & 31, "width": 64 if word >> 31 else 32,
                "target": pc + (sign_extend((word >> 5) & 0x7FFFF, 19) << 2)}
    if word & 0x7E000000 == 0x36000000:
        return {"kind": "tbnz" if word & (1 << 24) else "tbz",
                "register": word & 31,
                "bit": ((word >> 26) & 32) | ((word >> 19) & 31),
                "target": pc + (sign_extend((word >> 5) & 0x3FFF, 14) << 2)}
    return None


def system_register(word: int) -> dict | None:
    """MRS/MSR register transfers only; SYS/SYSL and immediate forms excluded."""
    if word & 0xFFC00000 != 0xD5000000:
        return None
    op0 = (word >> 19) & 3
    if op0 < 2:
        return None
    name = f"s{op0}_{(word >> 16) & 7}_c{(word >> 12) & 15}_c{(word >> 8) & 15}_{(word >> 5) & 7}"
    return {"kind": "mrs" if word & (1 << 21) else "msr",
            "system_register": name, "register": word & 31}


def materialized_address(word: int, next_word: int | None, pc: int) -> dict | None:
    """Recognize ADR and adjacent ADRP+ADD-immediate, never infer across a gap."""
    if word & 0x1F000000 != 0x10000000:
        return None
    immediate = sign_extend(((word >> 5) & 0x7FFFF) << 2 | ((word >> 29) & 3), 21)
    rd = word & 31
    if rd == 31:
        return None
    if not word & (1 << 31):
        return {"kind": "adr", "target": pc + immediate, "register": rd,
                "instruction_count": 1}
    if next_word is None or next_word & 0xFFC00000 != 0x91000000:
        return None
    if (next_word & 31) != rd or ((next_word >> 5) & 31) != rd:
        return None
    return {"kind": "adrp+add", "target": (pc & ~4095) + (immediate << 12) + ((next_word >> 10) & 4095),
            "register": rd, "instruction_count": 2}


def candidate_words(data: bytes, image) -> dict[int, tuple[int, int]]:
    """VA -> (word, file offset), with the parser's data exclusions respected."""
    words = {}
    for region in image.candidate_ranges:
        for offset in range(region.offset, region.end, 4):
            pc = region.vmaddr + offset - region.offset
            if pc in words:
                raise AuditError("overlapping instruction candidate addresses")
            words[pc] = (struct.unpack_from("<I", data, offset)[0], offset)
    return words


def candidate_inventory(data: bytes) -> dict:
    """Reusable structural census; output is explicitly not a reachability proof."""
    image = parse_macho(data)
    if image.blockers:
        raise AuditError("blocked Mach-O: " + "; ".join(image.blockers))
    sys.path.insert(0, str(Path(__file__).resolve().parent / "route_a_zeta"))
    from zeta_userland_code import poe2_instruction
    words = candidate_words(data, image)
    transitions, registers, branches, addresses = [], [], [], []
    for pc, (word, offset) in sorted(words.items()):
        common = {"address": hex(pc), "file_offset": hex(offset), "word": f"0x{word:08x}"}
        transition = poe2_instruction(word)
        if transition:
            transitions.append({**common, "mnemonic": transition[0], "operands": transition[1]})
        register = system_register(word)
        if register:
            registers.append({**common, **register})
        edge = direct_branch(word, pc)
        if edge:
            branches.append({**common, **edge, "target": hex(edge["target"])})
        following = words.get(pc + 4)
        address = materialized_address(word, following[0] if following else None, pc)
        if address:
            addresses.append({**common, **address, "target": hex(address["target"])})
    return {"transitions": transitions, "system_registers": registers,
            "branches": branches, "materialized_addresses": addresses,
            "candidate_word_count": len(words), "scan_is_code_proof": False}


def read_at_va(data: bytes, image, address: int, size: int) -> bytes:
    matches = [seg for seg in image.segments
               if seg.vmaddr <= address and address + size <= seg.vmaddr + seg.filesize]
    if len(matches) != 1:
        raise AuditError(f"VA {address:#x} does not map to one file-backed range")
    seg = matches[0]
    start = seg.fileoff + address - seg.vmaddr
    return data[start:start + size]


def check_apple_vector(entries: list[str]) -> dict:
    """Check a captured/supplied apple vector, not shell environment variables.

    Presence enables dyld's features even when the value is "0" or empty.
    Passing this check alone never certifies actual kernel dispatch or commpage.
    """
    if any(not isinstance(item, str) or "\0" in item for item in entries):
        raise AuditError("apple vector entries must be NUL-free strings")
    present = sorted({item.partition("=")[0] for item in entries if "=" in item} & set(FEATURE_KEYS))
    malformed = sorted(set(entries) & set(FEATURE_KEYS))
    return {"required_absent_keys": list(FEATURE_KEYS), "present_keys": present,
            "malformed_feature_entries": malformed,
            "non_tpro_keys_absent": not present and not malformed,
            "runtime_dispatch_verified": False,
            "commpage_verified": False,
            "vm_protection_verified": False}


def collect_disassembly_windows(data: bytes, image, *, enabled: bool = False) -> list[dict]:
    """Opt-in private diagnostics; the normal audit never performs this sweep."""
    if not enabled:
        return []
    sys.path.insert(0, str(Path(__file__).resolve().parent / "route_a_zeta"))
    from zeta_userland_code import decode
    sections = [dict(offset=r.offset, size=r.size, addr=r.vmaddr) for r in image.candidate_ranges]
    instructions = decode(data, sections)
    windows = []
    for name, low, high in INSPECTION_RANGES:
        windows.append({"name": name, "start": hex(low), "end": hex(high),
                        "instructions": [{"address": hex(pc), "mnemonic": instructions[pc][0],
                                          "operands": instructions[pc][1]}
                                         for pc in sorted(instructions) if low <= pc < high]})
    return windows


def audit_bytes(data: bytes, *, apple_vector: list[str] | None = None, include_disassembly: bool = False) -> dict:
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != SOURCE_BYTES or digest != SOURCE_SHA256:
        raise AuditError("source mismatch: this audit is bound to the original 24A446 iPad17,3 dyld")
    image = parse_macho(data)
    if not image.is_arm64e or image.code_signature is None:
        raise AuditError("expected signed, original arm64e dyld")
    signature = verify_code_pages(data, image.code_signature)
    for address, expected in STRINGS.items():
        if read_at_va(data, image, address, len(expected)) != expected:
            raise AuditError(f"pinned string assertion failed at {address:#x}")
    inventory = candidate_inventory(data)
    actual_counts = Counter(int(row["word"], 16) for row in inventory["transitions"])
    if dict(actual_counts) != EXPECTED_TCHANGE_WORDS:
        raise AuditError("TCHANGE census differs from the pinned observed image")
    refs = [row for row in inventory["materialized_addresses"]
            if int(row["target"], 16) in STRINGS]
    incoming = [row for row in inventory["branches"]
                if any(low <= int(row["target"], 16) < high
                       and not low <= int(row["address"], 16) < high
                       for _, low, high in INSPECTION_RANGES)]
    constructor_calls = [row for row in inventory["branches"]
                         if row["kind"] in ("b", "bl") and int(row["target"], 16) in (0x3CB2C, 0x21264)]
    selected_registers = [row for row in inventory["system_registers"]
                          if row["system_register"] in TRACKED_REGISTERS]
    windows = collect_disassembly_windows(data, image, enabled=include_disassembly)
    return {
        "schema": "route-a-tpro-audit-v1",
        "input": {"path": "usr/lib/dyld", "product": "iPad17,3", "version": "27.0.1",
                  "build": "24A446", "sha256": digest, "bytes": len(data)},
        "original_code_pages": signature,
        "candidate_word_count": inventory["candidate_word_count"],
        "tchange_sites": inventory["transitions"],
        "tchange_count": len(inventory["transitions"]),
        "selected_system_register_sites": selected_registers,
        "system_register_inventory": dict(sorted(Counter(row["system_register"] for row in inventory["system_registers"]).items())),
        "literal_static_references": refs,
        "literal_references_complete": False,
        "external_direct_edges_into_inspection_ranges": incoming,
        "direct_protected_stack_calls": constructor_calls,
        "inspection_windows": windows,
        "supplied_apple_vector_check": None if apple_vector is None else check_apple_vector(apple_vector),
        "required_absent_apple_keys": list(FEATURE_KEYS),
        "limits": [
            "Candidate census and direct edges are not a CFG or feature-gate dominance proof.",
            "ADR and adjacent ADRP+ADD references do not cover GOT, data pointers or indirect materialization.",
            "An omitted key in a supplied vector does not prove that startup never inserts it later.",
            "Commpage values, early startup, indirect callbacks, shared-cache dyld and loaded libraries remain separate obligations.",
            "No input bytes are changed; TCHANGE and Apple-specific register accesses are not emulated."
        ],
        "all_tchange_sites_dispatch_verified": False,
        "runtime_dispatch_verified": False,
        "target_isa_audited": False,
        "os_boot_verified": False,
        "binary_was_modified_by_this_audit": False,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True, help="new JSON file; never overwritten")
    parser.add_argument("--include-disassembly", action="store_true", help="include private diagnostic disassembly windows")
    parser.add_argument("--apple-vector", type=Path, help="JSON list of captured/supplied apple-vector strings")
    args = parser.parse_args(argv)
    try:
        if args.report.exists():
            raise AuditError("report exists; choose a new report path")
        vector = None
        if args.apple_vector is not None:
            vector = json.loads(args.apple_vector.read_text(encoding="utf-8"))
            if not isinstance(vector, list):
                raise AuditError("apple-vector JSON must be a list of strings")
            check_apple_vector(vector)
        if args.input.stat().st_size != SOURCE_BYTES:
            raise AuditError("source size mismatch; expected original 24A446 standalone dyld")
        report = audit_bytes(args.input.read_bytes(), apple_vector=vector, include_disassembly=args.include_disassembly)
        with args.report.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
    except (AuditError, MachOError, OSError, ValueError) as error:
        print(f"TPRO audit blocked: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"report": str(args.report), "tchange_count": report["tchange_count"],
                      "runtime_dispatch_verified": False, "os_boot_verified": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
