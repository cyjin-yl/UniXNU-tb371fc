#!/usr/bin/env python3
"""Read-only, exact-source TPRO inventory for the 24A446 standalone dyld.

This is an evidence collector, not an instruction rewriter or an A77 verifier.
It intentionally emits false whole-program/runtime verification flags.
"""
from __future__ import annotations

import argparse
from collections import Counter, deque
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
# These describe the observed branch instructions, not established runtime
# values or dominance over every caller. A mismatch blocks the local analysis.
LOCAL_GATE_SCOPES = (
    {"name": "MemoryManager null getenv result", "start": 0x713C, "end": 0x7208,
     "gate": 0x7188, "disabled_successor": 0x7194,
     "expected_gate": {"kind": "cbz", "register": 0, "width": 64, "target": 0x7194},
     "assumption": "X0 is zero at the first visit to the observed getenv-result branch."},
    {"name": "defaultTproStack null getenv result", "start": 0x21264, "end": 0x212F0,
     "gate": 0x2128C, "disabled_successor": 0x212E0,
     "expected_gate": {"kind": "cbz", "register": 0, "width": 64, "target": 0x212E0},
     "assumption": "X0 is zero at the first visit to the observed getenv-result branch."},
    {"name": "ProtectedStack false constructor argument", "start": 0x3CB2C, "end": 0x3CB68,
     "gate": 0x3CB4C, "disabled_successor": 0x3CB58,
     "expected_gate": {"kind": "cbz", "register": 1, "width": 32, "target": 0x3CB58},
     "assumption": "W1 is zero at the first visit to the observed constructor branch."},
    {"name": "ReadOnlyCallback disabled hardware branch", "start": 0x2FFC, "end": 0x3284,
     "gate": 0x3048, "disabled_successor": 0x31E4,
     "expected_gate": {"kind": "b.cond", "condition": 1, "target": 0x31E4},
     "assumption": "NE holds at the first visit to the observed hardware-enable branch."},
)


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


def analyze_local_gate(data: bytes, image, *, name: str, start: int, end: int,
                       gate: int, disabled_successor: int, expected_gate: dict,
                       assumption: str, max_states: int = 4096) -> dict:
    """Close a small normal-control-flow region under one initial edge assumption.

    This deliberately does not infer the branch predicate from an apple vector,
    memory, a caller, or a preceding getenv call. Unknown instructions, calls,
    indirect branches, traps and exits outside the region block certification.
    The chosen edge applies only on the first visit: a loop back to the gate
    explores both outcomes because the predicate may have changed.
    """
    if (start % 4 or end % 4 or gate % 4 or disabled_successor % 4
            or not start <= gate < end or max_states <= 0):
        raise AuditError("invalid local gate region or state budget")
    from capstone import (Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN,
                          CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET, CS_GRP_INT, CS_GRP_IRET)
    sys.path.insert(0, str(Path(__file__).resolve().parent / "route_a_zeta"))
    from zeta_userland_code import poe2_instruction

    words = {pc: entry for pc, entry in candidate_words(data, image).items() if start <= pc < end}
    actual = direct_branch(words[gate][0], gate) if gate in words else None
    result = {
        "name": name, "region_start": hex(start), "region_end": hex(end),
        "gate": hex(gate), "disabled_successor": hex(disabled_successor),
        "expected_gate": {**expected_gate, "target": hex(expected_gate["target"])},
        "observed_gate": None if actual is None else {**actual, "target": hex(actual["target"])},
        "assumption": assumption, "initial_branch_outcome_assumed": True,
        "normal_control_flow_only": True,
        "gate_predecessors_verified": False, "predicate_dataflow_verified": False,
        "callee_bodies_verified": False, "return_value_verified": False, "return_targets_verified": False,
        "termination_verified": False, "runtime_dispatch_verified": False,
        "whole_function_dispatch_verified": False,
        "normal_control_flow_closed": False,
        "conditional_region_without_tracked_hazards": False,
        "visited_addresses": [], "normal_return_sites": [],
        "reachable_tracked_hazards": [], "blockers": [],
    }
    if (actual != expected_gate or actual is None or actual["kind"] in ("b", "bl")
            or disabled_successor not in (actual["target"], gate + 4)):
        result["status"] = "gate_mismatch"
        result["blockers"].append({"address": hex(gate), "reason": "expected conditional gate does not match"})
        return result

    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    initial = (gate, True)
    queue, parents, processed = deque([initial]), {initial: None}, set()
    visited, returns, hazards = set(), set(), {}

    def witness(state):
        path = []
        while state is not None:
            path.append(hex(state[0]))
            state = parents[state]
        return list(reversed(path))

    def block(state, reason):
        result["blockers"].append({"address": hex(state[0]), "reason": reason,
                                   "path_from_assumed_gate": witness(state)})

    def enqueue(state, successors):
        for target in successors:
            next_state = (target, False)
            if next_state not in parents:
                parents[next_state] = state
                queue.append(next_state)

    while queue:
        state = queue.popleft()
        pc, first_visit = state
        if len(processed) >= max_states:
            block(state, "state budget exhausted; pending paths remain")
            break
        processed.add(state)
        if not start <= pc < end:
            block(state, "control flow leaves the selected region")
            continue
        if pc not in words:
            block(state, "target is outside validated instruction candidates")
            continue
        visited.add(pc)
        word = words[pc][0]
        transition, register = poe2_instruction(word), system_register(word)
        if transition or (register and register["system_register"] in TRACKED_REGISTERS):
            hazards.setdefault(pc, {"address": hex(pc), "word": f"0x{word:08x}",
                                    "kind": "TCHANGE" if transition else register["system_register"],
                                    "path_from_assumed_gate": witness(state)})
        if first_visit:
            enqueue(state, [disabled_successor])
            continue
        branch = direct_branch(word, pc)
        if branch:
            if branch["kind"] == "bl":
                block(state, "direct call requires a separately verified callee and return contract")
            elif branch["kind"] == "b":
                enqueue(state, [branch["target"]])
            else:
                enqueue(state, [branch["target"], pc + 4])
            continue
        if transition:
            # TCHANGE's normal flow is known; its availability/traps are not
            # waived. Reaching it already makes the hazard-free result false.
            enqueue(state, [pc + 4])
            continue
        decoded = next(decoder.disasm(struct.pack("<I", word), pc, count=1), None)
        if decoded is None or decoded.size != 4:
            block(state, "unknown instruction; fallthrough is not assumed")
            continue
        groups = set(decoded.groups)
        if (groups & {CS_GRP_INT, CS_GRP_IRET}
                or decoded.mnemonic in {"brk", "hlt", "udf", "eret", "eretaa", "eretab", "drps"}
                or decoded.mnemonic.startswith("dcps")):
            block(state, "trap or exception control flow is outside the local model")
        elif groups & {CS_GRP_CALL, CS_GRP_JUMP}:
            block(state, "indirect or unmodeled control transfer")
        elif CS_GRP_RET in groups:
            if word in (0xD65F03C0, 0xD65F0BFF, 0xD65F0FFF):
                returns.add(pc)
            else:
                block(state, "nonstandard return register requires an indirect-target contract")
        else:
            enqueue(state, [pc + 4])

    result["visited_addresses"] = [hex(pc) for pc in sorted(visited)]
    result["normal_return_sites"] = [hex(pc) for pc in sorted(returns)]
    result["reachable_tracked_hazards"] = [hazards[pc] for pc in sorted(hazards)]
    result["normal_control_flow_closed"] = not result["blockers"]
    result["conditional_region_without_tracked_hazards"] = not result["blockers"] and not hazards
    result["status"] = ("reachable_tracked_hazard" if hazards else "incomplete" if result["blockers"]
                        else "closed_under_initial_branch_assumption")
    return result


def collect_local_gate_analyses(data: bytes, image) -> list[dict]:
    """Run only the fixed source's four selected, explicitly conditional scopes."""
    return [analyze_local_gate(data, image, **scope) for scope in LOCAL_GATE_SCOPES]


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
    local_gates = collect_local_gate_analyses(data, image)
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
        "local_gate_analyses": local_gates,
        "inspection_windows": windows,
        "supplied_apple_vector_check": None if apple_vector is None else check_apple_vector(apple_vector),
        "required_absent_apple_keys": list(FEATURE_KEYS),
        "limits": [
            "Candidate census and direct edges are not a CFG or feature-gate dominance proof.",
            "ADR and adjacent ADRP+ADD references do not cover GOT, data pointers or indirect materialization.",
            "An omitted key in a supplied vector does not prove that startup never inserts it later.",
            "Local gate checks assume only the first branch outcome; they do not prove predicate dataflow, predecessors, callees or whole-function dispatch.",
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
