"""Explicit PACGA compatibility ABI and its target-kernel admission.

The default policy still rejects PACGA. QARMA5-SVC-V1 is a new, whole-process
ordinary-pointer contract. It preserves generic-signature computation and
recomputation under a fresh boot key, not Apple PAC authentication or the
numeric value of signatures made under another key/algorithm.
"""
from __future__ import annotations

from collections import deque
import hashlib
import json
import os
from pathlib import Path

ABI = "qarma5-svc-v1"
POLICIES = ("reject", ABI)
SVC_MASK = 0xFFF0001F
SVC_WORD = 0xD4100001
ROOT = Path(__file__).resolve().parents[2]
HEADER = "scripts/arm64_lowering/runtime/pacga_qarma5.h"
PATCH = "patches/route-a-pacga-svc-12377.patch"
XNU_COMMIT = "ac9718fb1af618d5ce8678d0dc6e8a58f252216f"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def policy(value):
    require(value in POLICIES, "unsupported PACGA policy")
    return value


def is_pacga(word):
    return word & 0xFFE0FC00 == 0x9AC03000


def is_svc(word):
    return word & SVC_MASK == SVC_WORD


def encode(word):
    require(type(word) is int and 0 <= word <= 0xFFFFFFFF and is_pacga(word),
            "not a PACGA encoding")
    return SVC_WORD | ((word & 0x3FF) << 5) | (((word >> 16) & 31) << 15)


def decode(word):
    require(type(word) is int and 0 <= word <= 0xFFFFFFFF and is_svc(word),
            "not a Route A PACGA SVC encoding")
    immediate = (word >> 5) & 0x7FFF
    return 0x9AC03000 | (immediate & 0x3FF) | (((immediate >> 10) & 31) << 16)


def contract():
    return dict(abi=ABI, algorithm="QARMA-64-5/Arm-S-box",
                input_bits=[64, 64], key_bits=128, result_mask="0xffffffff00000000",
                register_31=dict(destination="discard", source="zero", modifier="sp"),
                svc_mask=hex(SVC_MASK), svc_word=hex(SVC_WORD),
                key_scope="one random kernel boot key shared by tasks and threads",
                key_source="read_random after provider POST and register_and_init_prng",
                key_startup="EARLY_BOOT/FIRST after source-provider SYSCTL/LAST",
                pointer_authentication_preserved=False,
                apple_signature_values_preserved=False,
                exclusive_reservation="reject PACGA with a live reservation and any unsupported live-state escape",
                requires="all signature producers and consumers use this ABI; no imported old-key tags")


def implementation():
    sources = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
               for name in (HEADER, PATCH)}
    value = dict(contract=contract(), xnu_commit=XNU_COMMIT, sources=sources)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return dict(value, sha256=hashlib.sha256(raw).hexdigest())


def descriptor():
    """Exact public, non-secret descriptor retained in the linked kernel."""
    return ("UNIXNU-PACGA-SVC-QARMA5-V1\n"
            "impl-sha256:" + implementation()["sha256"] + "\n"
            "key:boot/read_random\nresult:hi32/zero32\n").encode() + b"\0"


def _generation(fd):
    s = os.fstat(fd)
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def runtime_kernel(path):
    """Bind a linked, ordinary-arm64 kernel carrying this exact runtime identity.

    The descriptor is a reproducible build contract, not an attestation by an
    untrusted producer and not evidence that this kernel has booted. The caller
    must deploy this same digest with the converted userland.
    """
    from .macho import parse_macho
    require(path is not None, "PACGA ABI requires the matching runtime kernel")
    path = Path(path)
    with path.open("rb") as stream:
        before = _generation(stream.fileno())
        raw = stream.read()
        require(_generation(stream.fileno()) == before, "PACGA runtime changed while read")
    image = parse_macho(raw)
    require(image.file_type == 2 and image.subtype_raw == 0 and not image.blockers,
            "PACGA runtime must be a supported linked ordinary-arm64 kernel")
    require(bool(image.candidate_ranges), "PACGA runtime has no executable code")
    sections = [(segment, section) for segment in image.segments for section in segment.sections
                if section.name == "__unixnu_pacga"]
    require(len(sections) == 1, "PACGA runtime descriptor is missing or duplicated")
    segment, section = sections[0]
    require(segment.name == "__DATA_CONST" and section.segment == "__DATA_CONST"
            and not section.zero_fill and not (segment.initprot & 4),
            "PACGA runtime descriptor is not non-executable file-backed constant data")
    require(raw[section.offset:section.offset + section.size] == descriptor(),
            "PACGA runtime implementation identity differs")
    return dict(schema="route-a-pacga-runtime-v1", abi=ABI,
                kernel=dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()),
                implementation=implementation(), runtime_boot_verified=False)


def runtime_binding(selected, kernel=None):
    policy(selected)
    if selected == "reject":
        require(kernel is None, "a PACGA kernel requires explicit PACGA ABI selection")
        return None
    return runtime_kernel(kernel)


def exclusive_analysis(insns, proven, tables):
    """Reject a new exception inside a load-exclusive/store-exclusive interval.

    The scan adds no roots and reads only already-proven instructions belonging
    to this owner. It starts after each proven load-exclusive and follows both
    conditional edges plus structurally decoded jump-table targets. A call does
    NOT clear the reservation: it records an unsupported escape and continues
    the caller fallthrough as live. Returns, unknown indirect branches, and
    edges out of the proven owner also escape. Accepting those paths requires a
    separate interprocedural reservation proof; a closed-state callee root is
    not sufficient. Existing exceptions, CLREX, and store-exclusive end a path.
    """
    from route_a_zeta import zeta_userland_code as cfg
    loads = {"ldxr", "ldxrb", "ldxrh", "ldaxr", "ldaxrb", "ldaxrh", "ldxp", "ldaxp"}
    stores = {"stxr", "stxrb", "stxrh", "stlxr", "stlxrb", "stlxrh", "stxp", "stlxp"}
    clear = stores | {"clrex", "svc", "hvc", "smc", "brk", "udf", "hlt"}
    jumps = {table["dispatch"]: table["targets"] for table in tables}
    work = deque((pc + 4, pc) for pc in proven if insns[pc][0] in loads)
    # One 1024-bit integer per reached 4-KiB code page avoids another
    # Python integer/set entry for every instruction in a very large owner.
    visited, hazards, escaped = {}, set(), set()

    def escape(pc, reason, target=None):
        escaped.add((pc, reason, target))

    while work:
        pc, source = work.pop()
        if pc not in proven:
            escape(source, "leaves proven instruction owner", pc)
            continue
        require((pc & 3) == 0, "unaligned proven instruction in PACGA reservation analysis")
        page, bit = pc >> 12, 1 << ((pc & 0xfff) >> 2)
        seen = visited.get(page, 0)
        if seen & bit:
            continue
        visited[page] = seen | bit
        mnemonic, operands = insns[pc]
        if mnemonic == "pacga":
            hazards.add(pc)
        if mnemonic in clear:
            continue
        if mnemonic in cfg.CALLS:
            target = cfg.TARGET.search(operands) if mnemonic == "bl" else None
            escape(pc, "call with live reservation",
                   int(target.group(1), 0) if target else None)
            work.append((pc + 4, pc))
            continue
        if mnemonic in cfg.STOPS:
            escape(pc, "return with live reservation")
            continue
        if mnemonic in cfg.INDIRECT:
            targets = jumps.get(pc)
            if not targets:
                escape(pc, "unknown indirect branch with live reservation")
            else:
                work.extend((target, pc) for target in targets)
            continue
        target = cfg.TARGET.search(operands)
        if mnemonic == "b":
            if target:
                work.append((int(target.group(1), 0), pc))
            else:
                escape(pc, "unresolved branch with live reservation")
            continue
        if mnemonic.startswith(("b.", "bc.")) or mnemonic in cfg.CONDITIONAL:
            if target:
                work.append((int(target.group(1), 0), pc))
            else:
                escape(pc, "unresolved conditional branch with live reservation")
        work.append((pc + 4, pc))
    escapes = [dict(va=hex(pc), reason="unsupported exclusive-state escape: " + reason,
                    **({"target": hex(target)} if target is not None else {}))
               for pc, reason, target in sorted(
                   escaped, key=lambda item: (item[0], item[1], -1 if item[2] is None else item[2]))]
    return dict(pacga=hazards, escapes=escapes)
