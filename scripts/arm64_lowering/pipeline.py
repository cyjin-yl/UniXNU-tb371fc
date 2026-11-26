"""Connect bounded Mach-O parsing to the pinned zeta CFG/re-signing engine."""

from __future__ import annotations

from collections import Counter
import hashlib
import importlib.util
from pathlib import Path
import struct
import sys

from .instructions import describe
from .macho import MachOError, parse_macho


VENDOR = Path(__file__).resolve().parents[1] / "route_a_zeta"


def load_rewriter():
    """Load the vendored script, whose imports intentionally retain upstream names."""
    directory = str(VENDOR)
    if directory not in sys.path:
        sys.path.insert(0, directory)
    spec = importlib.util.spec_from_file_location(
        "route_a_userland_rewriter", VENDOR / "rewrite-zeta-userland.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def audit_userland(data: bytes) -> dict:
    image = parse_macho(data)
    counts, unsupported, hints = Counter(), [], 0
    samples = []
    for region in image.candidate_ranges:
        for offset in range(region.offset, region.end, 4):
            word = struct.unpack_from("<I", data, offset)[0]
            result = describe(word)
            if result is None:
                continue
            counts[result["mnemonic"]] += 1
            hints += result["family"] == "hint"
            entry = dict(file_offset=offset,
                         vm_address=region.vmaddr + offset - region.offset, **result)
            if not result["supported"]:
                unsupported.append(entry)
            if len(samples) < 64:
                samples.append(entry)
    return {
        "schema": "route-a-userland-audit-v1",
        "input_sha256": hashlib.sha256(data).hexdigest(),
        "input_bytes": len(data),
        "image": image.to_dict(),
        "candidate_pauth_counts": dict(sorted(counts.items())),
        "candidate_pauth_total": sum(counts.values()),
        "preserved_hint_candidates": hints,
        "unsupported_candidates": unsupported,
        "preflight_status": "blocked" if image.blockers or unsupported else "candidate_scan_completed",
        "samples": samples,
        "scan_is_code_proof": False,
        "target_isa_audited": False,
        "os_boot_verified": False,
    }


def validated_code_directory(data: bytes, signature: dict, *,
                             require_ad_hoc: bool = False,
                             page_shifts: tuple[int, ...] = (12, 14)) -> dict:
    """Parse the supported CodeDirectory layout and its effective signing limit.

    Shared by the independent page verifier and the public vendor signer.
    Version-specific fields follow Apple's CS_CodeDirectory in
    https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h
    The nonzero codeLimit64 override follows CodeDirectory::signingLimit() in
    https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_codesigning/lib/codedirectory.h

    Scatter, pre-encryption and linkage signatures require other hashing or
    signing rules and are rejected. Ordinary layouts through 0x20600 are read.
    """
    offset, size = signature["offset"], signature["size"]
    if offset < 0 or size < 12 or offset + size > len(data):
        raise MachOError("signature range is invalid")
    magic, length, count = struct.unpack_from(">III", data, offset)
    if magic != 0xFADE0CC0 or not 12 + count * 8 <= length <= size:
        raise MachOError("invalid embedded signature")
    found, slot_types, blobs = [], set(), {}
    for slot in range(count):
        slot_type, relative = struct.unpack_from(">II", data, offset + 12 + 8 * slot)
        if slot_type in slot_types:
            raise MachOError("duplicate embedded signature slot")
        slot_types.add(slot_type)
        if relative < 12 + count * 8 or relative + 8 > length:
            raise MachOError("signature slot leaves superblob")
        kind, blob_length = struct.unpack_from(">II", data, offset + relative)
        if blob_length < 8 or relative + blob_length > length:
            raise MachOError("signature blob is truncated")
        blobs[slot_type] = (kind, blob_length)
        if kind == 0xFADE0C02:
            found.append((slot_type, offset + relative, blob_length))
    if len(found) != 1 or found[0][0] != 0:
        raise MachOError("expected exactly one primary CodeDirectory")
    if any(0x1000 <= slot < 0x1005 for slot in slot_types):
        raise MachOError("alternate CodeDirectories are unsupported")
    _, base, length = found[0]
    if length < 44:
        raise MachOError("CodeDirectory header is truncated")
    version, flags, hash_offset, ident_offset, special, slots, limit32 = struct.unpack_from(">7I", data, base + 8)
    if not 0x20001 <= version <= 0x20600:
        raise MachOError(f"unsupported CodeDirectory version {version:#x}")
    header_size = next(size for minimum, size in (
        (0x20600, 108), (0x20500, 96), (0x20400, 88), (0x20300, 64),
        (0x20200, 52), (0x20100, 48), (0x20001, 44)) if version >= minimum)
    if length < header_size:
        raise MachOError("versioned CodeDirectory header is truncated")
    if struct.unpack_from(">I", data, base + 40)[0]:
        raise MachOError("nonzero CodeDirectory spare2")
    if version >= 0x20100 and struct.unpack_from(">I", data, base + 44)[0]:
        raise MachOError("CodeDirectory scatter signatures are unsupported")
    team_offset = struct.unpack_from(">I", data, base + 48)[0] if version >= 0x20200 else 0
    limit64 = 0
    if version >= 0x20300:
        if struct.unpack_from(">I", data, base + 52)[0]:
            raise MachOError("nonzero CodeDirectory spare3")
        limit64 = struct.unpack_from(">Q", data, base + 56)[0]
        if limit64 and limit32 != min(limit64, 0xFFFFFFFF):
            raise MachOError("CodeDirectory codeLimit and codeLimit64 disagree")
    if version >= 0x20500 and struct.unpack_from(">I", data, base + 92)[0]:
        raise MachOError("pre-encryption CodeDirectory hashes are unsupported")
    if version >= 0x20600 and any(struct.unpack_from(">BBHII", data, base + 96)):
        raise MachOError("linked CodeDirectory signatures are unsupported")
    limit = limit64 or limit32
    hash_size, hash_type, _, shift = struct.unpack_from(">BBBB", data, base + 36)
    if (hash_size, hash_type) != (32, 2) or shift not in page_shifts:
        raise MachOError("unsupported code-page signature layout")
    page = 1 << shift
    if limit != offset or slots != (limit + page - 1) // page:
        raise MachOError("CodeDirectory does not cover every code byte")
    hashes_start, hashes_end = hash_offset - special * 32, hash_offset + slots * 32
    if hashes_start < header_size or hashes_end > length:
        raise MachOError("code-page hashes leave CodeDirectory")
    def string_at(relative, label):
        if not header_size <= relative < length:
            raise MachOError(f"CodeDirectory {label} offset is outside its payload")
        end = data.find(b"\0", base + relative, base + length)
        if end < 0:
            raise MachOError(f"CodeDirectory {label} is unterminated")
        if relative < hashes_end and hashes_start < end + 1 - base:
            raise MachOError(f"CodeDirectory {label} overlaps hash slots")
        return bytes(data[base + relative:end]).decode("utf-8")
    identifier = string_at(ident_offset, "identifier")
    if team_offset:
        string_at(team_offset, "team identifier")
    if require_ad_hoc:
        if not flags & 2:
            raise MachOError("not an ad-hoc CodeDirectory")
        if 0x10000 in blobs and blobs[0x10000] != (0xFADE0B01, 8):
            raise MachOError("CMS-signed image; only ad-hoc images are supported")
    return dict(at=base, length=length, version=version, flags=flags,
                hash_offset=hash_offset, special_slots=special, code_slots=slots,
                code_limit=limit, code_limit32=limit32, code_limit64=limit64,
                identifier=identifier, page_shift=shift)


def verify_code_pages(data: bytes, signature: dict) -> dict:
    """Independently verify all supported code-page hashes, without the signer."""
    directory = validated_code_directory(data, signature)
    base, length = directory["at"], directory["length"]
    slots, limit = directory["code_slots"], directory["code_limit"]
    shift, hash_offset = directory["page_shift"], directory["hash_offset"]
    page = 1 << shift
    for index in range(slots):
        expected = hashlib.sha256(data[index * page:min(limit, (index + 1) * page)]).digest()
        start = base + hash_offset + index * 32
        if data[start:start + 32] != expected:
            raise MachOError(f"code-page hash mismatch at page {index}")
    return {
        "code_pages_verified": slots,
        "code_page_shift": shift,
        "code_directory_version": hex(directory["version"]),
        "effective_code_limit": limit,
        "cdhash": hashlib.sha256(data[base:base + length]).hexdigest()[:40],
        "cms_or_apple_trust_verified": False,
    }


def rewrite_userland(data: bytes, *, plain_pointers: bool = False,
                     platform_identifier: int | None = None,
                     hardened_runtime: bool | None = None,
                     pacga_policy: str = "reject", pacga_kernel=None) -> tuple[bytes, dict]:
    """Create a staged binary; the loader/kernel plain-pointer contract is external."""
    if not plain_pointers:
        raise MachOError("ordinary-pointer ABI must be explicitly selected")
    image = parse_macho(data)
    if image.blockers:
        raise MachOError("blocked input: " + "; ".join(image.blockers))
    if not image.is_arm64e:
        raise MachOError("rewrite requires a thin arm64e userland image")
    if image.code_signature is None:
        raise MachOError("rewrite requires an existing supported CodeDirectory")
    if platform_identifier is not None and not 0 <= platform_identifier <= 255:
        raise MachOError("platform identifier must fit one byte")
    original_signature = verify_code_pages(data, image.code_signature)
    rewriter = load_rewriter()
    # The stronger parser owns all geometry used by the upstream CFG engine.
    rewriter.parse = lambda blob: parse_macho(blob).to_zeta_info()
    upstream_lower = rewriter.lower

    def checked_lower(blob, info, **options):
        edits, proof = upstream_lower(blob, info, **options)
        seen = set()
        for edit in edits:
            offset = edit["fileoff"]
            if offset % 4 or offset in seen or not image.is_candidate(offset, 4):
                raise MachOError(f"CFG edit outside validated code candidates: {offset:#x}")
            seen.add(offset)
        return edits, proof

    rewriter.lower = checked_lower
    output, report = rewriter.rewrite(
        data, platform_identifier=platform_identifier, hardened_runtime=hardened_runtime,
        pacga_policy=pacga_policy, pacga_kernel=pacga_kernel)
    if len(output) != len(data):
        raise MachOError("equal-width rewrite changed the file size")
    result_image = parse_macho(output)
    if result_image.subtype_raw != 0 or result_image.blockers:
        raise MachOError("rewritten image has unexpected architecture/geometry")
    verified = verify_code_pages(output, result_image.code_signature)
    if verified["cdhash"] != report["cdhash"]:
        raise MachOError("independent CodeDirectory hash differs from signer")
    report.update(
        schema="route-a-userland-rewrite-v1",
        input_sha256=hashlib.sha256(data).hexdigest(),
        output_sha256=hashlib.sha256(output).hexdigest(),
        input_bytes=len(data), output_bytes=len(output),
        original_signature=original_signature, independent_signature=verified,
        plain_pointer_abi=True, authentication_preserved=False,
        target_isa_audited=False, os_boot_verified=False,
        artifact_kind="staged_userland_binary",
        runtime_requirements=[
            "all interacting loaders and code use ordinary pointers",
            "dyld authenticated fixups resolve to ordinary pointers",
            "kernel dyld/shared-region pagers implement ordinary authenticated rebases",
            "4K/16K slide-page handling matches the target XNU build",
            "new cdhash is included in the matching owner trust bundle",
            "non-PAuth instructions and runtime feature dispatch are verified for A77",
        ],
    )
    return output, report
