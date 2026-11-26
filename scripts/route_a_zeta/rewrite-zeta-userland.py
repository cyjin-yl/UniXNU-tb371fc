#!/usr/bin/env python3
"""Rewrite one thin arm64e userland Mach-O into the ordinary-pointer arm64 ABI.

The SM8350 cores have no FEAT_PAuth, and XNU refuses arm64e images on an
ARM64_V8 host. Control flow is walked from the image's own function starts,
entry point and symbols (zeta_userland_code), with llvm-mc decoding the words
Capstone cannot (AMX, newer SVE) and a last gap grade for dead code after a
proven terminator. Every non-hint PAC instruction it proves to be code gets
its ordinary lowering (zeta_userland_pauth); a PAC-shaped word that is neither
proven code nor a decoded jump table stops the rewrite. Hint-space forms
(pacibsp, autibsp and friends) are architectural NOPs without FEAT_PAuth and
stay as they are. The report counts edits by the
grade of evidence that proved them code. The header becomes
CPU_SUBTYPE_ARM64_ALL: dyld then grades the process keys-off and still
accepts arm64e dylibs. Chained fixups stay unchanged; the rewritten
dyld's signing instructions are lowered too, so authenticated fixups resolve
to plain pointers. The ad-hoc CodeDirectory keeps its exact layout; its
code-page hashes are recomputed. The trust cache entry copies the original
entry's hash type, flags and launch-constraint category.

CodeDirectory platform and runtime policy fields are preserved by default.
The upstream 26-era KDK environment forced platform identifier 26 and
CS_RUNTIME on executables; these are available only as explicit overrides.
A platform byte is a signature policy field, not a way to select OS version.
This tool does not establish compatibility with any 27-era restore image.

Primary Apple references:
https://github.com/apple-oss-distributions/dyld/blob/fd8d0c4d52320ebf64db34f3cb280310d905c5ae/dyld/DyldProcessConfig.cpp
https://github.com/apple-oss-distributions/dyld/blob/fd8d0c4d52320ebf64db34f3cb280310d905c5ae/mach_o/GradedArchitectures.cpp
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from route_a_zeta import zeta_userland_code as code_proof
from route_a_zeta import zeta_userland_pauth as pauth
from arm64_lowering.macho import parse_macho
from arm64_lowering import pacga
from arm64_lowering.pipeline import validated_code_directory, verify_code_pages

CPU_TYPE_ARM64 = 0x0100000c
CPU_SUBTYPE_ARM64_ALL = 0
CPU_SUBTYPE_ARM64E = 2
CPU_SUBTYPE_MASK = 0xff000000
FILETYPES = {2: 'execute', 6: 'dylib', 7: 'dylinker', 8: 'bundle'}
LC_SEGMENT_64, LC_CODE_SIGNATURE, LC_DATA_IN_CODE = 0x19, 0x1d, 0x29
INSTRUCTIONS = 0x80000400
CSMAGIC_EMBEDDED_SIGNATURE, CSMAGIC_CODEDIRECTORY = 0xfade0cc0, 0xfade0c02
CSMAGIC_BLOBWRAPPER, CSSLOT_CODEDIRECTORY, CSSLOT_SIGNATURESLOT = 0xfade0b01, 0, 0x10000
CS_ADHOC, CS_HASHTYPE_SHA256 = 0x2, 2
CS_RUNTIME = 0x10000
CD_FLAGS, CD_PLATFORM = 12, 38    # CodeDirectory flags word and platform byte
HINT, HINT_MASK = 0xd503201f, 0xfffff01f
PAC_NAMES = ('pac', 'aut', 'xpac', 'bra', 'blra', 'reta', 'ldra')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def parse(data):
    image = parse_macho(data)
    require(not image.blockers, 'blocked input: ' + '; '.join(image.blockers))
    require(image.is_arm64e, 'not an arm64e image')
    require(image.file_type in FILETYPES, f'unsupported file type {image.file_type}')
    require(image.code_signature is not None, 'missing code signature')
    return image.to_zeta_info()


def instruction_sections(info):
    result = []
    for segment in info['segments']:
        for section in segment['sections']:
            if not section['size'] or not section['flags'] & INSTRUCTIONS:
                continue
            require(segment['initprot'] & 4, f'instruction section {section["name"]} is not executable')
            require(section['flags'] & 0xff not in (1, 0xc, 0x12), 'zero-fill instruction section')
            require(section['addr'] % 4 == 0 and section['size'] % 4 == 0, 'unaligned instruction section')
            result.append(section)
    return result


def va_to_off(info):
    def translate(address, length):
        for segment in info['segments']:
            if segment['vmaddr'] <= address and address + length <= segment['vmaddr'] + segment['filesize']:
                return segment['fileoff'] + address - segment['vmaddr']
        raise ValueError(f'address {address:#x} is not file-backed')
    return translate


def lower(data, info, *, pacga_policy="reject"):
    """Edits for proven-code PAC instructions; fails on any unproven PAC word."""
    pacga.policy(pacga_policy)
    sections = instruction_sections(info)
    if not sections:
        # Umbrella and resource-only images: an empty __text, nothing to lower.
        return [], dict(roots={}, proven_instructions=0, jump_tables=0, jump_table_entries=0, kept={},
                        edits_by_evidence={}, anomalies={})
    insns, code, tables_data, tables, anomalies, roots = code_proof.prove(
        data, info, sections, va_to_off(info), code_proof.llvm_oracle, gaps=True)
    reservation = (pacga.exclusive_analysis(insns, code, tables) if pacga_policy == pacga.ABI
                   else dict(pacga=set(), escapes=[]))
    require(not reservation["escapes"],
            "PACGA ABI rejects " + "; ".join(
                item["reason"] + " at " + item["va"] for item in reservation["escapes"][:8]))
    hazards = reservation["pacga"]
    dice = set()
    for offset, length, kind in info['dice']:
        dice.update(range(offset & ~3, (offset + length + 3) & ~3, 4))
    edits, kept, unproven, retained_poe2 = [], Counter(), [], []
    for section in sections:
        for address in range(section['addr'], section['addr'] + section['size'], 4):
            fileoff = section['offset'] + address - section['addr']
            word = struct.unpack_from('<I', data, fileoff)[0]
            mnemonic = insns[address][0]
            if address in code and fileoff not in dice and code_proof.poe2_instruction(word):
                retained_poe2.append(dict(va=hex(address), fileoff=fileoff,
                                          word=hex(word), mnemonic=mnemonic))
            try:
                if address in hazards and pacga.is_pacga(word):
                    raise ValueError("PACGA spans a live load-exclusive reservation")
                lowered = pauth.lower(word, pacga_policy=pacga_policy)
            except ValueError as error:
                if address in code and fileoff not in dice:
                    raise ValueError(f'unlowerable PAC instruction in proven code at {address:#x}: {error}')
                if address not in tables_data and fileoff not in dice:
                    unproven.append(f'unlowerable@{address:#x}: {error}')
                lowered = None
            if not lowered:
                # Only the hint-space forms decode to a PAC name and need no lowering.
                require(address not in code or word & HINT_MASK == HINT or not mnemonic.startswith(PAC_NAMES),
                        f'unsupported PAC instruction {mnemonic} in proven code at {address:#x}')
                continue
            name, ordinary = lowered
            if address in code and fileoff not in dice:
                require(mnemonic == name, f'PAC opcode/decoder disagreement at {address:#x}')
                edits.append(dict(va=hex(address), fileoff=fileoff, mnemonic=name, evidence=code[address],
                                  original_word=hex(word), ordinary_word=hex(ordinary)))
            elif address in tables_data or fileoff in dice:
                kept['table:' + name] += 1
            else:
                unproven.append(f'{name}@{address:#x}')
    require(not unproven, f'{len(unproven)} PAC-shaped words are not proven code: {", ".join(unproven[:8])}')
    proof = dict(roots=roots, proven_instructions=len(code), jump_tables=len(tables),
                 jump_table_entries=sum(t['entries'] for t in tables), kept=dict(kept),
                 edits_by_evidence=dict(Counter(edit['evidence'] for edit in edits)),
                 anomalies=dict(Counter(a['kind'] for a in anomalies)))
    proof['retained_isa_requirements'] = []
    if retained_poe2:
        proof['retained_isa_requirements'].append(dict(
            feature='FEAT_S1POE2', instruction_count=len(retained_poe2),
            mnemonic_counts=dict(Counter(item['mnemonic'] for item in retained_poe2)),
            instructions=retained_poe2, instructions_unchanged=True,
            native_on_a77=False, runtime_dispatch_verified=False))
    return edits, proof


def code_directory(data, info):
    offset, size = info['signature']
    return validated_code_directory(data, {'offset': offset, 'size': size},
                                    require_ad_hoc=True, page_shifts=(12,))


def cdhash(data, directory):
    return hashlib.sha256(data[directory['at']:directory['at'] + directory['length']]).digest()[:20]


def resign(data, directory):
    for index in range(directory['code_slots']):
        page = data[index * 4096:min((index + 1) * 4096, directory['code_limit'])]
        slot = directory['at'] + directory['hash_offset'] + 32 * index
        data[slot:slot + 32] = hashlib.sha256(page).digest()


def rewrite(original, *, platform_identifier=None, hardened_runtime=None,
            pacga_policy="reject", pacga_kernel=None):
    runtime = pacga.runtime_binding(pacga_policy, pacga_kernel)
    require(platform_identifier is None or type(platform_identifier) is int and 0 <= platform_identifier <= 255,
            'platform identifier must be an explicit byte value')
    require(hardened_runtime is None or type(hardened_runtime) is bool, 'invalid hardened runtime override')
    info = parse(original)
    geometry = parse_macho(original)
    directory = code_directory(original, info)
    original_signature = verify_code_pages(original, geometry.code_signature)
    edits, proof = lower(original, info, pacga_policy=pacga_policy)
    data = bytearray(original)
    for edit in edits:
        at = edit['fileoff']
        require(geometry.is_candidate(at, 4), 'instruction edit is outside strict code/data boundaries')
        require(at + 4 <= directory['code_limit'], 'instruction edit inside the signature')
        require(data[at:at + 4] == int(edit['original_word'], 16).to_bytes(4, 'little'), 'stale instruction edit')
        data[at:at + 4] = int(edit['ordinary_word'], 16).to_bytes(4, 'little')
    struct.pack_into('<I', data, 8, CPU_SUBTYPE_ARM64_ALL)
    flags = directory['flags']
    if hardened_runtime is not None and info['filetype'] == 2:
        flags = flags | CS_RUNTIME if hardened_runtime else flags & ~CS_RUNTIME
    struct.pack_into('>I', data, directory['at'] + CD_FLAGS, flags)
    if platform_identifier is not None:
        data[directory['at'] + CD_PLATFORM] = platform_identifier
    old_hash = cdhash(original, directory)
    resign(data, directory)
    new_hash = cdhash(data, directory)
    independent_signature = verify_code_pages(data, geometry.code_signature)
    require(independent_signature['cdhash'] == new_hash.hex(), 'independent CodeDirectory hash differs')
    # Every byte outside the edits, the subtype word and the code-page hashes is unchanged.
    changed = [i for i in range(len(data)) if data[i] != original[i]]
    owned = set(range(8, 12)) | set(range(directory['at'] + CD_FLAGS, directory['at'] + CD_FLAGS + 4))
    owned.add(directory['at'] + CD_PLATFORM)
    for edit in edits:
        owned.update(range(edit['fileoff'], edit['fileoff'] + 4))
    first = directory['at'] + directory['hash_offset']
    owned.update(range(first, first + 32 * directory['code_slots']))
    require(set(changed) <= owned, 'rewrite changed bytes it does not own')
    retained_isa = proof.pop('retained_isa_requirements', [])
    report = dict(schema='zeta-userland-rewrite-v1', filetype=FILETYPES[info['filetype']],
                  identifier=directory['identifier'], original_subtype=hex(info['subtype']),
                  subtype=hex(CPU_SUBTYPE_ARM64_ALL), code_directory_flags=hex(flags),
                  platform_identifier=data[directory['at'] + CD_PLATFORM],
                  signing_policy_overrides=dict(platform_identifier=platform_identifier, hardened_runtime=hardened_runtime),
                  instruction_counts=dict(Counter(e['mnemonic'] for e in edits)),
                  instruction_edits=len(edits), code_proof=proof, data_in_code_ranges=len(info['dice']),
                  code_slots=directory['code_slots'], original_cdhash=old_hash.hex(), cdhash=new_hash.hex(),
                  chained_fixups_unchanged=True, hardware_tested=False, os_boot_verified=False,
                  original_signature=original_signature, independent_signature=independent_signature,
                  retained_isa_requirements=retained_isa, target_isa_audited=False,
                  pacga_policy=pacga_policy, pacga_runtime=runtime)
    return bytes(data), report


def im4p_payload(blob):
    """The payload OCTET STRING of an IM4P, as (type, bytes)."""
    def element(at):
        tag, length = blob[at], blob[at + 1]
        at += 2
        if length & 0x80:
            count = length & 0x7f
            length, at = int.from_bytes(blob[at:at + count], 'big'), at + count
        return tag, at, length
    tag, at, length = element(0)
    require(tag == 0x30, 'IM4P is not a DER sequence')
    items, end = [], at + length
    while at < end:
        tag, start, length = element(at)
        items.append((tag, blob[start:start + length]))
        at = start + length
    require(len(items) >= 4 and items[0][1] == b'IM4P', 'not an IM4P')
    return items[1][1].decode(), items[3][1]


def trust_cache_entries(raw):
    version, count = struct.unpack_from('<I', raw)[0], struct.unpack_from('<I', raw, 20)[0]
    require(version == 2 and len(raw) == 24 + 24 * count, 'not a version 2 trust cache')
    return {raw[24 + 24 * i:44 + 24 * i]: raw[44 + 24 * i:48 + 24 * i] for i in range(count)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--apple-trust-cache', required=True, action='append', type=Path,
                        help='IM4P trust cache that lists the original image (repeatable)')
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--pacga-policy', choices=pacga.POLICIES, default='reject')
    parser.add_argument('--pacga-kernel', type=Path, help='matching linked kernel for the explicit PACGA ABI')
    parser.add_argument('--platform-identifier', type=int, help='explicit CodeDirectory platform byte override')
    parser.add_argument('--hardened-runtime', action=argparse.BooleanOptionalAction, default=None,
                        help='explicit executable CS_RUNTIME override; default preserves original flags')
    args = parser.parse_args(argv)
    require(not args.output.exists() and not args.report.exists(), 'refusing to overwrite output')
    original = args.input.read_bytes()
    data, report = rewrite(original, platform_identifier=args.platform_identifier, hardened_runtime=args.hardened_runtime,
                           pacga_policy=args.pacga_policy, pacga_kernel=args.pacga_kernel)
    entries = {}
    for path in args.apple_trust_cache:
        kind, raw = im4p_payload(path.read_bytes())
        entries.update(trust_cache_entries(raw))
    attributes = entries.get(bytes.fromhex(report['original_cdhash']))
    require(attributes is not None, 'the original image is not in the supplied Apple trust caches')
    report.update(input=dict(path=str(args.input), sha256=hashlib.sha256(original).hexdigest()),
                  output_sha256=hashlib.sha256(data).hexdigest(),
                  trust_cache_entry=dict(cdhash=report['cdhash'], hash_type=attributes[0], flags=attributes[1],
                                         constraint_category=attributes[2], copied_from_original=True))
    with args.output.open('xb') as stream:
        stream.write(data)
    args.output.chmod(0o755)
    with args.report.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({key: report[key] for key in ('identifier', 'instruction_edits', 'original_cdhash', 'cdhash')}))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, struct.error) as error:
        print(f'rewrite-zeta-userland: {error}', file=sys.stderr)
        sys.exit(2)
