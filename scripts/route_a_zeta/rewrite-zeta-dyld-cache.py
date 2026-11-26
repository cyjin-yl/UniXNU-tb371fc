#!/usr/bin/env python3
"""Apply a dyld shared cache code proof: lower PAC words and re-sign each file.

Reads prove-zeta-dyld-cache.py results and writes a copy of every cache
file (the unmapped .symbols file excepted) to --output. Each edit's
original word is checked before its ordinary word is written. All original
code pages pass the standalone pipeline's strict signature verifier before
any output is created; completed files are independently verified again.
Every file
with edits gets its CodeDirectory code-page hashes recomputed in place:
same layout, same special slots, same flags. Its new cdhash takes the
attributes (hash type, flags, constraint category) of the original's entry
in the given Apple trust caches. A file without edits is copied unchanged.

A kernel built with 4 KiB pages accepts only 4 KiB code-signature pages
(cs_validate_codedirectory), while Apple signs cache files with 16 KiB
pages. --page-shift 12 rebuilds every file's signature: the CodeDirectory
keeps its header, identifier and special slots and hashes 4 KiB pages; the
signature is padded to 16 KiB like Apple's, the file grows to hold it, and
the header's codeSignatureSize, which dyld requires to end at the file's
end, is set before the pages are hashed. Every file then has a new cdhash
and a trust entry.

The kernel slides authenticated pointers as plain pointers when it is built
without ptrauth (vm_shared_region_slide_page_v5), so DATA needs no change.

Lowering changes corecrypto's code, whose FIPS POST integrity test
(cc_fips_test, launchd's fips boot task) compares an HMAC of it with the
value stored in __TEXT,__fips_hmacs. Each such field is filled again after
the edits, by the corecrypto fipspost_get_hmac contract that UniXNU's
seal-source-crypto-kernel.py follows for the kernel: HMAC-SHA256 with a
zero key over the first __TEXT or __TEXT_EXEC __text section, which user
code reads at the header plus the section's file offset. A field is sealed
only when that offset is header-relative and the original field holds the
HMAC of the original section, so the contract is proven on Apple's own value.
No self-test is skipped.

Primary Apple references:
https://github.com/apple-oss-distributions/dyld/blob/main/dyld/SharedCacheRuntime.cpp
https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/vm/vm_shared_region.c
"""
import argparse
from collections import Counter
import hashlib
import hmac
import importlib.util
import json
import mmap
from pathlib import Path
import shutil
import struct
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from route_a_zeta import zeta_dyld_cache as dc
from arm64_lowering.proof import validate_summary
from arm64_lowering import pacga
from arm64_lowering.pipeline import validated_code_directory, verify_code_pages

CSMAGIC_EMBEDDED_SIGNATURE, CSMAGIC_CODEDIRECTORY = 0xfade0cc0, 0xfade0c02
CS_HASHTYPE_SHA256 = 2
HEADER_SIGNATURE_SIZE = 0x30   # dyld_cache_header.codeSignatureSize
SIGNATURE_ALIGN = 0x4000


def sibling(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rewriter = sibling('zeta_cache_trust_rewriter', 'rewrite-zeta-userland.py')
FIPS_HMAC_KEY = bytes(32)


def fips_seals(cache):
    """{file index: [(image path, HMAC field offset, __text offset, __text size)]}: the corecrypto
    POST HMAC fields whose original value proves the fipspost_get_hmac contract on the original code."""
    seals = {}
    for address, path in cache.images:
        image = dc.Image(cache, address, path)
        fields = [s for s in image.sections if s['name'] == '__fips_hmacs']
        if not fields:
            continue
        if len(fields) != 1 or fields[0]['size'] != 32:
            raise ValueError(f'{path}: expected one 32-byte __fips_hmacs field')
        # fipspost_get_hmac: the first __text of a segment named __TEXT* (strncmp), in load order.
        text = next((s for s in image.sections if s['name'] == '__text' and s['segment'] in ('__TEXT', '__TEXT_EXEC')), None)
        if text is None or text['fileoff'] != text['addr'] - address:
            continue   # user code would hash other bytes; Apple's value does not hold either
        index, text_offset, room = cache.locate(text['addr'])
        field_index, field_offset, _ = cache.locate(fields[0]['addr'])
        if room < text['size'] or field_index != index:
            raise ValueError(f'{path}: __text and __fips_hmacs are not in one mapping of one file')
        if text_offset <= field_offset < text_offset + text['size']:
            raise ValueError(f'{path}: the HMAC field lies in the hashed code')
        data = cache.files[index].data
        stored = bytes(data[field_offset:field_offset + 32])
        if hmac.digest(FIPS_HMAC_KEY, data[text_offset:text_offset + text['size']], 'sha256') != stored:
            continue   # the original does not pass its own test; leave it as Apple shipped it
        seals.setdefault(index, []).append((path, field_offset, text_offset, text['size']))
    return seals


def signature_info(data, signature_offset, signature_size):
    """The cache format places its bounded signature at the file's end."""
    if signature_offset + signature_size != len(data):
        raise ValueError('cache signature does not end at the file end')
    return dict(offset=signature_offset, size=signature_size)


def code_directory(data, signature_offset, signature_size):
    """(offset, length), admitted by the same strict parser as standalone images."""
    directory = validated_code_directory(data, signature_info(data, signature_offset, signature_size))
    return directory['at'], directory['length']


def resign(data, signature_offset, signature_size, offsets):
    """Hash edited pages in place after main has verified every original page.

    This signer never supplies the independent input/output verification result.
    Returns (cdhash, number of pages rehashed).
    """
    directory = validated_code_directory(data, signature_info(data, signature_offset, signature_size))
    cd, length = directory['at'], directory['length']
    hash_offset, limit = directory['hash_offset'], directory['code_limit']
    page = 1 << directory['page_shift']
    if any(offset < 0 or offset >= limit for offset in offsets):
        raise ValueError('edited byte is outside signed code')
    pages = {offset // page for offset in offsets}
    for index in sorted(pages):
        digest = hashlib.sha256(data[index * page:min((index + 1) * page, limit)]).digest()
        data[cd + hash_offset + 32 * index:cd + hash_offset + 32 * (index + 1)] = digest
    return hashlib.sha256(data[cd:cd + length]).hexdigest()[:40], len(pages)


def rebuild_layout(original, signature_offset, signature_size, page_shift):
    """Validate the original mmap without concatenating another full cache copy."""
    if page_shift not in (12, 14):
        raise ValueError('unsupported code-page shift')
    directory = validated_code_directory(original, signature_info(original, signature_offset, signature_size))
    # Retain the established prefix+hashes layout; do not truncate trailing data.
    if directory['hash_offset'] + 32 * directory['code_slots'] != directory['length']:
        raise ValueError('CodeDirectory has trailing data unsupported by page-size rebuilding')
    return directory


def signature_blobs(original, signature_offset):
    """Iterate only after validated_code_directory has admitted the superblob."""
    count = struct.unpack_from('>I', original, signature_offset + 8)[0]
    for slot in range(count):
        kind, relative = struct.unpack_from('>II', original, signature_offset + 12 + 8 * slot)
        at = signature_offset + relative
        magic, length = struct.unpack_from('>II', original, at)
        yield kind, magic, at, length


def rebuilt_signature(code, original, signature_offset, signature_size, page_shift):
    """Rebuild using the validated original full file, usually an mmap.

    No code+signature concatenation is needed for validation. The original
    CodeDirectory prefix and its canonical 32/64-bit limits are preserved.
    main independently verifies both the original and the assembled output.
    Returns (signature, cdhash).
    """
    directory = rebuild_layout(original, signature_offset, signature_size, page_shift)
    if len(code) != directory['code_limit']:
        raise ValueError('rebuilt code size differs from the validated signing limit')
    page = 1 << page_shift
    slots = (len(code) + page - 1) // page
    blobs = []
    for kind, magic, at, length in signature_blobs(original, signature_offset):
        if magic == CSMAGIC_CODEDIRECTORY:
            hash_offset = directory['hash_offset']
            blob = bytearray(original[at:at + hash_offset])
            struct.pack_into('>I', blob, 4, hash_offset + 32 * slots)
            struct.pack_into('>I', blob, 28, slots)
            blob[39] = page_shift
            view = memoryview(code)
            for index in range(slots):
                blob.extend(hashlib.sha256(view[index * page:min((index + 1) * page, len(code))]).digest())
            del view
            blob = bytes(blob)
            cdhash = hashlib.sha256(blob).hexdigest()[:40]
        else:
            blob = bytes(original[at:at + length])
        blobs.append((kind, blob))
    offset, index = 12 + 8 * len(blobs), bytearray()
    for kind, blob in blobs:
        index.extend(struct.pack('>II', kind, offset))
        offset += len(blob)
    return struct.pack('>III', CSMAGIC_EMBEDDED_SIGNATURE, offset, len(blobs)) + bytes(index) + b''.join(
        blob for _, blob in blobs), cdhash


def signature_length(original, signature_offset, signature_size, page_shift):
    """Determine rebuilt size from the same admitted original layout."""
    directory = rebuild_layout(original, signature_offset, signature_size, page_shift)
    blobs = list(signature_blobs(original, signature_offset))
    slots = (directory['code_limit'] + (1 << page_shift) - 1) // (1 << page_shift)
    return 12 + 8 * len(blobs) + sum(
        directory['hash_offset'] + 32 * slots if magic == CSMAGIC_CODEDIRECTORY else length
        for _, magic, _, length in blobs)


def verified_signature(data, signature_offset, signature_size):
    """Independent verifier shared with the standalone pipeline, not this signer."""
    return verify_code_pages(data, signature_info(data, signature_offset, signature_size))


def verify_signature(data, signature_offset, signature_size):
    return verified_signature(data, signature_offset, signature_size)['cdhash']


def original_signatures(cache):
    """Verify every input before creating outputs or changing any code bytes."""
    return [dict(sha256=hashlib.sha256(item.data).hexdigest(),
                 signature=verified_signature(item.data, *item.signature)) for item in cache.files]


def trust_entries(paths):
    """Only known static/Cryptex OS envelopes; retain the original attributes."""
    trusted, sources = {}, []
    for path in paths:
        blob = path.read_bytes()
        kind, payload = rewriter.im4p_payload(blob)
        if kind not in ('trst', 'trcs'):
            raise ValueError(f'unexpected trust-cache IM4P type: {kind}')
        entries = rewriter.trust_cache_entries(payload)
        for cdhash, attributes in entries.items():
            if cdhash in trusted and trusted[cdhash] != attributes:
                raise ValueError('conflicting attributes for an original trust-cache entry')
            trusted[cdhash] = attributes
        sources.append(dict(name=path.name, im4p_type=kind, im4p_sha256=hashlib.sha256(blob).hexdigest(),
                            payload_sha256=hashlib.sha256(payload).hexdigest(), version=2, entries=len(entries)))
    return trusted, sources


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--cache', required=True, type=Path, help='main cache file (subcaches beside it)')
    parser.add_argument('--proof', required=True, type=Path, help='prove-zeta-dyld-cache.py work directory')
    parser.add_argument('--output', required=True, type=Path, help='new directory for the rewritten cache')
    parser.add_argument('--apple-trust-cache', action='append', required=True, type=Path)
    parser.add_argument('--page-shift', type=int, choices=(12, 14),
                        help='rebuild every file\'s signature with pages of this shift (12 for a 4 KiB-page kernel)')
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--pacga-policy', choices=pacga.POLICIES, default='reject')
    parser.add_argument('--pacga-kernel', type=Path, help='matching linked kernel for the explicit PACGA ABI')
    args = parser.parse_args(argv)
    cache = None
    try:
        summary = json.loads((args.proof / 'summary.json').read_text())
        cache = dc.Cache(args.cache)
        edits = validate_summary(cache, summary, args.proof,
                                 pacga_policy=args.pacga_policy, pacga_kernel=args.pacga_kernel)
        originals = original_signatures(cache)
        trusted, trust_sources = trust_entries(args.apple_trust_cache)
        seals = fips_seals(cache)
        args.output.mkdir(parents=True, exist_ok=False)
        files = []
        for index, cache_file in enumerate(cache.files):
            target = args.output / cache_file.path.name
            original = originals[index]['sha256']
            signature_offset, signature_size = cache_file.signature
            original_verification = originals[index]['signature']
            original_cdhash = original_verification['cdhash']
            entry = dict(name=cache_file.path.name, original_sha256=original, original_cdhash=original_cdhash,
                         original_signature=original_verification)
            if index not in edits and index not in seals and args.page_shift is None:
                shutil.copyfile(cache_file.path, target)
                with target.open('rb') as copied, mmap.mmap(copied.fileno(), 0, access=mmap.ACCESS_READ) as copied_data:
                    verified = verified_signature(copied_data, signature_offset, signature_size)
                if verified['cdhash'] != original_cdhash:
                    raise ValueError(f'{cache_file.path.name}: copied file has a different CodeDirectory')
                files.append(dict(entry, edits=0, sha256=original, cdhash=original_cdhash, independent_signature=verified))
                continue
            table = edits.get(index, np.zeros((0, 3), dtype=np.uint64))
            if args.page_shift is None:
                data = bytearray(cache_file.data)
            else:
                data = bytearray(memoryview(cache_file.data)[:signature_offset])
            if len(table):
                offsets = table[:, 0].astype(np.int64)
                if len(np.unique(offsets)) != len(offsets):
                    raise ValueError(f'{cache_file.path.name}: two edits share a word')
                if offsets.max() + 4 > signature_offset:
                    raise ValueError(f'{cache_file.path.name}: an edit lies in the code signature')
                words = np.frombuffer(data, dtype='<u4')   # a writable view of data
                if not (words[offsets // 4] == table[:, 1].astype(np.uint32)).all():
                    raise ValueError(f'{cache_file.path.name}: an original word is not what the proof saw')
                words[offsets // 4] = table[:, 2].astype(np.uint32)
                del words
            sealed = []
            for path, field, text, size in seals.get(index, []):
                mac = hmac.digest(FIPS_HMAC_KEY, data[text:text + size], 'sha256')
                data[field:field + 32] = mac
                sealed.append(dict(image=path, hmac_offset=field, text_offset=text, text_size=size, hmac=mac.hex()))
            if args.page_shift is None:
                changed = table[:, 0].astype(np.int64).tolist() + [
                    at for seal in sealed for at in range(seal['hmac_offset'], seal['hmac_offset'] + 32)]
                cdhash, pages = resign(data, signature_offset, signature_size, changed)
                new_size = signature_size
            else:
                length = signature_length(cache_file.data, signature_offset, signature_size, args.page_shift)
                new_size = -(-length // SIGNATURE_ALIGN) * SIGNATURE_ALIGN
                # The header is hashed too, so its signature size is set first.
                struct.pack_into('<Q', data, HEADER_SIGNATURE_SIZE, new_size)
                rebuilt, cdhash = rebuilt_signature(data, cache_file.data, signature_offset, signature_size, args.page_shift)
                if len(rebuilt) != length:
                    raise ValueError(f'{cache_file.path.name}: signature length changed while rebuilding')
                data += rebuilt + bytes(new_size - length)
                pages = -(-signature_offset // (1 << args.page_shift))
            verified = verified_signature(data, signature_offset, new_size)
            if verified['cdhash'] != cdhash:
                raise ValueError(f'{cache_file.path.name}: re-signed file does not verify')
            attributes = trusted.get(bytes.fromhex(original_cdhash))
            if attributes is None:
                raise ValueError(f'{cache_file.path.name}: original cdhash is not in the Apple trust caches')
            target.write_bytes(data)
            files.append(dict(entry, edits=len(table), fips_seals=sealed, pages=pages, signature_size=new_size,
                              sha256=hashlib.sha256(data).hexdigest(), cdhash=cdhash, independent_signature=verified,
                              trust_cache_entry=dict(cdhash=cdhash, hash_type=attributes[0], flags=attributes[1],
                                                     constraint_category=attributes[2], reserved0=attributes[3],
                                                     attributes_hex=attributes.hex(), copied_from_original=True)))
            print(f'{cache_file.path.name}: {len(table)} edits, cdhash {cdhash}', file=sys.stderr, flush=True)
    except (OSError, ValueError, KeyError, struct.error, IndexError, TypeError) as error:
        print(f'rewrite-zeta-dyld-cache: {error}', file=sys.stderr)
        return 2
    finally:
        if cache is not None:
            for item in cache.files:
                close = getattr(item.data, 'close', None)
                if close is not None:
                    close()
                handle = getattr(item, 'handle', None)
                if handle is not None:
                    handle.close()
    report = dict(schema='zeta-dyld-cache-rewrite-v1', cache=str(args.cache.resolve()),
                  proof=str(args.proof.resolve()), output=str(args.output.resolve()), proof_totals=summary['totals'],
                  edits=sum(f['edits'] for f in files),
                  files_changed=sum(1 for f in files if f['sha256'] != f['original_sha256']),
                  page_shift=args.page_shift, files=files, apple_trust_sources=trust_sources,
                  pacga_policy=args.pacga_policy, pacga_runtime=summary['rules']['pacga_runtime'],
                  pointer_authentication_preserved=False,
                  all_original_code_pages_verified=True, all_output_code_pages_verified=True,
                  target_isa_audited=False, os_boot_verified=False, hardware_tested=False)
    args.report.write_text(json.dumps(report, indent=1) + '\n')
    print(json.dumps({key: report[key] for key in ('edits', 'files_changed')}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
