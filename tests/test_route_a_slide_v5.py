"""Independent v5 vectors, plus optional host execution of extracted patched C.

Set ROUTE_A_XNU_PREPARED_DIR to the four-file XNU tree prepared as documented
in ROUTE_A_PLAIN_AUTH_PATCH.md. Without it only the public Python vectors run.
The C harness substitutes small type/diagnostic stubs; it is not a kernel build.
"""
import ctypes
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from arm64_lowering.slide_v5 import (
    NO_REBASE, PART_SIZE, SlideError, plain_pointer, rebase_page, rebase_part, rebase_parts,
)

VALUE_ADD, SLIDE = 0x180000000, 0x100000


def pointer(runtime_offset, *, next_bytes=0, auth=False, high8=0, diversity=0, addr_div=False, data_key=False):
    """Pack test input from the documented bit fields, not the converter API."""
    assert 0 <= runtime_offset < 1 << 34 and next_bytes % 8 == 0 and 0 <= next_bytes // 8 < 1 << 11
    raw = runtime_offset | (next_bytes // 8) << 52
    if auth:
        raw |= (1 << 63) | diversity << 34 | int(addr_div) << 50 | int(data_key) << 51
    else:
        raw |= high8 << 34
    return raw


def crossing_fixture():
    offsets = (0x20, 0xFF8, 0x1000, 0x1FF8, 0x2008, 0x3000, 0x3FF8)
    values = (0x180100010, 0xAB00000180100020, 0x180100030, 0x180100040,
              0x180100050, 0x7F00000180100060, 0x180100070)
    original, expected = bytearray(b"\xCC" * 0x4000), bytearray(b"\xCC" * 0x4000)
    for index, at in enumerate(offsets):
        step = offsets[index + 1] - at if index + 1 < len(offsets) else 0
        word = pointer(0x10 * (index + 1), next_bytes=step, auth=index % 2 == 0,
                       high8={1: 0xAB, 5: 0x7F}.get(index, 0), diversity=0xFFFF,
                       addr_div=True, data_key=bool(index & 2))
        struct.pack_into("<Q", original, at, word)
        struct.pack_into("<Q", expected, at, values[index])
    return bytes(original), bytes(expected), offsets[0]


class V5ReferenceTests(unittest.TestCase):
    def test_auth_metadata_does_not_become_a_high_tag(self):
        for key, addr_div, diversity in itertools.product((False, True), (False, True), (0, 0xFFFF)):
            raw = pointer(0x1234, auth=True, data_key=key, addr_div=addr_div, diversity=diversity)
            self.assertEqual(plain_pointer(raw, value_add=VALUE_ADD, slide=SLIDE, plain_pointers=True), 0x180101234)

    def test_nonauth_high8_is_preserved_and_slide_is_added(self):
        self.assertEqual(plain_pointer(pointer(0x5678, high8=0xAB), value_add=VALUE_ADD,
                                       slide=SLIDE, plain_pointers=True), 0xAB00000180105678)

    def test_full_page_matches_literal_expected_pointers(self):
        original, expected, start = crossing_fixture()
        self.assertEqual(rebase_page(original, start, value_add=VALUE_ADD, slide=SLIDE, plain_pointers=True), expected)

    def test_every_4k_request_order_matches_reference(self):
        original, expected, start = crossing_fixture()
        for order in itertools.permutations(range(4)):
            with self.subTest(order=order):
                self.assertEqual(rebase_parts(original, start, order=order, value_add=VALUE_ADD,
                                              slide=SLIDE, plain_pointers=True), expected)

    def test_discovery_walk_leaves_source_unmodified(self):
        original, _, start = crossing_fixture()
        result = rebase_part(original[:4096], part=0, start=start, page_size=len(original),
                             value_add=VALUE_ADD, slide=SLIDE, apply=False, plain_pointers=True)
        self.assertEqual(result.data, original[:4096])
        self.assertEqual(result.next_start, 0x1000)
        self.assertEqual(result.visited, (0x20, 0xFF8))

    def test_first_chain_start_can_be_in_last_part(self):
        page = bytearray(0x4000)
        struct.pack_into("<Q", page, 0x3020, pointer(0x1234, auth=True))
        expected = bytearray(page)
        struct.pack_into("<Q", expected, 0x3020, 0x180101234)
        for order in ((0, 1, 2, 3), (3, 2, 1, 0)):
            self.assertEqual(rebase_parts(page, 0x3020, order=order, value_add=VALUE_ADD,
                                          slide=SLIDE, plain_pointers=True), expected)

    def test_chain_can_skip_parts(self):
        page = bytearray(0x4000)
        struct.pack_into("<Q", page, 0x20, pointer(0x1234, auth=True, next_bytes=0x3000))
        struct.pack_into("<Q", page, 0x3020, pointer(0x5678, high8=0xAB))
        expected = bytearray(page)
        struct.pack_into("<Q", expected, 0x20, 0x180101234)
        struct.pack_into("<Q", expected, 0x3020, 0xAB00000180105678)
        self.assertEqual(rebase_parts(page, 0x20, order=(3, 1, 2, 0), value_add=VALUE_ADD,
                                      slide=SLIDE, plain_pointers=True), expected)

    def test_no_rebase_page_is_unchanged(self):
        page = bytes(range(256)) * 64
        for function in (rebase_page, rebase_parts):
            self.assertEqual(function(page, NO_REBASE, value_add=VALUE_ADD, slide=SLIDE, plain_pointers=True), page)

    def test_a_single_4k_slide_page_is_supported(self):
        page = bytearray(4096)
        struct.pack_into("<Q", page, 4088, pointer(0x1234, auth=True))
        expected = bytearray(page)
        struct.pack_into("<Q", expected, 4088, 0x180101234)
        self.assertEqual(rebase_parts(page, 4088, value_add=VALUE_ADD, slide=SLIDE, plain_pointers=True), expected)

    def test_plain_pointer_contract_is_required(self):
        for function, args in ((plain_pointer, (0,)), (rebase_page, (bytes(4096), NO_REBASE)),
                               (rebase_parts, (bytes(4096), NO_REBASE))):
            with self.assertRaisesRegex(SlideError, "asserted explicitly"):
                function(*args, value_add=VALUE_ADD, slide=SLIDE)

    def test_invalid_starts_and_chain_exit_are_rejected(self):
        for start in (1, 0x4000, 0xFFFE):
            with self.assertRaises(SlideError):
                rebase_page(bytes(0x4000), start, value_add=VALUE_ADD, slide=0, plain_pointers=True)
        page = bytearray(0x4000)
        struct.pack_into("<Q", page, 0x3FF8, pointer(0, auth=True, next_bytes=8))
        for function in (rebase_page, rebase_parts):
            with self.assertRaisesRegex(SlideError, "chain leaves"):
                function(page, 0x3FF8, value_add=VALUE_ADD, slide=0, plain_pointers=True)

    def test_invalid_part_and_duplicate_request_are_rejected(self):
        with self.assertRaisesRegex(SlideError, "requested part"):
            rebase_part(bytes(4096), part=1, start=0, page_size=16384,
                        value_add=VALUE_ADD, slide=0, plain_pointers=True)
        with self.assertRaisesRegex(SlideError, "exactly once"):
            rebase_parts(bytes(16384), NO_REBASE, order=(0, 1, 2, 2),
                         value_add=VALUE_ADD, slide=0, plain_pointers=True)

    def test_uint64_wrap_matches_source_type(self):
        self.assertEqual(plain_pointer(pointer(0x10, auth=True), value_add=0xFFFFFFFFFFFFFFF8,
                                       slide=0x10, plain_pointers=True), 0x18)

    def test_slide_rejects_a_value_that_would_truncate(self):
        with self.assertRaisesRegex(SlideError, "invalid slide"):
            plain_pointer(0, value_add=VALUE_ADD, slide=1 << 32, plain_pointers=True)


def extract_function(source, name):
    match = re.search(r"(?:static )?kern_return_t\n" + re.escape(name) + r"\(\n", source)
    if match is None:
        raise ValueError(f"missing source function: {name}")
    end = source.index("\n}\n", match.start()) + 3
    return source[match.start():end]


C_TYPES = r"""
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef __has_feature
#define __has_feature(x) 0
#endif
#define __unused __attribute__((unused))
#define PAGE_SIZE 4096u
#define CONFIG_SPTM 0
#define VM_SR_PART_NONE 0xFFFFu
#define DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE 0xFFFFu
#define DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE 0xFFFFu
#define DYLD_CHAINED_PTR_START_NONE 0xFFFFu
#define DYLD_CHAINED_PTR_ARM64E 1
#define DYLD_CHAINED_PTR_64 2
#define DYLD_CHAINED_PTR_32 3
#define DYLD_CHAINED_PTR_64_OFFSET 6
#define DYLD_CHAINED_PTR_ARM64E_USERLAND 9
#define DYLD_CHAINED_PTR_ARM64E_USERLAND24 12
#define DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE 13
#define KERN_SUCCESS 0
#define KERN_FAILURE 5
#define ktriage_record(...) ((void)0)
#define panic(...) abort()
static const bool panic_on_dyld_issue = false;
typedef int kern_return_t;
typedef uintptr_t vm_offset_t;
typedef uint64_t mach_vm_offset_t;
typedef int ptrauth_key;
enum {ptrauth_key_asia = 0, ptrauth_key_asda = 2};
typedef struct {void *dyld_link_info; uint32_t dyld_link_info_size;} pager_t;
typedef pager_t *dyld_pager_t;
struct mwl_info_hdr {
    uint32_t mwli_binds_offset, mwli_binds_count, mwli_chains_offset, mwli_pointer_format;
    uint64_t mwli_image_address, mwli_slide;
};
struct dyld_chained_starts_in_image {uint32_t seg_count, seg_info_offset[1];};
struct dyld_chained_starts_in_segment {
    uint32_t size;
    uint16_t page_size, pointer_format;
    uint64_t segment_offset;
    uint32_t max_valid_pointer;
    uint16_t page_count, page_start[1];
};
/* Model only architectural results, not speculation barriers or kernel locking. */
static bool _delta_ptr_within_page_nospec(uint64_t **chain, uint64_t delta, bool *crossing, __unused uintptr_t userVA) {
    if (delta == 0) {return false;}
    uintptr_t offset = (uintptr_t)*chain & (PAGE_SIZE - 1);
    if (delta > PAGE_SIZE - sizeof(**chain) - offset) {
        *crossing = true;
        return false;
    }
    *chain = (uint64_t *)((uintptr_t)*chain + delta);
    return true;
}
/* The tested Route A paths use the real auth helpers; other formats are stubs. */
static kern_return_t fixupPage64(__unused uint64_t userVA, __unused vm_offset_t contents,
    __unused void *link_info, __unused struct dyld_chained_starts_in_segment *segInfo,
    __unused uint32_t pageIndex, __unused bool offsetBased) {return KERN_FAILURE;}
static kern_return_t fixupPage32(__unused uint64_t userVA, __unused vm_offset_t contents,
    __unused void *link_info, __unused uint32_t link_info_size,
    __unused struct dyld_chained_starts_in_segment *segInfo,
    __unused uint32_t pageIndex) {return KERN_FAILURE;}
typedef struct {uint32_t page_size, page_starts_count; uint64_t value_add; uint16_t page_starts[1];} entry_t;
typedef entry_t *vm_shared_region_slide_info_entry_v3_t;
typedef entry_t *vm_shared_region_slide_info_entry_v5_t;
typedef union {entry_t v3, v5;} entries_t;
typedef struct {uint32_t si_slide; entries_t *si_slide_info_entry;} slide_t;
typedef slide_t *vm_shared_region_slide_info_t;
"""

C_WRAPPERS = r"""
int route_full(uint8_t *page, uint32_t page_size, uint16_t start, uint64_t add, uint32_t slide, int version) {
    entries_t entry = {.v5 = {page_size, 1, add, {start}}};
    slide_t si = {slide, &entry};
    return version == 3 ? vm_shared_region_slide_page_v3(&si, (uintptr_t)page, 0, 0, 0)
                        : vm_shared_region_slide_page_v5(&si, (uintptr_t)page, 0, 0, 0);
}
int route_part(uint8_t *page, uint32_t page_size, uint32_t part, uint32_t start, int apply,
               uint32_t *next, uint64_t add, uint32_t slide) {
    entries_t entry = {.v5 = {page_size, 1, add, {0}}};
    slide_t si = {slide, &entry};
    return vm_shared_region_slide_part_v5(&si, (uintptr_t)page, 0, part, start, apply, next, 0);
}
int route_sign(uint64_t value, int key, uint64_t *out) {
    return signPointer(value, NULL, true, 0xFFFF, key, NULL, out);
}
int route_dyld(uint64_t word, uint32_t format, uint16_t start, uint32_t binds_count, uint64_t *out) {
    struct linking {
        struct mwl_info_hdr hdr;
        struct dyld_chained_starts_in_image starts;
        struct dyld_chained_starts_in_segment segment;
        uint64_t binds[1];
    } link = {0};
    _Alignas(4096) uint8_t page[PAGE_SIZE] = {0};
    if (start <= PAGE_SIZE - sizeof(word)) {memcpy(page + start, &word, sizeof(word));}
    link.hdr.mwli_binds_offset = offsetof(struct linking, binds);
    link.hdr.mwli_binds_count = binds_count;
    link.hdr.mwli_chains_offset = offsetof(struct linking, starts);
    link.hdr.mwli_pointer_format = format;
    link.hdr.mwli_image_address = 0x180000000ULL;
    link.hdr.mwli_slide = 0x100000;
    link.starts.seg_count = 1;
    link.starts.seg_info_offset[0] = offsetof(struct linking, segment) - offsetof(struct linking, starts);
    link.segment.size = sizeof(link.segment);
    link.segment.page_size = PAGE_SIZE;
    link.segment.page_count = 1;
    link.segment.page_start[0] = start;
    link.binds[0] = 0x220123450ULL;
    pager_t pager = {&link, sizeof(link)};
    int result = fixup_page((uintptr_t)page, link.hdr.mwli_image_address, &pager);
    if (start <= PAGE_SIZE - sizeof(word)) {memcpy(out, page + start, sizeof(word));}
    return result;
}
"""


@unittest.skipUnless(os.environ.get("ROUTE_A_XNU_PREPARED_DIR"), "requires the pinned prepared XNU source tree")
class ExtractedKernelCTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_root = Path(os.environ["ROUTE_A_XNU_PREPARED_DIR"])
        manifest = json.loads((ROOT / "upstream/route-a-kernel-sources.json").read_text())
        cls.sources = {}
        for item in manifest["xnu"]["files"]:
            raw = (cls.source_root / item["path"]).read_bytes()
            if hashlib.sha256(raw).hexdigest() != item["after_plain_auth_sha256"]:
                raise ValueError(f"prepared source differs: {item['path']}")
            cls.sources[item["path"]] = raw.decode()
        cls.compiler = shutil.which(os.environ.get("CC", "cc"))
        if not cls.compiler:
            raise RuntimeError("a C compiler is required for the explicitly requested source check")
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.native = cls.compile_library("patched", cls.sources["osfmk/vm/vm_shared_region.c"])

    @classmethod
    def compile_library(cls, name, shared_source, dyld_source=None):
        functions = "\n".join(extract_function(shared_source, function) for function in (
            "vm_shared_region_slide_page_v3", "vm_shared_region_slide_page_v5", "vm_shared_region_slide_part_v5"))
        dyld_source = cls.sources["osfmk/vm/vm_dyld_pager.c"] if dyld_source is None else dyld_source
        functions += "\n" + "\n".join(extract_function(dyld_source, function) for function in (
            "signPointer", "fixupPageAuth64", "fixupCachePageAuth64", "fixup_page"))
        work = Path(cls.temporary.name)
        source, library = work / (name + ".c"), work / (name + ".so")
        source.write_text(C_TYPES + functions + C_WRAPPERS)
        completed = subprocess.run([cls.compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC",
                                    str(source), "-o", str(library)], capture_output=True, text=True)
        if completed.returncode:
            raise RuntimeError("extracted C compilation failed:\n" + completed.stderr)
        loaded = ctypes.CDLL(str(library))
        pointer_type = ctypes.POINTER(ctypes.c_uint8)
        loaded.route_full.argtypes = [pointer_type, ctypes.c_uint32, ctypes.c_uint16, ctypes.c_uint64, ctypes.c_uint32, ctypes.c_int]
        loaded.route_part.argtypes = [pointer_type, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_int,
                                      ctypes.POINTER(ctypes.c_uint32), ctypes.c_uint64, ctypes.c_uint32]
        loaded.route_sign.argtypes = [ctypes.c_uint64, ctypes.c_int, ctypes.POINTER(ctypes.c_uint64)]
        loaded.route_dyld.argtypes = [ctypes.c_uint64, ctypes.c_uint32, ctypes.c_uint16,
                                      ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint64)]
        for function in (loaded.route_full, loaded.route_part, loaded.route_sign, loaded.route_dyld):
            function.restype = ctypes.c_int
        return loaded

    def call_parts(self, native, original, start, order):
        result = bytearray(original)
        for target in order:
            entry = start
            while entry != NO_REBASE and entry // PART_SIZE <= target:
                current = entry // PART_SIZE
                buffer = (ctypes.c_uint8 * PART_SIZE).from_buffer_copy(original[current * PART_SIZE:(current + 1) * PART_SIZE])
                following = ctypes.c_uint32()
                self.assertEqual(native.route_part(buffer, len(original), current, entry, current == target,
                                                    ctypes.byref(following), VALUE_ADD, SLIDE), 0)
                if current == target:
                    result[current * PART_SIZE:(current + 1) * PART_SIZE] = bytes(buffer)
                    break
                self.assertEqual(bytes(buffer), original[current * PART_SIZE:(current + 1) * PART_SIZE])
                entry = following.value
        return bytes(result)

    def test_patched_v5_whole_and_parts_match_literal_expected_values(self):
        original, expected, start = crossing_fixture()
        whole = (ctypes.c_uint8 * len(original)).from_buffer_copy(original)
        self.assertEqual(self.native.route_full(whole, len(original), start, VALUE_ADD, SLIDE, 5), 0)
        self.assertEqual(bytes(whole), expected)
        for order in itertools.permutations(range(4)):
            self.assertEqual(self.call_parts(self.native, original, start, order), expected)

    def test_c_no_rebase_page_and_late_chain_start(self):
        original = bytes(range(256)) * 64
        whole = (ctypes.c_uint8 * len(original)).from_buffer_copy(original)
        self.assertEqual(self.native.route_full(whole, len(original), NO_REBASE, VALUE_ADD, SLIDE, 5), 0)
        self.assertEqual(bytes(whole), original)
        late = bytearray(16384)
        struct.pack_into("<Q", late, 0x3020, pointer(0x1234, auth=True, diversity=0xFFFF, data_key=True))
        expected = bytearray(late)
        struct.pack_into("<Q", expected, 0x3020, 0x180101234)
        self.assertEqual(self.call_parts(self.native, late, 0x3020, (3, 2, 1, 0)), expected)

    def test_old_part_branch_is_a_failing_control(self):
        shared = self.sources["osfmk/vm/vm_shared_region.c"]
        addition = "#else /* __has_feature(ptrauth_calls) */\n\t\t\t\t/* Route A's plain-pointer ABI also applies to each 4 KiB part. */\n\t\t\t\tmemcpy(rebaseLocation, &value, sizeof(value));\n"
        self.assertEqual(shared.count(addition), 1)
        control = self.compile_library("missing-part-writeback", shared.replace(addition, ""))
        original, expected, start = crossing_fixture()
        observed = self.call_parts(control, original, start, (3, 2, 1, 0))
        self.assertNotEqual(observed, expected)
        self.assertEqual(observed[0x20:0x28], original[0x20:0x28])

    def test_patched_v3_auth_writeback(self):
        page = bytearray(4096)
        # V3 auth has a 32-bit runtime offset, unlike v5's 34 bits.
        struct.pack_into("<Q", page, 16, (1 << 63) | (0xFFFF << 32) | 0x1234)
        raw = (ctypes.c_uint8 * len(page)).from_buffer_copy(page)
        self.assertEqual(self.native.route_full(raw, len(page), 16, VALUE_ADD, SLIDE, 3), 0)
        self.assertEqual(struct.unpack_from("<Q", bytes(raw), 16)[0], 0x180101234)

    def test_dyld_sign_pointer_accepts_only_existing_A_key_cases(self):
        for key in (0, 2):
            value = ctypes.c_uint64(0xFFFFFFFFFFFFFFFF)
            self.assertEqual(self.native.route_sign(0x180101234, key, ctypes.byref(value)), 0)
            self.assertEqual(value.value, 0x180101234)
        value = ctypes.c_uint64(123)
        self.assertEqual(self.native.route_sign(0, 0, ctypes.byref(value)), 0)
        self.assertEqual(value.value, 0)
        self.assertEqual(self.native.route_sign(0x180101234, 1, ctypes.byref(value)), 5)

    def test_c_part_refuses_misaligned_start(self):
        page = (ctypes.c_uint8 * 4096)()
        following = ctypes.c_uint32()
        self.assertEqual(self.native.route_part(page, 16384, 0, 1, 1, ctypes.byref(following), VALUE_ADD, 0), 5)

    def test_dyld_dispatch_propagates_auth_failures(self):
        for format in (1, 9, 12):
            cases = (
                ((1 << 63) | (1 << 49) | 0x1234, 0),  # unsupported IB key
                ((1 << 63) | (3 << 49) | 0x1234, 0),  # unsupported DB key
                ((1 << 63) | (1 << 62) | 1, 0),       # auth bind ordinal == count
                ((1 << 62) | 1, 0),                   # nonauth bind ordinal == count
                ((1 << 63) | (512 << 51) | 0x1234, 0),  # chain crosses 4 KiB boundary
                ((1 << 63) | 0x1234, 4096),          # first pointer outside page
            )
            for word, start in cases:
                with self.subTest(format=format, word=word, start=start):
                    output = ctypes.c_uint64()
                    self.assertEqual(self.native.route_dyld(word, format, start, 1, ctypes.byref(output)), 5)
        for word, start in ((pointer(0x1234, auth=True), 4096),
                            (pointer(0x1234, auth=True, next_bytes=4096), 0)):
            output = ctypes.c_uint64()
            self.assertEqual(self.native.route_dyld(word, 13, start, 1, ctypes.byref(output)), 5)

    def test_dyld_dispatch_preserves_valid_rebases_and_binds(self):
        for format in (1, 9, 12):
            for key in (0, 2):
                output = ctypes.c_uint64()
                raw = (1 << 63) | (key << 49) | 0x1234
                self.assertEqual(self.native.route_dyld(raw, format, 0, 1, ctypes.byref(output)), 0)
                self.assertEqual(output.value, 0x180001234)
            for raw in ((1 << 63) | (1 << 62), (1 << 62)):
                output = ctypes.c_uint64()
                self.assertEqual(self.native.route_dyld(raw, format, 0, 1, ctypes.byref(output)), 0)
                self.assertEqual(output.value, 0x220123450)
        for raw, expected in ((pointer(0x1234, auth=True), 0x180001234),
                               (pointer(0x1234, high8=0xAB), 0xAB00000180001234)):
            output = ctypes.c_uint64()
            self.assertEqual(self.native.route_dyld(raw, 13, 0, 1, ctypes.byref(output)), 0)
            self.assertEqual(output.value, expected)

    def test_old_dispatch_is_a_failing_control(self):
        dyld = self.sources["osfmk/vm/vm_dyld_pager.c"]
        dispatch = extract_function(dyld, "fixup_page")
        old, count = re.subn(r"\t\treturn (fixup[^\n]+);", r"\t\t\1;\n\t\tbreak;", dispatch)
        self.assertEqual(count, 6)
        old = old[:-2] + "\treturn KERN_SUCCESS;\n}\n"
        control = self.compile_library("missing-error-propagation", self.sources["osfmk/vm/vm_shared_region.c"],
                                       dyld.replace(dispatch, old))
        for word, start in (((1 << 63) | (1 << 49) | 0x1234, 0),
                            ((1 << 63) | (1 << 62) | 1, 0), ((1 << 63) | 0x1234, 4096)):
            output = ctypes.c_uint64()
            self.assertEqual(control.route_dyld(word, 9, start, 1, ctypes.byref(output)), 0)
            self.assertEqual(self.native.route_dyld(word, 9, start, 1, ctypes.byref(output)), 5)


if __name__ == "__main__":
    unittest.main()
