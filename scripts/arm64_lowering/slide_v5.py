"""Reference semantics for dyld cache v5 rebases under the plain-pointer ABI.

The full-page walker and independently paged walker operate on immutable source
bytes. They model pointer values and chain traversal, not VM fault locking,
signature validation, allocation, cache coherency or kernel concurrency.

Format source: Apple XNU ac9718fb1af618d5ce8678d0dc6e8a58f252216f,
osfmk/vm/vm_shared_region.c::vm_shared_region_slide_page_v5. The patched C
functions can be exercised separately by test_route_a_slide_v5.py.
"""
from __future__ import annotations

from dataclasses import dataclass
import struct

NO_REBASE = 0xFFFF
PART_SIZE = 4096
V5_PAGE_SIZE = 16384
_U64 = (1 << 64) - 1
_OFFSET_MASK = (1 << 34) - 1


class SlideError(ValueError):
    """The proposed v5 chain or plain-pointer contract is not admitted."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SlideError(message)


def _unsigned(value: int, bits: int, name: str) -> int:
    _require(type(value) is int and 0 <= value < 1 << bits, f"invalid {name}")
    return value


def _contract(plain_pointers: bool) -> None:
    _require(plain_pointers is True, "plain-pointer ABI must be asserted explicitly")


def plain_pointer(word: int, *, value_add: int, slide: int,
                  plain_pointers: bool = False) -> int:
    """Decode one v5 pointer; authentication/diversity are intentionally absent.

    Arithmetic follows the source's uint64_t wraparound. For non-auth pointers
    the high8 field contributes to bits 56..63. For auth pointers those bits
    belong to diversity metadata and do not become a pointer tag.
    """
    _contract(plain_pointers)
    _unsigned(word, 64, "pointer word")
    _unsigned(value_add, 64, "value_add")
    _unsigned(slide, 32, "slide")
    pointer = (word & _OFFSET_MASK) + value_add + slide
    if not word >> 63:
        pointer += ((word >> 34) & 0xFF) << 56
    return pointer & _U64


def _geometry(page: bytes, start: int) -> None:
    _require(len(page) in (PART_SIZE, V5_PAGE_SIZE), "unsupported v5 page size")
    _unsigned(start, 16, "page start")
    if start != NO_REBASE:
        _require(start % 8 == 0 and start + 8 <= len(page), "page start leaves v5 page or is unaligned")


def rebase_page(page: bytes, start: int, *, value_add: int, slide: int,
                plain_pointers: bool = False) -> bytes:
    """Reference full-page traversal; reject a chain that exits its page."""
    _contract(plain_pointers)
    _geometry(page, start)
    _unsigned(value_add, 64, "value_add")
    _unsigned(slide, 32, "slide")
    output = bytearray(page)
    if start == NO_REBASE:
        return bytes(output)
    at = start
    while True:
        _require(at % 8 == 0 and at + 8 <= len(page), "chain leaves v5 page")
        word, = struct.unpack_from("<Q", page, at)
        value = plain_pointer(word, value_add=value_add, slide=slide, plain_pointers=True)
        struct.pack_into("<Q", output, at, value)
        step = ((word >> 52) & 0x7FF) * 8
        if step == 0:
            break
        at += step
    return bytes(output)


@dataclass(frozen=True)
class PartResult:
    data: bytes
    next_start: int
    visited: tuple[int, ...]


def rebase_part(source: bytes, *, part: int, start: int, page_size: int,
                value_add: int, slide: int, apply: bool = True,
                plain_pointers: bool = False) -> PartResult:
    """Traverse one 4 KiB part using offsets relative to the entire slide page.

    With apply=False, source bytes are returned unchanged and only the next
    part's entry point is discovered. Malformed chains are rejected more
    strictly than the inherited C implementation; this is not its bounds proof.
    """
    _contract(plain_pointers)
    _require(type(apply) is bool, "apply must be a bool")
    _require(page_size in (PART_SIZE, V5_PAGE_SIZE), "unsupported v5 page size")
    _require(len(source) == PART_SIZE, "part must contain exactly 4 KiB")
    _require(type(part) is int and 0 <= part < page_size // PART_SIZE, "invalid part index")
    _unsigned(start, 16, "part chain start")
    _unsigned(value_add, 64, "value_add")
    _unsigned(slide, 32, "slide")
    output, visited = bytearray(source), []
    if start == NO_REBASE:
        return PartResult(bytes(output), NO_REBASE, ())
    begin, end = part * PART_SIZE, (part + 1) * PART_SIZE
    _require(begin <= start and start + 8 <= end and start % 8 == 0, "chain start is not in requested part")
    at = start
    while True:
        relative = at - begin
        word, = struct.unpack_from("<Q", source, relative)
        visited.append(at)
        if apply:
            value = plain_pointer(word, value_add=value_add, slide=slide, plain_pointers=True)
            struct.pack_into("<Q", output, relative, value)
        step = ((word >> 52) & 0x7FF) * 8
        if step == 0:
            return PartResult(bytes(output), NO_REBASE, tuple(visited))
        at += step
        _require(at + 8 <= page_size, "chain leaves v5 page")
        if at >= end:
            return PartResult(bytes(output), at, tuple(visited))


def rebase_parts(page: bytes, start: int, *, value_add: int, slide: int,
                 order: tuple[int, ...] | None = None,
                 plain_pointers: bool = False) -> bytes:
    """Resolve each requested 4 KiB part from original bytes, in any page order.

    This deliberately does not share the full-page traversal or a mutable
    per-pager cache. Earlier parts are inspected with apply=False to discover
    where the original chain enters the requested part.
    """
    _contract(plain_pointers)
    _geometry(page, start)
    _unsigned(value_add, 64, "value_add")
    _unsigned(slide, 32, "slide")
    count = len(page) // PART_SIZE
    if order is None:
        order = tuple(range(count))
    _require(len(order) == count and all(type(index) is int for index in order) and
             sorted(order) == list(range(count)), "page request order must cover every part exactly once")
    output = bytearray(page)
    for target in order:
        entry = start
        while entry != NO_REBASE and entry // PART_SIZE < target:
            earlier = entry // PART_SIZE
            found = rebase_part(page[earlier * PART_SIZE:(earlier + 1) * PART_SIZE],
                                part=earlier, start=entry, page_size=len(page), value_add=value_add,
                                slide=slide, apply=False, plain_pointers=True)
            entry = found.next_start
        if entry == NO_REBASE or entry // PART_SIZE > target:
            continue
        result = rebase_part(page[target * PART_SIZE:(target + 1) * PART_SIZE],
                             part=target, start=entry, page_size=len(page), value_add=value_add,
                             slide=slide, plain_pointers=True)
        output[target * PART_SIZE:(target + 1) * PART_SIZE] = result.data
    return bytes(output)
