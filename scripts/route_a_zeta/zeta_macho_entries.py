"""Read declared Mach-O addresses only to veto jump-table guard proofs.

The returned set is not code evidence and must never be added to CFG roots.
It includes LC_MAIN, LC_THREAD/LC_UNIXTHREAD, LC_ROUTINES_64, defined symbols, and
local export addresses (including both a resolver stub and its resolver).
Re-exports name another image; their library ordinals are not addresses.
An unsupported or malformed declaration fails closed with ValueError.

These independently implemented readers follow Apple's dyld at commit
fd8d0c4d52320ebf64db34f3cb280310d905c5ae:
  mach_o/UnsafeHeader.cpp (preferredLoadAddress, getEntry, thread state)
  mach_o/ExportsTrie.cpp (terminalPayloadToSymbol)
  common/MachOLoaded.cpp (header-relative and resolver addresses)
https://github.com/apple-oss-distributions/dyld/tree/fd8d0c4d52320ebf64db34f3cb280310d905c5ae

The cache adapter deliberately translates Mach-O logical file offsets through
that image's __LINKEDIT. They are not offsets in a guessed cache member.
Input identity/immutability and full-image coverage remain caller obligations.
"""
from dataclasses import dataclass
import struct


LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_THREAD = 0x4
LC_UNIXTHREAD = 0x5
LC_ROUTINES_64 = 0x1a
LC_MAIN = 0x80000028
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_DYLD_EXPORTS_TRIE = 0x80000033
_DYLIB_LOADS = frozenset((0xc, 0x80000018, 0x8000001f, 0x20, 0x80000023))
_U64_LIMIT = 1 << 64
_MAX_COMMAND_BYTES = 16 * 1024 * 1024
_MAX_METADATA_BYTES = 128 * 1024 * 1024
_MAX_TRIE_NODES = 1_000_000
_MAX_TRIE_EDGES = 2_000_000


def _require(condition, message):
    if not condition:
        raise ValueError('Mach-O declared entries: ' + message)


def _range(start, size, limit, label):
    _require(isinstance(start, int) and isinstance(size, int) and
             0 <= start <= limit and 0 <= size <= limit - start,
             label + ' is out of bounds')


def _name(raw):
    return raw.split(b'\0', 1)[0]


@dataclass(frozen=True)
class _Segment:
    name: bytes
    address: int
    size: int
    fileoff: int
    filesize: int
    initprot: int


@dataclass(frozen=True)
class _Section:
    address: int
    size: int


class _Layout:
    def __init__(self, read_header, standalone_size=None, image_address=None):
        header = read_header(0, 32)
        _require(len(header) == 32, 'truncated Mach-O header')
        magic, cpu, _, filetype, ncmds, sizeofcmds, _, _ = struct.unpack('<8I', header)
        _require(magic == 0xfeedfacf and cpu == 0x0100000c,
                 'requires a thin little-endian ARM64 Mach-O')
        _require(filetype in (2, 6, 7, 8, 11), 'unsupported Mach-O file type')
        _require(sizeofcmds <= _MAX_COMMAND_BYTES and sizeofcmds % 8 == 0 and
                 ncmds <= sizeofcmds // 8, 'invalid load-command geometry')
        commands = read_header(32, sizeofcmds)
        _require(len(commands) == sizeofcmds, 'truncated load commands')
        self.segments, self.sections, self.commands = [], [], []
        self.dependencies = 0
        names, singletons = set(), set()
        cursor = 0
        for _ in range(ncmds):
            _range(cursor, 8, len(commands), 'load-command header')
            command, size = struct.unpack_from('<II', commands, cursor)
            _require(size >= 8 and size % 8 == 0, 'invalid load-command size')
            _range(cursor, size, len(commands), 'load command')
            body = commands[cursor:cursor + size]
            if command == LC_SEGMENT_64:
                _require(size >= 72, 'truncated segment command')
                name = _name(body[8:24])
                address, length, fileoff, filesize = struct.unpack_from('<4Q', body, 24)
                _, initprot, nsects, flags = struct.unpack_from('<4I', body, 56)
                _require(name and name not in names, 'empty or duplicate segment name')
                names.add(name)
                _require(not flags & 1, 'SG_HIGHVM segment is unsupported')
                _range(address, length, _U64_LIMIT, 'segment VM range')
                _range(fileoff, filesize, _U64_LIMIT, 'segment file range')
                _require(filesize <= length, 'segment file size exceeds VM size')
                if standalone_size is not None:
                    _range(fileoff, filesize, standalone_size, 'standalone segment bytes')
                _require(size == 72 + 80 * nsects, 'invalid section-table size')
                segment = _Segment(name, address, length, fileoff, filesize, initprot)
                self.segments.append(segment)
                for index in range(nsects):
                    at = 72 + index * 80
                    section_address, section_size = struct.unpack_from('<QQ', body, at + 32)
                    _require(_name(body[at + 16:at + 32]) == name,
                             'section declares a different segment')
                    _require(address <= section_address <= address + length and
                             section_size <= address + length - section_address,
                             'section leaves its segment')
                    self.sections.append(_Section(section_address, section_size))
            else:
                # DYLD_INFO and DYLD_INFO_ONLY are the same command family.
                key = LC_DYLD_INFO if command == LC_DYLD_INFO_ONLY else command
                if key in (LC_MAIN, LC_THREAD, LC_UNIXTHREAD, LC_ROUTINES_64, LC_SYMTAB,
                           LC_DYLD_INFO, LC_DYLD_EXPORTS_TRIE):
                    _require(key not in singletons, 'duplicate declaration command')
                    singletons.add(key)
                    self.commands.append((command, body))
                elif command in _DYLIB_LOADS:
                    _require(size >= 24, 'truncated dependent-library command')
                    nameoff = struct.unpack_from('<I', body, 8)[0]
                    _require(24 <= nameoff < size and body.find(b'\0', nameoff) >= 0,
                             'unterminated dependent-library name')
                    self.dependencies += 1
            cursor += size
        _require(cursor == len(commands), 'unconsumed load-command bytes')
        _require(len(singletons & {LC_MAIN, LC_THREAD, LC_UNIXTHREAD}) <= 1,
                 'conflicting process/thread entry commands')
        occupied = sorted((s.address, s.address + s.size) for s in self.segments if s.size)
        _require(all(a[1] <= b[0] for a, b in zip(occupied, occupied[1:])),
                 'overlapping segment VM ranges')
        self.text = next((s for s in self.segments if s.name == b'__TEXT'), None)
        self.linkedit = next((s for s in self.segments if s.name == b'__LINKEDIT'), None)
        _require(self.text is not None and self.text.filesize >= 32 + sizeofcmds,
                 'Mach-O header is not covered by __TEXT')
        if standalone_size is not None:
            _require(self.text.fileoff == 0, 'standalone __TEXT does not contain file header')
        if image_address is not None:
            _require(self.text.address == image_address, 'cache image address differs from __TEXT')

    def relative_address(self, value):
        # dyld supports two's-complement offsets for segments below __TEXT.
        delta = value if value < (1 << 63) else value - _U64_LIMIT
        address = self.text.address + delta
        _require(0 <= address < _U64_LIMIT and
                 any(s.address <= address < s.address + s.size for s in self.segments),
                 'export address leaves image VM ranges')
        return address

    def code_address(self, address, label):
        _require(0 <= address < _U64_LIMIT and address % 4 == 0 and
                 any(s.initprot & 4 and s.address <= address and
                     address + 4 <= s.address + s.filesize for s in self.segments),
                 label + ' is not an aligned file-backed executable address')
        return address


class _Metadata:
    def __init__(self, layout, read_file=None, read_vm=None):
        self.layout, self.read_file, self.read_vm = layout, read_file, read_vm
        self.remaining = _MAX_METADATA_BYTES

    def read(self, offset, length, label):
        if not length:
            return b''
        _require(0 <= length <= self.remaining, label + ' exceeds metadata budget')
        linkedit = self.layout.linkedit
        _require(linkedit is not None, label + ' lacks __LINKEDIT')
        _require(linkedit.fileoff <= offset <= linkedit.fileoff + linkedit.filesize and
                 length <= linkedit.fileoff + linkedit.filesize - offset,
                 label + ' leaves file-backed __LINKEDIT')
        self.remaining -= length
        if self.read_file is not None:
            result = self.read_file(offset, length)
        else:
            address = linkedit.address + (offset - linkedit.fileoff)
            result = self.read_vm(address, length)
        _require(len(result) == length, 'short ' + label + ' read')
        return result


def _uleb(blob, cursor, end):
    value = 0
    for index in range(10):
        _require(cursor < end, 'truncated ULEB128')
        byte = blob[cursor]
        cursor += 1
        _require(index != 9 or byte <= 1, 'ULEB128 overflows uint64')
        value |= (byte & 0x7f) << (index * 7)
        if not byte & 0x80:
            return value, cursor
    raise ValueError('Mach-O declared entries: unterminated ULEB128')


def _terminal(blob, begin, end, layout, found):
    flags, cursor = _uleb(blob, begin, end)
    value, cursor = _uleb(blob, cursor, end)
    kind = flags & 3
    _require(flags < 64 and kind != 3, 'unknown export flags or kind')
    _require(not flags & 32, 'function-variant exports need an explicit variant-table model')
    reexport, resolver = bool(flags & 8), bool(flags & 16)
    _require(not (reexport and resolver) and (kind == 0 or not (reexport or resolver)),
             'incompatible export flags')
    if reexport:
        _require(1 <= value <= layout.dependencies, 'invalid re-export library ordinal')
        _require(cursor < end and blob.find(b'\0', cursor, end) == end - 1,
                 'unterminated or trailing re-export name')
        cursor = end
    elif kind == 2:
        found.add(value)
    else:
        address = layout.relative_address(value)
        if resolver:
            resolver_offset, cursor = _uleb(blob, cursor, end)
            resolver_address = layout.relative_address(resolver_offset)
            layout.code_address(address, 'export stub')
            layout.code_address(resolver_address, 'export resolver')
            found.add(resolver_address)
        # Thread-local exports name descriptors. Keeping those addresses is a
        # conservative veto, not a claim that a descriptor is executable.
        found.add(address)
    _require(cursor == end, 'unconsumed export terminal payload')


def _export_entries(blob, layout, found):
    if not blob:
        return
    states, spans = {}, []
    stack = [(0, False)]
    parsed_bytes = edge_count = 0
    while stack:
        node, leaving = stack.pop()
        if leaving:
            states[node] = 2
            continue
        state = states.get(node, 0)
        _require(state != 1, 'cycle in export trie')
        if state == 2:
            continue
        _require(len(states) < _MAX_TRIE_NODES, 'export trie exceeds node budget')
        _range(node, 1, len(blob), 'export trie node')
        states[node] = 1
        terminal_size, cursor = _uleb(blob, node, len(blob))
        _range(cursor, terminal_size, len(blob), 'export terminal')
        terminal_end = cursor + terminal_size
        if terminal_size:
            _terminal(blob, cursor, terminal_end, layout, found)
        _range(terminal_end, 1, len(blob), 'export child count')
        children_count = blob[terminal_end]
        cursor = terminal_end + 1
        edge_count += children_count
        _require(edge_count <= _MAX_TRIE_EDGES, 'export trie exceeds edge budget')
        children, initials = [], set()
        for _ in range(children_count):
            name_end = blob.find(b'\0', cursor)
            _require(name_end > cursor, 'empty or unterminated export trie edge')
            first = blob[cursor]
            _require(first not in initials, 'ambiguous export trie edges')
            initials.add(first)
            child, cursor = _uleb(blob, name_end + 1, len(blob))
            _require(0 < child < len(blob), 'invalid export trie child offset')
            children.append(child)
        parsed_bytes += cursor - node
        _require(parsed_bytes <= len(blob), 'overlapping or excessive export trie records')
        spans.append((node, cursor))
        stack.append((node, True))
        stack.extend((child, False) for child in reversed(children))
    spans.sort()
    _require(all(a[1] <= b[0] for a, b in zip(spans, spans[1:])),
             'overlapping export trie node records')


def _symbol_entries(body, layout, metadata, found):
    _require(len(body) == 24, 'invalid LC_SYMTAB size')
    symoff, count, stroff, strsize = struct.unpack_from('<4I', body, 8)
    symbols = metadata.read(symoff, count * 16, 'symbol table')
    strings = metadata.read(stroff, strsize, 'symbol strings')
    last_nul = strings.rfind(b'\0')
    for index in range(count):
        strx, kind, section, _, value = struct.unpack_from('<IBBHQ', symbols, index * 16)
        _require(strx <= last_nul, 'symbol name leaves its string table')
        if kind & 0xe0:  # N_STAB debug values are not symbol addresses.
            continue
        symbol_type = kind & 0xe
        _require(symbol_type == 0xe or section == 0,
                 'non-section symbol has a section ordinal')
        if symbol_type == 0xe:  # N_SECT: preferred absolute VM address.
            _require(1 <= section <= len(layout.sections), 'invalid symbol section ordinal')
            owner = layout.sections[section - 1]
            _require(owner.address <= value <= owner.address + owner.size,
                     'defined symbol leaves its section')
            found.add(value)
        elif symbol_type == 2:  # N_ABS has no image-relative adjustment.
            found.add(value)
        elif symbol_type == 0xa:  # N_INDR's value is a string-table index.
            _require(value <= last_nul, 'indirect symbol name leaves its string table')
        else:
            _require(symbol_type in (0, 0xc), 'unknown nlist symbol type')


def _collect(layout, metadata):
    found, read_tries = set(), set()
    for command, body in layout.commands:
        if command == LC_MAIN:
            _require(len(body) == 24, 'invalid LC_MAIN size')
            entryoff = struct.unpack_from('<Q', body, 8)[0]
            found.add(layout.code_address(layout.text.address + entryoff, 'LC_MAIN entry'))
        elif command in (LC_THREAD, LC_UNIXTHREAD):
            _require(len(body) == 16 + 68 * 4, 'unsupported LC_UNIXTHREAD state size')
            flavor, count = struct.unpack_from('<II', body, 8)
            _require(flavor == 6 and count == 68, 'unsupported LC_UNIXTHREAD state')
            pc = struct.unpack_from('<Q', body, 16 + 32 * 8)[0]
            found.add(layout.code_address(pc, 'LC_UNIXTHREAD PC'))
        elif command == LC_ROUTINES_64:
            _require(len(body) == 72, 'invalid LC_ROUTINES_64 size')
            address = struct.unpack_from('<Q', body, 8)[0]
            if address:
                found.add(layout.code_address(address, 'LC_ROUTINES_64 initializer'))
        elif command == LC_SYMTAB:
            _symbol_entries(body, layout, metadata, found)
        else:
            if command == LC_DYLD_EXPORTS_TRIE:
                _require(len(body) == 16, 'invalid LC_DYLD_EXPORTS_TRIE size')
                offset, length = struct.unpack_from('<II', body, 8)
            else:
                _require(len(body) == 48, 'invalid LC_DYLD_INFO size')
                offset, length = struct.unpack_from('<II', body, 40)
            if (offset, length) not in read_tries:
                read_tries.add((offset, length))
                _export_entries(metadata.read(offset, length, 'exports trie'), layout, found)
    return frozenset(found)


def standalone_declared_entries(data):
    """Return only guard-veto addresses for one thin, immutable ARM64 Mach-O."""
    def read_file(offset, length):
        _range(offset, length, len(data), 'standalone read')
        return bytes(data[offset:offset + length])

    layout = _Layout(read_file, standalone_size=len(data))
    return _collect(layout, _Metadata(layout, read_file=read_file))


def cache_declared_entries(cache, image_address):
    """Read unslid veto addresses using Cache.locate/read, across cache members.

    This accepts the existing zeta_dyld_cache.Cache interface without importing
    it (and without a dependency cycle through the CFG module).
    """
    _range(image_address, 1, _U64_LIMIT, 'cache image address')

    def read_vm(address, length):
        _range(address, length, _U64_LIMIT, 'cache VM read')
        chunks, remaining = [], length
        while remaining:
            try:
                _, _, room = cache.locate(address)
                _require(isinstance(room, int) and room > 0, 'invalid cache mapping extent')
                take = min(room, remaining)
                part = bytes(cache.read(address, take))
            except (KeyError, IndexError, OSError, TypeError, ValueError) as error:
                raise ValueError('Mach-O declared entries: unmapped cache metadata') from error
            _require(len(part) == take, 'short cache mapping read')
            chunks.append(part)
            address += take
            remaining -= take
        return b''.join(chunks)

    def read_header(offset, length):
        return read_vm(image_address + offset, length)

    layout = _Layout(read_header, image_address=image_address)
    return _collect(layout, _Metadata(layout, read_vm=read_vm))
