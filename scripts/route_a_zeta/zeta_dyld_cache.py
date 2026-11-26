"""Read a split arm64e dyld shared cache: files, mappings, images and code roots.

Only what proving and rewriting the cache's code needs: the main file and
its subcaches, every mapping with its slide info, the image list, each
image's segments, instruction sections, function starts and unwind
encodings, the rebase targets of slide info version 5, and each file's
code signature location. Nothing here writes.

Structures follow dyld's include/mach-o/dyld_cache_format.h and
fixup-chains.h:
https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/dyld_cache_format.h
"""
import bisect
from contextlib import ExitStack
import mmap
import os
from pathlib import Path
import struct

import numpy as np

from route_a_zeta import zeta_userland_code as code

LC_SEGMENT_64, LC_FUNCTION_STARTS = 0x19, 0x26
INSTRUCTIONS = 0x80000400
S_SYMBOL_STUBS = 8
OBJC_STUB = 32             # fast-mode __objc_stubs entry: adrp/ldr x1, adrp/add/ldr/braa x16, 2 brk
VM_PROT_EXECUTE = 4
SLIDE_V5_NO_REBASE = 0xffff
HEADER_MAPPINGS, HEADER_SIGNATURE, HEADER_MAPPING_SLIDE = 0x10, 0x28, 0x138
HEADER_SUBCACHES, HEADER_IMAGES = 0x188, 0x1c0
SUBCACHE_ENTRY = 56          # dyld_subcache_entry: uuid, cacheVMOffset, fileSuffix[32]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def bounded(data, offset, size, label):
    require(offset >= 0 and size >= 0 and offset <= len(data) and size <= len(data) - offset,
            f'{label} leaves the cache file')


class CacheFile:
    def __init__(self, path):
        self.path = Path(path)
        with ExitStack() as stack:
            self.handle = self.path.open('rb')
            stack.callback(self.handle.close)
            self.opened_generation = self.generation()
            require(self.opened_generation['size'] >= HEADER_IMAGES + 8,
                    f'{self.path.name}: truncated cache header')
            self.data = mmap.mmap(self.handle.fileno(), 0, access=mmap.ACCESS_READ)
            stack.callback(self.data.close)
            if not self.data[:16].startswith(b'dyld_v1') or not self.data[:16].rstrip(b'\0').endswith(b'arm64e'):
                raise ValueError(f'{self.path.name}: not an arm64e dyld cache file')
            offset, count = struct.unpack_from('<II', self.data, HEADER_MAPPINGS)
            require(offset >= HEADER_IMAGES + 8 and count > 0, 'unsupported cache header/mapping layout')
            bounded(self.data, offset, 32 * count, 'mapping table')
            self.mappings = [struct.unpack_from('<QQQII', self.data, offset + 32 * i) for i in range(count)]
            self.signature = struct.unpack_from('<QQ', self.data, HEADER_SIGNATURE)
            bounded(self.data, *self.signature, 'code signature')
            require(self.signature[0] > 0 and self.signature[1] > 0, 'cache lacks a code signature')
            occupied = []
            for address, size, fileoff, maxprot, initprot in self.mappings:
                bounded(self.data, fileoff, size, 'mapped bytes')
                require(size > 0 and address + size <= 1 << 64 and fileoff + size <= self.signature[0],
                        'invalid mapping range')
                require(initprot & ~maxprot == 0, 'mapping protection exceeds maximum')
                occupied.append((fileoff, fileoff + size))
            occupied.sort()
            require(all(a[1] <= b[0] for a, b in zip(occupied, occupied[1:])), 'overlapping file mappings')
            slide_offset, slide_count = struct.unpack_from('<II', self.data, HEADER_MAPPING_SLIDE)
            bounded(self.data, slide_offset, 56 * slide_count, 'mapping/slide table')
            self.slid = [struct.unpack_from('<QQQQQQII', self.data, slide_offset + 56 * i) for i in range(slide_count)]
            mappings = set(self.mappings)
            for address, size, fileoff, info_offset, info_size, flags, maxprot, initprot in self.slid:
                require((address, size, fileoff, maxprot, initprot) in mappings, 'slide mapping differs from mapping table')
                bounded(self.data, info_offset, info_size, 'slide info')
            stack.pop_all()

    def close(self):
        try:
            self.data.close()
        finally:
            self.handle.close()


    def generation(self):
        st = os.fstat(self.handle.fileno())
        return dict(dev=st.st_dev, ino=st.st_ino, size=st.st_size,
                    mtime_ns=st.st_mtime_ns, ctime_ns=st.st_ctime_ns)


class Cache:
    def __init__(self, main):
        with ExitStack() as stack:
            main = Path(main)
            self.files = [CacheFile(main)]
            stack.callback(self.files[0].close)
            header = self.files[0].data
            offset, count = struct.unpack_from('<II', header, HEADER_SUBCACHES)
            bounded(header, offset, SUBCACHE_ENTRY * count, 'subcache table')
            suffixes = set()
            for index in range(count):
                entry = offset + SUBCACHE_ENTRY * index
                raw = header[entry + 24:entry + 56]
                require(b'\0' in raw, 'unterminated subcache suffix')
                suffix = raw.split(b'\0', 1)[0].decode('ascii')
                require(suffix.startswith('.') and '/' not in suffix and '\\' not in suffix and
                        suffix not in ('.', '..') and suffix not in suffixes, 'invalid/duplicate subcache suffix')
                suffixes.add(suffix)
                child = CacheFile(str(main) + suffix)
                stack.callback(child.close)
                require(bytes(child.data[0x58:0x68]) == bytes(header[entry:entry + 16]), 'subcache UUID mismatch')
                self.files.append(child)
            self.regions = sorted((address, size, index, fileoff, maxprot)
                                  for index, cache_file in enumerate(self.files)
                                  for address, size, fileoff, maxprot, _ in cache_file.mappings)
            self.starts = [region[0] for region in self.regions]
            require(all(a[0] + a[1] <= b[0] for a, b in zip(self.regions, self.regions[1:])),
                    'overlapping virtual cache mappings')
            offset, count = struct.unpack_from('<II', header, HEADER_IMAGES)
            bounded(header, offset, 32 * count, 'image table')
            self.images = []
            paths, addresses = set(), set()
            for index in range(count):
                address, _, _, path_offset = struct.unpack_from('<QQQI', header, offset + 32 * index)
                bounded(header, path_offset, 1, 'image path')
                end = header.find(b'\0', path_offset)
                require(end > path_offset, 'missing/unterminated image path')
                path = header[path_offset:end].decode()
                require(path not in paths and address not in addresses, 'duplicate image path/address')
                paths.add(path)
                addresses.add(address)
                self.locate(address)
                self.images.append((address, path))
            stack.pop_all()

    def check_opened_generations(self):
        # This detects observable changes to the open files. The producer must
        # still provide immutable inputs for the full attempt on its filesystem.
        for member in self.files:
            require(member.generation() == member.opened_generation,
                    f'opened cache generation changed: {member.path.name}')

    def locate(self, address):
        """(file index, file offset, bytes left in the mapping) of an unslid address."""
        index = bisect.bisect_right(self.starts, address) - 1
        if index >= 0:
            start, size, file_index, fileoff, _ = self.regions[index]
            if address < start + size:
                return file_index, fileoff + address - start, start + size - address
        raise KeyError(f'{address:#x} is not mapped by the cache')

    def read(self, address, length):
        require(length >= 0, 'negative cache read size')
        index, offset, room = self.locate(address)
        if room < length:
            raise ValueError(f'{address:#x}+{length:#x} crosses a mapping')
        return self.files[index].data[offset:offset + length]

    def executable_regions(self):
        return [(start, size, index, fileoff) for start, size, index, fileoff, prot in self.regions
                if prot & VM_PROT_EXECUTE]

    def slide_targets(self):
        """Sorted unique rebase targets of every slid mapping (slide info version 5)."""
        targets = []
        for index, cache_file in enumerate(self.files):
            for address, size, fileoff, info_offset, info_size, flags, _, _ in cache_file.slid:
                if not info_size:
                    continue
                data = cache_file.data
                require(info_size >= 24, 'truncated slide info header')
                version, page_size, count, value_add = struct.unpack_from('<III4xQ', data, info_offset)
                if version != 5:
                    raise ValueError(f'{cache_file.path.name}: slide info version {version}, expected 5')
                require(page_size in (4096, 16384) and count * page_size == size,
                        'unsupported slide page geometry')
                require(24 + 2 * count <= info_size, 'slide page starts leave slide info')
                require(value_add + 0x3ffffffff < 1 << 64, 'slide target overflows address')
                pages = struct.unpack_from(f'<{count}H', data, info_offset + 24)
                found = []
                for page, delta in enumerate(pages):
                    if delta == SLIDE_V5_NO_REBASE:
                        continue
                    at = fileoff + page * page_size + delta
                    end = fileoff + (page + 1) * page_size
                    while True:
                        require(at % 8 == 0 and at + 8 <= end, 'slide chain leaves its page')
                        raw = struct.unpack_from('<Q', data, at)[0]
                        found.append(raw & 0x3ffffffff)
                        step = (raw >> 52) & 0x7ff
                        if not step:
                            break
                        at += step * 8
                targets.append(np.array(found, dtype=np.uint64) + np.uint64(value_add))
        return np.unique(np.concatenate(targets)) if targets else np.zeros(0, dtype=np.uint64)


class Image:
    def __init__(self, cache, address, path):
        self.cache, self.address, self.path = cache, address, path
        magic, cpu, _, filetype, ncmds, sizeofcmds = struct.unpack('<6I', cache.read(address, 24))
        if magic != 0xfeedfacf or cpu != 0x0100000c or filetype not in (2, 6, 7, 8):
            raise ValueError(f'{path}: no 64-bit Mach-O header at {address:#x}')
        require(sizeofcmds % 8 == 0 and ncmds <= sizeofcmds // 8, f'{path}: bad command geometry')
        commands = cache.read(address + 32, sizeofcmds)
        self.segments, self.sections, self.function_starts_command = {}, [], None
        at = 0
        for _ in range(ncmds):
            require(at + 8 <= len(commands), f'{path}: truncated command')
            command, size = struct.unpack_from('<II', commands, at)
            require(size >= 8 and size % 8 == 0 and at + size <= len(commands), f'{path}: bad command size')
            if command == LC_SEGMENT_64:
                require(size >= 72, f'{path}: truncated segment')
                name = commands[at + 8:at + 24].split(b'\0', 1)[0].decode()
                vmaddr, vmsize, fileoff, _ = struct.unpack_from('<4Q', commands, at + 24)
                require(name not in self.segments and vmaddr + vmsize <= 1 << 64, f'{path}: invalid segment range')
                self.segments[name] = dict(vmaddr=vmaddr, vmsize=vmsize, fileoff=fileoff)
                nsects = struct.unpack_from('<I', commands, at + 64)[0]
                require(size == 72 + 80 * nsects, f'{path}: bad section table')
                for index in range(nsects):
                    base = at + 72 + 80 * index
                    addr, length, fileoff = struct.unpack_from('<QQI', commands, base + 32)
                    flags, _, reserved2 = struct.unpack_from('<III', commands, base + 64)
                    require(vmaddr <= addr <= vmaddr + vmsize and length <= vmaddr + vmsize - addr,
                            f'{path}: section leaves its segment')
                    self.sections.append(dict(segment=name, name=commands[base:base + 16].split(b'\0', 1)[0].decode(),
                                              addr=addr, size=length, fileoff=fileoff, flags=flags, reserved2=reserved2))
            elif command == LC_FUNCTION_STARTS:
                require(size == 16 and self.function_starts_command is None, f'{path}: invalid function starts command')
                self.function_starts_command = struct.unpack_from('<II', commands, at + 8)
            at += size
        require(at == sizeofcmds, f'{path}: unconsumed load command bytes')

    def instruction_sections(self):
        """Instruction sections with the file and offset that hold them, all in one cache file."""
        found, files = [], set()
        for section in self.sections:
            if section['flags'] & INSTRUCTIONS and section['size']:
                require(section['addr'] % 4 == 0 and section['size'] % 4 == 0 and
                        section['flags'] & 0xff not in (1, 0xc, 0x12), f'{self.path}: invalid instruction section')
                index, offset, room = self.cache.locate(section['addr'])
                if room < section['size']:
                    raise ValueError(f'{self.path}: {section["name"]} crosses a mapping')
                require(offset % 4 == 0, f'{self.path}: unaligned code file offset')
                require(any(start <= section['addr'] and section['addr'] + section['size'] <= start + size and prot & VM_PROT_EXECUTE
                            for start, size, owner, _, prot in self.cache.regions if owner == index),
                        f'{self.path}: instruction section is not executable')
                files.add(index)
                found.append(dict(section, offset=offset, file=index))
        if len(files) > 1:
            raise ValueError(f'{self.path}: instruction sections span cache files')
        return found

    def function_starts(self):
        linkedit = self.segments.get('__LINKEDIT')
        if not self.function_starts_command or not self.function_starts_command[1] or not linkedit:
            return []
        dataoff, datasize = self.function_starts_command
        blob = self.cache.read(linkedit['vmaddr'] + dataoff - linkedit['fileoff'], datasize)
        starts, cursor, address = [], 0, self.segments['__TEXT']['vmaddr']
        while cursor < len(blob) and blob[cursor]:
            delta, cursor = code.uleb128(blob, cursor, len(blob))
            address += delta
            starts.append(address)
        return starts

    def unwind_encodings(self):
        section = next((s for s in self.sections if s['name'] == '__unwind_info'), None)
        if not section:
            return {}
        blob = self.cache.read(section['addr'], section['size'])
        info = dict(segments=[dict(name='__TEXT', vmaddr=0, sections=[
            dict(name='__unwind_info', offset=0, size=len(blob))])])
        return code.unwind_encodings(blob, info, self.segments['__TEXT']['vmaddr'])

    def landing_pads(self):
        """Exception landing pads named by the LSDAs that __unwind_info lists."""
        section = next((s for s in self.sections if s['name'] == '__unwind_info'), None)
        if not section:
            return set()
        lsdas = code.unwind_lsdas(self.cache.read(section['addr'], section['size']), self.segments['__TEXT']['vmaddr'])
        pads = set()
        for function, lsda in lsdas.items():
            pads |= code.landing_pads(self.cache.read, function, lsda)
        return pads

    def stub_entries(self):
        """Entry points of stub sections: S_SYMBOL_STUBS by their stub size, and fast-mode
        __objc_stubs when every entry has the fixed layout."""
        entries = set()
        for section in self.sections:
            if section['flags'] & 0xff == S_SYMBOL_STUBS and section['reserved2']:
                entries.update(range(section['addr'], section['addr'] + section['size'], section['reserved2']))
            elif section['name'] == '__objc_stubs' and section['size'] % OBJC_STUB == 0:
                words = np.frombuffer(self.cache.read(section['addr'], section['size']), dtype='<u4').reshape(-1, 8)
                selector = (words[:, 0] & 0x9f00001f) == 0x90000001      # adrp x1
                branch = (words[:, 5] == 0xd71f0a11) | (words[:, 5] == 0xd61f0200)   # braa x16, x17 / br x16
                if selector.all() and branch.all():
                    entries.update(range(section['addr'], section['addr'] + section['size'], OBJC_STUB))
        return entries

    def roots(self):
        """(strong, weak, starts): unwind-covered function starts, the other starts, all starts."""
        starts = self.function_starts()
        covering = self.unwind_encodings()
        keys = sorted(covering)
        strong = set()
        for start in starts:
            index = bisect.bisect_right(keys, start) - 1
            if index >= 0 and covering[keys[index]]:
                strong.add(start)
        return strong, set(starts) - strong, set(starts)


class Coverage:
    """Address ranges of code other proofs own; membership tests and a record of what was reached."""
    def __init__(self, ranges):
        ranges = sorted(ranges)
        self.begins = [begin for begin, end in ranges]
        self.ends = [end for begin, end in ranges]
        self.reached = set()

    def __contains__(self, address):
        index = bisect.bisect_right(self.begins, address) - 1
        return index >= 0 and address < self.ends[index]
