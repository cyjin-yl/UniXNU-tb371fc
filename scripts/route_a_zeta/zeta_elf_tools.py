"""Read and bind the native ELF files used by the Linux LLVM oracle.

Only ELF64 little-endian x86-64/AArch64 executables and shared objects are
supported. Dynamic filters/auditors and dependency names containing paths are
rejected rather than delegated to an unbound secondary loader.
"""
import hashlib
import os
from pathlib import Path
import re
import stat
import struct


def require(condition, message):
    if not condition:
        raise ValueError(message)


def generation(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mode,
            value.st_mtime_ns, value.st_ctime_ns)


def elf_info(reader, size):
    require(size >= 64, "llvm-mc dependency must be a native ELF64 binary")
    def read(offset, length):
        require(0 <= offset <= size and 0 <= length <= size - offset, "ELF file range is invalid")
        value = reader(offset, length)
        require(len(value) == length, "ELF file changed or is truncated")
        return value
    header = read(0, 64)
    require(header[:7] == b"\x7fELF\x02\x01\x01" and header[7] in (0, 3),
            "llvm-mc dependency must be a native ELF64 little-endian binary")
    kind, machine, version, _, phoff, _, _, ehsize, phsize, count, _, _, _ = struct.unpack_from("<HHIQQQIHHHHHH", header, 16)
    require(kind in (2, 3) and machine in (62, 183) and version == 1 and ehsize == 64
            and phsize == 56 and 0 < count <= 1024, "unsupported ELF program header geometry")
    segments = [struct.unpack("<IIQQQQQQ", read(phoff + index * phsize, phsize)) for index in range(count)]
    for _, _, offset, _, _, filesz, memsz, _ in segments:
        require(filesz <= memsz and offset <= size and filesz <= size - offset,
                "ELF program segment leaves its file or memory range")
    interpreters = [segment for segment in segments if segment[0] == 3]
    require(len(interpreters) <= 1, "multiple ELF interpreters")
    interpreter = None
    if interpreters:
        segment = interpreters[0]
        require(1 < segment[5] <= 4096, "invalid ELF interpreter size")
        value = read(segment[2], segment[5])
        require(value.endswith(b"\0") and b"\0" not in value[:-1], "invalid ELF interpreter string")
        interpreter = value[:-1].decode("ascii")
        require(interpreter.startswith("/") and not re.search(r"[\s:]", interpreter),
                "unsupported ELF interpreter path")
    dynamic = [segment for segment in segments if segment[0] == 2]
    require(len(dynamic) <= 1, "multiple ELF dynamic tables")
    tags = {}
    if dynamic:
        segment = dynamic[0]
        require(0 < segment[5] <= 1024 * 1024 and segment[5] % 16 == 0, "invalid ELF dynamic table size")
        entries = list(struct.iter_unpack("<qQ", read(segment[2], segment[5])))
        ended = False
        for tag, value in entries:
            if ended:
                require(tag == 0 and value == 0, "nonzero ELF dynamic entries after DT_NULL")
            elif tag == 0:
                ended = True
            else:
                tags.setdefault(tag, []).append(value)
        require(ended, "unterminated ELF dynamic table")
    require(not any(tag in tags for tag in (0x7ffffffd, 0x7fffffff, 0x6ffffefb, 0x6ffffefc)),
            "ELF filters or auditors are not a closed decoder dependency graph")
    values = {tag: tags.get(tag, []) for tag in (1, 14, 15, 29)}
    require(all(len(values[tag]) <= 1 for tag in (14, 15, 29)), "duplicate ELF SONAME or search path")
    strings = {}
    if any(values.values()):
        require(len(tags.get(5, [])) == len(tags.get(10, [])) == 1, "missing ELF dynamic string table")
        address, length = tags[5][0], tags[10][0]
        require(0 < length <= size, "ELF dynamic string table size is invalid")
        mappings, cursor = [], address
        while cursor < address + length:
            candidates = [segment for segment in segments if segment[0] == 1
                          and segment[3] <= cursor < segment[3] + segment[5]]
            require(len(candidates) == 1, "ELF string table has missing or ambiguous file backing")
            segment = candidates[0]
            end = min(address + length, segment[3] + segment[5])
            require(not any(other[0] == 1 and cursor < other[3] < end for other in segments),
                    "ELF string table LOADs overlap")
            mappings.append((cursor, end, segment[2] + cursor - segment[3]))
            cursor = end
        def string_bytes(start, amount):
            end, chunks = start + amount, []
            for low, high, offset in mappings:
                if low <= start < high:
                    count = min(high, end) - start
                    chunks.append(read(offset + start - low, count))
                    start += count
                    if start == end:
                        return b"".join(chunks)
            raise ValueError("ELF dynamic string leaves its file-backed mappings")
        for tag, indexes in values.items():
            for index in indexes:
                require(index < length, "ELF dynamic string index is outside its table")
                raw = string_bytes(address + index, min(4096, length - index))
                require(b"\0" in raw, "unterminated or oversized ELF dynamic string")
                strings[(tag, index)] = raw.split(b"\0", 1)[0].decode("ascii")
    names = [strings[(1, index)] for index in values[1]]
    require(len(set(names)) == len(names) and all(re.fullmatch(r"[A-Za-z0-9_+.-]+", name)
                                               and name not in (".", "..") for name in names),
            "ELF DT_NEEDED is duplicate or contains an unsupported search path")
    singleton = lambda tag: strings[(tag, values[tag][0])] if values[tag] else None
    return dict(kind=kind, machine=machine, interpreter=interpreter, needed=names,
                soname=singleton(14), rpath=singleton(15), runpath=singleton(29))


class BoundELF:
    def __init__(self, selected, *, executable=False, max_bytes=4 * 1024 ** 3):
        self.fd = None
        self.invocation = str(Path(selected).absolute())
        require(not re.search(r"[\s:]", self.invocation), "unsupported decoder ELF path")
        try:
            self.path = str(Path(self.invocation).resolve(strict=True))
            require(not re.search(r"[\s:]", self.path), "unsupported resolved decoder ELF path")
            self.invocation_generation = generation(os.lstat(self.invocation))
            self.fd = os.open(self.path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            metadata = os.fstat(self.fd)
            require(stat.S_ISREG(metadata.st_mode) and (not executable or metadata.st_mode & 0o111),
                    "decoder ELF is not a regular readable/executable file")
            require(0 <= metadata.st_size <= max_bytes, "decoder ELF exceeds the remaining content-byte budget")
            self.binary_generation = generation(metadata)
            self.verify()
            self.elf = elf_info(lambda offset, length: os.pread(self.fd, length, offset), metadata.st_size)
            digest, offset = hashlib.sha256(), 0
            while offset < metadata.st_size:
                block = os.pread(self.fd, min(1024 * 1024, metadata.st_size - offset), offset)
                require(bool(block), "decoder ELF truncated while hashing")
                digest.update(block)
                offset += len(block)
            self.verify()
            self.identity = dict(path=self.path, size=metadata.st_size, sha256=digest.hexdigest())
        except BaseException as error:
            try:
                self.close()
            except BaseException as cleanup:
                error.add_note("bound ELF cleanup: " + str(cleanup))
            raise

    def verify(self):
        require(self.fd is not None
                and generation(os.fstat(self.fd)) == self.binary_generation
                and generation(os.stat(self.path)) == self.binary_generation
                and generation(os.lstat(self.invocation)) == self.invocation_generation
                and str(Path(self.invocation).resolve(strict=True)) == self.path,
                "decoder ELF generation changed during this attempt: " + self.invocation)

    def close(self):
        if self.fd is not None:
            descriptor = self.fd
            self.fd = None
            os.close(descriptor)
