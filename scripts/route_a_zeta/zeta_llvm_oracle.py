"""A content-bound, attempt-scoped LLVM MC oracle for Linux proof workers.

The opened executable, rather than a later PATH lookup, is executed via procfs.
Fork workers inherit that same descriptor and expected content identity. Kernel
file generations are checked around every invocation and remain sticky on drift;
they are not serialized into the reproducible rules manifest.
"""
from contextlib import contextmanager
from copy import deepcopy
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import tempfile
import time

from route_a_zeta.zeta_elf_tools import BoundELF, generation

VERSION_TIMEOUT = 60
DECODE_TIMEOUT = 60
CLEANUP_TIMEOUT = 5
BATCH_WORDS = 4096
OUTPUT_BYTES = 2 * 1024 * 1024
IDENTITY_BYTES = 4 * 1024 ** 3
SYSTEM_PRELOAD_DIRECTORY = "/etc"
_ACTIVE = None
_UNSET = object()
_UNREAPED = []


def require(condition, message):
    if not condition:
        raise ValueError(message)


def _group_absent(pid):
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


def _cleanup(process):
    """Only this newly created process group is signalled; no unbounded wait."""
    errors = []
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as error:
        errors.append("signal: " + str(error))
    try:
        process.wait(timeout=CLEANUP_TIMEOUT)
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        errors.append("reap: " + str(error))
    deadline = time.monotonic() + CLEANUP_TIMEOUT
    while not _group_absent(process.pid) and time.monotonic() < deadline:
        time.sleep(0.01)
    return dict(direct_child_reaped=process.returncode is not None,
                group_absent=_group_absent(process.pid), errors=errors)


def _communicate_bounded(process, data, timeout):
    """Drain both pipes under one deadline and independent byte budgets."""
    deadline = time.monotonic() + timeout
    output = {"stdout": bytearray(), "stderr": bytearray()}
    offset = 0
    with selectors.DefaultSelector() as selector:
        for name in ("stdout", "stderr"):
            stream = getattr(process, name)
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        if data:
            os.set_blocking(process.stdin.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        else:
            process.stdin.close()
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(process.args, timeout)
            for key, _ in selector.select(remaining):
                stream, name = key.fileobj, key.data
                try:
                    if name == "stdin":
                        offset += os.write(stream.fileno(), data[offset:offset + 65536])
                        if offset == len(data):
                            selector.unregister(stream)
                            stream.close()
                    else:
                        block = os.read(stream.fileno(), 65536)
                        if not block:
                            selector.unregister(stream)
                            stream.close()
                        else:
                            require(len(output[name]) + len(block) <= OUTPUT_BYTES,
                                    "llvm-mc output exceeds the bounded batch protocol")
                            output[name].extend(block)
                except BlockingIOError:
                    continue
        process.wait(timeout=max(0, deadline - time.monotonic()))
    return bytes(output["stdout"]), bytes(output["stderr"])


def parse_loader_list(stdout, stderr):
    """The glibc --list protocol; absent or extra libraries are never ignored."""
    require(not stderr, "decoder loader emitted diagnostics")
    text = stdout.decode("ascii")
    require(all(char in "\n\t" or 0x20 <= ord(char) <= 0x7e for char in text),
            "decoder loader emitted control bytes")
    libraries, direct, vdso = {}, [], False
    for line in text.splitlines():
        if not line:
            continue
        virtual = re.fullmatch(r"\tlinux-vdso(?:64)?\.so\.1 \(0x[0-9a-f]+\)", line)
        if virtual:
            require(not vdso, "duplicate virtual loader object")
            vdso = True
            continue
        item = re.fullmatch(r"\t([A-Za-z0-9_+.-]+) => (/[^\s:]+) \(0x[0-9a-f]+\)", line)
        if item:
            require(item[1] not in libraries, "duplicate decoder dependency resolution")
            libraries[item[1]] = item[2]
            continue
        loader = re.fullmatch(r"\t(/[^\s:]+)(?: => (/[^\s:]+))? \(0x[0-9a-f]+\)", line)
        require(loader is not None and not direct, "unknown decoder loader output: " + line[:240])
        direct.extend(value for value in loader.groups() if value is not None)
    require(len(libraries) <= 256, "decoder dependency count exceeds its budget")
    return libraries, direct


class DecoderSession:
    def __init__(self):
        require(not _UNREAPED, "an earlier llvm-mc child was not reaped")
        self.fd = None
        self.failed = None
        self.closed = False
        self.record = None
        self.bound = _UNSET
        self.program = None
        self.loader = None
        self.libraries = {}
        self.directory = None
        self.directory_fd = None
        self.directory_generation = None
        self.directory_entries = {}
        self.preload_directory_fd = None
        self.preload_directory_generation = None
        self.remaining_identity_bytes = IDENTITY_BYTES
        selected = shutil.which("llvm-mc")
        if selected is None:
            return
        try:
            self.program = BoundELF(selected, executable=True, max_bytes=self.remaining_identity_bytes)
            self.remaining_identity_bytes -= self.program.identity["size"]
            self.fd = self.program.fd
            self.invocation, self.path = self.program.invocation, self.program.path
            self._bind_libraries()
            self.verify()
            stdout, stderr = self.run(["--version"], b"", VERSION_TIMEOUT)
            require(not stderr, "llvm-mc version emitted diagnostics")
            version = stdout.decode("utf-8", errors="strict").strip()
            require(bool(version) and re.search(r"\bLLVM version\b", version),
                    "llvm-mc version output does not identify LLVM")
            self.record = dict(schema="route-a-llvm-mc-v2", invocation=self.invocation,
                               binary=self.program.identity, version=version,
                               execution="held-fd-library-directory-v1",
                               loader_inventory="glibc-list-trace-one-v1" if self.loader else None,
                               loader=self.loader.identity if self.loader else None,
                               system_preload=dict(path=str(Path(SYSTEM_PRELOAD_DIRECTORY) / "ld.so.preload"),
                                                   policy="require-absence") if self.loader else None,
                               dependencies={name: item.identity for name, item in sorted(self.libraries.items())})
        except BaseException as error:
            try:
                self.close()
            except BaseException as cleanup:
                error.add_note("decoder initialization cleanup: " + str(cleanup))
            raise

    def _bind_libraries(self):
        info = self.program.elf
        if info["interpreter"] is None:
            require(not info["needed"], "ELF dependencies without an identified interpreter")
            return
        self._bind_system_preload()
        self.loader = BoundELF(info["interpreter"], executable=True, max_bytes=self.remaining_identity_bytes)
        self.remaining_identity_bytes -= self.loader.identity["size"]
        require(self.loader.elf["machine"] == info["machine"]
                and self.loader.elf["interpreter"] is None and not self.loader.elf["needed"],
                "decoder interpreter is not a self-contained native loader")
        raw = self._invoke([self.loader.invocation, "--list", self.path], self.loader.fd,
                           (self.fd, self.loader.fd), b"", VERSION_TIMEOUT, loader_listing=True)
        resolutions, direct = parse_loader_list(*raw)
        require(all(str(Path(path).resolve(strict=True)) == self.loader.path for path in direct),
                "loader inventory contains an unexpected direct object")
        queue = list(info["needed"])
        while queue:
            name = queue.pop()
            if name in self.libraries:
                continue
            require(len(self.libraries) < 256, "decoder dependency graph exceeds its budget")
            if name == self.loader.elf["soname"]:
                item = self.loader
                if name in resolutions:
                    require(str(Path(resolutions[name]).resolve(strict=True)) == item.path,
                            "decoder interpreter dependency resolves to another file")
            else:
                require(name in resolutions, "unresolved decoder dependency: " + name)
                item = BoundELF(resolutions[name], max_bytes=self.remaining_identity_bytes)
                self.remaining_identity_bytes -= item.identity["size"]
            # Own it before further checks, so every failure closes its FD.
            self.libraries[name] = item
            require(item.elf["kind"] == 3 and item.elf["machine"] == info["machine"]
                    and item.elf["soname"] == name, "decoder dependency ELF or SONAME differs: " + name)
            queue.extend(item.elf["needed"])
        require(set(resolutions) <= set(self.libraries), "loader selected a library outside the DT_NEEDED closure")
        self.directory = tempfile.TemporaryDirectory(prefix="route-a-llvm-libraries-")
        for name, item in self.libraries.items():
            os.symlink(f"/proc/self/fd/{item.fd}", Path(self.directory.name) / name)
        os.chmod(self.directory.name, 0o555)
        self.directory_fd = os.open(self.directory.name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.directory_generation = generation(os.fstat(self.directory_fd))
        self.directory_entries = {name: generation(os.stat(name, dir_fd=self.directory_fd, follow_symlinks=False))
                                  for name in self.libraries}
        # Probe the exact loader/options/main/library FDs used for all later
        # version and disassembly calls. No preload changes symbol lookup order.
        argv, executable, descriptors = self._command([], listing=True)
        self._check_frozen_list(*self._invoke(argv, executable, descriptors, b"", VERSION_TIMEOUT,
                                              loader_listing=True))

    def _bind_system_preload(self):
        # glibc elf/rtld.c reads /etc/ld.so.preload independently of environment
        # LD_PRELOAD and --inhibit-cache. Bind absence AND its directory so a
        # transient create/delete cannot disappear between invocation checks.
        require(self.preload_directory_fd is None, "system preload absence is already bound")
        self.preload_directory_fd = os.open(SYSTEM_PRELOAD_DIRECTORY,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        self.preload_directory_generation = generation(os.fstat(self.preload_directory_fd))
        self.verify()

    def _check_frozen_list(self, stdout, stderr):
        resolutions, direct = parse_loader_list(stdout, stderr)
        loader_paths = {self.loader.invocation, self.loader.path, f"/proc/self/fd/{self.loader.fd}"}
        loader_paths.update(f"/proc/self/fd/{self.directory_fd}/{name}"
                            for name, item in self.libraries.items() if item is self.loader)
        require(all(path in loader_paths for path in direct), "frozen decoder selected an external direct object")
        for name, item in self.libraries.items():
            if item is self.loader and name not in resolutions:
                require(bool(direct), "frozen decoder loader object is missing")
                continue
            allowed = {f"/proc/self/fd/{self.directory_fd}/{name}", f"/proc/self/fd/{item.fd}"}
            if item is self.loader:
                allowed.update(loader_paths)
            require(resolutions.get(name) in allowed, "frozen decoder library escaped its held FD directory: " + name)
        require(set(resolutions) <= set(self.libraries), "frozen decoder loaded an unbound dependency")

    def _command(self, arguments, *, listing=False):
        if self.loader is None:
            require(not listing, "static decoder has no loader list")
            return [self.invocation, *arguments], self.fd, (self.fd,)
        directory = f"/proc/self/fd/{self.directory_fd}"
        # glibc matches --inhibit-rpath against each link_map's l_name. Cover the
        # main's empty name, original aliases, procfs paths and every library's
        # exact search-directory alias; unknown resolutions fail the probe above.
        names = {"", self.invocation, self.path, f"/proc/self/fd/{self.fd}",
                 self.loader.invocation, self.loader.path, f"/proc/self/fd/{self.loader.fd}"}
        for name, item in self.libraries.items():
            names.update((name, item.invocation, item.path, f"{directory}/{name}", f"/proc/self/fd/{item.fd}"))
        argv = [self.loader.invocation, "--inhibit-cache", "--inhibit-rpath", ":".join(sorted(names)),
                "--library-path", directory, "--argv0", self.invocation]
        if listing:
            argv.append("--list")
        argv += [f"/proc/self/fd/{self.fd}", *arguments]
        descriptors = {self.fd, self.loader.fd, self.directory_fd}
        descriptors.update(item.fd for item in self.libraries.values())
        return argv, self.loader.fd, tuple(sorted(descriptors))

    def reject(self, message):
        self.failed = self.failed or message
        raise ValueError(self.failed)

    def verify(self):
        require(not self.closed, "llvm-mc decoder session is closed")
        if self.failed is not None:
            raise ValueError(self.failed)
        try:
            require(self.bound is _UNSET or self.record == self.bound,
                    "llvm-mc session identity differs from its initial rules binding")
            if self.fd is None:
                require(shutil.which("llvm-mc") is None,
                        "llvm-mc became available after absence was bound")
            else:
                self.program.verify()
                if self.preload_directory_fd is not None:
                    require(generation(os.fstat(self.preload_directory_fd)) == self.preload_directory_generation
                            and generation(os.stat(SYSTEM_PRELOAD_DIRECTORY, follow_symlinks=False))
                            == self.preload_directory_generation, "system preload directory generation changed")
                    try:
                        os.stat("ld.so.preload", dir_fd=self.preload_directory_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        raise ValueError("system loader preload file is unsupported")
                for item in set(self.libraries.values()) | ({self.loader} if self.loader else set()):
                    item.verify()
                if self.directory_fd is not None:
                    require(generation(os.fstat(self.directory_fd)) == self.directory_generation
                            and set(os.listdir(self.directory_fd)) == set(self.libraries),
                            "decoder FD library directory generation changed")
                    for name, item in self.libraries.items():
                        require(generation(os.stat(name, dir_fd=self.directory_fd, follow_symlinks=False))
                                == self.directory_entries[name]
                                and os.readlink(name, dir_fd=self.directory_fd) == f"/proc/self/fd/{item.fd}",
                                "decoder FD library alias changed: " + name)
        except (OSError, ValueError) as error:
            self.reject("cannot retain llvm-mc decoder identity: " + str(error))

    def manifest(self):
        self.verify()
        return deepcopy(self.record)

    def bind(self, expected):
        if self.manifest() != expected:
            self.reject("worker llvm-mc differs from initial rules identity")
        self.bound = deepcopy(expected)

    def run(self, arguments, input_bytes, timeout):
        self.verify()
        require(self.fd is not None, "llvm-mc is unavailable for an undecoded instruction")
        argv, executable, descriptors = self._command(arguments)
        return self._invoke(argv, executable, descriptors, input_bytes, timeout)

    def _invoke(self, argv, executable, descriptors, input_bytes, timeout, *, loader_listing=False):
        self.verify()
        process = None
        try:
            env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C", "NO_COLOR": "1"}
            if loader_listing:
                require(self.loader is not None and executable == self.loader.fd and not input_bytes,
                        "decoder inventory requires its held loader and empty input")
                expected = ([self.loader.invocation, "--list", self.path] if self.directory_fd is None
                            else self._command([], listing=True)[0])
                require(argv == expected, "decoder inventory command differs from its explicit --list")
                # glibc 2.43 leaves mode_trace_program uninitialized for --list.
                # Its environment handler sets this flag to false for value 1;
                # the following explicit --list then selects the normal list
                # mode. Unknown objects still fail the unchanged strict parser.
                # This variable MUST NOT reach version/disassembly invocations.
                env["LD_TRACE_LOADED_OBJECTS"] = "1"
            # The FD is held across fork and exec. A rename/PATH change cannot
            # select another executable after the identity checks above.
            process = subprocess.Popen(argv,
                executable=f"/proc/self/fd/{executable}", pass_fds=descriptors,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True,
                env=env)
            stdout, stderr = _communicate_bounded(process, input_bytes, timeout)
            require(process.returncode == 0, f"llvm-mc exited with status {process.returncode}")
            require(_group_absent(process.pid), "llvm-mc left processes in its owned group")
            require(len(stdout) <= OUTPUT_BYTES and len(stderr) <= OUTPUT_BYTES,
                    "llvm-mc output exceeds the bounded batch protocol")
            self.verify()
            return stdout, stderr
        except BaseException as error:
            self.failed = self.failed or f"llvm-mc invocation failed: {error}"
            if process is not None:
                cleanup = _cleanup(process)
                if not cleanup["direct_child_reaped"] or not cleanup["group_absent"]:
                    _UNREAPED.append(process)
                    self.failed += "; incomplete cleanup: " + repr(cleanup)
                if hasattr(error, "add_note"):
                    error.add_note("llvm-mc cleanup: " + repr(cleanup))
            if isinstance(error, (OSError, subprocess.SubprocessError)):
                raise ValueError(self.failed) from error
            raise
        finally:
            if process is not None:
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None and not stream.closed:
                        try:
                            stream.close()
                        except OSError:
                            pass  # Preserve the invocation/cleanup failure.

    def close(self):
        if self.closed:
            return
        errors = []
        def release(label, operation):
            try:
                operation()
            except BaseException as error:
                errors.append((label, error))
        if self.preload_directory_fd is not None:
            descriptor = self.preload_directory_fd
            self.preload_directory_fd = None
            release("system preload directory FD", lambda: os.close(descriptor))
        if self.directory_fd is not None:
            descriptor = self.directory_fd
            self.directory_fd = None
            release("library directory permissions", lambda: os.fchmod(descriptor, 0o700))
            release("library directory FD", lambda: os.close(descriptor))
        if self.directory is not None:
            directory = self.directory
            self.directory = None
            release("library directory " + directory.name, directory.cleanup)
        for item in set(self.libraries.values()) | ({self.loader} if self.loader else set()):
            release("dependency FD " + item.invocation, item.close)
        if self.program is not None:
            release("llvm-mc FD", self.program.close)
        self.fd = None
        self.closed = True
        if errors:
            raise ValueError("decoder cleanup failed: " + "; ".join(label + ": " + str(error)
                             for label, error in errors)) from errors[0][1]


@contextmanager
def session(expected=_UNSET):
    """Nested consumers reuse an attempt; its owner always closes the binary FD."""
    global _ACTIVE
    owner = _ACTIVE is None
    if owner:
        _ACTIVE = DecoderSession()
    current = _ACTIVE
    primary = None
    try:
        if expected is not _UNSET:
            current.bind(expected)
        else:
            current.verify()
        yield current
    except BaseException as error:
        primary = error
        raise
    finally:
        if owner:
            _ACTIVE = None
            try:
                current.close()
            except BaseException as cleanup:
                if primary is None:
                    raise
                primary.add_note("decoder session cleanup: " + str(cleanup))


def decoder_manifest():
    with session() as decoder:
        return decoder.manifest()


def bind_initial_rules(expected):
    require(_ACTIVE is not None, "cache worker preparation lacks an owned decoder session")
    _ACTIVE.bind(expected)


def input_lines(words):
    return [" ".join(f"0x{(word >> shift) & 255:02x}" for shift in (0, 8, 16, 24))
            for word in words]


def parse_output(words, features, stdout, stderr):
    """Consume every output line; a skipped word needs one exact LLVM warning.

    The permitted formats are from LLVM llvmorg-19.1.7:
    llvm/tools/llvm-mc/Disassembler.cpp (Fail, not SoftFail),
    llvm/lib/Support/SourceMgr.cpp (source line/caret), and
    llvm/lib/MC/MCSubtargetInfo.cpp (requested unrecognized feature).
    AArch64Disassembler::getInstruction consumes four bytes even on Fail.
    """
    require(all(character in "\n\t" or 0x20 <= ord(character) <= 0x7e
                for character in stdout + stderr), "non-ASCII/control bytes in llvm-mc protocol")
    source = input_lines(words)
    invalid = set()
    requested = set(features.split(","))
    diagnostics = stderr.splitlines()
    index = 0
    while index < len(diagnostics):
        line = diagnostics[index]
        if not line:
            index += 1
            continue
        feature = re.fullmatch(r"'([+-][a-zA-Z0-9._-]+)' is not a recognized feature for this target \(ignoring feature\)", line)
        if feature is not None:
            require(feature[1] in requested, "llvm-mc warned about an unrequested feature")
            index += 1
            continue
        warning = re.fullmatch(r"<stdin>:([1-9][0-9]*):1: warning: invalid instruction encoding", line)
        require(warning is not None, "unexpected llvm-mc diagnostic: " + line[:240])
        number = int(warning[1])
        require(1 <= number <= len(source) and number not in invalid,
                "llvm-mc invalid-instruction index is duplicate or outside the batch")
        require(index + 2 < len(diagnostics) and diagnostics[index + 1] == source[number - 1]
                and diagnostics[index + 2] == "^", "llvm-mc invalid-instruction context differs")
        invalid.add(number)
        index += 3
    emitted, section = [], False
    for line in stdout.splitlines():
        if not line:
            continue
        if line == "\t.text":
            require(not section and not emitted, "duplicate or misplaced llvm-mc section directive")
            section = True
            continue
        require(section, "llvm-mc output is missing its text section")
        instruction = re.fullmatch(r"\t([a-z][a-z0-9.]*)(?:\t([\x20-\x7e\t]*))?", line)
        require(instruction is not None, "unexpected llvm-mc output line: " + line[:240])
        emitted.append((instruction[1], (instruction[2] or "").strip()))
    require(section and len(emitted) == len(words) - len(invalid),
            "llvm-mc output instruction count differs from input minus invalid words")
    iterator = iter(emitted)
    return {word: next(iterator) for index, word in enumerate(words, 1) if index not in invalid}


def disassemble(words, features):
    words = list(words)
    require(all(type(word) is int and 0 <= word <= 0xffffffff for word in words),
            "llvm-mc input is not a set of 32-bit instruction words")
    words = sorted(set(words))
    result = {}
    if not words:
        return result
    with session() as decoder:
        for start in range(0, len(words), BATCH_WORDS):
            batch = words[start:start + BATCH_WORDS]
            data = ("\n".join(input_lines(batch)) + "\n").encode("ascii")
            stdout, stderr = decoder.run(["--disassemble", "-triple=aarch64", "-mattr=" + features],
                                         data, DECODE_TIMEOUT)
            try:
                result.update(parse_output(batch, features, stdout.decode("ascii"), stderr.decode("ascii")))
            except (UnicodeError, ValueError) as error:
                decoder.reject("llvm-mc disassembly protocol failed: " + str(error))
        decoder.verify()
    return result
