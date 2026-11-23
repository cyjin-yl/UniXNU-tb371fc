#!/usr/bin/env python3
"""Build the pinned XNU Clang in a persistent, resumable work directory.

Large downloads/builds are explicit build-clang actions. verify-clang is local
and never substitutes successful compiler checks for a complete XNU build.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
UNIXNU_COMMIT = "8542980d02b4d2cc5c32ee3542de1760b2562aac"
LLVM_COMMIT = "58c46bae21181fb4240cf964461bea738d96d50e"
LLVM_URL = "https://github.com/llvm/llvm-project.git"
PATCH_PATH = "scripts/linux/llvm-xnu-builtin-type.patch"

# Expected values come from the documented XNU KT_GRANULE encodings, with
# eight-byte granules. This verifies actual constant evaluation and templates,
# rather than only __has_builtin or parsing three expressions.
TRAIT_PROBE = r'''#if defined(__arm64e__) || __has_feature(ptrauth_calls)
#error ordinary arm64 is required
#endif
struct PointerData { void *pointer; unsigned long data; };
struct TwoPointers { void *p[2]; };
union Overlay { void *pointer; unsigned long data; };
struct Dual { unsigned long value __attribute__((xnu_usage_semantics("pointer", "data"))); };
struct Padded { char value; alignas(16) void *pointer; };
typedef unsigned long SemanticPointer __attribute__((xnu_usage_semantics("pointer")));
struct Annotated { SemanticPointer pointer; unsigned long data; };
template<class T> constexpr const char *type_signature() {
    return __builtin_xnu_type_signature(T);
}
static_assert(__builtin_xnu_type_signature(void *)[0] == '1');
static_assert(__builtin_xnu_type_signature(unsigned long)[0] == '2');
static_assert(__builtin_xnu_type_signature(PointerData)[0] == '1');
static_assert(__builtin_xnu_type_signature(PointerData)[1] == '2');
static_assert(__builtin_xnu_type_signature(PointerData)[2] == '\0');
static_assert(__builtin_xnu_type_signature(TwoPointers)[1] == '1');
static_assert(__builtin_xnu_type_signature(Overlay)[0] == '3');
static_assert(__builtin_xnu_type_signature(Dual)[0] == '4');
static_assert(__builtin_xnu_type_signature(Padded)[1] == '0');
static_assert(__builtin_xnu_type_signature(Padded)[2] == '1');
static_assert(__builtin_xnu_type_summary(PointerData) == 6);
static_assert(__builtin_xnu_type_summary(Overlay) == 8);
static_assert(__builtin_xnu_type_summary(Dual) == 16);
static_assert(__builtin_xnu_type_summary(Padded) == 7);
static_assert(__builtin_xnu_types_compatible(PointerData, Annotated));
static_assert(!__builtin_xnu_types_compatible(void *, unsigned long));
static_assert(__builtin_xnu_types_compatible(void, void));
static_assert(!__builtin_xnu_types_compatible(void, unsigned long));
static_assert(type_signature<PointerData>()[1] == '2');
extern "C" unsigned long route_a_codegen(void *p) {
    return reinterpret_cast<unsigned long>(p) + 3;
}
'''


class ToolchainError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(part)
    return result.hexdigest()


def command(args, *, cwd=None, check=True):
    result = subprocess.run([str(arg) for arg in args], cwd=cwd, capture_output=True)
    if check and result.returncode:
        raise ToolchainError(result.stderr.decode("utf-8", "replace")[-12000:])
    return result


def save_json(path: Path, value):
    temporary = path.with_suffix(path.suffix + ".new")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def require_external_work(path: Path):
    path = path.resolve()
    if path == ROOT or ROOT in path.parents or path == Path("/"):
        raise ToolchainError("large toolchain work must be outside the device repository")
    return path


def tool_identity(name: str) -> dict:
    found = shutil.which(name)
    if not found:
        raise ToolchainError(f"required host tool is missing: {name}")
    # Preserve argv[0] for driver aliases such as clang++ and ld.lld. Resolving
    # the symlink to clang/lld would change link language or linker flavour.
    path = Path(found).absolute()
    version = command([path, "--version"]).stdout.decode("utf-8", "replace").strip()
    return {"path": str(path), "realpath": str(path.resolve()),
            "sha256": sha256_file(path), "version": version}


def load_patch(repository: Path) -> bytes:
    kind = command(["git", "-C", repository, "cat-file", "-t", UNIXNU_COMMIT]).stdout.strip()
    if kind != b"commit":
        raise ToolchainError("pinned UniXNU commit is absent")
    return command(["git", "-C", repository, "show", f"{UNIXNU_COMMIT}:{PATCH_PATH}"]).stdout


def cmake_arguments(source: Path, build: Path, prefix: Path, cc: str, cxx: str, linker: str):
    return ["cmake", "-G", "Ninja", "-S", str(source / "llvm"), "-B", str(build),
            "-DLLVM_ENABLE_PROJECTS=clang", "-DLLVM_TARGETS_TO_BUILD=AArch64",
            "-DCMAKE_BUILD_TYPE=Release", "-DLLVM_ENABLE_ASSERTIONS=ON",
            "-DLLVM_INCLUDE_TESTS=OFF", "-DLLVM_INCLUDE_EXAMPLES=OFF",
            "-DLLVM_INCLUDE_BENCHMARKS=OFF", "-DCLANG_ENABLE_STATIC_ANALYZER=OFF",
            "-DCLANG_ENABLE_ARCMT=OFF", "-DLLVM_PARALLEL_LINK_JOBS=1",
            f"-DLLVM_USE_LINKER={linker}", f"-DCMAKE_C_COMPILER={cc}",
            f"-DCMAKE_CXX_COMPILER={cxx}", f"-DCMAKE_INSTALL_PREFIX={prefix / 'llvm'}"]


def verify_clang(clang: str, output: Path) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    compiler = tool_identity(clang)
    source, obj = output / "xnu-traits.cpp", output / "xnu-traits.o"
    source.write_text(TRAIT_PROBE)
    args = [compiler["path"], "-target", "arm64-apple-ios27.0", "-march=armv8-a",
            "-std=c++17", "-ffreestanding", "-Werror", "-c", source, "-o", obj]
    result = command(args, check=False)
    (output / "compiler.stderr").write_bytes(result.stderr)
    header = None
    if result.returncode == 0 and obj.is_file() and obj.stat().st_size >= 32:
        with obj.open("rb") as stream:
            header = list(struct.unpack("<IIII", stream.read(16)))
    passed = result.returncode == 0 and header == [0xFEEDFACF, 0x0100000C, 0, 1]
    report = {"schema_version": 1, "status": "passed" if passed else "failed",
              "compiler": compiler, "command": [str(arg) for arg in args],
              "probe_sha256": sha256_file(source), "static_assertions": 19,
              "compiler_exit_code": result.returncode,
              "compiler_stderr": result.stderr.decode("utf-8", "replace")[-12000:],
              "object_header_words": header,
              "object_sha256": sha256_file(obj) if obj.is_file() else None,
              "kernel_compiled": False, "kernel_linked": False, "os_boot_verified": False}
    save_json(output / "verification.json", report)
    if not passed:
        raise ToolchainError(f"XNU Clang semantic probe failed; see {output / 'verification.json'}")
    return report


def source_state(source: Path) -> dict:
    # Build outputs live elsewhere. Include untracked files added by the LLVM
    # patch, and reject changes to the state before resuming a long build.
    status = command(["git", "-C", source, "status", "--porcelain=v1", "-uall"]).stdout
    paths = []
    for line in status.decode().splitlines():
        name = line[3:]
        path = source / name
        if not path.is_file() or path.is_symlink():
            raise ToolchainError(f"unexpected LLVM source change: {line}")
        paths.append({"path": name, "sha256": sha256_file(path)})
    return {"git_status": status.decode(), "changed_files": sorted(paths, key=lambda x: x["path"])}


def stage(work: Path, name: str, args, state: dict):
    log = work / "logs" / f"{name}.log"
    state.update(status="running", stage=name, command=[str(arg) for arg in args])
    save_json(work / "state.json", state)
    print(f"{name}: {log}", flush=True)
    with log.open("ab") as stream:
        stream.write(("\nCOMMAND " + json.dumps([str(arg) for arg in args]) + "\n").encode())
        result = subprocess.run([str(arg) for arg in args], stdout=stream, stderr=subprocess.STDOUT)
    if result.returncode:
        state.update(status="failed", exit_code=result.returncode)
        save_json(work / "state.json", state)
        raise ToolchainError(f"{name} failed with {result.returncode}; full log: {log}")


def build_clang(args):
    if sys.platform != "linux" or args.jobs < 1:
        raise ToolchainError("build-clang requires Linux and a positive job limit")
    work = require_external_work(args.work_dir)
    work.mkdir(parents=True, exist_ok=True)
    prefix = require_external_work(args.prefix) if args.prefix else work / "install"
    source, build = work / "llvm-project", work / "llvm-build"
    (work / "logs").mkdir(exist_ok=True)
    with (work / "build.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ToolchainError("this work directory already has a running toolchain build") from exc
        host = {name: tool_identity(value) for name, value in (
            ("cc", args.host_cc), ("cxx", args.host_cxx), ("cmake", "cmake"),
            ("ninja", "ninja"), ("linker", "ld.lld"))}
        patch = load_patch(args.unixnu_repository)
        identity = {"schema_version": 1, "unixnu_commit": UNIXNU_COMMIT,
                    "llvm_commit": LLVM_COMMIT, "llvm_url": LLVM_URL,
                    "patch_path": PATCH_PATH, "patch_sha256": hashlib.sha256(patch).hexdigest(),
                    "host_tools": host, "prefix": str(prefix),
                    "cmake_arguments": cmake_arguments(source, build, prefix,
                        host["cc"]["path"], host["cxx"]["path"], "lld")}
        identity_path = work / "identity.json"
        if identity_path.exists():
            if json.loads(identity_path.read_text()) != identity:
                raise ToolchainError("source, host tool or configuration identity changed; use a new work directory")
        else:
            if (source.exists() or build.exists() or
                    (prefix.exists() and any(prefix.iterdir()))):
                raise ToolchainError("refusing to adopt an unowned existing build tree")
            save_json(identity_path, identity)
        patch_file = work / "llvm-xnu-builtin-type.patch"
        if patch_file.exists() and patch_file.read_bytes() != patch:
            raise ToolchainError("saved patch differs from the fixed source")
        patch_file.write_bytes(patch)
        state = {"kernel_compiled": False, "kernel_linked": False,
                 "os_boot_verified": False, "jobs": args.jobs, "link_jobs": 1}
        try:
            if not source.exists():
                source.mkdir()
                command(["git", "-C", source, "init", "--quiet"])
            head = command(["git", "-C", source, "rev-parse", "HEAD"], check=False)
            if head.returncode:
                stage(work, "fetch-llvm", ["git", "-C", source, "fetch", "--depth", "1",
                      "--no-tags", LLVM_URL, LLVM_COMMIT], state)
                command(["git", "-C", source, "checkout", "--quiet", "--detach", LLVM_COMMIT])
            elif head.stdout.decode().strip() != LLVM_COMMIT:
                raise ToolchainError("LLVM source HEAD differs from the fixed commit")
            source_record = work / "patched-source.json"
            if source_record.exists():
                if json.loads(source_record.read_text()) != source_state(source):
                    raise ToolchainError("patched LLVM source changed since preparation")
            else:
                if source_state(source)["git_status"]:
                    raise ToolchainError("unrecorded LLVM changes; refuse to reset or overwrite them")
                command(["git", "-C", source, "apply", "--check", patch_file])
                command(["git", "-C", source, "apply", patch_file])
                save_json(source_record, source_state(source))
            stage(work, "configure-clang", identity["cmake_arguments"], state)
            stage(work, "build-clang", [host["ninja"]["path"], "-C", build,
                  f"-j{args.jobs}", "install-clang", "install-clang-resource-headers"], state)
            checks = work / "checks"
            checks.mkdir(exist_ok=True)
            attempt = 1
            while (checks / f"run-{attempt:03d}").exists():
                attempt += 1
            result = verify_clang(str(prefix / "llvm/bin/clang"), checks / f"run-{attempt:03d}")
            state.update(status="clang_verified", stage="complete", verification=result)
            save_json(work / "state.json", state)
            print(json.dumps({"status": state["status"], "clang": str(prefix / "llvm/bin/clang"),
                              "report": str(work / "state.json"), "kernel_compiled": False}, indent=2))
        except (ToolchainError, OSError) as exc:
            state.update(status="failed", error=str(exc))
            save_json(work / "state.json", state)
            raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build-clang")
    build.add_argument("--unixnu-repository", type=Path, required=True)
    build.add_argument("--work-dir", type=Path, required=True)
    build.add_argument("--prefix", type=Path, help="installation prefix; defaults to WORK_DIR/install")
    build.add_argument("--host-cc", default="clang")
    build.add_argument("--host-cxx", default="clang++")
    build.add_argument("--jobs", type=int, default=2)
    verify = commands.add_parser("verify-clang")
    verify.add_argument("--clang", required=True)
    verify.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "build-clang":
            build_clang(args)
        else:
            report = verify_clang(args.clang, args.output)
            print(json.dumps(report, indent=2))
    except (ToolchainError, OSError, ValueError) as exc:
        print(f"toolchain operation failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
