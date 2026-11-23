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
import types

ROOT = Path(__file__).resolve().parents[1]
UNIXNU_COMMIT = "8542980d02b4d2cc5c32ee3542de1760b2562aac"
LLVM_COMMIT = "58c46bae21181fb4240cf964461bea738d96d50e"
LLVM_URL = "https://github.com/llvm/llvm-project.git"
PATCH_PATH = "scripts/linux/llvm-xnu-builtin-type.patch"
HOST_SOURCE_PINS = {
    "https://github.com/tpoechtrager/cctools-port": {
        "ref": "1030.6.3-ld64-956.6", "commit": "3e694ee7393af2a4ce8bd6e7dae28fe37450aa87"},
    "https://github.com/swiftlang/swift-corelibs-libdispatch": {
        "ref": "swift-6.4.0-RELEASE", "commit": "024805abec6daa9cdda569fd736b9c7686dfd735"},
    "https://github.com/apple-oss-distributions/bootstrap_cmds": {
        "ref": "bootstrap_cmds-138", "commit": "c71d2d72f48995baaea76148f61002e5299841de"},
    "https://github.com/Nyktis/iig-port": {
        "ref": "ea6d147d668ca15d490da638012243fcd705f30d", "commit": "ea6d147d668ca15d490da638012243fcd705f30d"},
    "https://github.com/lzfse/lzfse": {
        "ref": "e634ca58b4821d9f3d560cdc6df5dec02ffc93fd", "commit": "e634ca58b4821d9f3d560cdc6df5dec02ffc93fd"},
}

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


def source_pin(url: str, ref: str) -> dict:
    normalized = url.removesuffix(".git").rstrip("/")
    pin = HOST_SOURCE_PINS.get(normalized)
    if pin is None or ref != pin["ref"]:
        raise ToolchainError(f"unreviewed host tool source/ref: {url} {ref}")
    return {"url": normalized + ".git", **pin}


def toolchain_environment(prefix: Path, sdk: Path) -> dict:
    clt, xct = prefix / "CommandLineTools/usr", prefix / "XcodeDefault.xctoolchain/usr"
    return {
        "UNIXNU_TOOLCHAIN": str(prefix), "CLT_PREFIX": str(clt), "XCTOOLCHAIN_PREFIX": str(xct),
        "XNU_TOOLCHAIN_BIN": f"{clt / 'bin'} {xct / 'bin'}",
        "CROSS_CLANG": str(prefix / "llvm/bin/clang"), "DARWIN_TRIPLE": "arm64-apple-ios27.0",
        "CROSS_EXTRA_FLAGS": "-mllvm -disable-atexit-based-global-dtor-lowering",
        "UNIXNU_SDKROOT": str(sdk), "UNIXNU_SDK_VERSION": "27.0", "UNIXNU_SDK_BUILD": "24A446",
        "UNIXNU_PLATFORM_PATH": str(sdk / "Platforms/iPhoneOS.platform"),
        "UNIXNU_XNU_ARCH": "arm64", "XNU_BOOT_PROGRESS": "0", "ZERO_AR_DATE": "1",
        "CCC_OVERRIDE_OPTIONS": "# +-Wno-missing-designated-field-initializers +-Wno-unused-but-set-global",
        "LC_ALL": "C",
    }


def export_linux_support(repository: Path, destination: Path) -> dict:
    # Read the fixed Git objects, not the caller's possibly dirty checkout.
    listing = command(["git", "-C", repository, "ls-tree", "-r", UNIXNU_COMMIT,
                       "scripts/linux", "LICENSE"]).stdout.decode()
    records = {}
    for line in listing.splitlines():
        metadata, relative = line.split("\t", 1)
        mode, kind, blob = metadata.split()
        if kind != "blob" or mode not in ("100644", "100755"):
            raise ToolchainError(f"unexpected support object: {relative}")
        if relative != "LICENSE" and not relative.startswith("scripts/linux/"):
            raise ToolchainError("support path outside the pinned Linux directory")
        data = command(["git", "-C", repository, "show", f"{UNIXNU_COMMIT}:{relative}"]).stdout
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.read_bytes() != data:
            raise ToolchainError(f"pinned support file changed: {relative}")
        target.write_bytes(data)
        target.chmod(int(mode, 8) & 0o777)
        records[relative] = {"git_blob": blob, "sha256": hashlib.sha256(data).hexdigest()}
    if "scripts/linux/setup-toolchain.py" not in records:
        raise ToolchainError("the fixed Linux installer is missing")
    return records


def installer_without_existence_shortcuts(source: str) -> str:
    """Keep the fixed build recipes; require fresh builds on a cache miss."""
    clauses = [
        "    if all((clt / path).exists() for path in ('bin/ld', 'lib/libmacho.a', 'lib/libstuff.a')):\n        return\n",
        "    if (clt / 'libexec/migcom').exists():\n        return\n",
        "    if (prefix / 'bin/lzfse').exists():\n        return\n",
    ]
    for clause in clauses:
        if source.count(clause) != 1:
            raise ToolchainError("fixed installer cache-guard shape changed")
        source = source.replace(clause, "")
    # Preserve the libdispatch body verbatim except for one level of indentation.
    start = "    if not (dispatch_prefix / 'lib/libdispatch.so').exists():\n"
    end = "    tree = src / 'cctools'\n"
    if source.count(start) != 1 or source.count(end) != 1:
        raise ToolchainError("fixed libdispatch cache-guard shape changed")
    before, rest = source.split(start, 1)
    body, after = rest.split(end, 1)
    source = before + "".join(line[4:] if line.startswith("    ") else line
                             for line in body.splitlines(keepends=True)) + end + after
    return source


def component_inventory(prefix: Path) -> list[dict]:
    result = []
    for root in (prefix / "CommandLineTools", prefix / "XcodeDefault.xctoolchain", prefix / "bin"):
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                if not path.resolve().is_relative_to(prefix.resolve()):
                    raise ToolchainError(f"component symlink escapes its prefix: {path}")
                result.append({"path": str(path.relative_to(prefix)), "symlink": os.readlink(path)})
            elif path.is_file():
                result.append({"path": str(path.relative_to(prefix)), "sha256": sha256_file(path)})
    return result


def validate_component_cache(prefix: Path, record: dict, identity: dict):
    if record.get("identity") != identity:
        raise ToolchainError("cached host components have different source/host/compiler inputs")
    for item in record["outputs"]:
        path = prefix / item["path"]
        if "symlink" in item:
            valid = path.is_symlink() and os.readlink(path) == item["symlink"]
        else:
            valid = path.is_file() and not path.is_symlink() and sha256_file(path) == item["sha256"]
        if not valid:
            raise ToolchainError(f"cached host component changed: {path}")


def build_host_tools(args):
    if sys.platform != "linux" or os.geteuid() != 0 or args.jobs < 1:
        raise ToolchainError("host-tools requires Linux container root and a positive job limit")
    if not (Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()):
        raise ToolchainError("host-tools installs /usr/bin shims; run in an isolated Docker/Podman container")
    work = require_external_work(args.work_dir)
    identity = json.loads((work / "identity.json").read_text())
    prefix = Path(identity["prefix"])
    if identity["unixnu_commit"] != UNIXNU_COMMIT or identity["llvm_commit"] != LLVM_COMMIT:
        raise ToolchainError("toolchain workspace has different source pins")
    with (work / "host-tools.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ToolchainError("the toolchain workspace is already in use") from exc
        attempts = work / "host-attempts"
        attempts.mkdir(exist_ok=True)
        index = 1
        while (attempts / f"run-{index:03d}").exists():
            index += 1
        attempt = attempts / f"run-{index:03d}"
        attempt.mkdir()
        support = attempt / "support"
        support_record = export_linux_support(args.unixnu_repository, support)
        script = support / "scripts/linux/setup-toolchain.py"
        adapted_source = installer_without_existence_shortcuts(script.read_text())
        module = types.ModuleType("route_a_pinned_linux_installer")
        module.__file__ = str(script)
        exec(compile(adapted_source, str(script), "exec"), module.__dict__)
        report = {"schema_version": 1, "status": "preparing", "unixnu_commit": UNIXNU_COMMIT,
                  "support_files": support_record, "host_source_pins": HOST_SOURCE_PINS,
                  "source_checkouts": [], "kernel_compiled": False, "kernel_linked": False,
                  "os_boot_verified": False, "sdk_headers_prepared": False,
                  "kernel_interfaces_generated": False, "combined_toolchain_verified": False,
                  "installer_adapter_sha256": hashlib.sha256(adapted_source.encode()).hexdigest()}
        log = attempt / "build.log"

        def logged_run(argv, cwd=None, env=None, input=None):
            argv = [str(item) for item in argv]
            report["last_command"] = argv
            save_json(work / "host-tools-state.json", report)
            with log.open("a") as stream:
                stream.write("COMMAND " + json.dumps(argv) + "\n")
                stream.flush()
                effective_env = {**os.environ, **(env or {}),
                                 **toolchain_environment(prefix, args.sdk_root.resolve())}
                result = subprocess.run(argv, cwd=cwd, env=effective_env, input=input, text=True,
                    stdout=subprocess.PIPE if input is not None else stream, stderr=stream)
            if result.returncode:
                raise ToolchainError(f"host tool command failed ({result.returncode}); see {log}")
            return result.stdout

        def pinned_checkout(directory, url, ref):
            pin = source_pin(url, ref)
            directory = Path(directory)
            if directory.exists():
                actual = command(["git", "-C", directory, "rev-parse", "HEAD"]).stdout.decode().strip()
                dirty = command(["git", "-C", directory, "status", "--porcelain", "-uno"]).stdout
                if actual != pin["commit"] or dirty:
                    raise ToolchainError(f"refuse to overwrite a different/dirty source tree: {directory}")
            else:
                directory.mkdir(parents=True)
                logged_run(["git", "-C", directory, "init", "--quiet"])
                logged_run(["git", "-C", directory, "fetch", "--depth", "1", "--no-tags",
                            pin["url"], pin["commit"]])
                logged_run(["git", "-C", directory, "checkout", "--quiet", "--detach", pin["commit"]])
            actual = command(["git", "-C", directory, "rev-parse", "HEAD"]).stdout.decode().strip()
            if actual != pin["commit"]:
                raise ToolchainError("host source checkout does not match the pinned commit")
            report["source_checkouts"].append({**pin, "directory": str(directory)})

        class PersistentProbeDirectory:
            # host_tools() normally uses TemporaryDirectory for its link/run
            # check. Keep that small probe and all source/build attempts too.
            def __init__(self, prefix="probe-", **unused):
                count = 1
                self.path = attempt / f"{prefix}{count:03d}"
                while self.path.exists():
                    count += 1
                    self.path = attempt / f"{prefix}{count:03d}"
                self.path.mkdir()
            def __enter__(self):
                return str(self.path)
            def __exit__(self, *_):
                return False

        def prohibit_removal(*unused, **kwargs):
            raise ToolchainError("the persistent toolchain wrapper does not remove source/build trees")

        module.run = logged_run
        module.git_checkout = pinned_checkout
        module.tempfile = types.SimpleNamespace(TemporaryDirectory=PersistentProbeDirectory)
        module.shutil = types.SimpleNamespace(**{**vars(shutil), "rmtree": prohibit_removal})
        clt, xct = prefix / "CommandLineTools/usr", prefix / "XcodeDefault.xctoolchain/usr"
        include = clt.parent / "SDKs/MacOSX.sdk/usr/include"
        try:
            host = module.host_tools(args.llvm_config)
            host_identity = {"cc": tool_identity(str(host.cc)), "cxx": tool_identity(str(host.cxx)),
                             "llvm_config": tool_identity(str(host.config)), "resource": host.resource,
                             "libclang_sha256": sha256_file(host.libdir / "libclang.so")}
            cache_identity = {"support": support_record, "pins": HOST_SOURCE_PINS,
                              "host": host_identity, "adapter_sha256": report["installer_adapter_sha256"]}
            report["host_identity"] = host_identity
            cache_path = work / "host-components.json"
            reuse = cache_path.exists()
            if reuse:
                validate_component_cache(prefix, json.loads(cache_path.read_text()), cache_identity)
            for label, action in (() if reuse else (
                ("cctools", lambda: module.cctools(clt, include, attempt, args.jobs, host)),
                ("mig", lambda: module.mig(clt, include, attempt, host)),
                ("iig", lambda: module.iig(xct, attempt, host)),
                ("host-cc", lambda: module.host_cc(clt, include, host)),
                ("lzfse", lambda: module.lzfse(prefix, attempt)),
            )):
                report.update(status="building", stage=label)
                save_json(work / "host-tools-state.json", report)
                print(f"host-tools {label}: {log}", flush=True)
                action()
            component_outputs = [clt / "bin" / name for name in
                                 ("ld", "libtool", "nm", "lipo", "mig", "xnu-host-cc")]
            component_outputs += [clt / "libexec/migcom", xct / "bin/iig", prefix / "bin/lzfse"]
            component_outputs += [clt / "lib" / name for name in ("libmacho.a", "libstuff.a")]
            if any(not path.is_file() for path in component_outputs):
                raise ToolchainError("host component output set is incomplete; no cache published")
            if not reuse:
                save_json(cache_path, {"identity": cache_identity, "outputs": component_inventory(prefix)})
            if not args.components_only:
                clang_state = json.loads((work / "state.json").read_text())
                clang = prefix / "llvm/bin/clang"
                if (clang_state.get("status") != "clang_verified" or
                        sha256_file(clang) != clang_state["verification"]["compiler"]["sha256"]):
                    raise ToolchainError("current Clang binary does not match its successful build/verification")
                report["clang_verification"] = verify_clang(str(clang), attempt / "clang-final-check")
                module.shims(clt, xct, clang)
            outputs = [clt / "bin" / name for name in ("ld", "libtool", "nm", "lipo", "mig", "xnu-host-cc")]
            outputs += [clt / "libexec/migcom", xct / "bin/iig", prefix / "bin/lzfse"]
            if not args.components_only:
                outputs += [Path("/usr/bin") / name for name in ("xcrun", "plutil", "codesign")]
            outputs += [clt / "lib" / name for name in ("libmacho.a", "libstuff.a")]
            for output in outputs:
                if not output.is_file():
                    raise ToolchainError(f"host tool output missing: {output}")
            report["outputs"] = [{"path": str(path), "sha256": sha256_file(path)} for path in outputs]
            environment = toolchain_environment(prefix, args.sdk_root.resolve())
            if not args.components_only:
                save_json(work / "toolchain-environment.json", environment)
            report.update(status="host_components_built_clang_pending" if args.components_only else "host_tools_built",
                          stage="complete", environment=environment, component_cache_reused=reuse,
                          combined_toolchain_verified=not args.components_only)
            save_json(work / "host-tools-state.json", report)
            print(json.dumps({"status": report["status"], "report": str(work / "host-tools-state.json"),
                              "kernel_compiled": False}, indent=2))
        except (ToolchainError, OSError, ValueError, SystemExit) as exc:
            report.update(status="failed", error=str(exc))
            save_json(work / "host-tools-state.json", report)
            raise ToolchainError(str(exc)) from exc


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
                        host["cc"]["path"], host["cxx"]["path"], host["linker"]["path"])}
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
    host = commands.add_parser("host-tools")
    host.add_argument("--unixnu-repository", type=Path, required=True)
    host.add_argument("--work-dir", type=Path, required=True)
    host.add_argument("--sdk-root", type=Path, required=True)
    host.add_argument("--llvm-config", default="llvm-config")
    host.add_argument("--jobs", type=int, default=2)
    host.add_argument("--components-only", action="store_true",
                      help="build native host components while the independent Clang build runs")
    args = parser.parse_args(argv)
    try:
        if args.command == "build-clang":
            build_clang(args)
        elif args.command == "host-tools":
            build_host_tools(args)
        else:
            report = verify_clang(args.clang, args.output)
            print(json.dumps(report, indent=2))
    except (ToolchainError, OSError, ValueError) as exc:
        print(f"toolchain operation failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
