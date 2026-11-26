#!/usr/bin/env python3
"""Run a small QEMU PACGA oracle and EL0 SVC fixture through agent-heavy.

This neither links nor boots XNU and does not use an Apple image. All keys are
public deterministic test vectors. The production helper and handler are copied
from the currently selected source identity into a new output directory.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
import hashlib
import json
import os
import re
import shlex
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from arm64_lowering import pacga

HERE = Path(__file__).resolve().parent


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def generation(path, *, follow_symlinks=True):
    s = Path(path).stat(follow_symlinks=follow_symlinks)
    return dict(device=s.st_dev, inode=s.st_ino, bytes=s.st_size,
                mtime_ns=s.st_mtime_ns, ctime_ns=s.st_ctime_ns, mode=s.st_mode)


def file_identity(path):
    path = Path(path).resolve()
    before = generation(path)
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        pacga.require((opened.st_dev, opened.st_ino) == (before["device"], before["inode"]),
                      "file changed before hash: " + str(path))
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    pacga.require(generation(path) == before, "file changed during hash: " + str(path))
    return dict(path=str(path), sha256=digest, generation=before)


def verify_files(records, *, hashes=False):
    for record in records.values():
        if hashes:
            pacga.require(file_identity(record["path"]) == record,
                          "bound file changed: " + record["path"])
        else:
            pacga.require(generation(record["path"]) == record["generation"],
                          "bound file generation changed: " + record["path"])


def tool_identity(invocation):
    """Preserve a multicall driver's invocation name; hash its resolved binary."""
    invocation = str(Path(invocation).absolute())
    realpath = str(Path(invocation).resolve(strict=True))
    return dict(invocation=invocation, realpath=realpath,
                invocation_generation=generation(invocation, follow_symlinks=False),
                binary=file_identity(realpath))


def verify_tools(records, *, hashes=False):
    for name, record in records.items():
        invocation = record["invocation"]
        pacga.require(str(Path(invocation).resolve(strict=True)) == record["realpath"]
                      and generation(invocation, follow_symlinks=False) == record["invocation_generation"],
                      "bound tool invocation changed: " + invocation)
        verify_files({name: record["binary"]}, hashes=hashes)


@contextmanager
def owned_children():
    """Linux-only fixture runner; adopt/reap our own orphaned descendants."""
    libc = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    pacga.require(libc.prctl(37, ctypes.byref(previous), 0, 0, 0) == 0,
                  "PR_GET_CHILD_SUBREAPER failed")
    pacga.require(libc.prctl(36, 1, 0, 0, 0) == 0, "PR_SET_CHILD_SUBREAPER failed")

    def interrupted(signum, _frame):
        raise InterruptedError("PACGA fixture interrupted by signal " + str(signum))

    watched = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    original = {sig: signal.signal(sig, interrupted) for sig in watched}
    try:
        yield
    finally:
        for sig, handler in original.items():
            signal.signal(sig, handler)
        libc.prctl(36, previous.value, 0, 0, 0)


def stop_group(process):
    """Terminate only this command's new session and reap its adopted children."""
    watched = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    original = {sig: signal.signal(sig, signal.SIG_IGN) for sig in watched}
    record = dict(group=process.pid, signals=[], reaped_descendants=[])
    try:
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(process.pid, sig)
                record["signals"].append(sig.name)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                continue
            deadline = time.monotonic() + 1
            while True:
                try:
                    child, status = os.waitpid(-process.pid, os.WNOHANG)
                    if child:
                        record["reaped_descendants"].append(dict(pid=child, status=status))
                        continue
                except ChildProcessError:
                    pass
                try:
                    os.killpg(process.pid, 0)
                except ProcessLookupError:
                    record.update(group_absent=True, direct_child_reaped=True,
                                  direct_exit_code=process.returncode)
                    return record
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.02)
        record.update(group_absent=False, direct_child_reaped=process.poll() is not None,
                      direct_exit_code=process.returncode)
        return record
    finally:
        for sig, handler in original.items():
            signal.signal(sig, handler)


def function_from_patch(patch, name, kind):
    added = "\n".join(line[1:] for line in patch.splitlines()
                      if line.startswith("+") and not line.startswith("+++"))
    signature = "static " + kind + "\n" + name + "("
    pacga.require(added.count(signature) == 1, "ambiguous production function: " + name)
    start = added.index(signature)
    cursor = added.index("{", start) + 1
    depth = 1
    while depth:
        pacga.require(cursor < len(added), "truncated production function: " + name)
        depth += (added[cursor] == "{") - (added[cursor] == "}")
        cursor += 1
    return added[start:cursor]


def dependency_paths(path, directory):
    text = Path(path).read_text().replace(chr(92) + chr(10), " ")
    pacga.require(":" in text, "compiler dependency output lacks a target")
    result = set()
    for name in shlex.split(text.split(":", 1)[1]):
        source = Path(name)
        if not source.is_absolute():
            source = Path(directory) / source
        result.add(source.resolve())
    pacga.require(bool(result), "empty compiler dependency closure")
    return result


def compile_with_dependencies(command, output, name, manifest, *, timeout=60, cwd=None):
    """Bind resource/system headers before the compile and verify its actual closure."""
    directory = Path(cwd or output)
    arguments = [str(item) for item in command]
    pacga.require(arguments.count("-c") == 1 and arguments.count("-o") == 1,
                  "dependency-bound compile requires one source/output command")
    pacga.require(not any(item in ("-M", "-MM", "-MD", "-MMD") or item.startswith("-MF")
                         for item in arguments), "compile already has dependency options")
    compilations = manifest.setdefault("compilations", {})
    pacga.require(name not in compilations, "compile receipt name is not unique")
    dep = output / (name + ".d")
    discovered = output / (name + "-discovered.d")
    pacga.require(not dep.exists() and not discovered.exists(), "dependency output already exists")
    arguments += ["-MD", "-MF", str(dep)]
    discovery = list(arguments)
    discovery[discovery.index("-MD")] = "-M"
    discovery[discovery.index("-MF") + 1] = str(discovered)
    discovery[discovery.index("-o") + 1] = str(output / (name + "-discovered.stdout"))
    execute(discovery, output, name + "-discover-headers", manifest, timeout=timeout, cwd=directory)
    declared = dependency_paths(discovered, directory)
    records = {str(path): file_identity(path) for path in sorted(declared)}
    for path, record in records.items():
        previous = manifest["frozen"].setdefault("dependency:" + path, record)
        pacga.require(previous == record, "dependency changed between translation units: " + path)
    receipt = dict(complete=False, declared=records, discovery=file_identity(discovered))
    compilations[name] = receipt
    execute(arguments, output, name, manifest, timeout=timeout, cwd=directory)
    actual = dependency_paths(dep, directory)
    receipt["actual_dependency_file"] = file_identity(dep)
    receipt["actual_paths"] = sorted(str(path) for path in actual)
    pacga.require(actual == declared,
                  "actual compiler dependencies differ from the declared header closure")
    verify_files(manifest["frozen"], hashes=True)
    receipt["complete"] = True
    return records


def oracle_cpu(version_output):
    """Select QARMA5 explicitly across QEMU's 8.2/9.x and 10+ CPU interfaces."""
    matches = re.findall(r"^QEMU emulator version (\d+)\.(\d+)\.(\d+)(?:\s|$)",
                         version_output, re.M)
    pacga.require(len(matches) == 1, "unrecognized QEMU emulator version")
    version = tuple(int(part) for part in matches[0])
    pacga.require(version >= (8, 2, 0), "PACGA oracle requires QEMU 8.2 or later")
    properties = ["max", "pauth=on"]
    if version >= (10, 0, 0):
        properties.append("pauth-qarma5=on")
    properties += ["pauth-qarma3=off", "pauth-impdef=off"]
    return dict(version=list(version), cpu=",".join(properties),
                selection="explicit QARMA5 properties with guest ISAR1 verification")


def verify_pauth_features(result, *, native):
    value = result.get("isar1")
    pacga.require(isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{16}", value),
                  "guest did not report a complete ISAR1 value")
    isar1 = int(value, 16)
    if native:
        pacga.require(((isar1 >> 24) & 15) == 1 and ((isar1 >> 28) & 15) == 0,
                      "native oracle did not expose QARMA5 GPA=1/GPI=0")
    else:
        pacga.require((isar1 & 0xff000ff0) == 0, "SVC fixture unexpectedly exposes pointer authentication")


def execute(command, output, name, manifest, timeout=60, cwd=None):
    verify_tools(manifest["tools"])
    verify_files(manifest["frozen"])
    started = time.monotonic()
    record = dict(name=name, arguments=[str(item) for item in command],
                  directory=str(cwd or output), status="started")
    manifest["commands"].append(record)
    (output / "report.json").write_text(json.dumps(manifest, indent=2) + "\n")
    process = None
    try:
        with (output / (name + ".stdout")).open("xb") as out, \
                (output / (name + ".stderr")).open("xb") as err:
            process = subprocess.Popen(record["arguments"], cwd=cwd or output, stdin=subprocess.DEVNULL,
                                       stdout=out, stderr=err, start_new_session=True)
            record["pid"] = process.pid
            record["exit_code"] = process.wait(timeout=timeout)
            record["status"] = "finished"
    except BaseException as error:
        record.update(status="interrupted" if isinstance(error, InterruptedError) else "failed",
                      error=type(error).__name__, message=str(error))
        raise
    finally:
        active_error = sys.exc_info()[0] is not None
        if process is not None:
            try:
                record["cleanup"] = stop_group(process)
            except BaseException as secondary:
                record["cleanup"] = dict(group_absent=False, error=str(secondary))
                if not active_error:
                    raise
        record["seconds"] = round(time.monotonic() - started, 3)
        try:
            (output / "report.json").write_text(json.dumps(manifest, indent=2) + "\n")
        except OSError as secondary:
            if not active_error:
                raise
            print("interrupted command receipt write failed: " + str(secondary), file=sys.stderr)
    pacga.require(record["cleanup"]["group_absent"] is True,
                  name + " left an owned process group; see cleanup receipt")
    pacga.require(record["exit_code"] == 0, name + " failed; see its retained logs")
    verify_tools(manifest["tools"])
    verify_files(manifest["frozen"])
    return (output / (name + ".stdout")).read_text()


def run(args):
    output = args.output.resolve()
    pacga.require(not output.exists(), "probe output must be new")
    selected = {name: shutil.which(value) for name, value in
                (("clang", args.clang), ("lld", args.lld), ("qemu", args.qemu))}
    pacga.require(all(selected.values()), "compiler, linker or QEMU is unavailable")
    tools = {name: tool_identity(path) for name, path in selected.items()}
    clang, lld, qemu = (tools[name]["invocation"] for name in ("clang", "lld", "qemu"))
    identity = pacga.implementation()
    helper = (ROOT / pacga.HEADER).read_bytes()
    patch = (ROOT / pacga.PATCH).read_bytes()
    pacga.require(sha(helper) == identity["sources"][pacga.HEADER]
                  and sha(patch) == identity["sources"][pacga.PATCH],
                  "production source changed during capture")
    sources = {name: (HERE / name).read_bytes() for name in ("probe.c", "entry.S", "link.ld")}
    sources["pacga_qarma5.h"] = helper
    sources["runtime.patch"] = patch
    sources["handler.inc"] = ("\n\n".join(
        function_from_patch(patch.decode(), name, kind) for name, kind in (
            ("route_a_pacga_register", "uint64_t"), ("route_a_pacga_svc", "bool"))) + "\n").encode()
    output.mkdir(parents=True)
    for name, raw in sources.items():
        (output / name).write_bytes(raw)
        (output / name).chmod(0o444)
    frozen = {name: file_identity(output / name) for name in sources}
    frozen["runner"] = file_identity(__file__)
    manifest = dict(schema="route-a-pacga-probe-report-v1", complete=False,
                    scope="freestanding QEMU virt fixtures with public test keys",
                    implementation=identity, source_sha256={name: sha(raw) for name, raw in sources.items()},
                    xnu_boot_verified=False, real_cache_proven=False, device_tested=False,
                    tools=tools, frozen=frozen, commands=[], results={},
                    cleanup_scope="owned process groups, Linux subreaper, SIGINT/SIGTERM/SIGHUP; not SIGKILL")
    report = output / "report.json"
    try:
        manifest["compiler"] = execute([clang, "--version"], output, "compiler-version", manifest).strip()
        manifest["qemu"] = execute([qemu, "--version"], output, "qemu-version", manifest).strip()
        manifest["lld"] = execute([lld, "--version"], output, "linker-version", manifest).strip()
        manifest["oracle"] = oracle_cpu(manifest["qemu"])
        target = ["--target=aarch64-none-elf", "-march=armv8-a", "-mgeneral-regs-only",
                  "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
                  "-fno-unwind-tables", "-fno-asynchronous-unwind-tables"]
        compile_with_dependencies([clang, *target, "-c", "entry.S", "-o", "entry.o"],
                                  output, "compile-entry", manifest)
        (output / "entry.o").chmod(0o444)
        manifest["frozen"]["entry.o"] = file_identity(output / "entry.o")
        for name, native, cpu in (
            ("native", 1, manifest["oracle"]["cpu"]),
            ("svc", 0, "cortex-a57"),
        ):
            compile_with_dependencies(
                [clang, *target, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                 "-DPROBE_NATIVE=" + str(native), "-c", "probe.c", "-o", name + ".o"],
                output, "compile-" + name, manifest)
            (output / (name + ".o")).chmod(0o444)
            manifest["frozen"][name + ".o"] = file_identity(output / (name + ".o"))
            elf = name + ".elf"
            execute([clang, *target, "-nostdlib", "--ld-path=" + lld, "-Wl,--build-id=none",
                     "-Wl,-T,link.ld", "entry.o", name + ".o", "-o", elf],
                    output, "link-" + name, manifest)
            (output / elf).chmod(0o444)
            manifest["frozen"][elf] = file_identity(output / elf)
            stdout = execute(
                [qemu, "-M", "virt,secure=off,virtualization=off", "-accel", "tcg,thread=single",
                 "-cpu", cpu, "-m", "128M", "-smp", "1", "-display", "none",
                 "-serial", "stdio", "-monitor", "none", "-no-reboot",
                 "-semihosting-config", "enable=on,target=native", "-kernel", elf],
                output, "qemu-" + name, manifest, timeout=args.timeout)
            lines = [line.removeprefix("PACGA-PROBE ") for line in stdout.splitlines()
                     if line.startswith("PACGA-PROBE ")]
            pacga.require(len(lines) == 1, name + " did not publish exactly one result")
            result = json.loads(lines[0])
            pacga.require(result["schema"] == "route-a-pacga-el0-probe-v1"
                          and result["cases"] == 1024 and result["native"] is bool(native)
                          and all(result.get(key) is True for key in
                                  ("paper_vector", "gpr", "pc_lr_sp", "nzcv", "simd", "fpcr_fpsr")),
                          name + " reported an incomplete register/algorithm result")
            verify_pauth_features(result, native=bool(native))
            if not native:
                pacga.require(result["ordinary_fallback"] is True, "ordinary SVC fallback was not reached")
            manifest["results"][name] = dict(result, cpu=cpu,
                                              elf_sha256=manifest["frozen"][elf]["sha256"])
        pacga.require(manifest["results"]["native"]["result_fold"] ==
                      manifest["results"]["svc"]["result_fold"], "oracle and SVC register results differ")
        pacga.require(pacga.implementation() == identity, "production sources changed during probe")
        verify_tools(manifest["tools"], hashes=True)
        verify_files(manifest["frozen"], hashes=True)
        manifest["complete"] = True
        report.write_text(json.dumps(manifest, indent=2) + "\n")
        return manifest
    except BaseException as error:
        manifest.update(complete=False, error=type(error).__name__, message=str(error))
        try:
            report.write_text(json.dumps(manifest, indent=2) + "\n")
        except OSError as secondary:
            print("probe report write failed: " + str(secondary), file=sys.stderr)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--qemu", default="qemu-system-aarch64")
    parser.add_argument("--lld", default="ld.lld")
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args(argv)
    pacga.require(1 <= args.timeout <= 300, "QEMU timeout must be 1..300 seconds")
    with owned_children():
        result = run(args)
    print(json.dumps({key: result[key] for key in
                      ("complete", "scope", "results", "xnu_boot_verified", "device_tested")}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print("PACGA probe: " + str(error), file=sys.stderr)
        raise SystemExit(2)
