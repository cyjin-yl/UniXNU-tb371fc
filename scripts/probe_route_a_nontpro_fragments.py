#!/usr/bin/env python3
"""Execute a bounded corpus of original dyld functions in a synthetic EL0 fixture.

This is neither an XNU user process nor ordinary-arm64 translation evidence.
The only EL1 syscall implementation is the explicitly recorded +38/#0x80
namespace-zero ENOTSUP model. Unsupported exceptions stop the fixture.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

from audit_route_a_nontpro import (AuditError, Standalone, entry_contract,
                                   file_identity, require, sha256)
from probe_route_a_qemu_entry import Remote, EntryError
import probe_route_a_corecrypto as process_tools
from route_a_pacga_probe import run as execution
from route_a_nontpro_xnu import bind_syscall38
from route_a_nontpro_fixture import (
    BOOT_BASE, COMPLETED, COMMPAGE_PA, DYLD_BASE, INPUT_BASE, INPUT_SIZE,
    MAX_CASES, MODEL_STATE, RESULTS_OFFSET, TABLE_BASE, UNEXPECTED,
    build_cases, check_results, decode_model_state, page_tables,
)

MAX_LOG = 8 << 20
HERE = Path(__file__).resolve().parent


def invocation_identity(invocation):
    """Bind every traversed alias plus the final binary, preserving argv[0]."""
    invocation = str(Path(invocation).absolute())
    current, pending, chain, links = Path("/"), list(Path(invocation).parts[1:]), [], 0
    while pending:
        component = pending.pop(0)
        if component in ("", "."):
            continue
        if component == "..":
            current = current.parent
            continue
        candidate = current / component
        info = candidate.lstat()
        item = {"path": str(candidate), "device": info.st_dev, "inode": info.st_ino,
                "mode": info.st_mode}
        if stat.S_ISLNK(info.st_mode):
            links += 1
            require(links <= 40, "too many tool-path symlinks")
            target = os.readlink(candidate)
            item.update(target=target, size=info.st_size, modified_ns=info.st_mtime_ns,
                        changed_ns=info.st_ctime_ns)
            chain.append(item)
            target_path = Path(target)
            if target_path.is_absolute():
                current = Path("/")
                pending = list(target_path.parts[1:]) + pending
            else:
                pending = list(target_path.parts) + pending
            continue
        if not pending:
            item.update(size=info.st_size, modified_ns=info.st_mtime_ns, changed_ns=info.st_ctime_ns)
        chain.append(item)
        current = candidate
    require(current == Path(invocation).resolve(strict=True), "tool path changed while resolving")
    return {"invocation": invocation, "resolved": str(current), "chain": chain,
            "binary": file_identity(current)}


def selected_tool(name):
    invocation = shutil.which(name)
    require(invocation is not None, f"tool missing: {name}")
    invocation = str(Path(invocation).absolute())
    before = invocation_identity(invocation)
    result = subprocess.run([invocation, "--version"], capture_output=True, timeout=10)
    require(result.returncode == 0, f"tool version failed: {invocation}")
    require(invocation_identity(invocation) == before, "tool identity changed during version check")
    return invocation, {"invocation": invocation, "identity": before,
                        "version": (result.stdout + result.stderr).decode(errors="replace")[:4096]}


def memory_read(remote, address, length, record):
    require(type(address) is int and type(length) is int and 0 <= address < 1 << 64 and
            0 < length <= 1 << 20 and address + length <= 1 << 64, "invalid bounded memory read")
    record.update(address=hex(address), requested_bytes=length, chunks=[], complete=False)
    result = bytearray()
    try:
        while len(result) < length:
            require(time.monotonic() < remote.deadline, "fixture observation timed out")
            amount = min(4096, length - len(result))
            command = f"m{address + len(result):x},{amount:x}"
            response = remote.request(command)
            chunk = {"command": command, "response_chars": len(response),
                     "response_sha256": sha256(response.encode("ascii"))}
            record["chunks"].append(chunk)
            if not (len(response) == amount * 2 and re.fullmatch("[0-9a-fA-F]+", response)):
                chunk["invalid_response_prefix"] = response[:512]
                raise AuditError("invalid or partial GDB memory reply")
            result.extend(bytes.fromhex(response))
        record["complete"] = True
        return bytes(result)
    finally:
        record.update(received_bytes=len(result), sha256=sha256(result))
        if length <= 4096:
            record["received_hex"] = result.hex()


def compile_fixture(output, tools, report):
    source = HERE / "route-a-nontpro"
    for name in ("entry.S", "link.ld"):
        (output / name).write_bytes((source / name).read_bytes())
    commands = [
        [tools["clang"], "--target=aarch64-none-elf", "-march=armv8.3-a", "-c",
         str(output / "entry.S"), "-o", str(output / "entry.o")],
        [tools["lld"], "-m", "aarch64elf", "-T", str(output / "link.ld"),
         "-o", str(output / "entry.elf"), str(output / "entry.o")],
        [tools["objcopy"], "-O", "binary", str(output / "entry.elf"), str(output / "entry.bin")],
    ]
    report["build"] = []
    for index, command in enumerate(commands):
        record = {"argv": command}
        report["build"].append(record)
        log = output / f"build-{index}.log"
        with log.open("wb") as stream:
            process = subprocess.run(command, stdout=stream, stderr=stream, timeout=20)
        record.update(exit_code=process.returncode, log=file_identity(log))
        require(process.returncode == 0, "fixture assembly/link failed")
    require(0x6340 <= (output / "entry.bin").stat().st_size <= 0x10000, "unexpected fixture extent")


def finish_launch(process, connection, log, report, paths, started, primary):
    """Use the shared owned-session cleanup and retain the observation error."""
    record, errors = report["qemu"], []

    def attempt(label, action):
        try:
            return action()
        except BaseException as error:
            errors.append((label, error))
            return None

    watched = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    mask = attempt("block-cleanup-signals", lambda: signal.pthread_sigmask(signal.SIG_BLOCK, watched))
    try:
        if process is not None:
            record["cleanup"] = {"group": process.pid, "group_absent": False,
                                 "direct_child_reaped": False}

            def initial_status():
                record["exit_before_termination"] = process.poll()

            attempt("initial-child-status", initial_status)
            # A zero-exit direct child can still have living descendants.
            cleanup = attempt("group-cleanup", lambda: execution.stop_group(process))
            if cleanup is not None:
                record["cleanup"] = cleanup

            def final_status():
                record.update(exit_code=process.poll(), reaped=process.returncode is not None)

            attempt("final-child-status", final_status)
        for label, handle in (("socket", connection), ("log", log)):
            if handle is not None:
                attempt(label + "-close", handle.close)

        def diagnostics():
            report["logs"] = {path.name: file_identity(path) for path in paths if path.exists()}

        attempt("log-identities", diagnostics)
        record["elapsed_seconds"] = round(time.monotonic() - started, 6)
    finally:
        if mask is not None:
            attempt("restore-cleanup-signals", lambda: signal.pthread_sigmask(signal.SIG_SETMASK, mask))
    record["teardown_errors"] = [{"phase": label, "type": type(error).__name__, "message": str(error)}
                                 for label, error in errors]
    if errors:
        failure = primary if primary is not None else errors[0][1]
        for label, error in errors:
            if error is not failure:
                failure.add_note(f"A01 QEMU teardown {label}: {type(error).__name__}: {error}")
        if primary is None:
            raise failure


def launch(args, output, source, cases, report):
    endpoint = output / "gdb.sock"
    require(len(os.fsencode(endpoint)) <= 100, "output path exceeds Unix-socket bound")
    trace, stderr = output / "exceptions.log", output / "qemu.log"
    loaders = [("entry.bin", BOOT_BASE, True), ("dyld.load.bin", DYLD_BASE, False),
               ("inputs.bin", INPUT_BASE, False), ("tables.bin", TABLE_BASE, False),
               ("commpage.bin", COMMPAGE_PA, False)]
    argv = [args.qemu, "-M", "virt,virtualization=off,secure=off,gic-version=3",
            "-accel", "tcg", "-cpu", "max", "-m", "256", "-smp", "1",
            "-display", "none", "-monitor", "none", "-serial", "none", "-nic", "none",
            "-no-reboot", "-S", "-gdb", f"unix:{endpoint},server=on,wait=off",
            "-d", "int", "-D", str(trace)]
    for name, address, reset_pc in loaders:
        value = f"loader,file={output / name},addr={address:#x},force-raw=on"
        if reset_pc:
            value += ",cpu-num=0"
        argv.extend(["-device", value])
    report["qemu"] = {"argv": argv, "timeout_seconds": args.timeout, "cpu": "max",
                      "gic_version": 3, "memory_mib": 256, "storage_devices": [], "network_devices": [],
                      "original_pauth_bytes_retained": True, "a77_isa_verified": False,
                      "stop_reason": None}
    started = time.monotonic()
    process = connection = log = None
    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_LOG, MAX_LOG))
    with execution.owned_children():
        try:
            log = stderr.open("xb")
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            with process_tools.defer_spawn_signals():
                process = subprocess.Popen(argv, stdout=log, stderr=log, stdin=subprocess.DEVNULL,
                                           start_new_session=True, preexec_fn=limits)
                report["qemu"]["pid"] = process.pid
            deadline = started + args.timeout
            while True:
                require(time.monotonic() < deadline, "QEMU attachment deadline expired")
                require(process.poll() is None, f"QEMU exited before debugger: {process.returncode}")
                try:
                    connection.connect(str(endpoint))
                    break
                except (FileNotFoundError, ConnectionRefusedError):
                    time.sleep(0.02)
            remote = Remote(connection, deadline, output, report.setdefault("gdb_xml", []))
            remote.validate_architecture()
            report["initial_core"] = {}
            initial = remote.core_registers(report["initial_core"])
            report["initial_core"]["registers"] = {k: hex(v) for k, v in initial.items()}
            require(initial["pc"] == BOOT_BASE and initial["cpsr"] & 0x1f == 5,
                    "fixture did not start at its EL1h entry")
            for address in (COMPLETED, UNEXPECTED):
                require(time.monotonic() < deadline, "breakpoint deadline expired")
                require(remote.request(f"Z1,{address:x},4") == "OK", "hardware breakpoint rejected")
            require(time.monotonic() < deadline, "fixture continuation deadline expired")
            report["stop_reply"] = remote.request("c")
            require(report["stop_reply"].startswith(("S05", "T05")), "unexpected debugger stop")
            report["final_core"] = {}
            core = remote.core_registers(report["final_core"])
            report["final_core"]["registers"] = {k: hex(v) for k, v in core.items()}
            report["qemu"]["stop_reason"] = "completed" if core["pc"] == COMPLETED else "unexpected"
            header_record = report.setdefault("model_header_read", {})
            header = memory_read(remote, MODEL_STATE, 64, header_record)
            attempts = struct.unpack_from("<Q", header)[0]
            require(attempts <= MAX_CASES, "model attempt count exceeds bound")
            model_raw = header
            if attempts:
                model_raw += memory_read(remote, MODEL_STATE + 64, attempts * 256,
                                         report.setdefault("model_records_read", {}))
            report["syscall_model"] = decode_model_state(model_raw)
            result = memory_read(remote, INPUT_BASE + RESULTS_OFFSET, 16 * len(cases),
                                 report.setdefault("results_read", {}))
            observations = []
            for case in cases:
                requested = case["observation"]
                if requested:
                    raw = memory_read(remote, int(requested["address"], 16), requested["size"],
                                      case.setdefault("object_read", {}))
                    observations.append(raw)
                else:
                    observations.append(None)
            matches = check_results(cases, result, observations, report["syscall_model"]["accepted"])
            text = memory_read(remote, DYLD_BASE + source.text.addr, source.text.size,
                               report.setdefault("loaded_code_read", {}))
            report["loaded_instruction_bytes_unchanged"] = text == source.read(source.text.addr, source.text.size)
            report["fixture_result_observed"] = (core["pc"] == COMPLETED and core["cpsr"] & 0x1f == 0 and
                                                  matches and report["syscall_model"]["synthetic_model_verified"] and
                                                  report["loaded_instruction_bytes_unchanged"])
            for address in (COMPLETED, UNEXPECTED):
                require(time.monotonic() < deadline, "breakpoint cleanup deadline expired")
                require(remote.request(f"z1,{address:x},4") == "OK", "hardware breakpoint cleanup rejected")
            require(report["fixture_result_observed"], "fragment results or syscall-model preconditions did not match")
        finally:
            finish_launch(process, connection, log, report, (trace, stderr), started, sys.exc_info()[1])
    require(report["qemu"]["exit_before_termination"] is None, "QEMU exited before owned cleanup")
    require(report["qemu"]["cleanup"].get("group_absent") is True and
            report["qemu"]["cleanup"].get("direct_child_reaped") is True,
            "QEMU owned process group did not finish cleanup")
    require(process.returncode == 0 and report["qemu"]["reaped"], "QEMU did not cleanly terminate and reap")


def run(args):
    require(2 <= args.timeout <= 60, "timeout must be between 2 and 60 seconds")
    output = Path(args.output).absolute()
    require(not output.exists() and not any(c in str(output) for c in ",\r\n"),
            "output must be a fresh QEMU-safe directory")
    output.mkdir(parents=True)
    report = {"schema": "route-a-nontpro-fragments-v1",
              "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "fixture_result_observed": False, "fragment_execution_verified": False,
              "status": "failed", "a01_verified": False, "actual_xnu_dispatch_verified": False,
              "darwin_process_started": False, "os_boot_verified": False, "tb371fc_verified": False,
              "scope": "finite original-dyld EL0 cases; synthetic vectors, commpage and syscall-38 model",
              "syscall_model_contract": {"svc_immediate": "0x80", "x16_signed": 38, "namespace": "0x0",
                                         "x0_return": "0x2d", "x1_return": "0x0", "carry": 1,
                                         "actual_xnu_dispatch_verified": False}}
    source, generated, dependencies, primary = None, {}, {}, None
    try:
        source = Standalone(args.input)
        report["standalone"] = source.identity
        report["entry_contract"] = entry_contract(source, None)
        report["source_code_pages"] = source.code_pages
        report["xnu_syscall_binding"] = bind_syscall38(args.kernel, args.objects, args.prepared, args.filelist)
        dependencies = {str(HERE / n): file_identity(HERE / n) for n in
                        ("audit_route_a_nontpro.py", "route_a_nontpro_fixture.py", "route_a_nontpro_xnu.py",
                         "probe_route_a_nontpro_fragments.py", "probe_route_a_qemu_entry.py",
                         "route-a-nontpro/entry.S", "route-a-nontpro/link.ld")}
        for path in (Path(process_tools.__file__), Path(execution.__file__)):
            dependencies[str(path)] = file_identity(path)
        report["source_files"] = list(dependencies.values())
        selected = {}
        report["tools"] = {}
        for name in ("qemu", "clang", "lld", "objcopy"):
            selected[name], report["tools"][name] = selected_tool(getattr(args, name))
        args.qemu = selected["qemu"]
        compile_fixture(output, selected, report)
        inputs, cases = build_cases()
        report["cases"] = cases
        for case in cases:
            require(int(case["target"], 16) in source.starts, "fixture target lacks a real function start")
        payloads = {"dyld.load.bin": source.flat_image(), "inputs.bin": inputs,
                    "tables.bin": page_tables(), "commpage.bin": bytes(4096)}
        for name, data in payloads.items():
            (output / name).write_bytes(data)
        generated = {str(output / name): file_identity(output / name)
                     for name in ("entry.bin", *payloads)}
        report["generated_inputs"] = list(generated.values())
        launch(args, output, source, cases, report)
        report["status"] = "passed"
    except BaseException as error:
        primary = error
        report["error"] = {"type": type(error).__name__, "message": str(error),
                           "notes": list(getattr(error, "__notes__", []))}
    finally:
        checks = {}
        try:
            if source is not None:
                checks["standalone"] = source.recheck()
            kernel_inputs = report.get("xnu_syscall_binding", {}).get("inputs", {})
            for path, expected in {**dependencies, **generated, **kernel_inputs}.items():
                checks[path] = file_identity(path) == expected
            for name, record in report.get("tools", {}).items():
                checks["tool:" + name] = invocation_identity(record["invocation"]) == record["identity"]
        except BaseException as error:
            checks["recheck_error"] = {"type": type(error).__name__, "message": str(error)}
            if primary is None:
                primary = error
                report["error"] = {"type": type(error).__name__, "message": str(error)}
            else:
                primary.add_note(f"A01 input recheck: {type(error).__name__}: {error}")
                report["error"]["notes"] = list(getattr(primary, "__notes__", []))
        report["input_recheck"] = checks
        unchanged = bool(source is not None and checks) and all(v is True for v in checks.values())
        report["inputs_unchanged"] = unchanged
        report["fragment_execution_verified"] = (report["status"] == "passed" and unchanged and
                                                   report["fixture_result_observed"])
        if not report["fragment_execution_verified"]:
            report["status"] = "failed"
        report["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        try:
            with (output / "report.json").open("x") as stream:
                json.dump(report, stream, indent=2)
                stream.write("\n")
        except BaseException as error:
            if primary is not None:
                primary.add_note(f"A01 report publication: {type(error).__name__}: {error}")
                raise primary
            raise
    if primary is not None and not isinstance(primary, Exception):
        raise primary
    print(json.dumps({"report": str(output / "report.json"), "status": report["status"],
                      "fragment_execution_verified": report["fragment_execution_verified"],
                      "a01_verified": False}))
    return 0 if report["fragment_execution_verified"] else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--objects", type=Path, required=True, help="BSD DEVELOPMENT object directory")
    parser.add_argument("--prepared", type=Path, required=True, help="fixed prepared XNU source tree")
    parser.add_argument("--filelist", type=Path, required=True, help="declared kernel link filelist")
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--qemu", default="qemu-system-aarch64")
    parser.add_argument("--clang", default="clang-19")
    parser.add_argument("--lld", default="ld.lld-19")
    parser.add_argument("--objcopy", default="llvm-objcopy-19")
    args = parser.parse_args()
    def interrupted(number, _frame):
        raise InterruptedError("A01 fixture interrupted by signal " + str(number))
    watched = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    previous = {number: signal.signal(number, interrupted) for number in watched}
    try:
        return run(args)
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuditError, OSError) as error:
        print(f"A01 fixture failed before report creation: {error}", file=sys.stderr)
        raise SystemExit(2)
