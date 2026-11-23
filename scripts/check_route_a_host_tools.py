#!/usr/bin/env python3
"""Exercise installed host components with self-authored inputs in a new directory.

Uses a stock host Clang for ARM64 objects; neither the custom Clang nor an SDK is
qualified by this check. It never installs tools, changes the prefix, or removes
an earlier attempt. Every command and its output are retained in report.json.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import time

PINS = {
    "https://github.com/tpoechtrager/cctools-port": "3e694ee7393af2a4ce8bd6e7dae28fe37450aa87",
    "https://github.com/apple-oss-distributions/bootstrap_cmds": "c71d2d72f48995baaea76148f61002e5299841de",
    "https://github.com/lzfse/lzfse": "e634ca58b4821d9f3d560cdc6df5dec02ffc93fd",
}
TOOL_PATHS = {
    "ld64": "CommandLineTools/usr/bin/ld",
    "libtool": "CommandLineTools/usr/bin/libtool",
    "nm": "CommandLineTools/usr/bin/nm",
    "lipo": "CommandLineTools/usr/bin/lipo",
    "migcom": "CommandLineTools/usr/libexec/migcom",
    "lzfse": "bin/lzfse",
}
DEFS = """subsystem route_a_smoke 48640;
type route_a_port_t = MACH_MSG_TYPE_COPY_SEND;
type route_a_integer_t = MACH_MSG_TYPE_INTEGER_32;
routine route_a_ping(
    server_port : route_a_port_t;
    in input : route_a_integer_t;
    out output : route_a_integer_t);
"""


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def macho(path: Path, filetype: int) -> dict:
    data = path.read_bytes()
    require(len(data) >= 32, f"short Mach-O: {path}")
    words = struct.unpack_from("<8I", data)
    require(words[:4] == (0xFEEDFACF, 0x0100000C, 0, filetype),
            f"expected ordinary ARM64 Mach-O type {filetype}: {words[:4]}")
    require(32 + words[5] <= len(data), "Mach-O load commands exceed file")
    pos, commands = 32, []
    for _ in range(words[4]):
        require(pos + 8 <= 32 + words[5], "truncated load command")
        command, size = struct.unpack_from("<II", data, pos)
        require(size >= 8 and pos + size <= 32 + words[5], "invalid load command size")
        commands.append(command)
        pos += size
    require(pos == 32 + words[5], "load-command size mismatch")
    return {"header_words": list(words), "load_commands": commands,
            "ordinary_arm64": True, "filetype": filetype}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--components-manifest", type=Path, required=True)
    parser.add_argument("--host-clang", default="clang-19")
    parser.add_argument("--output", type=Path, required=True,
                        help="new directory outside the toolchain prefix; never reused")
    args = parser.parse_args(argv)
    prefix, out = args.prefix.resolve(), args.output.resolve()
    require(not out.is_relative_to(prefix), "output must be outside the toolchain prefix")
    out.mkdir(parents=True, exist_ok=False)
    report = {"schema_version": 1, "status": "running", "scope": "host-component-smoke",
              "driver_sha256": sha256(Path(__file__)), "prefix": str(prefix),
              "output": str(out), "commands": [], "checks": [], "artifacts": [],
              "custom_clang_verified": False, "sdk_ready": False,
              "full_kernel_compiled": False, "full_kernel_linked": False,
              "os_boot_verified": False, "full_instruction_set_audited": False}

    def save():
        (out / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    env = {**os.environ, "LC_ALL": "C", "ZERO_AR_DATE": "1",
           "PATH": str(prefix / "CommandLineTools/usr/bin") + os.pathsep + os.environ.get("PATH", "")}
    # Keep inherited compiler overrides from altering the self-contained inputs.
    for key in ("CCC_OVERRIDE_OPTIONS", "SDKROOT", "MACOSX_DEPLOYMENT_TARGET", "IPHONEOS_DEPLOYMENT_TARGET"):
        env.pop(key, None)

    def run(label, argv, input=None):
        start = time.monotonic()
        item = {"label": label, "argv": [str(x) for x in argv], "cwd": str(out)}
        if input is not None:
            item["stdin_sha256"] = hashlib.sha256(input.encode()).hexdigest()
        report["commands"].append(item)
        save()
        completed = subprocess.run(item["argv"], cwd=out, env=env, input=input,
                                   text=True, capture_output=True, timeout=30)
        item.update(exit_code=completed.returncode, stdout=completed.stdout,
                    stderr=completed.stderr, elapsed_seconds=round(time.monotonic() - start, 3))
        save()
        require(completed.returncode == 0,
                f"{label} failed ({completed.returncode}): {completed.stderr.strip()}")
        return completed.stdout

    def group(name, function):
        check = {"name": name, "passed": False}
        report["checks"].append(check)
        try:
            check["evidence"] = function()
            check["passed"] = True
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
            check["error"] = str(exc)
        save()

    try:
        manifest = json.loads(args.components_manifest.read_text())
        report["component_manifest"] = {"path": str(args.components_manifest.resolve()),
                                        "sha256": sha256(args.components_manifest),
                                        "identity": manifest["identity"]}
        for source, commit in PINS.items():
            require(manifest["identity"]["pins"][source]["commit"] == commit,
                    f"component source pin mismatch: {source}")
        recorded = {item["path"]: item["sha256"] for item in manifest["outputs"]}
        tools = {name: prefix / rel for name, rel in TOOL_PATHS.items()}
        compiler = shutil.which(args.host_clang)
        require(compiler is not None, f"host compiler missing: {args.host_clang}")
        report["tools"] = {}
        for name, path in {**tools, "host_clang": Path(compiler)}.items():
            require(path.is_file() and os.access(path, os.X_OK), f"not an executable file: {path}")
            actual = sha256(path)
            if name in TOOL_PATHS:
                require(recorded.get(TOOL_PATHS[name]) == actual, f"tool differs from component manifest: {path}")
            report["tools"][name] = {"path": str(path), "realpath": str(path.resolve()),
                                      "sha256": actual, "size": path.stat().st_size}
        save()
        run("host_clang_version", [compiler, "--version"])
        run("ld64_version", [tools["ld64"], "-v"])

        def arm64_archive_link():
            (out / "entry.c").write_text("extern unsigned long route_a_helper(unsigned long);\n"
                                        "unsigned long route_a_entry(void) { return route_a_helper(0x1234UL); }\n")
            (out / "helper.c").write_text("unsigned long route_a_helper(unsigned long x) { return x ^ 0x5a5aUL; }\n")
            flags = ["--target=arm64-apple-ios27.0", "-march=armv8-a", "-ffreestanding",
                     "-fno-stack-protector", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables", "-fno-builtin"]
            objects = {}
            for name in ("entry", "helper"):
                run(f"compile_{name}", [compiler, *flags, "-c", name + ".c", "-o", name + ".o"])
                objects[name] = macho(out / (name + ".o"), 1)
            unresolved = run("nm_entry", [tools["nm"], "-g", "entry.o"])
            require(re.search(r"\bU\s+_route_a_helper\b", unresolved), "entry lacks the helper relocation")
            run("archive", [tools["libtool"], "-static", "-o", "libroute_a.a", "helper.o"])
            require((out / "libroute_a.a").read_bytes().startswith(b"!<arch>\n"), "invalid archive magic")
            symbols = run("nm_archive", [tools["nm"], "-g", "libroute_a.a"])
            require(re.search(r"\bT\s+_route_a_helper\b", symbols), "archive lacks its helper definition")
            for name in ("entry.o", "libroute_a.a"):
                require(run("lipo_" + name, [tools["lipo"], "-archs", name]).strip() == "arm64",
                        f"wrong architecture reported for {name}")
            run("ld64_kernel", [tools["ld64"], "-static", "-kernel", "-arch", "arm64",
                                "-e", "_route_a_entry", "-platform_version", "ios", "27.0", "27.0",
                                "-o", "route_a_kernel_smoke", "entry.o", "libroute_a.a"])
            executable = macho(out / "route_a_kernel_smoke", 2)
            require(0xE not in executable["load_commands"], "static smoke unexpectedly requests a dynamic linker")
            linked = run("nm_linked", [tools["nm"], "-g", "route_a_kernel_smoke"])
            for name in ("entry", "helper"):
                require(re.search(r"\bT\s+_route_a_" + name + r"\b", linked), f"linked {name} missing")
            require(not re.search(r"\bU\s+\S+", linked), "linked smoke still has undefined symbols")
            require(run("lipo_linked", [tools["lipo"], "-archs", "route_a_kernel_smoke"]).strip() == "arm64",
                    "linked executable architecture mismatch")
            return {"objects": objects, "linked_executable": executable,
                    "archive_member_resolved": True, "linked_sample_is_xnu": False,
                    "executable_was_run": False}

        def mig_generate():
            (out / "smoke.defs").write_text(DEFS)
            names = {"-header": "smoke_user.h", "-sheader": "smoke_server.h",
                     "-user": "smoke_user.c", "-server": "smoke_server.c", "-dheader": "smoke_ids.h"}
            run("migcom_generate", [tools["migcom"], *(v for pair in names.items() for v in pair)], input=DEFS)
            for name in names.values():
                content = (out / name).read_text()
                require("route_a_ping" in content, f"generated interface missing in {name}")
            require("48640" in (out / "smoke_ids.h").read_text(), "MIG message ID mismatch")
            require("_Xroute_a_ping" in (out / "smoke_server.c").read_text(), "server dispatcher missing")
            return {"generated_files": list(names.values()), "message_id": 48640,
                    "generated_c_compiled_against_sdk": False, "ipc_runtime_verified": False}

        def lzfse_roundtrip():
            sample = bytes(range(256)) * 257 + b"Route A self-authored LZFSE input\n" * 100
            (out / "sample.bin").write_bytes(sample)
            run("lzfse_encode", [tools["lzfse"], "-encode", "-i", "sample.bin", "-o", "sample.lzfse"])
            require((out / "sample.lzfse").stat().st_size > 0, "empty compressed output")
            run("lzfse_decode", [tools["lzfse"], "-decode", "-i", "sample.lzfse", "-o", "restored.bin"])
            require((out / "restored.bin").read_bytes() == sample, "LZFSE roundtrip differs")
            return {"input_bytes": len(sample), "compressed_bytes": (out / "sample.lzfse").stat().st_size,
                    "input_sha256": sha256(out / "sample.bin"), "restored_sha256": sha256(out / "restored.bin")}

        group("ordinary_arm64_archive_kernel_link", arm64_archive_link)
        group("migcom_interface_generation", mig_generate)
        group("lzfse_roundtrip", lzfse_roundtrip)
        for name, item in report["tools"].items():
            require(sha256(Path(item["path"])) == item["sha256"], f"tool changed during smoke: {name}")
        report["status"] = "passed" if all(item["passed"] for item in report["checks"]) else "failed"
    except (OSError, RuntimeError, KeyError, ValueError, subprocess.TimeoutExpired) as exc:
        report.update(status="failed", error=str(exc))
    finally:
        for path in sorted(out.iterdir()):
            if path.is_file() and path.name != "report.json":
                report["artifacts"].append({"path": path.name, "size": path.stat().st_size, "sha256": sha256(path)})
        save()
    print(json.dumps({"status": report["status"], "checks": report["checks"],
                      "report": str(out / "report.json")}, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
