#!/usr/bin/env python3
"""Build a separate source-bound PACGA sleh.o overlay, never modify a prepared tree.

Run this compiler job through the host's agent-heavy wrapper. The resulting
overlay is opt-in for the kernel linker; a completed compile is not a boot test.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

from arm64_lowering import pacga
from route_a_pacga_probe.run import (dependency_paths, execute, file_identity, owned_children,
                                     tool_identity, verify_files, verify_tools)

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "osfmk/arm64/sleh.c"
DEFAULT_COMPILE_TIMEOUT = 300
MAX_COMPILE_TIMEOUT = 900


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(arguments, *, cwd):
    result = subprocess.run([str(a) for a in arguments], cwd=cwd,
                            capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise ValueError(f"command failed ({result.returncode}): {arguments[0]}\n{result.stderr[-12000:]}")
    return result.stdout


def validate_compile_timeout(value):
    pacga.require(type(value) is int and 1 <= value <= MAX_COMPILE_TIMEOUT,
                  f"compile timeout must be an integer from 1 to {MAX_COMPILE_TIMEOUT} seconds")


def prepare(xnu, recipe_path, output, expected_sleh, *, compile_timeout=DEFAULT_COMPILE_TIMEOUT):
    validate_compile_timeout(compile_timeout)
    xnu, recipe_path, output = xnu.resolve(), recipe_path.resolve(), output.resolve()
    pacga.require(not output.exists(), "PACGA stage output must be new")
    pacga.require(not output.is_relative_to(xnu), "PACGA output must be outside the prepared source tree")
    pacga.require(run(["git", "rev-parse", "HEAD"], cwd=xnu).strip() == pacga.XNU_COMMIT,
                  "wrong XNU source baseline")
    source = xnu / SOURCE
    prepared = source.read_bytes()
    pacga.require(hashlib.sha256(prepared).hexdigest() == expected_sleh,
                  "prepared sleh.c differs from the reviewed input")
    identity = pacga.implementation()
    helper_bytes = (ROOT / pacga.HEADER).read_bytes()
    patch_bytes = (ROOT / pacga.PATCH).read_bytes()
    pacga.require(hashlib.sha256(helper_bytes).hexdigest() == identity["sources"][pacga.HEADER]
                  and hashlib.sha256(patch_bytes).hexdigest() == identity["sources"][pacga.PATCH],
                  "PACGA runtime sources changed while captured")
    recipe_identity = file_identity(recipe_path)
    recipe_bytes = recipe_path.read_bytes()
    pacga.require(hashlib.sha256(recipe_bytes).hexdigest() == recipe_identity["sha256"],
                  "recipe changed while captured")
    recipe = json.loads(recipe_bytes.decode().rstrip().removesuffix(","))
    pacga.require(Path(recipe["file"]).resolve() == source, "recipe is not for the selected sleh.c")
    arguments = list(recipe["arguments"])
    pacga.require(arguments.count(str(source)) == 1 and arguments.count("-o") == 1,
                  "recipe source/output identity is ambiguous")
    pacga.require("-c" in arguments, "recipe is not a compile-only command")
    pacga.require(not any(a.startswith(("@", "-save-temps", "-MJ", "-MF")) or
                         a in ("-M", "-MD", "-MMD", "-MM", "-fsyntax-only", "-E")
                         for a in arguments),
                  "recipe has unreviewed auxiliary output/preprocessing options")
    pacga.require(not any("CONFIG_ROUTE_A_PACGA_SVC" in a or
                         "ROUTE_A_PACGA_IMPLEMENTATION_SHA256" in a for a in arguments),
                  "input recipe already selects a PACGA runtime")
    output.mkdir(parents=True)
    tree = output / "source"
    staged = tree / SOURCE
    staged.parent.mkdir(parents=True)
    staged.write_bytes(prepared)
    include = tree / "osfmk/arm64/route_a_pacga_qarma5.h"
    include.write_bytes(helper_bytes)
    patch = output / "runtime.patch"
    patch.write_bytes(patch_bytes)
    run(["git", "init", "--quiet"], cwd=tree)
    run(["git", "apply", "--check", str(patch)], cwd=tree)
    run(["git", "apply", str(patch)], cwd=tree)
    obj = output / "sleh.o"
    dep = output / "sleh.d"
    arguments[arguments.index(str(source))] = str(staged)
    arguments[arguments.index("-o") + 1] = str(obj)
    arguments += ["-march=armv8-a", "-DCONFIG_ROUTE_A_PACGA_SVC=1",
                  '-DROUTE_A_PACGA_IMPLEMENTATION_SHA256="' + identity["sha256"] + '"',
                  "-mgeneral-regs-only", "-MD", "-MF", str(dep),
                  "-Werror=implicit-function-declaration",
                  "-Werror=incompatible-function-pointer-types", "-Werror=return-type"]
    # Only the new header has a new path; no original header is shadowed.
    arguments[1:1] = ["-I", str(tree / "osfmk")]
    old_object = Path(recipe["directory"]) / recipe["output"]
    pacga.require(Path(arguments[0]).is_absolute(), "recipe compiler invocation must be absolute")
    compiler = tool_identity(arguments[0])
    for path in (staged, include, patch):
        path.chmod(0o444)
    frozen = {name: file_identity(path) for name, path in
              (("source", staged), ("helper", include), ("patch", patch),
               ("recipe", recipe_path), ("stage", __file__),
               ("execution", ROOT / "scripts/route_a_pacga_probe/run.py"))}
    pacga.require(frozen["recipe"] == recipe_identity, "recipe changed before it was bound")
    manifest = dict(
        schema="route-a-pacga-stage-v1", abi=pacga.ABI, implementation=identity,
        xnu_commit=pacga.XNU_COMMIT, source_file=SOURCE,
        prepared_sleh_sha256=expected_sleh, staged_sleh_sha256=sha(staged),
        helper_sha256=sha(include), patch_sha256=sha(patch), recipe_sha256=sha(recipe_path),
        compiler=compiler["invocation"], tools=dict(clang=compiler), frozen=frozen, commands=[],
        arguments=arguments, directory=recipe["directory"], compile_timeout_seconds=compile_timeout,
        previous_object=dict(name=recipe["output"], sha256=sha(old_object)),
        provider_prerequisite="successful source-provider POST and register_and_init_prng at SYSCTL/LAST",
        key_material_recorded=False, compile_passed=False, kernel_linked=False, runtime_boot_verified=False)
    try:
        (output / "compile-command.json").write_text(json.dumps(manifest, indent=2) + "\n")
        with owned_children():
            manifest["compiler_version"] = execute(
                [arguments[0], "--version"], output, "compiler-version", manifest).strip()
            # Discover the complete closure, including resource/SDK/system
            # headers, with the exact feature/include options used to compile.
            discovery = list(arguments)
            discovery[discovery.index("-MD")] = "-M"
            discovery[discovery.index("-MF") + 1] = str(output / "discovered.d")
            discovery[discovery.index("-o") + 1] = str(output / "discovered.stdout")
            execute(discovery, output, "discover-headers", manifest, timeout=300,
                    cwd=recipe["directory"])
            declared = dependency_paths(output / "discovered.d", recipe["directory"])
            manifest["header_closure"] = {str(path): file_identity(path) for path in sorted(declared)}
            # Shared prepared headers are only read and bound, never chmod-ed
            # or rewritten. Any generation change makes this build ineligible.
            manifest["frozen"].update({"dependency:" + path: record
                                       for path, record in manifest["header_closure"].items()})
            execute(arguments, output, "compile", manifest, timeout=compile_timeout, cwd=recipe["directory"])
            actual = dependency_paths(dep, recipe["directory"])
            pacga.require(actual == declared,
                          "actual compiler dependencies differ from the declared header closure")
            verify_files(manifest["frozen"], hashes=True)
        manifest["compile_exit_code"] = manifest["commands"][-1]["exit_code"]
        obj.chmod(0o444)
        manifest["frozen"]["object"] = file_identity(obj)
        with obj.open("rb") as stream:
            header = stream.read(16)
        pacga.require(len(header) == 16 and struct.unpack("<4I", header) ==
                      (0xFEEDFACF, 0x0100000C, 0, 1), "overlay is not an ordinary-arm64 Mach-O object")
        headers = {path: record["sha256"] for path, record in manifest["header_closure"].items()}
        (output / "dependencies.json").write_text(json.dumps(headers, indent=2, sort_keys=True) + "\n")
        pacga.require(pacga.implementation() == identity and sha(source) == expected_sleh,
                      "PACGA implementation/prepared source changed during the build")
        verify_tools(manifest["tools"], hashes=True)
        verify_files(manifest["frozen"], hashes=True)
        manifest.update(object=dict(name=obj.name, bytes=manifest["frozen"]["object"]["generation"]["bytes"],
                                    sha256=manifest["frozen"]["object"]["sha256"],
                                    cpu_type="arm64", cpu_subtype=0),
                        dependencies_sha256=sha(output / "dependencies.json"), dependency_count=len(headers),
                        descriptor_hex=pacga.descriptor().hex(),
                        compile_passed=True, overlay_enabled_by_default=False)
        (output / "stage-report.json").write_text(json.dumps(manifest, indent=2) + "\n")
        return manifest
    except BaseException as error:
        manifest.update(compile_passed=False, error=type(error).__name__, message=str(error))
        try:
            (output / "stage-report.json").write_text(json.dumps(manifest, indent=2) + "\n")
        except OSError as secondary:
            print("PACGA stage receipt write failed: " + str(secondary), file=sys.stderr)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xnu-work", type=Path, required=True)
    parser.add_argument("--recipe", type=Path, required=True)
    parser.add_argument("--expected-sleh-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--compile-timeout", type=int, default=DEFAULT_COMPILE_TIMEOUT,
                        help=f"compile-only deadline in seconds (1..{MAX_COMPILE_TIMEOUT}; default {DEFAULT_COMPILE_TIMEOUT})")
    args = parser.parse_args(argv)
    try:
        validate_compile_timeout(args.compile_timeout)
    except ValueError as error:
        parser.error(str(error))
    result = prepare(args.xnu_work, args.recipe, args.output, args.expected_sleh_sha256,
                     compile_timeout=args.compile_timeout)
    print(json.dumps({key: result[key] for key in
                      ("abi", "compile_passed", "object", "kernel_linked", "runtime_boot_verified")}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"build-route-a-pacga: {error}", file=sys.stderr)
        raise SystemExit(2)
