#!/usr/bin/env python3
"""Build one atomic PACGA sleh.o + locore.o overlay from retained XNU recipes.

Run compiler jobs through the host's agent-heavy wrapper. Only a new output
tree is written. Successful compilation does not establish a kernel boot.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

from arm64_lowering import pacga
from route_a_pacga_probe.run import (dependency_paths, execute, file_identity, owned_children,
                                    tool_identity, verify_files, verify_tools)

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "osfmk/arm64/sleh.c"
LOCORE = "osfmk/arm64/locore.s"
EXCEPTION_ASM = "osfmk/arm64/exception_asm.h"
SOURCES = (SOURCE, LOCORE, EXCEPTION_ASM)
UNITS = {"sleh": SOURCE, "locore": LOCORE}
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


def captured_file(path):
    record = file_identity(path)
    raw = Path(path).read_bytes()
    pacga.require(hashlib.sha256(raw).hexdigest() == record["sha256"]
                  and file_identity(path) == record, "input changed while captured: " + str(path))
    return raw, record


def recipe_for(path, source, unit):
    raw, record = captured_file(path)
    recipe = json.loads(raw.decode().rstrip().removesuffix(","))
    pacga.require(isinstance(recipe, dict) and Path(recipe["file"]).resolve() == source,
                  "recipe is not for the selected " + unit + " source")
    arguments = recipe.get("arguments")
    pacga.require(isinstance(arguments, list) and arguments
                  and all(isinstance(a, str) and a and "\0" not in a for a in arguments),
                  "invalid compile recipe arguments")
    pacga.require(arguments.count(str(source)) == 1 and arguments.count("-o") == 1
                  and arguments.index("-o") + 1 < len(arguments) and arguments.count("-c") == 1,
                  "recipe needs exactly one compile source/output")
    pacga.require(not any(a.startswith(("@", "-save-temps", "-MJ", "-MF")) or
                         a in ("-M", "-MD", "-MMD", "-MM", "-fsyntax-only", "-E", "-S")
                         for a in arguments), "recipe has unreviewed auxiliary/preprocessing options")
    pacga.require(not any("CONFIG_ROUTE_A_PACGA_SVC" in a or
                         "ROUTE_A_PACGA_IMPLEMENTATION_SHA256" in a for a in arguments),
                  "input recipe already selects a PACGA runtime")
    pacga.require(Path(arguments[0]).is_absolute() and Path(recipe["directory"]).is_absolute()
                  and Path(recipe["directory"]).resolve() == path.parent,
                  "recipe compiler/cwd is not the retained absolute build directory")
    languages = []
    for index, argument in enumerate(arguments):
        if argument == "-x":
            pacga.require(index + 1 < len(arguments), "recipe language is truncated")
            languages.append(arguments[index + 1])
        elif argument.startswith("-x"):
            languages.append(argument[2:])
    if unit == "locore":
        pacga.require(languages == ["assembler-with-cpp"],
                      "locore recipe must explicitly select assembler-with-cpp")
    else:
        pacga.require(not languages or languages == ["c"], "sleh recipe is not C")
    # The retained locore compile database names a temporary preprocessor .s
    # output. The original platform member is explicitly locore.o, never that
    # temporary output. The complete, unchanged recipe bytes are still bound.
    previous = path.parent / (unit + ".o")
    pacga.require(previous.is_file(), "missing retained platform object: " + str(previous))
    return recipe, record, previous


def compile_arguments(recipe, source, staged, output, unit, implementation):
    arguments = list(recipe["arguments"])
    arguments[arguments.index(str(source))] = str(staged)
    arguments[arguments.index("-o") + 1] = str(output / (unit + ".o"))
    arguments[1:1] = ["-I", str(output / "source/osfmk")]
    arguments += ["-march=armv8-a", "-DCONFIG_ROUTE_A_PACGA_SVC=1",
                  '-DROUTE_A_PACGA_IMPLEMENTATION_SHA256="' + implementation["sha256"] + '"']
    if unit == "sleh":
        arguments += ["-mgeneral-regs-only"]
    arguments += ["-MD", "-MF", str(output / (unit + ".d"))]
    if unit == "sleh":
        arguments += ["-Werror=implicit-function-declaration",
                      "-Werror=incompatible-function-pointer-types", "-Werror=return-type"]
    return arguments


def discovery_arguments(arguments, output, unit):
    result = list(arguments)
    result[result.index("-MD")] = "-M"
    result[result.index("-MF") + 1] = str(output / (unit + ".discovered.d"))
    result[result.index("-o") + 1] = str(output / (unit + ".discovered.stdout"))
    return result


def configuration_arguments(arguments, output, unit):
    result = []
    cursor = 0
    while cursor < len(arguments):
        argument = arguments[cursor]
        if argument == "-MF":
            cursor += 2
            continue
        if argument not in ("-c", "-MD"):
            result.append(argument)
        cursor += 1
    result[result.index("-o") + 1] = str(output / (unit + ".macros.txt"))
    return result + ["-E", "-dM"]


def read_configuration(path, unit):
    definitions = {}
    for line in Path(path).read_text().splitlines():
        match = re.fullmatch(r"#define\s+([A-Za-z_]\w*)\s+(.*?)\s*", line)
        if match:
            definitions.setdefault(match[1], []).append(match[2])
    pacga.require(definitions.get("CONFIG_ROUTE_A_PACGA_SVC") == ["1"],
                  "actual CPP did not enable exactly one PACGA configuration")
    pacga.require(definitions.get("__ARM_KERNEL_PROTECT__", []) in ([], ["0"]),
                  "actual CPP selected an unsupported ARM_KERNEL_PROTECT configuration")
    pacga.require("__arm64e__" not in definitions,
                  "actual CPP selected the arm64e ABI")
    if unit == "locore":
        pacga.require(definitions.get("__ASSEMBLER__") == ["1"],
                      "locore was not preprocessed as assembly")
    else:
        pacga.require("__ASSEMBLER__" not in definitions, "sleh was preprocessed as assembly")
    return dict(macros_sha256=sha(path), route_a_pacga_svc=1, arm_kernel_protect=0,
                language="c" if unit == "sleh" else "assembler-with-cpp")


def validate_closure(paths, source, tree, xnu, unit, assym):
    allowed = {tree / name for name in SOURCES}
    helper = tree / "osfmk/arm64/route_a_pacga_qarma5.h"
    abi_header = tree / "osfmk/arm64/route_a_pacga_abi.h"
    allowed |= {helper, abi_header}
    pacga.require(source in paths, "dependency closure omits the compiled source")
    pacga.require(all(path in allowed for path in paths if tree in path.parents),
                  "unreviewed header shadows a prepared source in the overlay")
    required = {helper, abi_header} if unit == "sleh" else {tree / EXCEPTION_ASM, abi_header, assym}
    pacga.require(required <= paths, "dependency closure omits a required PACGA implementation input")
    pacga.require(xnu / EXCEPTION_ASM not in paths,
                  "compile used the original exception header instead of the reviewed entry reset")


def prepare(xnu, recipe_path, output, expected_sleh, *, locore_recipe, expected_locore,
            expected_exception_asm, compile_timeout=DEFAULT_COMPILE_TIMEOUT):
    validate_compile_timeout(compile_timeout)
    expected = dict(zip(SOURCES, (expected_sleh, expected_locore, expected_exception_asm)))
    pacga.require(all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
                      for value in expected.values()), "prepared source identities must be SHA-256 digests")
    xnu, output = xnu.resolve(), output.resolve()
    recipes = {"sleh": recipe_path.resolve(), "locore": locore_recipe.resolve()}
    pacga.require(not output.exists(), "PACGA stage output must be new")
    pacga.require(not output.is_relative_to(xnu), "PACGA output must be outside the prepared source tree")
    pacga.require(run(["git", "rev-parse", "HEAD"], cwd=xnu).strip() == pacga.XNU_COMMIT,
                  "wrong XNU source baseline")
    prepared, initial = {}, {}
    for relative in SOURCES:
        prepared[relative], initial["prepared:" + relative] = captured_file(xnu / relative)
        pacga.require(initial["prepared:" + relative]["sha256"] == expected[relative],
                      "prepared source differs from the reviewed input: " + relative)
    recipe_values, previous = {}, {}
    for unit, relative in UNITS.items():
        recipe_values[unit], initial["recipe:" + unit], previous[unit] = recipe_for(
            recipes[unit], xnu / relative, unit)
    pacga.require(recipes["sleh"].parent == recipes["locore"].parent,
                  "PACGA recipes use different retained kernel builds")
    assym = recipes["locore"].parent / "assym.s"
    _, initial["assym"] = captured_file(assym)
    _, initial["genassym"] = captured_file(xnu / "osfmk/arm64/genassym.c")
    identity = pacga.implementation()
    runtime = {}
    for key, relative in (("helper", pacga.HEADER), ("abi_header", pacga.ABI_HEADER), ("patch", pacga.PATCH)):
        runtime[key], record = captured_file(ROOT / relative)
        pacga.require(record["sha256"] == identity["sources"][relative],
                      "PACGA runtime source changed while captured")
    compiler = tool_identity(recipe_values["sleh"]["arguments"][0])
    pacga.require(tool_identity(recipe_values["locore"]["arguments"][0]) == compiler,
                  "PACGA translation units do not use the same compiler invocation")
    manifest = dict(schema="route-a-pacga-stage-v2", abi=pacga.ABI, implementation=identity,
                    xnu_commit=pacga.XNU_COMMIT, prepared_sources=expected, staged_sources={},
                    tools=dict(clang=compiler), compiler=compiler["invocation"], frozen=initial,
                    translation_units={}, commands=[], compile_timeout_seconds=compile_timeout,
                    provider_prerequisite="successful source-provider POST and register_and_init_prng at SYSCTL/LAST",
                    key_material_recorded=False, compile_passed=False, kernel_linked=False,
                    runtime_boot_verified=False, overlay_enabled_by_default=False)
    created = False
    try:
        output.mkdir(parents=True)
        created = True
        tree = output / "source"
        for relative, raw in prepared.items():
            staged = tree / relative
            staged.parent.mkdir(parents=True, exist_ok=True)
            staged.write_bytes(raw)
        helper = tree / "osfmk/arm64/route_a_pacga_qarma5.h"
        abi_header = tree / "osfmk/arm64/route_a_pacga_abi.h"
        patch = output / "runtime.patch"
        for key, path in (("helper", helper), ("abi_header", abi_header), ("patch", patch)):
            path.write_bytes(runtime[key])
            path.chmod(0o444)
            manifest["frozen"][key] = file_identity(path)
            manifest[key + "_sha256"] = manifest["frozen"][key]["sha256"]
        run(["git", "init", "--quiet"], cwd=tree)
        run(["git", "apply", "--check", str(patch)], cwd=tree)
        run(["git", "apply", str(patch)], cwd=tree)
        for relative in SOURCES:
            path = tree / relative
            path.chmod(0o444)
            record = file_identity(path)
            manifest["frozen"]["source:" + relative] = record
            manifest["staged_sources"][relative] = record["sha256"]
        for key, path in (("stage", Path(__file__)), ("execution", ROOT / "scripts/route_a_pacga_probe/run.py")):
            manifest["frozen"][key] = file_identity(path)
        for unit, relative in UNITS.items():
            arguments = compile_arguments(recipe_values[unit], xnu / relative, tree / relative, output, unit, identity)
            manifest["translation_units"][unit] = dict(
                source_file=relative, recipe_sha256=initial["recipe:" + unit]["sha256"],
                arguments=arguments, directory=recipe_values[unit]["directory"],
                previous_object=dict(name=unit + ".o", sha256=sha(previous[unit])))
        (output / "compile-command.json").write_text(json.dumps(manifest, indent=2) + "\n")
        with owned_children():
            manifest["compiler_version"] = execute(
                [compiler["invocation"], "--version"], output, "compiler-version", manifest).strip()
            for unit, relative in UNITS.items():
                record = manifest["translation_units"][unit]
                arguments, directory = record["arguments"], record["directory"]
                execute(discovery_arguments(arguments, output, unit), output, unit + "-discover-headers",
                        manifest, timeout=300, cwd=directory)
                declared = dependency_paths(output / (unit + ".discovered.d"), directory)
                validate_closure(declared, tree / relative, tree, xnu, unit, assym)
                closure = {str(path): file_identity(path) for path in sorted(declared)}
                record["header_closure"] = closure
                for path, dependency in closure.items():
                    bound = manifest["frozen"].setdefault("dependency:" + path, dependency)
                    pacga.require(bound == dependency, "dependency changed between translation units: " + path)
                execute(configuration_arguments(arguments, output, unit), output, unit + "-config",
                        manifest, timeout=300, cwd=directory)
                macro_path = output / (unit + ".macros.txt")
                record["configuration"] = read_configuration(macro_path, unit)
                macro_path.chmod(0o444)
                manifest["frozen"]["configuration:" + unit] = file_identity(macro_path)
                execute(arguments, output, unit + "-compile", manifest, timeout=compile_timeout, cwd=directory)
                record["compile_exit_code"] = manifest["commands"][-1]["exit_code"]
                actual = dependency_paths(output / (unit + ".d"), directory)
                pacga.require(actual == declared, "actual compiler dependencies differ from the declared header closure")
                verify_files(manifest["frozen"], hashes=True)
                obj = output / (unit + ".o")
                obj.chmod(0o444)
                obj_identity = file_identity(obj)
                manifest["frozen"]["object:" + unit] = obj_identity
                with obj.open("rb") as stream:
                    header = stream.read(16)
                pacga.require(len(header) == 16 and struct.unpack("<4I", header) ==
                              (0xFEEDFACF, 0x0100000C, 0, 1),
                              unit + " overlay is not an ordinary-arm64 Mach-O object")
                headers = {path: value["sha256"] for path, value in closure.items()}
                publication = output / (unit + ".dependencies.json")
                publication.write_text(json.dumps(headers, indent=2, sort_keys=True) + "\n")
                record.update(object=dict(name=obj.name, bytes=obj_identity["generation"]["bytes"],
                                          sha256=obj_identity["sha256"], cpu_type="arm64", cpu_subtype=0),
                              dependency_count=len(headers), dependencies_sha256=sha(publication))
        manifest["compile_exit_code"] = 0
        pacga.require(pacga.implementation() == identity, "PACGA implementation changed during the build")
        verify_tools(manifest["tools"], hashes=True)
        verify_files(manifest["frozen"], hashes=True)
        manifest.update(descriptor_hex=pacga.descriptor().hex(), compile_passed=True)
        (output / "stage-report.json").write_text(json.dumps(manifest, indent=2) + "\n")
        return manifest
    except BaseException as error:
        manifest.update(compile_passed=False, error=type(error).__name__, message=str(error))
        if created:
            try:
                (output / "stage-report.json").write_text(json.dumps(manifest, indent=2) + "\n")
            except OSError as secondary:
                print("PACGA stage receipt write failed: " + str(secondary), file=sys.stderr)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xnu-work", type=Path, required=True)
    parser.add_argument("--recipe", type=Path, required=True, help="retained sleh.o.json recipe")
    parser.add_argument("--locore-recipe", type=Path, required=True)
    parser.add_argument("--expected-sleh-sha256", required=True)
    parser.add_argument("--expected-locore-sha256", required=True)
    parser.add_argument("--expected-exception-asm-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--compile-timeout", type=int, default=DEFAULT_COMPILE_TIMEOUT,
                        help=f"per-TU compile deadline in seconds (1..{MAX_COMPILE_TIMEOUT}; default {DEFAULT_COMPILE_TIMEOUT})")
    args = parser.parse_args(argv)
    try:
        validate_compile_timeout(args.compile_timeout)
    except ValueError as error:
        parser.error(str(error))
    result = prepare(args.xnu_work, args.recipe, args.output, args.expected_sleh_sha256,
                     locore_recipe=args.locore_recipe, expected_locore=args.expected_locore_sha256,
                     expected_exception_asm=args.expected_exception_asm_sha256,
                     compile_timeout=args.compile_timeout)
    summary = {key: result[key] for key in ("abi", "compile_passed", "kernel_linked", "runtime_boot_verified")}
    summary["objects"] = {key: value["object"] for key, value in result["translation_units"].items()}
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"build-route-a-pacga: {error}", file=sys.stderr)
        raise SystemExit(2)
