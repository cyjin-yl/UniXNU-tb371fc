#!/usr/bin/env python3
"""Compile the two pinned public platform providers against the actual XNU ABI.

Requires the recorded successful generic kernel and its unchanged C++ recipe.
All source snapshots, dependency files, logs, objects and archives go to a new
external output directory. This command neither links nor modifies the kernel.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from prepare_route_a_toolchain import sha256_file, save_json

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/route-a-platform.json"
PLAIN_HEADER = (0xFEEDFACF, 0x0100000C, 0)
STANDALONE_FLAGS = {
    "-xc++", "--driver-mode=g++", "-c", "-std=gnu++2b", "-fsized-deallocation",
    "-fapple-kext", "-g", "-nostdlibinc", "-ferror-limit=10000", "-fno-builtin",
    "-fno-common", "-ftrivial-auto-var-init=zero", "-fsigned-bitfields",
    "-fmerge-all-constants", "-fc++-static-destructors=none",
    "-fsanitize-minimal-runtime", "-fsanitize=signed-integer-overflow",
    "-momit-leaf-frame-pointer", "-fno-strict-aliasing", "-mkernel", "-O2",
}


class PlatformError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise PlatformError(message)


def child(root: Path, relative: str) -> Path:
    part = Path(relative)
    require(bool(part.parts) and not part.is_absolute() and ".." not in part.parts,
            f"invalid relative input: {relative}")
    result = root / part
    require(result.resolve().is_relative_to(root.resolve()), f"input escapes its root: {relative}")
    return result


def file_identity(path: Path) -> dict:
    require(path.is_file(), f"missing regular input: {path}")
    return {"path": str(path), "sha256": sha256_file(path), "size": path.stat().st_size}


def new_output(path: Path, protected: list[Path]) -> Path:
    require(not path.is_symlink() and not path.exists(), "output must be new; previous attempts are retained")
    output = path.resolve()
    require(output != Path("/"), "invalid output directory")
    for base in [ROOT, *protected]:
        base = base.resolve()
        require(not output.is_relative_to(base) and not base.is_relative_to(output),
                f"output overlaps a protected input: {base}")
    output.mkdir(parents=True, exist_ok=False)
    return output


def macho(data: bytes, filetype: int) -> tuple[dict, dict]:
    """Check the thin header, deployment command and bounded nlist_64 table.

    This is a format/target and symbol-name audit, not an instruction-set or
    relocation audit. N_WEAK_REF (0x40) is retained separately from strong U.
    """
    require(len(data) >= 32, "truncated Mach-O header")
    words = struct.unpack_from("<8I", data)
    require(words[:4] == (*PLAIN_HEADER, filetype),
            f"expected ordinary ARM64 Mach-O type {filetype}, got {words[:4]}")
    end, pos = 32 + words[5], 32
    require(end <= len(data), "Mach-O load commands exceed file")
    versions, symtabs = [], []
    for _ in range(words[4]):
        require(pos + 8 <= end, "truncated Mach-O load command")
        cmd, size = struct.unpack_from("<II", data, pos)
        require(size >= 8 and size % 8 == 0 and pos + size <= end, "invalid Mach-O command size")
        require(cmd not in (0x24, 0x25, 0x2F, 0x30), "unexpected legacy deployment command")
        if cmd == 0x32:
            require(size >= 24, "truncated LC_BUILD_VERSION")
            platform, minimum, sdk, count = struct.unpack_from("<4I", data, pos + 8)
            require(size == 24 + count * 8, "invalid LC_BUILD_VERSION tool array")
            versions.append({"platform": platform, "minos": minimum, "sdk": sdk})
        if cmd == 0x2:
            require(size == 24, "invalid LC_SYMTAB")
            symtabs.append(struct.unpack_from("<4I", data, pos + 8))
        pos += size
    require(pos == end, "Mach-O load-command total differs from sizeofcmds")
    require(len(versions) == 1 and versions[0]["platform"] == 2 and versions[0]["minos"] == 27 << 16,
            "expected exactly one LC_BUILD_VERSION for iOS 27.0")
    require(len(symtabs) == 1, "expected one retained Mach-O symbol table")
    symoff, nsyms, stroff, strsize = symtabs[0]
    require(symoff >= end and symoff + nsyms * 16 <= len(data) and
            stroff >= end and stroff + strsize <= len(data), "Mach-O symbols exceed file")
    require(symoff + nsyms * 16 <= stroff or stroff + strsize <= symoff,
            "overlapping Mach-O symbol and string tables")
    strings = data[stroff:stroff + strsize]
    records = []
    groups = {key: [] for key in ("defined_external", "strong_undefined", "weak_undefined",
                                  "common_external", "unsupported_external")}
    for index in range(nsyms):
        string_index, typ, section, desc, value = struct.unpack_from("<IBBHQ", data, symoff + index * 16)
        require(string_index < strsize, "symbol string index exceeds string table")
        stop = strings.find(b"\0", string_index)
        require(stop >= 0, "unterminated Mach-O symbol name")
        name = strings[string_index:stop].decode("utf-8", "strict")
        if typ & 0xE0:  # STAB debug entries are not link symbols.
            continue
        records.append({"name": name, "n_type": typ, "n_sect": section, "n_desc": desc, "value": value})
        if not typ & 1:
            continue
        kind = typ & 0xE
        if kind == 0 and value == 0:
            groups["weak_undefined" if desc & 0x40 else "strong_undefined"].append(name)
        elif kind == 0:
            groups["common_external"].append(name)
        elif kind in (2, 0xE):
            groups["defined_external"].append(name)
        else:
            # Indirect/prebound symbols need actual linker semantics; do not
            # count them as definitions in the optional name-set comparison.
            groups["unsupported_external"].append(name)
    symbols = {"records": records, **{key: sorted(set(value)) for key, value in groups.items()}}
    header = {"header_words": list(words), "ordinary_arm64": True, "filetype": filetype,
              "build_version": versions[0], "symbol_count": nsyms,
              "full_instruction_set_audited": False, "relocations_audited": False}
    return header, symbols


def replay_recipe(record: dict, kernel: Path, source: Path, output: Path,
                  warnings: list[str]) -> tuple[list[str], dict]:
    """Accept the reviewed driver option grammar; never forward unknown flags."""
    args = record["arguments"]
    require(isinstance(args, list) and len(args) > 1 and all(isinstance(v, str) and v for v in args),
            "invalid compilation arguments")
    require(all("\0" not in v and not v.startswith("@") for v in args), "response files are not permitted")
    cwd = Path(record["directory"])
    require(cwd.is_absolute() and cwd.resolve().is_relative_to(kernel.resolve()), "recipe cwd escapes kernel")
    require(Path(record["file"]).resolve() == (kernel / ".cache/xnu-work/iokit/Kernel/IOPlatformExpert.cpp").resolve(),
            "recipe does not compile the actual IOPlatformExpert source")
    require(Path(args[0]).is_absolute(), "compiler path must be absolute")
    require(source.is_absolute() and output.is_absolute(), "isolated source/output must be absolute")
    destination = output / (source.stem + ".o")
    depfile, mjfile = output / "dependencies.d", output / "compile-record.json"
    result, removed, isolated = [args[0], "--no-default-config"], [], []
    counts = {key: 0 for key in ("source", "output", "arch", "cpu", "target", "minos", "compile")}
    index = 1
    while index < len(args):
        value = args[index]

        def following():
            require(index + 1 < len(args), f"missing value after {value}")
            return args[index + 1]

        if value == record["file"]:
            counts["source"] += 1
            result.append(str(source))
        elif value == "-o":
            original = following()
            require(original == record.get("output"), "recipe output disagrees with -o")
            result.extend(("-o", str(destination)))
            counts["output"] += 1
            isolated.append({"flag": value, "original": original, "replacement": str(destination)})
            index += 1
        elif value.startswith(("-Wp,", "-Wa,", "-Wl,")):
            raise PlatformError(f"preprocessor/assembler/linker passthrough is not permitted: {value}")
        elif value == "-Xclang":
            warning = following()
            require(warning.startswith("-W") and not warning.startswith(("-Wp,", "-Wa,", "-Wl,")),
                    "unreviewed -Xclang option (plugins and extra cc1 outputs are not permitted)")
            removed.extend((value, warning))
            index += 1
        elif value.startswith("-W"):
            removed.append(value)
        elif value in ("-MD", "-MMD", "-MP"):
            isolated.append({"flag": value, "replacement": "explicit -MD/-MF/-MT below"})
        elif any(value.startswith(flag) for flag in ("-MF", "-MJ", "-MT", "-MQ")):
            flag = value[:3]
            original = following() if value == flag else value[3:]
            require(bool(original), f"empty {flag} output")
            target = mjfile if flag == "-MJ" else depfile if flag == "-MF" else destination
            isolated.append({"flag": flag, "original": original, "replacement": str(target)})
            if flag == "-MJ":
                require(not any(arg == "-MJ" for arg in result), "multiple -MJ outputs")
                result.extend(("-MJ", str(mjfile)))
            index += value == flag
        elif value in ("-arch", "-target", "--target"):
            target = following()
            if value == "-arch":
                require(target == "arm64", "recipe architecture is not plain arm64")
                counts["arch"] += 1
            else:
                require(re.fullmatch(r"arm64-apple-ios27\.0(?:\.0)?", target), "recipe target changed")
                counts["target"] += 1
            result.extend((value, target))
            index += 1
        elif value.startswith("--target="):
            require(re.fullmatch(r"--target=arm64-apple-ios27\.0(?:\.0)?", value), "recipe target changed")
            counts["target"] += 1
            result.append(value)
        elif value.startswith("-mcpu="):
            require(value == "-mcpu=generic", "recipe CPU must remain generic")
            counts["cpu"] += 1
            result.append(value)
        elif value.startswith("-mios-version-min="):
            require(value in ("-mios-version-min=27.0", "-mios-version-min=27.0.0"), "deployment target changed")
            counts["minos"] += 1
            result.append(value)
        elif value == "-mllvm":
            require(following() == "-disable-atexit-based-global-dtor-lowering", "unreviewed LLVM option")
            result.extend((value, following()))
            index += 1
        elif value in ("-D", "-U", "-I", "-include"):
            argument = following()
            require(not argument.startswith(("-", "@")), f"invalid {value} argument")
            if value == "-I":
                path = Path(argument) if Path(argument).is_absolute() else cwd / argument
                require(path.resolve().is_relative_to(kernel.resolve()), "include directory escapes kernel")
            elif value == "-include":
                require(argument == "meta_features.h", "unreviewed forced header")
            elif value == "-D":
                require(argument.split("=", 1)[0] not in ("__arm64e__", "__PTRAUTH__", "HAS_NATIVE_PAC"),
                        "recipe enables pointer authentication")
            result.extend((value, argument))
            index += 1
        elif value.startswith("-fsanitize-ignorelist="):
            path = Path(value.split("=", 1)[1])
            require(path.is_absolute() and path.resolve().is_relative_to(kernel.resolve()), "ignorelist escapes kernel")
            result.append(value)
        elif value in STANDALONE_FLAGS:
            counts["compile"] += value == "-c"
            result.append(value)
        else:
            raise PlatformError(f"unreviewed compiler argument: {value}")
        index += 1
    require(all(counts[key] == 1 for key in ("source", "output", "arch", "cpu", "minos", "compile")) and
            counts["target"] >= 1, f"recipe target/source/output contract is incomplete: {counts}")
    require(warnings and all(v.startswith("-W") and not v.startswith(("-Wp,", "-Wa,", "-Wl,")) for v in warnings)
            and "-Werror" in warnings, "invalid upstream warning policy")
    result.extend([*warnings, "-I", str(kernel / ".cache/xnu-work/osfmk"),
                   "-MD", "-MF", str(depfile), "-MT", str(destination)])
    return result, {"removed_warning_arguments": removed, "isolated_outputs": isolated,
                    "added_no_default_config": True, "added_dependency_inventory": str(depfile),
                    "upstream_warning_arguments": warnings, "cpu": "generic", "target": "arm64-apple-ios27.0"}


def git(repository: Path, *args) -> bytes:
    executable = shutil.which("git", path=os.defpath)
    require(executable is not None, "git is required")
    env = {"PATH": os.defpath, "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_NO_LAZY_FETCH": "1"}
    argv = [executable, "-c", "core.fsmonitor=false", "-C", str(repository), *args]
    result = subprocess.run(argv, env=env, capture_output=True)
    require(result.returncode == 0, f"source Git check failed: {result.stderr.decode('utf-8', 'replace')[-4000:]}")
    return result.stdout


def snapshot_source(repository: Path, spec: dict, destination: Path) -> dict:
    require(repository.is_dir() and not repository.is_symlink(), "source must be a normal checkout directory")
    require(Path(git(repository, "rev-parse", "--show-toplevel").decode().strip()).resolve() == repository.resolve(),
            "source path is not its own Git working tree")
    require(git(repository, "rev-parse", "HEAD").decode().strip() == spec["commit"],
            f"source commit changed: {spec['name']}")
    require(not git(repository, "status", "--porcelain=v1", "--untracked-files=no"),
            f"tracked source files are dirty: {spec['name']}")
    destination.mkdir(parents=True, exist_ok=False)
    records = []
    for entry in spec["files"]:
        relative = entry["path"]
        source, target = child(repository, relative), child(destination, relative)
        require(not source.is_symlink() and source.is_file(), f"source is not a regular file: {source}")
        blob = git(repository, "rev-parse", f"{spec['commit']}:{relative}").decode().strip()
        require(blob == entry["git_blob"], f"catalog source blob changed: {relative}")
        data = git(repository, "cat-file", "blob", blob)
        require(data == source.read_bytes(), f"source bytes differ from Git object: {relative}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        records.append({"source_path": relative, "git_blob": blob, **file_identity(target)})
    require(spec["translation_unit"] in {entry["source_path"] for entry in records} and
            "LICENSE" in {entry["source_path"] for entry in records}, "source or license absent from snapshot")
    return {"repository": spec["repository"], "commit": spec["commit"], "checkout": str(repository),
            "license": spec["license"], "files": records,
            "untracked_checkout_files_used": False, "tracked_checkout_clean": True}


def verified_json(path: Path, expected_sha256: str | None = None) -> tuple[dict, dict]:
    raw = path.read_bytes()
    identity = {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
    require(expected_sha256 is None or identity["sha256"] == expected_sha256, f"input digest changed: {path}")
    return json.loads(raw), identity


def verify_inputs(kernel: Path, toolwork: Path, config: dict) -> tuple[dict, dict, Path, dict, dict]:
    baseline = config["baseline"]
    report, report_id = verified_json(child(kernel, baseline["build_report_path"]), baseline["build_report_sha256"])
    require(report.get("status") == "builder_completed" and report.get("exit_code") == 0 and
            report.get("builder_completed") is True and report.get("ordinary_arm64_candidate_headers_verified") is True,
            "generic kernel build has not succeeded")
    require(report.get("unixnu_commit") == config["unixnu_commit"] and report.get("xnu_commit") == config["xnu_commit"],
            "kernel source pins differ from the provider baseline")
    candidate = child(kernel, baseline["kernel_path"])
    candidate_id = file_identity(candidate)
    require(candidate_id["sha256"] == baseline["kernel_sha256"] and candidate_id["size"] == baseline["kernel_size"],
            "actual kernel candidate changed")
    require(any(entry.get("path") == baseline["kernel_path"] and entry.get("sha256") == candidate_id["sha256"]
                for entry in report["artifacts"]), "kernel report does not identify this candidate")
    header, symbols = macho(candidate.read_bytes(), 2)
    recipe_path = child(kernel, baseline["recipe_path"])
    recipe_raw = recipe_path.read_bytes()
    require(hashlib.sha256(recipe_raw).hexdigest() == baseline["recipe_sha256"], "actual compilation recipe changed")
    recipe = json.loads(recipe_raw.decode().strip().rstrip(","))
    original_object = child(Path(recipe["directory"]), recipe["output"])
    require(original_object.resolve().is_relative_to(kernel), "original recipe output escapes kernel")
    clang_state, clang_id = verified_json(toolwork / "state.json")
    host_state, host_id = verified_json(toolwork / "host-tools-state.json")
    require(clang_state.get("status") == "clang_verified" and host_state.get("status") == "host_tools_built" and
            host_state.get("combined_toolchain_verified") is True and host_state.get("unixnu_commit") == config["unixnu_commit"],
            "custom compiler and combined host tools are not verified")
    verifications = [clang_state["verification"], host_state["clang_verification"]]
    compiler = Path(recipe["arguments"][0])
    prefix = Path(host_state["environment"]["UNIXNU_TOOLCHAIN"]).resolve()
    require(compiler.is_file() and os.access(compiler, os.X_OK) and compiler.resolve().is_relative_to(prefix),
            "recipe compiler is outside the verified toolchain")
    compiler_id = {**file_identity(compiler), "realpath": str(compiler.resolve())}
    expected = baseline["compiler_sha256"]
    require(compiler_id["sha256"] == expected and report["compiler"]["sha256"] == expected,
            "actual compiler differs from the successful kernel compiler")
    for verification in verifications:
        require(verification.get("status") == "passed" and verification.get("static_assertions") == 19 and
                verification["compiler"]["sha256"] == expected and
                Path(verification["compiler"]["path"]).resolve() == compiler.resolve(),
                "verified compiler identity/trait contract changed")
    for entry in host_state["outputs"]:
        require(sha256_file(Path(entry["path"])) == entry["sha256"], f"verified host tool changed: {entry['path']}")
    kernel_id = {**candidate_id, "macho": header, "build_report": report_id,
                 "recipe": file_identity(recipe_path), "compiler": compiler_id,
                 "original_recipe_object": file_identity(original_object)}
    states = {"clang": clang_id, "host_tools": host_id}
    return kernel_id, recipe, prefix, states, symbols


class Execution:
    def __init__(self, output: Path, report: dict, env: dict):
        self.output, self.report, self.env = output, report, env
        (output / "logs").mkdir()

    def save(self):
        save_json(self.output / "report.json", self.report)

    def run(self, label: str, argv, cwd: Path, timeout=600) -> dict:
        stdout, stderr = self.output / "logs" / (label + ".stdout"), self.output / "logs" / (label + ".stderr")
        item = {"label": label, "argv": [str(value) for value in argv], "cwd": str(cwd),
                "stdout": str(stdout), "stderr": str(stderr), "status": "running"}
        self.report["commands"].append(item)
        self.save()
        start = time.monotonic()
        try:
            with stdout.open("xb") as out, stderr.open("xb") as err:
                process = subprocess.run(item["argv"], cwd=cwd, env=self.env, stdout=out, stderr=err, timeout=timeout)
            item.update(exit_code=process.returncode, status="completed")
        except (OSError, subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
            item.update(status="interrupted" if isinstance(exc, KeyboardInterrupt) else "failed", error=str(exc))
            raise
        finally:
            item["elapsed_seconds"] = round(time.monotonic() - start, 3)
            for key, path in (("stdout", stdout), ("stderr", stderr)):
                if path.is_file():
                    item[key + "_sha256"] = sha256_file(path)
                    if item.get("exit_code", 1) != 0:
                        with path.open("rb") as stream:
                            stream.seek(max(0, path.stat().st_size - 12000))
                            item[key + "_tail"] = stream.read().decode("utf-8", "replace")
            self.save()
        return item


def dependencies(path: Path, cwd: Path, roots: list[Path]) -> list[dict]:
    text = path.read_text().replace("\\\n", "")
    require(":" in text, "compiler dependency output lacks its target")
    records = []
    for name in sorted(set(shlex.split(text.split(":", 1)[1]))):
        dependency = Path(name) if Path(name).is_absolute() else cwd / name
        resolved = dependency.resolve()
        require(any(resolved.is_relative_to(root.resolve()) for root in roots),
                f"compiler used a header outside the bound source/SDK/toolchain roots: {dependency}")
        records.append({**file_identity(dependency), "realpath": str(resolved)})
    require(records, "compiler dependency inventory is empty")
    return records


def compile_component(spec: dict, snapshot: dict, recipe: dict, kernel: Path,
                      prefix: Path, output: Path, ar: Path, warnings: list[str], execution: Execution) -> dict:
    name = spec["name"]
    component = {"name": name, "status": "compiling", "source": snapshot}
    execution.report["components"].append(component)
    destination = output / name
    destination.mkdir()
    source = output / "sources" / name / spec["translation_unit"]
    argv, changes = replay_recipe(recipe, kernel, source, destination, warnings)
    component["recipe_changes"] = changes
    save_json(destination / "compile-command.json", argv)
    item = execution.run(name + "-compile", argv, Path(recipe["directory"]))
    component["compile"] = item
    obj = destination / (source.stem + ".o")
    if item["exit_code"]:
        component["status"] = "compile_failed"
        if obj.is_file():
            component["partial_object"] = file_identity(obj)
        execution.save()
        return component
    component["status"] = "checking_object"
    header, symbols = macho(obj.read_bytes(), 1)
    symbol_path = destination / "symbols.json"
    save_json(symbol_path, symbols)
    component["object"] = {**file_identity(obj), "macho": header, "symbols": file_identity(symbol_path)}
    dependency_path = destination / "dependencies.json"
    save_json(dependency_path, dependencies(destination / "dependencies.d", Path(recipe["directory"]),
                                            [kernel, prefix, output / "sources"]))
    component["dependencies"] = file_identity(dependency_path)
    archive = destination / ("lib" + name + ".a")
    component["status"] = "archiving"
    result = execution.run(name + "-archive", [ar, "--format=darwin", "rcsD", archive, obj], output)
    if result["exit_code"]:
        component["status"] = "archive_failed"
        if archive.is_file():
            component["partial_archive"] = file_identity(archive)
    require(result["exit_code"] == 0, f"archive failed for {name}")
    component["status"] = "checking_archive"
    require(archive.read_bytes().startswith(b"!<arch>\n"), "not a normal archive")
    listing = execution.run(name + "-archive-list", [ar, "t", archive], output)
    require(listing["exit_code"] == 0 and Path(listing["stdout"]).read_text().splitlines() == [obj.name],
            f"archive member list differs for {name}")
    member = execution.run(name + "-archive-member", [ar, "p", archive, obj.name], output)
    require(member["exit_code"] == 0 and member["stdout_sha256"] == component["object"]["sha256"],
            f"archive member bytes differ for {name}")
    component["archive"] = {**file_identity(archive),
                            "members": [{"name": obj.name, "object_path": str(obj), "sha256": sha256_file(obj)}]}
    component["status"] = "archive_built"
    execution.save()
    return component


def symbol_comparison(kernel: dict, components: list[dict]) -> dict:
    definitions = set(kernel["defined_external"])
    providers, duplicates = {}, []
    for component in components:
        if component["status"] != "archive_built":
            continue
        symbols = json.loads(Path(component["object"]["symbols"]["path"]).read_text())
        providers[component["name"]] = symbols
        duplicates += [{"provider": component["name"], "symbol": name}
                       for name in symbols["defined_external"] if name in definitions]
        definitions.update(symbols["defined_external"])
    return {"scope": "external-symbol-name-set-comparison-only", "link_verified": False,
            "potential_duplicate_names": duplicates,
            "duplicate_definition_strength_classified": False,
            "kernel_unsupported_external": kernel["unsupported_external"],
            "components": [{"name": name,
                            "strong_unresolved": sorted(set(symbols["strong_undefined"]) - definitions),
                            "weak_unresolved": sorted(set(symbols["weak_undefined"]) - definitions),
                            "common_external": symbols["common_external"],
                            "unsupported_external": symbols["unsupported_external"]}
                           for name, symbols in providers.items()]}


def recheck_inputs(report: dict, identities: list[dict]):
    """Called before the shared locks are released, including failed attempts."""
    checks = []
    for identity in identities:
        item = {"path": identity["path"], "expected_sha256": identity["sha256"]}
        try:
            item["actual_sha256"] = sha256_file(Path(identity["path"]))
            item["unchanged"] = item["actual_sha256"] == identity["sha256"]
        except OSError as exc:
            item.update(unchanged=False, error=str(exc))
        checks.append(item)
    report["protected_input_rechecks"] = checks
    report["protected_inputs_unchanged"] = bool(checks) and all(item["unchanged"] for item in checks)
    if not report["protected_inputs_unchanged"]:
        report.update(status="failed", provider_archives_built=False,
                      error="one or more bound inputs changed during the attempt")


def build(args) -> dict:
    config, config_id = verified_json(CONFIG)
    require(config.get("schema_version") == 1 and config["target"] == {
        "architecture": "arm64", "cpu": "generic", "platform": 2, "minimum_os": "27.0", "macho_subtype": 0},
        "unsupported provider configuration")
    kernel, toolwork, sources = args.kernel_dir.resolve(), args.toolchain_work.resolve(), args.sources.resolve()
    for path in (kernel, toolwork, sources):
        require(path.is_dir(), f"missing input directory: {path}")
    # Read the installation location before creating anything, so an invalid
    # output inside that prefix is rejected without adding a directory there.
    prefix_hint = Path(json.loads((toolwork / "host-tools-state.json").read_text())["environment"]["UNIXNU_TOOLCHAIN"])
    require(prefix_hint.is_absolute(), "toolchain prefix must be absolute")
    output = new_output(args.output, [kernel, toolwork, sources, prefix_hint])
    report = {"schema_version": 1, "status": "validating", "scope": config["scope"],
              "driver": file_identity(Path(__file__)), "config": config_id, "output": str(output),
              "support_files": [file_identity(Path(sha256_file.__code__.co_filename))],
              "commands": [], "components": [], "provider_archives_built": False,
              "provider_kernel_link_verified": False, "complete_board_archive_closure": False,
              "tb371fc_kernel_qualified": False, "full_instruction_set_audited": False, "os_boot_verified": False,
              "protected_inputs_unchanged": None}
    save_json(output / "report.json", report)
    try:
        with ExitStack() as locks:
            # Read-only opens: never create or update a file inside the kernel
            # or toolchain workspace. Cooperate with their existing writers.
            for path in (kernel / ".route-a/build.lock", toolwork / "build.lock", toolwork / "host-tools.lock"):
                handle = locks.enter_context(path.open("rb"))
                try:
                    fcntl.flock(handle, fcntl.LOCK_SH | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise PlatformError(f"input build/installation is active: {path}") from exc
            kernel_id, recipe, prefix, states, kernel_symbols = verify_inputs(kernel, toolwork, config)
            protected = [kernel_id, kernel_id["recipe"], kernel_id["build_report"], kernel_id["compiler"],
                         kernel_id["original_recipe_object"], states["clang"], states["host_tools"], config_id]
            locks.callback(recheck_inputs, report, protected)
            require(not output.is_relative_to(prefix) and not prefix.is_relative_to(output),
                    "output overlaps the compiler installation")
            report.update(kernel=kernel_id, toolchain_states=states, status="compiling")
            (output / "tmp").mkdir()
            env = {"PATH": os.pathsep.join((str(Path(recipe["arguments"][0]).parent), os.defpath)),
                   "LC_ALL": "C", "ZERO_AR_DATE": "1", "TMPDIR": str(output / "tmp")}
            report["environment"] = env
            execution = Execution(output, report, env)
            inputs = output / "inputs"
            inputs.mkdir()
            for name, identity in (("kernel-build-report.json", kernel_id["build_report"]),
                                   ("original-compile-record.json", kernel_id["recipe"]),
                                   ("clang-state.json", states["clang"]), ("host-tools-state.json", states["host_tools"]),
                                   ("platform-config.json", config_id)):
                shutil.copyfile(identity["path"], inputs / name)
            save_json(inputs / "kernel-symbols.json", kernel_symbols)
            report["kernel"]["symbols"] = file_identity(inputs / "kernel-symbols.json")
            ar_name = args.ar or shutil.which("llvm-ar-19") or shutil.which("llvm-ar")
            require(ar_name is not None, "a Mach-O-capable LLVM archiver is required (use --ar)")
            ar_found = shutil.which(str(ar_name))
            require(ar_found is not None, f"archiver is not executable: {ar_name}")
            ar = Path(ar_found).absolute()
            report["archiver"] = {**file_identity(ar), "realpath": str(ar.resolve())}
            protected.append(report["archiver"])
            ar_version = execution.run("archiver-version", [ar, "--version"], output)
            require(ar_version["exit_code"] == 0, "could not read archiver version")
            version = Path(ar_version["stdout"]).read_text()
            require("LLVM" in version, "the reviewed archive command requires LLVM ar with Darwin format support")
            report["archiver"]["version"] = version
            compiler_version = execution.run("compiler-version", [recipe["arguments"][0], "--version"], output)
            require(compiler_version["exit_code"] == 0, "could not execute the verified compiler")
            report["kernel"]["compiler"]["version"] = Path(compiler_version["stdout"]).read_text()
            snapshots = {}
            for spec in config["components"]:
                snapshots[spec["name"]] = snapshot_source(child(sources, spec["name"]), spec,
                                                          output / "sources" / spec["name"])
            report["source_snapshots"] = snapshots
            for spec in config["components"]:
                compile_component(spec, snapshots[spec["name"]], recipe, kernel, prefix, output, ar,
                                  config["upstream_compile_policy"]["warnings"], execution)
            comparison = output / "symbol-comparison.json"
            save_json(comparison, symbol_comparison(kernel_symbols, report["components"]))
            report["symbol_comparison"] = file_identity(comparison)
            require(len(report["components"]) == 2 and all(c["status"] == "archive_built" for c in report["components"]),
                    "one or more provider compilations failed; complete diagnostics are retained")
            report.update(status="archives_built", provider_archives_built=True)
    except (PlatformError, OSError, ValueError, KeyError, TypeError, struct.error, subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
        report.update(status="failed", error=str(exc), error_type=type(exc).__name__)
    finally:
        report["finished_at_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        save_json(output / "report.json", report)
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-dir", type=Path, required=True)
    parser.add_argument("--toolchain-work", type=Path, required=True)
    parser.add_argument("--sources", type=Path, required=True, help="contains the two fixed clean provider checkouts")
    parser.add_argument("--output", type=Path, required=True, help="new external directory; never reused")
    parser.add_argument("--ar", help="existing LLVM ar, default llvm-ar-19 or llvm-ar")
    args = parser.parse_args(argv)
    try:
        report = build(args)
    except (PlatformError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"status": report["status"], "report": str(Path(report["output"]) / "report.json"),
                      "error": report.get("error")}, indent=2))
    return 0 if report["status"] == "archives_built" else 2


if __name__ == "__main__":
    raise SystemExit(main())
