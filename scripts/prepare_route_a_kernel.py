#!/usr/bin/env python3
"""Prepare a pinned, ordinary-arm64 XNU candidate; never claim a kernel build.

The source repositories are local Git object stores. Network fetching is a
separate, explicit step. Every read uses the pinned commit, not checkout files.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "configs/kernel-route-a-ipados27.json"
REQUIRED_PATCHES = {
    "bcm2837-machine-config.patch", "native-4k-user-abi.patch",
    "native-4k-shared-region-slide.patch", "darwin26-syscalls.patch",
    "darwin26-kpi.patch", "darwin26-shared-region.patch", "native-arm-pan.patch",
}
FORBIDDEN_PATCHES = {"native-pac-keys.patch", "native-pac-arm64-user-jop.patch"}
DEFERRED_BOOT_PROGRESS = "patches/xnu-12377/zzz-boot-progress.patch"
EXPECTED_BUILD = {
    "UNIXNU_XNU_ARCH": "arm64", "UNIXNU_XNU_TARGET": "ios",
    "UNIXNU_XNU_TAG": "xnu-12377.121.6", "UNIXNU_XNU_VERSION": "12377.121.6",
    "UNIXNU_XNU_DARWIN": "25.5.0", "UNIXNU_IOS_VERSION": "27.0",
    "XNU_BOOT_PROGRESS": "0",
}
CONTRACT_PROBE = """#if !defined(__arm64__) && !defined(__aarch64__)
#error ordinary arm64 target required
#endif
#if defined(__arm64e__) || __has_feature(ptrauth_calls)
#error arm64e/ptrauth_calls must be disabled
#endif
#include "pexpert/pexpert/arm64/BCM2837.h"
#if defined(HAS_NATIVE_PAC) || defined(HAS_APPLE_PAC)
#error this machine configuration must not enable PAC
#endif
#if __ARM_ARCH__ != 8 || __ARM64_PMAP_SUBPAGE_L1__ != 1
#error unexpected generic armv8 configuration
#endif
unsigned long route_a_configuration_probe(void) { return 4096; }
"""
BUILTIN_PROBE = """struct route_a_type { void *pointer; unsigned long value; };
const char *route_a_signature = __builtin_xnu_type_signature(struct route_a_type);
unsigned long route_a_summary = __builtin_xnu_type_summary(struct route_a_type);
_Static_assert(__builtin_xnu_types_compatible(struct route_a_type, struct route_a_type),
               "XNU type compatibility trait required");
"""


class PreparationError(ValueError):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(args, *, cwd=None, check=True):
    result = subprocess.run([str(x) for x in args], cwd=cwd, capture_output=True)
    if check and result.returncode:
        raise PreparationError(
            f"command failed ({result.returncode}): {args[0]} {args[1:]}\n"
            + result.stderr.decode("utf-8", "replace")[-12000:])
    return result


def safe_path(value: str) -> str:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts or str(path) != value:
        raise PreparationError(f"unsafe/noncanonical repository path: {value!r}")
    return value


def git_blob(repository: Path, commit: str, path: str) -> bytes:
    safe_path(path)
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise PreparationError("source revision must be a full lowercase Git commit")
    return run(["git", "-C", repository, "show", f"{commit}:{path}"]).stdout


def verify_commit(repository: Path, commit: str):
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise PreparationError("source revision must be a full lowercase Git commit")
    if run(["git", "-C", repository, "cat-file", "-t", commit]).stdout.strip() != b"commit":
        raise PreparationError("pinned object is not a commit")


def series_paths(text: str, kind: str) -> list[str]:
    prefix = "../../../../../" if kind == "arch" else "arch:../../../"
    result = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if not line.startswith(prefix):
            raise PreparationError(f"unexpected {kind} series entry: {line!r}")
        path = safe_path(line[len(prefix):])
        if not path.startswith("patches/xnu-12377/") or not path.endswith(".patch"):
            raise PreparationError(f"patch is outside the XNU 12377 baseline: {path}")
        result.append(path)
    return result


def selected_paths(arch_text: str, os_text: str, exclusions: dict) -> list[str]:
    original = series_paths(arch_text, "arch") + series_paths(os_text, "os")
    if len(set(original)) != len(original):
        raise PreparationError("duplicate patch in upstream series")
    if set(exclusions) != {f"patches/xnu-12377/{p}" for p in FORBIDDEN_PATCHES}:
        raise PreparationError("the two reviewed native-PAC exclusions must be explicit")
    if not set(exclusions).issubset(original):
        raise PreparationError("an excluded patch is missing from the pinned upstream series")
    selected = [path for path in original if path not in exclusions]
    basenames = {PurePosixPath(path).name for path in selected}
    if not REQUIRED_PATCHES.issubset(basenames):
        raise PreparationError("required machine, page or Darwin 26 patch is missing")
    if basenames & FORBIDDEN_PATCHES:
        raise PreparationError("native-PAC patch is still selected")
    return selected


def validate_config(config: dict):
    target, sources = config["target"], config["sources"]
    if config["schema_version"] != 1 or target["kernel_arch"] != "arm64":
        raise PreparationError("only the ordinary arm64 schema version 1 is supported")
    if target["compiler_target"] != "arm64-apple-ios27.0" or target["compiler_march"] != "armv8-a":
        raise PreparationError("candidate must explicitly compile for ordinary Armv8-A")
    if target["machine_config"] != "BCM2837" or target["plain_pointer_abi"] is not True:
        raise PreparationError("generic machine / plain-pointer contract changed")
    if target["translation_granule"] != 4096 or target["vm_page_size"] != 4096:
        raise PreparationError("this candidate only prepares the audited 4 KiB paths")
    if sources["xnu"]["version"] != "12377.121.6" or sources["xnu"]["darwin"] != "25.5.0":
        raise PreparationError("wrong XNU baseline")
    env = config["build_environment"]
    if any(env.get(key) != value for key, value in EXPECTED_BUILD.items()):
        raise PreparationError("build environment does not match the reviewed candidate")
    if env.get("UNIXNU_XNU_COMMIT") != sources["xnu"]["commit"]:
        raise PreparationError("build environment/source revision mismatch")
    if set(env) != set(EXPECTED_BUILD) | {"UNIXNU_XNU_COMMIT"}:
        raise PreparationError("unreviewed build environment variable")
    for source in sources.values():
        if not re.fullmatch(r"[0-9a-f]{40}", source["commit"]):
            raise PreparationError("all sources must use immutable full Git revisions")
    replacements = config.get("patch_replacements", [])
    if (len(replacements) != 1 or replacements[0].get("upstream_path") !=
            "patches/xnu-12377/native-arm-pan.patch" or replacements[0].get("path") !=
            "patches/route-a-native-arm-pan-12377.patch"):
        raise PreparationError("the reviewed context-only native PAN replacement is required")
    for key in ("sha256", "upstream_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", replacements[0].get(key, "")):
            raise PreparationError("patch replacement digests must be full SHA-256 values")
    deferred = config.get("deferred_patches", [])
    if (len(deferred) != 1 or deferred[0].get("path") != DEFERRED_BOOT_PROGRESS or
            not re.fullmatch(r"[0-9a-f]{64}", deferred[0].get("sha256", "")) or
            not deferred[0].get("reason")):
        raise PreparationError("only the explicit source-bound board boot-progress deferral is supported")
    if config.get("preparation_scope") != "architecture-darwin26-plain-pager":
        raise PreparationError("preparation scope must exclude the unresolved board profile")
    status = config["status"]
    if status["kind"] != "source-preparation-candidate" or any(
        status.get(k) is not False for k in (
            "kernel_compiled", "kernel_linked", "boot_verified", "board_integration_complete",
            "full_upstream_profile_applied")
    ):
        raise PreparationError("a preparation configuration cannot assert runtime success")


def patch_change_signature(data: bytes):
    """Retain file/hunk identities and every edit; context may differ."""
    lines = data.decode("utf-8").splitlines()
    headers = [line for line in lines if line.startswith(
        ("diff --git ", "--- ", "+++ ", "@@ "))]
    edits = [line for line in lines if line.startswith(("+", "-"))
             and not line.startswith(("--- ", "+++ "))]
    if sum(line.startswith("@@ ") for line in headers) != 1:
        raise PreparationError("context replacement must preserve exactly one reviewed hunk")
    return headers, edits


def context_replacement(original: bytes, spec: dict, repo_root: Path) -> dict:
    if digest(original) != spec["upstream_sha256"]:
        raise PreparationError("upstream context-replacement patch digest differs")
    data = (repo_root / safe_path(spec["path"])).read_bytes()
    if digest(data) != spec["sha256"]:
        raise PreparationError("local context-replacement patch digest differs")
    if patch_change_signature(original) != patch_change_signature(data):
        raise PreparationError("context replacement changed the target, hunk identity or edits")
    return {
        "source": "device-repository-replacement", "path": spec["path"],
        "sha256": digest(data), "data": data,
        "upstream_path": spec["upstream_path"],
        "upstream_sha256": digest(original), "replacement_reason": spec["reason"],
    }


def defer_board_progress(paths: list[str], specs: list[dict], read_patch):
    if len(specs) != 1 or specs[0]["path"] != DEFERRED_BOOT_PROGRESS:
        raise PreparationError("only the reviewed board boot-progress patch may be deferred")
    spec = specs[0]
    if spec["path"] not in paths:
        raise PreparationError("deferred patch is absent from the pinned upstream sequence")
    data = read_patch(spec["path"])
    if digest(data) != spec["sha256"]:
        raise PreparationError("deferred patch source digest differs")
    kept = [path for path in paths if path != spec["path"]]
    if not REQUIRED_PATCHES.issubset({PurePosixPath(path).name for path in kept}):
        raise PreparationError("deferral cannot remove required kernel patches")
    return kept, [{
        "source": "unixnu", "path": spec["path"], "sha256": digest(data),
        "original_selected_index": paths.index(spec["path"]),
        "applied": False, "reason": spec["reason"],
        "requires_board_profile_integration": True,
    }]


def make_plan(config: dict, unixnu: Path, repo_root=ROOT):
    validate_config(config)
    commit = config["sources"]["unixnu"]["commit"]
    verify_commit(unixnu, commit)
    upstream = config["upstream"]
    profile_bytes = git_blob(unixnu, commit, upstream["os_profile"])
    profile = tomllib.loads(profile_bytes.decode())
    expected = config["sources"]["xnu"]
    if (profile["os"]["xnu_revision"], profile["os"]["xnu_version"],
            profile["os"]["arch"]) != (expected["commit"], expected["version"], "arm64e"):
        raise PreparationError("upstream OS profile no longer matches the reviewed source contract")
    if (profile["ipsw"]["version"], profile["ipsw"]["build"]) != (
            config["target"]["userland_version"], config["target"]["userland_build"]):
        raise PreparationError("upstream userland identity differs")
    arch = git_blob(unixnu, commit, upstream["arch_series"])
    os_series = git_blob(unixnu, commit, upstream["os_series"])
    paths = selected_paths(arch.decode(), os_series.decode(), config["exclude_patches"])
    paths, deferred = defer_board_progress(
        paths, config["deferred_patches"], lambda path: git_blob(unixnu, commit, path))
    replacements = {spec["upstream_path"]: spec for spec in config["patch_replacements"]}
    if not set(replacements).issubset(paths):
        raise PreparationError("a replacement has no selected upstream patch")
    patches = []
    for path in paths:
        data = git_blob(unixnu, commit, path)
        added = "\n".join(s[1:] for s in data.decode().splitlines()
                          if s.startswith("+") and not s.startswith("+++"))
        if re.search(r"(?m)^\s*#\s*define\s+(HAS_NATIVE_PAC|HAS_APPLE_PAC)\b", added):
            raise PreparationError(f"selected patch adds a PAC capability definition: {path}")
        if path in replacements:
            patches.append(context_replacement(data, replacements[path], repo_root))
        else:
            patches.append({"source": "unixnu", "path": path, "sha256": digest(data), "data": data})
    if len(config["local_patches"]) != 1:
        raise PreparationError("exactly the reviewed plain-auth patch is required")
    local = config["local_patches"][0]
    if local["path"] != "patches/route-a-plain-auth-12377.patch" or local["after"] not in paths:
        raise PreparationError("plain-auth patch or its 4 KiB prerequisite is missing")
    data = (repo_root / safe_path(local["path"])).read_bytes()
    if digest(data) != local["sha256"]:
        raise PreparationError("local plain-auth patch digest differs")
    patches.append({"source": "device-repository", "path": local["path"],
                    "sha256": digest(data), "data": data})
    return patches, {
        "os_profile_sha256": digest(profile_bytes), "arch_series_sha256": digest(arch),
        "os_series_sha256": digest(os_series), "excluded_patches": config["exclude_patches"],
        "patch_replacements": config["patch_replacements"],
        "deferred_patches": deferred,
    }


def snapshot(source_repo: Path, commit: str, destination: Path):
    verify_commit(source_repo, commit)
    # FETCH_HEAD-only bare inputs have no advertised branch for clone. Fetch
    # the pinned object explicitly and keep independent objects in the output.
    destination.mkdir(parents=False, exist_ok=False)
    run(["git", "-C", destination, "init", "--quiet"])
    run(["git", "-C", destination, "fetch", "--quiet", "--no-tags", "--depth", "1",
         source_repo.resolve(), commit])
    run(["git", "-C", destination, "checkout", "--quiet", "--detach", commit])
    actual = run(["git", "-C", destination, "rev-parse", "HEAD"]).stdout.decode().strip()
    if actual != commit or run(["git", "-C", destination, "status", "--porcelain"]).stdout:
        raise PreparationError("source snapshot is not a clean copy of the pinned commit")


def apply_series(tree: Path, patches: list[dict], patch_dir: Path, report: dict):
    patch_dir.mkdir()
    for index, item in enumerate(patches):
        filename = f"{index:03d}-{PurePosixPath(item['path']).name}"
        path = patch_dir / filename
        path.write_bytes(item["data"])
        run(["git", "-C", tree, "apply", "--check", path])
        run(["git", "-C", tree, "apply", path])
        record = {
            "index": index, "source": item["source"], "path": item["path"],
            "sha256": item["sha256"], "stored_file": f"patches/{filename}",
        }
        for key in ("upstream_path", "upstream_sha256", "replacement_reason"):
            if key in item:
                record[key] = item[key]
        report["applied_patches"].append(record)


def compiler_probes(tree: Path, output: Path, clang: str) -> dict:
    compiler = shutil.which(clang)
    if compiler is None:
        return {"status": "compiler_missing", "macro_contract_verified": False,
                "xnu_type_builtins_available": False, "kernel_compiled": False}
    probe_dir = output / "compiler-probes"
    probe_dir.mkdir()
    contract, builtin = probe_dir / "contract.c", probe_dir / "xnu-builtins.c"
    contract.write_text(CONTRACT_PROBE)
    builtin.write_text(BUILTIN_PROBE)
    flags = ["-target", "arm64-apple-ios27.0", "-march=armv8-a", "-ffreestanding", "-Werror"]
    obj = probe_dir / "contract.o"
    native = run([compiler, *flags, "-I", tree, "-c", contract, "-o", obj], check=False)
    (probe_dir / "contract.stderr").write_bytes(native.stderr)
    valid_object = False
    object_header_words = None
    if native.returncode == 0:
        raw = obj.read_bytes()
        if len(raw) >= 16:
            object_header_words = list(struct.unpack("<IIII", raw[:16]))
        valid_object = len(raw) >= 32 and struct.unpack("<IIII", raw[:16]) == (
            0xFEEDFACF, 0x0100000C, 0, 1)
    builtins = run([compiler, *flags, "-fsyntax-only", builtin], check=False)
    (probe_dir / "xnu-builtins.stderr").write_bytes(builtins.stderr)
    macros = run([compiler, *flags, "-I", tree, "-dM", "-E", contract], check=False)
    (probe_dir / "macros.txt").write_bytes(macros.stdout)
    return {
        "status": "passed" if native.returncode == 0 and valid_object else "failed",
        "compiler": compiler,
        "compiler_version": run([compiler, "--version"]).stdout.decode().strip(),
        "target": "arm64-apple-ios27.0", "march": "armv8-a",
        "macro_contract_verified": native.returncode == 0 and valid_object,
        "contract_probe_exit_code": native.returncode,
        "contract_probe_stderr": native.stderr.decode("utf-8", "replace")[-12000:],
        "object_sha256": digest(obj.read_bytes()) if valid_object else None,
        "object_cpu_subtype": 0 if valid_object else None,
        "object_header_words": object_header_words,
        "xnu_type_builtins_available": builtins.returncode == 0,
        "xnu_builtin_probe_exit_code": builtins.returncode,
        "xnu_builtin_probe_stderr": builtins.stderr.decode("utf-8", "replace")[-12000:],
        "kernel_compiled": False,
        "scope": "generic machine header and compiler target; not full kernel ISA or ABI",
    }


def prepare(config: dict, unixnu: Path, xnu: Path, output: Path, clang="clang", repo_root=ROOT):
    patches, provenance = make_plan(config, unixnu, repo_root)
    verify_commit(xnu, config["sources"]["xnu"]["commit"])
    output = output.resolve()
    if output == repo_root.resolve() or repo_root.resolve() in output.parents:
        raise PreparationError("generated source and build files must be outside the device repository")
    output.mkdir(parents=False, exist_ok=False)
    report = {
        "schema_version": 1, "target": config["target"], "sources": config["sources"],
        "preparation_scope": config["preparation_scope"],
        "full_upstream_profile_applied": False,
        "profile_sha256": digest(json.dumps(config, sort_keys=True).encode()),
        "provenance": provenance, "status": "preparing", "applied_patches": [],
        "kernel_compiled": False, "kernel_linked": False, "os_boot_verified": False,
        "board_integration_complete": False, "full_kernel_isa_audited": False,
        "remaining_gates": config["remaining_gates"],
    }
    try:
        tree = output / "tree"
        snapshot(xnu, config["sources"]["xnu"]["commit"], tree)
        apply_series(tree, patches, output / "patches", report)
        inventory = []
        for directory, dirs, files in os.walk(tree, followlinks=False):
            if Path(directory) == tree:
                dirs[:] = [name for name in dirs if name != ".git"]
            for name in sorted(dirs + files):
                path = Path(directory) / name
                if path.is_symlink():
                    data, kind = os.readlink(path).encode(), "symlink"
                elif path.is_file():
                    data, kind = path.read_bytes(), "file"
                else:
                    continue
                inventory.append({"path": str(path.relative_to(tree)), "kind": kind,
                                  "mode": path.lstat().st_mode & 0o777,
                                  "size": len(data), "sha256": digest(data)})
        inventory.sort(key=lambda item: item["path"])
        inventory_bytes = (json.dumps(inventory, sort_keys=True, indent=2) + "\n").encode()
        (output / "source-inventory.json").write_bytes(inventory_bytes)
        report["source_inventory_sha256"] = digest(inventory_bytes)
        report["source_file_count"] = len(inventory)
        report["compiler_probes"] = compiler_probes(tree, output, clang)
        report["full_build_blockers"] = [
            "TB371FC board/archive closure is not qualified for this XNU revision",
            "complete Linux XNU toolchain and SDK headers have not been qualified",
            "kernel, external archives and prelinked kext ISA/ABI remain unaudited",
        ]
        if not report["compiler_probes"]["xnu_type_builtins_available"]:
            report["full_build_blockers"].append("selected compiler lacks XNU type builtins")
        if not report["compiler_probes"]["macro_contract_verified"]:
            raise PreparationError("ordinary-arm64 generic machine/compiler probe failed")
        report["status"] = "sources_prepared"
        # Informational inputs only: the upstream builder also requires its
        # matching resolver, headers, archives and complete board integration.
        (output / "build-environment.json").write_text(json.dumps(
            config["build_environment"], indent=2) + "\n")
        (output / "selected-patches.json").write_text(json.dumps(
            report["applied_patches"], indent=2) + "\n")
    except (PreparationError, OSError) as exc:
        report["status"], report["error"] = "failed", str(exc)
        raise
    finally:
        (output / "preparation-report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--unixnu-repository", type=Path, required=True)
    parser.add_argument("--xnu-repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new directory outside this repository")
    parser.add_argument("--clang", default="clang")
    args = parser.parse_args(argv)
    try:
        report = prepare(json.loads(args.config.read_text()), args.unixnu_repository.resolve(),
                         args.xnu_repository.resolve(), args.output, args.clang)
    except (PreparationError, OSError, KeyError, ValueError) as exc:
        print(f"kernel preparation blocked: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({
        "status": report["status"], "patches_applied": len(report["applied_patches"]),
        "compiler_probes": report["compiler_probes"],
        "report": str(args.output.resolve() / "preparation-report.json"),
        "kernel_compiled": False, "os_boot_verified": False,
        "full_upstream_profile_applied": False,
        "deferred_patch_count": len(report["provenance"]["deferred_patches"]),
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
