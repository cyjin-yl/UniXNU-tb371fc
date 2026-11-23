#!/usr/bin/env python3
"""Stage pinned public inputs and execute the first ordinary-arm64 XNU build.

stage downloads public sources into a new external work tree. run invokes the
fixed upstream builder once, retaining the actual exit status and partial
outputs. Neither command selects a crypto provider or produces a boot claim.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parent))
import prepare_route_a_toolchain as toolchain

ROOT = Path(__file__).resolve().parents[1]
UNIXNU_COMMIT = toolchain.UNIXNU_COMMIT
XNU_COMMIT = "ac9718fb1af618d5ce8678d0dc6e8a58f252216f"
SOURCE_INVENTORY_SHA256 = "16aed427ee21f60f7e8697dbd21f1fce75db653749e677a787c4844c44a438b8"
PROFILE_PATH = "profiles/os/ipados-27.0.1-24A446/profile.toml"
XNU_URL = "https://github.com/apple-oss-distributions/xnu.git"
PUBLIC_REFERENCES = {
    "libplatform": ("libplatform-375.120.2", "b7ed7cf5cf7dd12b98672435db2225a860f199d8"),
    "libdispatch": ("libdispatch-1542.100.32", "701f4d1a24ae9c6863901bbbb22624b7d1b87321"),
    "AvailabilityVersions": ("AvailabilityVersions-157.2", "149b1777f3e8c2133042d8e188f72e3adf6a7110"),
}
TRUSTCACHE_COMMIT = "aca3beaa3dfbd42498b42c5e5ce20a938e6554e5"
LIBC_COMMIT = "899a3b2d52d95d75e05fb286a5e64975ec3de757"
PREPARATION_SCOPE = "architecture-darwin26-plain-pager"
BUILD_ENVIRONMENT = {
    "UNIXNU_XNU_ARCH": "arm64", "UNIXNU_XNU_TAG": "xnu-12377.121.6",
    "UNIXNU_XNU_COMMIT": XNU_COMMIT, "UNIXNU_XNU_VERSION": "12377.121.6",
    "UNIXNU_XNU_DARWIN": "25.5.0", "UNIXNU_XNU_TARGET": "ios",
    "UNIXNU_IOS_VERSION": "27.0", "XNU_BOOT_PROGRESS": "0",
}


class BuildError(RuntimeError):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_json(path: Path):
    return json.loads(path.read_text())


def command(args, *, cwd=None):
    return toolchain.command(args, cwd=cwd)


def inventory(tree: Path) -> list[dict]:
    records = []
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
            records.append({"path": str(path.relative_to(tree)), "kind": kind,
                            "mode": path.lstat().st_mode & 0o777,
                            "size": len(data), "sha256": digest(data)})
    return sorted(records, key=lambda item: item["path"])


def safe_child(root: Path, relative: str) -> Path:
    part = Path(relative)
    if part.is_absolute() or ".." in part.parts or not part.parts:
        raise BuildError(f"invalid relative input path: {relative}")
    path = root / part
    if not path.resolve().is_relative_to(root.resolve()):
        raise BuildError(f"input path escapes its workspace: {relative}")
    return path


def verify_prepared(prepared: Path) -> dict:
    report = read_json(prepared / "preparation-report.json")
    if (report.get("status") != "sources_prepared" or
            report.get("preparation_scope") != PREPARATION_SCOPE or
            report.get("full_upstream_profile_applied") is not False or
            report["sources"]["unixnu"]["commit"] != UNIXNU_COMMIT or
            report["sources"]["xnu"]["commit"] != XNU_COMMIT):
        raise BuildError("prepared kernel does not match the qualified source subset")
    data = (prepared / "source-inventory.json").read_bytes()
    if digest(data) != SOURCE_INVENTORY_SHA256 or report["source_inventory_sha256"] != digest(data):
        raise BuildError("source inventory differs from the 71-patch baseline")
    tree = prepared / "tree"
    if not (tree / ".git").is_dir() or (tree / ".git/objects/info/alternates").exists():
        raise BuildError("prepared XNU must have its own Git object store")
    if command(["git", "-C", tree, "rev-parse", "HEAD"]).stdout.decode().strip() != XNU_COMMIT:
        raise BuildError("prepared XNU HEAD differs from its pinned base")
    if inventory(tree) != json.loads(data):
        raise BuildError("prepared XNU files changed after source preparation")
    selected = read_json(prepared / "selected-patches.json")
    if len(selected) != 71 or selected != report["applied_patches"]:
        raise BuildError("selected patch manifest is incomplete or differs from its report")
    for entry in selected:
        if toolchain.sha256_file(safe_child(prepared, entry["stored_file"])) != entry["sha256"]:
            raise BuildError(f"selected patch bytes changed: {entry['stored_file']}")
    if read_json(prepared / "build-environment.json") != BUILD_ENVIRONMENT:
        raise BuildError("prepared build environment differs from ordinary-arm64/27")
    return report


def logged(argv, log: Path, *, cwd=None, env=None) -> int:
    argv = [str(item) for item in argv]
    with log.open("ab") as output:
        output.write(("COMMAND " + json.dumps(argv) + "\n").encode())
        output.flush()
        return subprocess.run(argv, cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT).returncode


def checkout(destination: Path, source: str, commit: str, log: Path, paths=(), shared=False):
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise BuildError(f"refuse to overwrite an existing source: {destination}")
    if shared:
        # This optional fast path only accepts a born, ordinary LLVM working
        # tree. The original build source and its objects must be retained.
        existing = Path(source).resolve()
        if not (existing / ".git").is_dir():
            raise BuildError("shared LLVM input must be a normal working repository")
        if command(["git", "-C", existing, "rev-parse", "HEAD"]).stdout.decode().strip() != commit:
            raise BuildError("shared LLVM input has a different source commit")
        commands = [["git", "clone", "--quiet", "--shared", "--no-checkout", existing, destination]]
    else:
        destination.mkdir()
        commands = [["git", "-C", destination, "init", "--quiet"]]
    if paths:
        commands.append(["git", "-C", destination, "sparse-checkout", "set", "--no-cone", *paths])
    if not shared:
        filters = ["--filter=blob:none"] if paths and source.startswith("https://") else []
        commands.append(["git", "-C", destination, "fetch", "--quiet", "--depth", "1", "--no-tags",
                         *filters, source, commit])
    commands.append(["git", "-C", destination, "checkout", "--quiet", "--detach", commit])
    for argv in commands:
        if logged(argv, log):
            raise BuildError(f"fixed source checkout failed; see {log}")
    actual = command(["git", "-C", destination, "rev-parse", "HEAD"]).stdout.decode().strip()
    if actual != commit:
        raise BuildError("source checkout does not match its fixed commit")
    return {"source": source, "commit": commit, "path": str(destination),
            "sparse_paths": list(paths), "shared_object_store": shared}


def seed_header_cache(repository: Path, commit: str, directory: str, target: Path,
                      cache: Path) -> list[dict]:
    listing = command(["git", "-C", repository, "ls-tree", commit, f"{directory}/"]).stdout.decode()
    entries, records = [], []
    for line in listing.splitlines():
        metadata, relative = line.split("\t", 1)
        mode, kind, blob = metadata.split()
        name = relative.removeprefix(directory + "/")
        if kind != "blob" or "/" in name or not name.endswith(".h"):
            continue
        if mode not in ("100644", "100755"):
            raise BuildError(f"unexpected public header mode: {relative}")
        data = command(["git", "-C", repository, "show", f"{commit}:{relative}"]).stdout
        target_file = safe_child(target, name)
        existed = target_file.exists()
        if not existed:
            target_file.parent.mkdir(parents=True, exist_ok=True)
            target_file.write_bytes(data)
        # Existing headers can contain the selected Darwin 26 patches. Preserve
        # their verified prepared bytes instead of replacing them with old ones.
        entries.append({"type": "file", "name": name, "sha": blob,
                        "download_url": f"https://raw.githubusercontent.com/apple-oss-distributions/xnu/{commit}/{relative}"})
        records.append({"source_commit": commit, "source_path": relative, "git_blob": blob,
                        "source_sha256": digest(data), "installed_sha256": toolchain.sha256_file(target_file),
                        "target": str(target_file), "preserved_prepared_header": existed})
    if not entries:
        raise BuildError(f"no public headers found at the fixed source: {directory}")
    cache.parent.mkdir(parents=True, exist_ok=True)
    toolchain.save_json(cache, entries)
    return records


def source_environment(work: Path) -> dict:
    env = {**BUILD_ENVIRONMENT, "UNIXNU_DRIVERKIT_TAG": "xnu-12377.121.6",
           "UNIXNU_TRUSTCACHE_TAG": "xnu-8796.101.5",
           "UNIXNU_PATCH_LIST": str(work / ".route-a/selected-patches.txt")}
    for name, (tag, commit) in PUBLIC_REFERENCES.items():
        env[f"UNIXNU_{name.upper()}_TAG"] = tag
        env[f"UNIXNU_{name.upper()}_COMMIT"] = commit
    return env


def stage_inputs(args):
    prepared = args.prepared_kernel.resolve()
    preparation = verify_prepared(prepared)
    work = toolchain.require_external_work(args.work_dir)
    # The fixed UniXNU checkout is the work root, beside .cache and scripts.
    work.mkdir(parents=True, exist_ok=False)
    metadata = work / ".route-a"
    metadata.mkdir()
    log = metadata / "stage.log"
    report = {"schema_version": 1, "status": "staging", "unixnu_commit": UNIXNU_COMMIT,
              "xnu_commit": XNU_COMMIT, "prepared_source_inventory_sha256": SOURCE_INVENTORY_SHA256,
              "preparation_scope": PREPARATION_SCOPE, "full_upstream_profile_applied": False,
              "sources": [], "restored_headers": [], "kernel_compiled": False,
              "kernel_linked": False, "os_boot_verified": False,
              "driver_sha256": toolchain.sha256_file(Path(__file__))}
    try:
        # work already contains only our state directory; initialize and fetch
        # explicitly, which also works with bare, shallow, FETCH_HEAD-only input.
        for argv in (["git", "-C", work, "init", "--quiet"],
                     ["git", "-C", work, "fetch", "--quiet", "--depth", "1", "--no-tags",
                      args.unixnu_repository.resolve(), UNIXNU_COMMIT],
                     ["git", "-C", work, "checkout", "--quiet", "--detach", UNIXNU_COMMIT]):
            if logged(argv, log):
                raise BuildError(f"pinned UniXNU checkout failed; see {log}")
        profile = tomllib.loads((work / PROFILE_PATH).read_text())
        entries = {entry["name"]: entry for entry in profile["source"]}
        for name, (tag, commit) in PUBLIC_REFERENCES.items():
            entry = entries[name]
            if (entry["ref"], entry["commit"], entry["git"]) != (
                    tag, commit, f"https://github.com/apple-oss-distributions/{name}.git"):
                raise BuildError(f"unexpected 27 profile source: {name}")
        xnu = work / ".cache/xnu-work"
        shutil.copytree(prepared / "tree", xnu, symlinks=True)
        if inventory(xnu) != read_json(prepared / "source-inventory.json"):
            raise BuildError("staged source copy differs from its prepared inventory")
        shutil.copytree(prepared / "patches", metadata / "patches")
        for name in ("preparation-report.json", "selected-patches.json", "source-inventory.json"):
            shutil.copy2(prepared / name, metadata / name)
        (metadata / "selected-patches.txt").write_text("".join(
            str(metadata / entry["stored_file"]) + "\n" for entry in preparation["applied_patches"]))
        report["sources"].append(checkout(work / "refer/xnu", str(xnu), XNU_COMMIT, log))
        for name, (tag, commit) in PUBLIC_REFERENCES.items():
            print(f"stage public source: {name} {commit}", flush=True)
            report["sources"].append(checkout(work / f"refer/{name}", entries[name]["git"], commit, log))
            toolchain.save_json(metadata / "stage-report.json", report)
        trust = work / ".cache/route-a-sources/xnu-trustcache"
        report["sources"].append(checkout(trust, XNU_URL, TRUSTCACHE_COMMIT, log,
            ("/EXTERNAL_HEADERS/TrustCache/", "/APPLE_LICENSE")))
        for repository, commit, directory, target, cache_name in (
            (work / "refer/xnu", XNU_COMMIT, "iokit/DriverKit", xnu / "iokit/DriverKit", "xnu-driverkit-12377.121.6.json"),
            (work / "refer/xnu", XNU_COMMIT, "iokit/DriverKit/crypto", xnu / "iokit/DriverKit/crypto", "xnu-driverkit-crypto-12377.121.6.json"),
            (trust, TRUSTCACHE_COMMIT, "EXTERNAL_HEADERS/TrustCache", xnu / "EXTERNAL_HEADERS/TrustCache", "xnu-trustcache-8796.101.5.json"),
        ):
            report["restored_headers"].extend(seed_header_cache(repository, commit, directory, target,
                                                               work / ".cache/sources" / cache_name))
        llvm_source = str(args.llvm_repository.resolve()) if args.llvm_repository else toolchain.LLVM_URL
        report["sources"].append(checkout(work / ".cache/linux/llvm-project", llvm_source,
            toolchain.LLVM_COMMIT, log, ("/compiler-rt/lib/profile/", "/compiler-rt/include/profile/", "/LICENSE.TXT"),
            shared=args.llvm_repository is not None))
        report["sources"].append(checkout(work / ".cache/linux/Libc",
            "https://github.com/apple-oss-distributions/Libc.git", LIBC_COMMIT, log,
            ("/include/", "/APPLE_LICENSE")))
        toolchain.save_json(metadata / "staged-source-inventory.json", inventory(xnu))
        report["staged_source_inventory_sha256"] = toolchain.sha256_file(metadata / "staged-source-inventory.json")
        report["source_environment"] = source_environment(work)
        report.update(status="inputs_staged", crypto_provider_selected=False,
                      complete_board_archive_closure=False)
        toolchain.save_json(metadata / "stage-report.json", report)
        print(json.dumps({"status": report["status"], "work_dir": str(work),
                          "report": str(metadata / "stage-report.json")}, indent=2))
    except (BuildError, toolchain.ToolchainError, OSError, ValueError, KeyError) as exc:
        report.update(status="failed", error=str(exc))
        toolchain.save_json(metadata / "stage-report.json", report)
        raise


def build_environment(work: Path, prefix: Path, jobs: int) -> dict:
    # A caller's other board configuration must not enable providers or supply
    # foreign archives in this explicit source-only first pass.
    reserved = {"CC", "CXX", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS", "MAKEFLAGS", "MFLAGS",
                "SDKROOT", "CLT_PREFIX", "XCTOOLCHAIN_PREFIX", "CCC_OVERRIDE_OPTIONS"}
    env = {key: value for key, value in os.environ.items()
           if key not in reserved and not key.startswith(("XNU_", "UNIXNU_", "CROSS_"))}
    env.update(toolchain.toolchain_environment(prefix, work / ".cache/fakeroot"))
    env.update(source_environment(work))
    env.update(XNU_BOOTSTRAP="1", XNU_BUILD_TARGET="build", JOBS=str(jobs))
    env["PATH"] = os.pathsep.join((str(prefix / "CommandLineTools/usr/bin"),
                                  str(prefix / "bin"), env.get("PATH", "/usr/bin:/bin")))
    return env


def kernel_header(path: Path) -> dict:
    words = None
    if path.stat().st_size >= 32:
        with path.open("rb") as stream:
            words = list(struct.unpack("<IIII", stream.read(16)))
    return {"macho_header_words": words,
            "ordinary_arm64_mh_execute": words == [0xFEEDFACF, 0x0100000C, 0, 2],
            "full_instruction_set_audited": False}


def run_build(args):
    if sys.platform != "linux" or args.jobs < 1:
        raise BuildError("run requires Linux and a positive job limit")
    work = toolchain.require_external_work(args.work_dir)
    metadata = work / ".route-a"
    report = read_json(metadata / "stage-report.json")
    if report.get("status") != "inputs_staged" or report.get("unixnu_commit") != UNIXNU_COMMIT:
        raise BuildError("source staging has not succeeded")
    if (work / "build").exists() or (metadata / "build-report.json").exists():
        raise BuildError("first-pass execution requires unused outputs; retain this attempt and stage a new work tree")
    if inventory(work / ".cache/xnu-work") != read_json(metadata / "staged-source-inventory.json"):
        raise BuildError("staged XNU sources changed before the build")
    if command(["git", "-C", work, "rev-parse", "HEAD"]).stdout.decode().strip() != UNIXNU_COMMIT:
        raise BuildError("UniXNU builder HEAD differs from the fixed commit")
    if command(["git", "-C", work, "status", "--porcelain", "-uno"]).stdout:
        raise BuildError("pinned UniXNU tracked build scripts have changed")
    for source in report["sources"]:
        path = Path(source["path"])
        if command(["git", "-C", path, "rev-parse", "HEAD"]).stdout.decode().strip() != source["commit"]:
            raise BuildError(f"staged source commit changed: {path}")
        if command(["git", "-C", path, "status", "--porcelain", "-uno"]).stdout:
            raise BuildError(f"staged public source files changed: {path}")
    toolwork = args.toolchain_work.resolve()
    with ExitStack() as locks:
        for path, mode in ((metadata / "build.lock", fcntl.LOCK_EX),
                           (toolwork / "build.lock", fcntl.LOCK_SH),
                           (toolwork / "host-tools.lock", fcntl.LOCK_SH)):
            lock = locks.enter_context(path.open("a"))
            try:
                fcntl.flock(lock, mode | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise BuildError("build or toolchain installation is active; retry when it finishes") from exc
        # Recheck within the workspace lock; do not run two first passes.
        if (metadata / "build-report.json").exists():
            raise BuildError("this first-pass attempt has already started")
        identity, clang_state = read_json(toolwork / "identity.json"), read_json(toolwork / "state.json")
        host_state = read_json(toolwork / "host-tools-state.json")
        prefix = Path(identity["prefix"])
        if (clang_state.get("status") != "clang_verified" or host_state.get("status") != "host_tools_built" or
                host_state.get("combined_toolchain_verified") is not True):
            raise BuildError("complete custom compiler and host tools have not been verified")
        clang = prefix / "llvm/bin/clang"
        if toolchain.sha256_file(clang) != clang_state["verification"]["compiler"]["sha256"]:
            raise BuildError("current Clang differs from its verified build")
        for entry in host_state["outputs"]:
            if toolchain.sha256_file(Path(entry["path"])) != entry["sha256"]:
                raise BuildError(f"host tool changed after verification: {entry['path']}")
        env = build_environment(work, prefix, args.jobs)
        public_env = {key: value for key, value in env.items() if
                      key.startswith(("XNU_", "UNIXNU_", "CROSS_")) or
                      key in ("PATH", "JOBS", "CLT_PREFIX", "XCTOOLCHAIN_PREFIX", "ZERO_AR_DATE", "LC_ALL", "CCC_OVERRIDE_OPTIONS")}
        result = {"schema_version": 1, "status": "running", "scope": "generic-architecture-first-pass",
                  "unixnu_commit": UNIXNU_COMMIT, "xnu_commit": XNU_COMMIT, "environment": public_env,
                  "driver_sha256": toolchain.sha256_file(Path(__file__)), "compiler": clang_state["verification"]["compiler"],
                  "whole_profile_applied": False, "complete_board_archive_closure": False,
                  "kernel_compiled": False, "kernel_linked": False, "os_boot_verified": False}
        toolchain.save_json(metadata / "build-report.json", result)
        log = metadata / "build.log"
        code = logged(["bash", "scripts/build-xnu-4k-baseline.sh"], log, cwd=work, env=env)
        objects = sorted((work / "build/xnu/ios-obj").rglob("*.o"))
        objects += sorted((work / "build/xnu/ios-obj").rglob("*.cpo"))
        filelists = sorted((work / "build/xnu").rglob("*link.filelist"))
        kernels = sorted((work / "build/xnu").rglob("mach.development.bcm2837.unstripped"))
        kernels += sorted((work / "build/xnu").rglob("mach.development.bcm2837.unstripped.noctf"))
        artifacts = []
        for path in [*filelists, *kernels]:
            if path.is_file():
                artifact = {"path": str(path.relative_to(work)), "size": path.stat().st_size,
                            "sha256": toolchain.sha256_file(path)}
                if path in kernels:
                    artifact.update(kernel_header(path))
                artifacts.append(artifact)
        with log.open("rb") as stream:
            stream.seek(max(0, log.stat().st_size - 24000))
            tail = stream.read().decode("utf-8", "replace")
        result.update(status="builder_completed" if code == 0 else "builder_failed", exit_code=code,
                      builder_completed=code == 0, compiled_object_file_count=len(objects),
                      link_filelist_count=len(filelists), artifacts=artifacts, log_tail=tail,
                      sdk_headers_marker_present=(work / ".cache/fakeroot/.xnu-12377.121.6-headers").exists())
        candidate_headers = [item["ordinary_arm64_mh_execute"] for item in artifacts
                             if "ordinary_arm64_mh_execute" in item]
        result["ordinary_arm64_candidate_headers_verified"] = bool(candidate_headers) and all(candidate_headers)
        if code == 0 and not result["ordinary_arm64_candidate_headers_verified"]:
            result.update(status="output_check_failed",
                          error="builder returned zero without verified ordinary-arm64 MH_EXECUTE kernel candidates")
        # Artifact existence and builder exit are reported directly. Qualifying
        # a full kernel/ISA/archive closure is a separate operation.
        toolchain.save_json(metadata / "build-report.json", result)
        print(json.dumps({"status": result["status"], "exit_code": code,
                          "report": str(metadata / "build-report.json"), "log": str(log)}, indent=2))
        if code:
            raise BuildError(f"upstream first-pass builder failed ({code}); see {log}")
        if result["status"] == "output_check_failed":
            raise BuildError(result["error"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    stage = commands.add_parser("stage")
    stage.add_argument("--unixnu-repository", type=Path, required=True)
    stage.add_argument("--prepared-kernel", type=Path, required=True)
    stage.add_argument("--work-dir", type=Path, required=True)
    stage.add_argument("--llvm-repository", type=Path,
                       help="reuse this retained LLVM working repository's Git objects instead of downloading them")
    run = commands.add_parser("run")
    run.add_argument("--work-dir", type=Path, required=True)
    run.add_argument("--toolchain-work", type=Path, required=True)
    run.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args(argv)
    try:
        stage_inputs(args) if args.command == "stage" else run_build(args)
    except (BuildError, toolchain.ToolchainError, OSError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
