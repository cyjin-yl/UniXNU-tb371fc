#!/usr/bin/env python3
"""Build a fixed private crypto source archive, bridge its KPIs, link and load.

Run heavy stages under the operator's existing resource-admission wrapper.
The source archive and Apple-derived build products remain outside this repo.
The retained XNU/platform objects are verified inputs, not a fresh XNU build.
No QEMU, firmware, device or operating-system success is claimed here.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import signal
import struct
import subprocess
import sys
import tarfile
import time
import ctypes

sys.path.insert(0, str(Path(__file__).resolve().parent))
import probe_route_a_loader as loader

ROOT = Path(__file__).resolve().parents[1]
GLUE = ROOT / "scripts/route_a_corecrypto"
SOURCE_REVISION = "11fba65b12d8830630e248dfa8344caf8b065f26"
SOURCE_ROOT = "corecrypto-2023-" + SOURCE_REVISION
PINS = {
    "archive": "fd04cb46cb733fdd8e6334702081a33b202ae7645140f59fa55b7d47de7e688f",
    "project": "20f83a7541be6afa2d859f157d9a2fd252e68377d66ebb79a4f2158a9ed9d8a9",
    "provider": "363ec8d29ea5d74f2772fcd5ba93f43695ac520fa90c492f1c70b9ccc3c09e38",
    "namespace": "607113cfb4d45d47772d5f6ae7f7e0223914afda4b54c9dd77417018dc1999db",
    "pbxproj": "8fe71e16f45db4ad1964fd748b7bed2a450ea55483fa8faddc2ad85519452ecf",
    "bootstrap_source": "cc677a1bd2effd70dd55af8d907bfbd37594f0a9a1679e4a55875fec705d9a5f",
    "bootstrap_recipe": "7b39218dddedd139b2cd70bcc209ea21069768c596a75616eb9e299d86f04027",
    "platform_report": "738a7af11b32c08d0a4261611ba69f325d5a29bf424791b18e98879864feff7c",
    "compiler": "85d220e32bd83d75de788c8beab0bea646a4684e1112f7c06266ca71e651bb04",
}
# The retained sleh source equals ac9718fb; locore includes the separately
# captured preparation instrumentation. These source/recipe identities are
# captured from the real prepared tree, never substituted with upstream bytes.
PACGA_PINS = {
    "source": "4eeb208fb2510bfdc0338d1a1d7d2d702fe9eb65d332eea388720ef6574375d1",
    "recipe": "8c60d7a8f85e060aae2a0c8faee343c5fbaf3be7d188be9847ec642effd29090",
    "locore_source": "e18b09d48981bdaec5dbdf43e47f223d953e5b65727e7ba199570b7a10cd6124",
    "exception_asm_source": "6175d244c81c112d05df65f0d4a1ee5f8f4a622ceb2f9e6fbcc5239e9e9a918e",
    "locore_recipe": "87c6a74ca6c0cc168e97dba1a86e3ecf61d57add27858fb3ffcb474a6b0c47cd",
    "assym": "b29e64676013a588acc16d0d0829701fac15ff93b1bd2accb2c6157724854636",
    "genassym": "4d44c588f045d21d0209647c4d366629896c34263c6545d2d4872962e132d27e",
    # Bind the reviewed producer and execution sources independently of each
    # report. New validation requires a fresh stage; old attempts stay immutable.
    "stage_driver": "c4c495340cce5f88f952f72851c3cc238bae78df34b286bf82a751a1e43d98bd",
    "execution_driver": "20848591b62d63274a7bfd09014e9c7f3be001d6bd067385668b825f2fc953ad",
}
ADDED_FIELDS = (
    "ccdigest_final_fn", "digest_ctx_size_fn", "digest_init_fn", "digest_update_fn", "digest_final_fn", "digest_fn",
    "hmac_ctx_size_fn", "hmac_init_fn", "hmac_update_fn", "hmac_final_generate_fn", "hmac_final_verify_fn",
    "hmac_generate_fn", "hmac_verify_fn",
)
ABI_RECORDS = (
    "crypto_functions", "cckprng_funcs", "ccdigest_info", "ccdigest_ctx", "cchmac_ctx",
    "ccmode_ecb", "ccmode_cbc", "ccmode_ctr", "ccmode_gcm", "ccmode_xts", "ccrng_state",
    "ccchacha20poly1305_fns",
    "ccrsa_pub_ctx", "ccrsa_full_ctx", "ccchacha20poly1305_info", "route_a_crypto_sizes",
)
RECIPE_REL = "build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/osfmk/DEVELOPMENT/prng_random.o.json"
ASSYM_REL = "build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/osfmk/DEVELOPMENT/assym.s"
SOURCE_DATE_EPOCH = "1700000000"


class BuildError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise BuildError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def safe_json(value):
    if isinstance(value, dict):
        return {k: safe_json(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [safe_json(v) for v in value]
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) >= 1 << 53:
        return hex(value)
    return value


def save(path, value):
    Path(path).write_text(json.dumps(safe_json(value), sort_keys=True, indent=2) + "\n")


def regular(path):
    path = Path(path).absolute()
    require(path.is_file() and not path.is_symlink(), f"not a regular nonsymlink input: {path}")
    require(not any(c in str(path) for c in "\x00\r\n,"), "unsafe path delimiter")
    return path.resolve()


def pin(path, expected):
    path = regular(path)
    data = path.read_bytes()
    require(sha(data) == expected, f"pinned input differs: {path}")
    return data


def fresh(path):
    logical = Path(path).absolute()
    require(not logical.is_symlink(), "output must not be a symlink")
    path = logical.resolve()
    require(not path.exists(), f"output already exists: {path}")
    require(ROOT != path and ROOT not in path.parents, "build outputs must be outside the source repository")
    require(not any(c in str(path) for c in "\x00\r\n,"), "unsafe output delimiter")
    path.mkdir(parents=True, exist_ok=False)
    return path.resolve()


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class Journal:
    def __init__(self, out):
        self.out, self.records, self.commands = out, {}, []
        self.failed = False
        self.environment = {"PATH": os.defpath, "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
                            "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH, "ZERO_AR_DATE": "1", "TMPDIR": str(out)}

    def protect(self, path, *, tool=False):
        path = Path(path).absolute()
        record = loader.platform_link.tool_identity(path) if tool else loader.identity(regular(path))
        prior = self.records.setdefault(record["path"], record)
        require(prior == record, f"input changed before reuse: {path}")
        return record

    def execute(self, argv, label, *, cwd=None, env=None, timeout=60):
        require(not self.failed, "cannot execute another command after a failed journal command")
        try:
            return self._execute(argv, label, cwd=cwd, env=env, timeout=timeout)
        except BaseException:
            self.failed = True
            raise

    def _execute(self, argv, label, *, cwd=None, env=None, timeout=60):
        from route_a_pacga_probe import run as execution
        self.protect(Path(execution.__file__))
        self.protect(argv[0], tool=True)
        stdout, stderr = self.out / (label + ".stdout"), self.out / (label + ".stderr")
        environment = dict(self.environment, **(env or {}))
        environment.update(SOURCE_DATE_EPOCH=SOURCE_DATE_EPOCH, ZERO_AR_DATE="1", TZ="UTC")
        record = {"argv": list(map(str, argv)), "cwd": str(cwd or self.out), "timeout_seconds": timeout,
                  "environment": environment}
        self.commands.append(record)
        save(self.out / "commands.json", self.commands)
        process = out = err = None
        with execution.owned_children():
            try:
                out = stdout.open("xb")
                err = stderr.open("xb")
                process = subprocess.Popen(record["argv"], cwd=cwd or self.out,
                                           env=environment, stdout=out, stderr=err, stdin=subprocess.DEVNULL,
                                           start_new_session=True)
                record["pid"] = process.pid
                save(self.out / "commands.json", self.commands)
                record["exit"] = process.wait(timeout=timeout)
                require(record["exit"] == 0, f"{label} exited {record['exit']}; inspect retained stderr")
            finally:
                self._finish_command(execution, process, record, stdout, stderr, (out, err), sys.exc_info()[1])
        require(record["cleanup"].get("group_absent") is True
                and record["cleanup"].get("direct_child_reaped") is True,
                f"{label} did not finish cleanup of its owned process group")
        require(record.get("group_absent_after_wait") is True,
                f"{label} exited while its process group was still active")
        return stdout.read_bytes()

    def _finish_command(self, execution, process, record, stdout, stderr, streams, primary):
        """Always attempt group cleanup; receipt errors must not replace the cause."""
        errors = []

        def attempt(label, function):
            try:
                return function()
            except BaseException as error:
                errors.append((label, error))
                return None

        watched = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
        previous_mask = attempt("block-cleanup-signals",
                                lambda: signal.pthread_sigmask(signal.SIG_BLOCK, watched))
        try:
            if process is not None:
                record["group_absent_after_wait"] = False
                record["cleanup"] = {"group": process.pid, "group_absent": False,
                                     "direct_child_reaped": False}

                def probe_group():
                    try: os.killpg(process.pid, 0)
                    except ProcessLookupError: record["group_absent_after_wait"] = True

                attempt("group-probe", probe_group)
                # A failed probe, a second signal or a failed PID receipt must
                # still reach bounded cleanup of this command's own session.
                cleanup = attempt("group-cleanup", lambda: execution.stop_group(process))
                if cleanup is not None:
                    record["cleanup"] = cleanup

                def poll_child():
                    record.update(exit=process.poll(), reaped=process.returncode is not None)

                attempt("direct-child-status", poll_child)
            for name, stream in zip(("stdout", "stderr"), streams):
                if stream is not None:
                    attempt(name + "-close", stream.close)
            for name, path in (("stdout", stdout), ("stderr", stderr)):
                identity = attempt(name + "-identity", lambda: loader.identity(path))
                if identity is not None:
                    record[name] = identity
        finally:
            if previous_mask is not None:
                # A pending signal may raise here, after group cleanup; retain
                # it as a secondary error when a primary failure already exists.
                attempt("restore-cleanup-signals",
                        lambda: signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask))
        record["teardown_errors"] = [dict(phase=label, type=type(error).__name__, error=str(error))
                                     for label, error in errors]
        attempt("command-receipt", lambda: save(self.out / "commands.json", self.commands))
        record["teardown_errors"] = [dict(phase=label, type=type(error).__name__, error=str(error))
                                     for label, error in errors]
        if errors:
            failure = primary if primary is not None else errors[0][1]
            for label, error in errors:
                if error is not failure:
                    failure.add_note(f"command teardown {label}: {type(error).__name__}: {error}")
            if primary is None:
                raise failure

    def recheck(self):
        return loader.platform_link.check_unchanged(list(self.records.values()))

    def headers(self, roots):
        """Freeze actual headers and alias bindings, including framework directory links."""
        visited = set()
        for root in roots:
            if not root.is_dir(): continue
            for directory, names, files in os.walk(root, followlinks=True):
                resolved = Path(directory).resolve()
                if resolved in visited:
                    names[:] = []
                    continue
                visited.add(resolved)
                for name in files:
                    path = Path(directory) / name
                    if path.suffix != ".h" or not path.is_file(): continue
                    target = path.resolve()
                    self.protect(target)
                    if path.absolute() != target:
                        self.protect(path.absolute(), tool=True)

    def compile(self, argv, label, **kwargs):
        dependencies = self.out / (label + ".d")
        self.execute([*argv, "-MD", "-MF", str(dependencies)], label, **kwargs)
        text = dependencies.read_text().replace("\\\n", " ")
        require(":" in text, "compiler did not record dependencies")
        paths = [Path(s).resolve() for s in shlex.split(text.split(":", 1)[1])]
        require(paths, "compiler dependency list is empty")
        for path in paths:
            require(str(path) in self.records, f"compiler consumed an undeclared input: {path}")
            self.protect(path)
        return {"dependency_file": loader.identity(dependencies), "input_count": len(paths)}


def extract_source(archive, output):
    pin(archive, PINS["archive"])
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        names = [m.name.rstrip("/") for m in members]
        require(len(names) == len(set(names)), "duplicate archive member")
        require(sum(m.size for m in members) < 1024 ** 3, "source archive size bound")
        for member in members:
            path = Path(member.name)
            require(not path.is_absolute() and ".." not in path.parts and path.parts[0] == SOURCE_ROOT,
                    "source archive path outside fixed root")
            require(member.isfile() or member.isdir(), "source archive contains a link or special file")
        source.extractall(output, members=members, filter="data")
    return output / SOURCE_ROOT


def target_sources(source, pbx):
    pin(source / "corecrypto.xcodeproj/project.pbxproj", PINS["project"])
    objects = pbx.load(source / "corecrypto.xcodeproj/project.pbxproj")["objects"]
    parents = {}
    for key, value in objects.items():
        for child in value.get("children", []):
            require(child not in parents, "PBX child has multiple parents")
            parents[child] = key

    def resolve(key, seen=()):
        require(key not in seen and len(seen) < 128, "PBX group cycle")
        item = objects[key]
        relative = item.get("path", "")
        require(not Path(relative).is_absolute() and ".." not in Path(relative).parts, "PBX path escapes source")
        if item.get("sourceTree") == "SOURCE_ROOT" or key not in parents:
            result = source / relative
        else:
            require(item.get("sourceTree") == "<group>", "unsupported PBX source tree")
            result = resolve(parents[key], (*seen, key)) / relative
        return result

    targets = [v for v in objects.values() if v.get("isa") == "PBXNativeTarget" and v.get("name") == "corecrypto_kext"]
    require(len(targets) == 1, "ambiguous corecrypto target")
    phases = [objects[k] for k in targets[0]["buildPhases"] if objects[k]["isa"] == "PBXSourcesBuildPhase"]
    require(len(phases) == 1, "ambiguous source phase")
    paths = [resolve(objects[k]["fileRef"]) for k in phases[0]["files"]
             if objects[objects[k]["fileRef"]].get("path", "").endswith(".c")]
    require(len(paths) == 529 and len(set(paths)) == 529, "fixed target C source count changed")
    require(all(p.is_file() and p.resolve().is_relative_to(source) for p in paths), "missing target source")
    return paths


def prepare_overlay(provider, bootstrap, directory):
    """Only add real callback adapters and a post-initialization consumer check."""
    text = provider.decode()
    needle = "    register_crypto_functions(&kpis);"
    require(text.count(needle) == 1, "provider registration insertion is not unique")
    original_fields = re.findall(r"kpis\.([A-Za-z0-9_]+)\s*=\s*([^;]+);", text)
    require(len(original_fields) == 43 and len({x[0] for x in original_fields}) == 43, "provider assignments changed")
    require(not set(ADDED_FIELDS) & {x[0] for x in original_fields}, "adapter would overwrite an existing callback")
    text = text.replace(needle, "    route_a_complete_crypto_table(&kpis);\n" + needle)
    include = '#include <libkern/crypto/register_crypto.h>'
    require(text.count(include) == 1, "provider header insertion is not unique")
    text = text.replace(include, include + '\n#include "adapter.h"')
    assertions = []
    for field, expression in original_fields:
        require("\n" not in expression and re.fullmatch(r"[&A-Za-z_][A-Za-z_0-9]*(?:\(\))?", expression),
                "unreviewed provider initializer expression")
        assertions.append('_Static_assert(__builtin_types_compatible_p(__typeof__(((struct crypto_functions *)0)->'
                          + field + '), __typeof__(1 ? (' + expression + ') : (' + expression + '))), "type ' + field + '");')
    text += "\n" + "\n".join(assertions) + "\n"
    (directory / "corecrypto_kext.c").write_text(text)
    original = bootstrap.decode()
    marker = '\t\tpanic("source corecrypto initialization failed: %d", source_corecrypto14_status);\n\t}\n}'
    require(original.count(marker) == 1, "bootstrap success insertion is not unique")
    updated = original.replace(marker, marker[:-1] + "\troute_a_crypto_consumer_check();\n}")
    updated = '#include "consumer_probe.h"\n' + updated
    (directory / "prng_random.c").write_text(updated)
    return {"original_provider_fields": [x[0] for x in original_fields], "added_fields": list(ADDED_FIELDS),
            "assignment_types_asserted": 56, "post_and_registration_order_preserved": True}


def apply_bootstrap_append(original, patch):
    """Interpret the fixed one-file append patch with exact context, no fuzz."""
    lines = patch.decode().splitlines(keepends=True)
    require(lines[:4] == ["diff --git a/osfmk/prng/prng_random.c b/osfmk/prng/prng_random.c\n",
                         "index 504b3fa..310719a 100644\n", "--- a/osfmk/prng/prng_random.c\n",
                         "+++ b/osfmk/prng/prng_random.c\n"], "bootstrap patch file/header changed")
    match = re.fullmatch(r"@@ -(\d+),(\d+) \+(\d+),(\d+) @@[^\n]*\n", lines[4])
    require(match is not None, "bootstrap patch needs exactly one explicit hunk")
    old_at, old_count, new_at, new_count = map(int, match.groups())
    require(old_at == new_at and all(line[:1] in (" ", "+") for line in lines[5:]),
            "bootstrap patch is no longer append-only")
    context = [line[1:] for line in lines[5:] if line.startswith(" ")]
    added = [line[1:] for line in lines[5:] if line.startswith("+")]
    source = original.decode().splitlines(keepends=True)
    require(len(context) == old_count and len(context) + len(added) == new_count
            and source[old_at - 1:] == context and lines[5:5 + old_count] == [" " + line for line in context],
            "bootstrap patch context/count does not exactly end the original file")
    return original + "".join(added).encode()


def reconstruct_bootstrap(journal, kernel_build):
    record = json.loads((GLUE / "sources.json").read_text())
    original, patch = record["bootstrap_original"], record["bootstrap_patch"]
    output = journal.out / "bootstrap-source"; output.mkdir()
    raw = journal.execute(["/usr/bin/git", "-C", str(kernel_build / "refer/xnu"), "show",
                           original["commit"] + ":" + original["path"]], "bootstrap-original", timeout=20)
    require(len(raw) == original["size"] and sha(raw) == original["sha256"], "original XNU bootstrap source differs")
    original_path = output / "prng_random.original.c"; original_path.write_bytes(raw); journal.protect(original_path)
    patch_raw = pin(kernel_build / patch["path"], patch["sha256"])
    journal.protect(kernel_build / patch["path"])
    require(len(patch_raw) == patch["size"], "bootstrap patch byte count differs")
    patch_path = output / "source-corecrypto14-bootstrap.patch"; patch_path.write_bytes(patch_raw); journal.protect(patch_path)
    license_raw = pin(kernel_build / patch["license_path"], patch["license_sha256"])
    journal.protect(kernel_build / patch["license_path"])
    (output / "UPSTREAM-LICENSE").write_bytes(license_raw)
    reconstructed = apply_bootstrap_append(raw, patch_raw)
    require(sha(reconstructed) == patch["reconstructed_sha256"] == PINS["bootstrap_source"], "reconstructed bootstrap differs")
    prepared = kernel_build / ".cache/xnu-work/osfmk/prng/prng_random.c"
    require(pin(prepared, PINS["bootstrap_source"]) == reconstructed, "declared prepared source does not match reconstruction")
    journal.protect(prepared)
    (output / "prng_random.reconstructed.c").write_bytes(reconstructed)
    return reconstructed, {"original": original, "patch": patch,
                           "reconstructed": loader.identity(output / "prng_random.reconstructed.c"),
                           "prepared_witness": loader.identity(prepared),
                           "method": "git show exact original, apply exact pinned append hunk in memory, compare SHA and prepared witness"}


def provider_command(compiler, kernel_build, source, output):
    include = output / "include/corecrypto"
    include.mkdir(parents=True)
    for header in sorted(source.glob("*/corecrypto/*.h")):
        destination = include / header.name
        require(not destination.exists(), f"duplicate exported header: {header.name}")
        destination.symlink_to(header)
    framework = kernel_build / ".cache/fakeroot/System/Library/Frameworks/Kernel.framework/Versions/A"
    argv = [str(compiler), "--no-default-config", "--target=arm64-apple-ios27.0", "-mcpu=generic",
            "-isysroot", str(kernel_build / ".cache/fakeroot"), "-mkernel", "-ffreestanding", "-fno-builtin",
            "-fno-stack-check", "-std=gnu99", "-fblocks", "-O2", "-fno-vectorize", "-fno-slp-vectorize",
            "-mno-implicit-float", "-DKERNEL=1", "-DKERNEL_PRIVATE=1", "-DBUILDKERNEL=1", "-DCC_USE_ASM=0",
            "-DNDEBUG=1", "-DCC_DISABLE_RSAKEYGEN=1", "-Wno-deprecated-declarations",
            "-Wno-incompatible-library-redeclaration", "-Werror=incompatible-function-pointer-types",
            "-Werror=incompatible-pointer-types", "-Werror=date-time", "-I" + str(include.parent), "-I" + str(output / "glue"),
            "-I" + str(framework / "PrivateHeaders"), "-I" + str(framework / "Headers"),
            "-include", str(output / "glue/namespace.h"), "-ffile-prefix-map=" + str(source) + "=corecrypto-2023",
            "-ffile-prefix-map=" + str(output) + "=route-a-corecrypto",
            "-fdebug-compilation-dir=route-a-corecrypto"]
    for folder in sorted({p.parent for p in source.rglob("*.h") if "test" not in str(p.relative_to(source)).lower()}):
        argv.append("-I" + str(folder))
    return argv


def replay_bootstrap(record, kernel_build, source, output):
    """The complete recipe is pinned before this narrow output/path rewrite."""
    require(record["file"] == str(kernel_build / ".cache/xnu-work/osfmk/prng/prng_random.c"), "wrong bootstrap source")
    require(record["output"] == "prng_random.o", "wrong bootstrap output")
    argv, changed = [], {"source": 0, "output": 0}
    original = record["arguments"]
    require(all(isinstance(s, str) and not s.startswith("@") for s in original), "response file in C recipe")
    i = 0
    while i < len(original):
        arg = original[i]
        if arg == record["file"]:
            argv.append(str(source)); changed["source"] += 1
        elif arg == "-o":
            require(original[i + 1] == "prng_random.o", "unexpected C output")
            argv.extend([arg, str(output / "prng_random.o")]); changed["output"] += 1; i += 1
        elif arg in ("-MJ", "-MF", "-MT", "-MQ"):
            raise BuildError("retained bootstrap recipe gained an output side channel")
        elif arg == "-I":
            value = Path(original[i + 1]); value = value if value.is_absolute() else Path(record["directory"]) / value
            argv.extend([arg, str(value.resolve())]); i += 1
        else:
            argv.append(arg)
        i += 1
    require(changed == {"source": 1, "output": 1}, "bootstrap source/output count")
    argv[1:1] = ["--no-default-config", "-DXNU_SOURCE_CORECRYPTO14=1", "-I" + str(source.parent),
                  "-ffile-prefix-map=" + str(source.parent) + "=route-a-corecrypto/glue",
                  "-fdebug-compilation-dir=route-a-corecrypto",
                  "-Werror=incompatible-function-pointer-types", "-Werror=incompatible-pointer-types", "-Werror=date-time"]
    require("-c" in argv and "-mcpu=generic" in argv, "bootstrap target recipe changed")
    return argv


def record_layouts(text):
    result = {}
    for block in text.split("*** Dumping AST Record Layout"):
        lines = block.strip().splitlines()
        if not lines:
            continue
        match = re.fullmatch(r"\s*0 \| struct (\w+)", lines[0])
        if match and match[1] in ABI_RECORDS:
            require(match[1] not in result, "duplicate ABI record")
            canonical = "\n".join(line.strip() for line in lines) + "\n"
            canonical = re.sub(r"\bcc14_(ccsha(?:256|512)_di)\b", r"\1", canonical)
            result[match[1]] = canonical
    return result


def abi_check(journal, provider_argv, bootstrap_argv, directory):
    layouts = {}
    for label, command in (("provider", provider_argv), ("consumer", bootstrap_argv)):
        command = list(map(str, command))
        at = command.index("-o"); del command[at:at + 2]
        command.remove("-c")
        command += ["-Xclang", "-fdump-record-layouts-complete", "-fsyntax-only"]
        raw = journal.execute(command, "abi-" + label, cwd=directory)
        layouts[label] = record_layouts(raw.decode())
        for name, text in layouts[label].items():
            (directory / (label + "." + name)).write_text(text)
    require(set(layouts["provider"]) == set(ABI_RECORDS) == set(layouts["consumer"]), "missing ABI carrier layout")
    mismatches = [name for name in ABI_RECORDS if layouts["provider"][name] != layouts["consumer"][name]]
    report = {"matches": not mismatches, "mismatches": mismatches, "records": {
        name: {side: sha(layouts[side][name].encode()) for side in layouts} for name in ABI_RECORDS},
        "normalization": "only the two cc14_ccsha{256,512}_di field-name aliases; no type/offset suppression"}
    save(directory / "abi.json", report)
    require(not mismatches, "provider/consumer ABI carrier layout differs: " + ", ".join(mismatches))
    return report


def symbol_span(strict, data, name, length, *, executable=False):
    found = [s for s in strict["metadata"]["symbols"]["records"] if s["name"] == name]
    require(len(found) == 1, f"ambiguous or missing symbol: {name}")
    symbol = found[0]
    require(symbol["n_type"] in (0xe, 0xf) and not symbol["n_desc"] & 0x80
            and 1 <= symbol["n_sect"] <= len(strict["metadata"]["sections"]) and 0 < length <= 65536,
            "symbol is not a strong section definition")
    sec = strict["metadata"]["sections"][symbol["n_sect"] - 1]
    va = symbol["value"]
    require(sec["addr"] <= va and va + length <= sec["addr"] + sec["size"], "symbol extent leaves section")
    owners = [s for s in strict["segments"] if s["vmaddr"] <= va and va + length <= s["vmaddr"] + s["filesize"]]
    require(len(owners) == 1, "symbol extent is not file backed")
    if executable:
        require(owners[0]["name"] == sec["segment"] and owners[0]["initprot"] & 4
                and sec["flags"] & 0x80000000 and sec["flags"] & 0xff == 0 and va % 4 == 0,
                "symbol is not aligned pure executable code")
    offset = owners[0]["fileoff"] + va - owners[0]["vmaddr"]
    return {"symbol": name, "va": va, "file_offset": offset, "size": length,
            "section": sec["name"], "segment": sec["segment"], "sha256": sha(data[offset:offset + length])}


def function_span(strict, data, name, *, bound=65536):
    """Use real symbols and section bounds, not a caller-supplied address root."""
    head = symbol_span(strict, data, name, 4, executable=True)
    following = [s["value"] for s in strict["metadata"]["symbols"]["records"]
                 if s["n_type"] in (0xe, 0xf) and s["value"] > head["va"]]
    section, = [s for s in strict["metadata"]["sections"]
                if s["name"] == head["section"] and s["segment"] == head["segment"]]
    end = min([section["addr"] + section["size"], *following])
    require(0 < end - head["va"] <= bound and (end - head["va"]) % 4 == 0,
            f"function extent exceeds the diagnostic bound: {name}")
    return symbol_span(strict, data, name, end - head["va"], executable=True)


def seal_kernel(raw):
    """Apply only the two fixed test-key flips, then the ordinary POST HMAC."""
    strict = loader.strict_kernel(raw)
    sections = strict["metadata"]["sections"]
    code, = [s for s in sections if s["name"] == "__text" and s["segment"] in ("__TEXT", "__TEXT_EXEC")]
    integrity, = [s for s in sections if s["name"] == "__fips_hmacs"]
    require(integrity["size"] == 32, "POST HMAC must be exactly 32 bytes")
    require(code["addr"] - strict["metadata"]["load_contract"]["virtual_base"] == code["offset"],
            "POST header-relative mapping changed")
    require(integrity["offset"] + 32 <= code["offset"] or code["offset"] + code["size"] <= integrity["offset"],
            "HMAC overlaps hashed text")
    symbol_span(strict, raw, "_source_corecrypto14_bootstrap", 4, executable=True)
    symbol_span(strict, raw, "_static_if_tests_setup", 4, executable=True)
    names = ("_static_if_test_key_true_to_false_jump_key", "_static_if_test_key_false_to_true_jump_key")
    mask = 0x7ffffffffff
    keys = {symbol_span(strict, raw, name, 4)["va"] & mask for name in names}
    entries, = [s for s in sections if s["name"] == "__static_if" and s["segment"] in ("__DATA_CONST", "__BOOTDATA")]
    require(entries["size"] % 16 == 0, "invalid static_if table size")
    data, sites = bytearray(raw), []
    for relative in range(0, entries["size"], 16):
        delta, target, link = struct.unpack_from("<iiQ", raw, entries["offset"] + relative)
        if (link & mask & ~3) not in keys:
            continue
        va = entries["addr"] + relative + delta
        require(code["addr"] <= va and va + 4 <= code["addr"] + code["size"] and va % 4 == 0 and target % 4 == 0,
                "static_if target outside bounded instruction region")
        require(-(1 << 27) <= target < 1 << 27 and code["addr"] <= va + target
                and va + target + 4 <= code["addr"] + code["size"], "static_if branch displacement leaves hashed code")
        require(all(site["va"] != hex(va) for site in sites), "duplicate static_if patch site")
        offset = code["offset"] + va - code["addr"]
        branch = 0x14000000 | ((target >> 2) & 0x3ffffff)
        old, new = (branch, 0xd503201f) if link & 1 else (0xd503201f, branch)
        actual, = struct.unpack_from("<I", raw, offset)
        require(actual == old, "static_if input is not the original emitted instruction")
        struct.pack_into("<I", data, offset, new)
        sites.append({"va": hex(va), "file_offset": hex(offset), "before": hex(old), "after": hex(new)})
    require(len(sites) == 10, "fixed static_if test-key site count changed")
    mac = hmac.digest(b"\0", data[code["offset"]:code["offset"] + code["size"]], "sha256")
    data[integrity["offset"]:integrity["offset"] + 32] = mac
    return bytes(data), {"input_sha256": sha(raw), "kernel_sha256": sha(data), "static_if_sites": sites,
                         "hmac_file_offset": hex(integrity["offset"]), "hmac_sha256": mac.hex(),
                         "code_file_offset": hex(code["offset"]), "code_bytes": code["size"],
                         "runtime_post_executed": False}


def load_kernel(journal, sources, directory, compiler, kernel, data, strict, symbols, assym):
    """Keep the original DarwinBoot extraction and ctypes ABI, with owned subprocess cleanup."""
    directory.mkdir()
    body, excerpts = loader.make_harness(sources)
    path = directory / "loader-probe.c"; path.write_text(body); journal.protect(path)
    for relative, record in sources.items():
        destination = directory / "sources" / relative
        destination.parent.mkdir(parents=True, exist_ok=True); destination.write_bytes(record["bytes"])
    library = directory / "loader-probe.so"
    journal.execute([str(compiler), "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                     "-shared", "-fPIC", str(path), "-o", str(library)], "host-loader", timeout=60)
    require(sys.byteorder == "little" and ctypes.sizeof(ctypes.c_void_p) == 8, "loader host must be little endian LP64")
    lib = ctypes.CDLL(str(library))
    lib.probe_parse.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(loader.CKernel)]
    lib.probe_parse.restype = ctypes.c_int
    lib.probe_load.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(loader.CKernel)]
    lib.probe_load.restype = ctypes.c_int
    for name in ("probe_loader_abi", "probe_xnu_abi"):
        getattr(lib, name).argtypes = [ctypes.c_uint, ctypes.c_uint]; getattr(lib, name).restype = ctypes.c_size_t
    lib.probe_video_abi.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_uint]; lib.probe_video_abi.restype = ctypes.c_size_t
    report = {"schema": "route-a-corecrypto-loader-v1", "kernel": loader.identity(kernel),
              "production_extractions": excerpts, "entry_symbols": symbols,
              "load_contract": strict["metadata"]["load_contract"],
              "byte_load": loader.verify_load(lib, data, strict, directory / "kernel.load.bin"),
              "boot_args_abi": loader.check_abi(lib, assym),
              "scope": "unchanged pinned DarwinBoot host extraction; no firmware or guest instruction execution"}
    save(directory / "report.json", report)
    return report


def platform_link_inputs(journal, baseline, baseline_path):
    """Replay the pinned platform report's one CPU substitution and ordered list."""
    spec = baseline["commands"][-1]
    argv = spec["argv"]
    require(argv.count("-filelist") == 1, "baseline link filelist is ambiguous")
    path = regular(argv[argv.index("-filelist") + 1])
    replacement = baseline["kernel_callback"]["filelist_replacement"]
    require(replacement["replacement_count"] == 1
            and loader.identity(path) == replacement["platform_filelist"],
            "platform filelist differs from the pinned callback receipt")
    original = regular(replacement["original_filelist"]["path"])
    raw = pin(original, loader.platform_link.FILELIST_SHA256)
    require(loader.identity(original) == replacement["original_filelist"],
            "original retained filelist identity differs")
    lines = raw.decode().splitlines(keepends=True)
    require(all(line.endswith("\n") and line[:-1] == line[:-1].strip() and line[:-1]
                for line in lines), "unsupported retained filelist line")
    index = replacement["line_index"]
    require(type(index) is int and 0 <= index < len(lines)
            and lines[index][:-1] == replacement["original_entry"],
            "pinned CPU replacement index or original entry differs")
    changed = list(lines)
    changed[index] = replacement["replacement_entry"] + "\n"
    require(path.read_bytes() == "".join(changed).encode(),
            "platform filelist does not reproduce the pinned single CPU replacement")
    cwd = Path(spec["cwd"])
    members = []
    for line in changed:
        item = Path(line[:-1])
        item = regular(item if item.is_absolute() else cwd / item)
        require(str(item) in journal.records, "platform object is absent from the pinned inventory")
        members.append(journal.protect(item))
    require(len(members) == loader.platform_link.FILELIST_OBJECT_COUNT
            and len({item["path"] for item in members}) == len(members),
            "platform ordered object inventory is incomplete or duplicated")
    for item in (path, original, baseline_path):
        journal.protect(item)
    return {"baseline_report": loader.identity(baseline_path),
            "baseline_filelist": loader.identity(path), "original_members": members,
            "cwd": str(cwd), "argv": list(argv)}


PACGA_SOURCES = ("osfmk/arm64/sleh.c", "osfmk/arm64/locore.s", "osfmk/arm64/exception_asm.h")
PACGA_HUNKS = (2, 1, 2)


def apply_pacga_patch(originals, patch):
    """Replay the three reviewed additions-only diffs, with no fuzz or offsets."""
    require(set(originals) == set(PACGA_SOURCES), "PACGA retained source set differs")
    lines, index, result = patch.splitlines(keepends=True), 0, {}
    for relative, hunk_count in zip(PACGA_SOURCES, PACGA_HUNKS):
        name = relative.encode()
        header = [b"diff --git a/" + name + b" b/" + name + b"\n",
                  b"--- a/" + name + b"\n", b"+++ b/" + name + b"\n"]
        require(lines[index:index + 3] == header, "PACGA patch file set or order differs")
        source, output, cursor, delta, hunks = originals[relative].splitlines(keepends=True), [], 0, 0, 0
        index += 3
        while index < len(lines) and not lines[index].startswith(b"diff --git "):
            match = re.fullmatch(rb"@@ -([1-9][0-9]*),([1-9][0-9]*) \+([1-9][0-9]*),([1-9][0-9]*) @@\n", lines[index])
            require(match is not None, "unsupported PACGA patch hunk header")
            old_start, old_count, new_start, new_count = map(int, match.groups())
            start = old_start - 1
            require(start >= cursor and start + old_count <= len(source)
                    and new_start == old_start + delta and new_count > old_count,
                    "PACGA patch hunk position, overlap or addition count differs")
            index += 1
            old, new = [], []
            while index < len(lines) and not lines[index].startswith((b"@@", b"diff --git ")):
                line = lines[index]
                require(line.endswith(b"\n") and line[:1] in (b" ", b"+"),
                        "PACGA patch is not an exact additions-only patch")
                if line[:1] == b" ":
                    old.append(line[1:])
                new.append(line[1:])
                index += 1
            require(len(old) == old_count and len(new) == new_count, "PACGA patch hunk line counts differ")
            require(source[start:start + old_count] == old, "PACGA patch retained source context differs")
            output.extend(source[cursor:start]); output.extend(new)
            cursor, delta, hunks = start + old_count, delta + new_count - old_count, hunks + 1
        require(hunks == hunk_count, "PACGA patch reviewed hunk count differs")
        output.extend(source[cursor:])
        result[relative] = b"".join(output)
    require(index == len(lines), "PACGA patch contains additional files")
    return result


def pacga_configuration(raw, unit):
    """Read the actual preprocessor output independently of the stage producer."""
    def definitions(name):
        return re.findall(rb"^#define[ \t]+" + name.encode() + rb"(?:[ \t]+([^\r\n]*))?$", raw, re.M)
    require(definitions("CONFIG_ROUTE_A_PACGA_SVC") == [b"1"],
            "PACGA configuration does not uniquely enable the selected ABI")
    require(definitions("__ARM_KERNEL_PROTECT__") in ([], [b"0"]),
            "PACGA x18 exception return is not reviewed for ARM_KERNEL_PROTECT")
    require(not definitions("__arm64e__"), "PACGA configuration selects the arm64e ABI")
    if unit == "locore":
        require(definitions("__ASSEMBLER__") == [b"1"], "PACGA locore configuration is not assembler preprocessing")
    else:
        require(not definitions("__ASSEMBLER__"), "PACGA sleh configuration is not C")
    return {"macros_sha256": sha(raw), "route_a_pacga_svc": 1, "arm_kernel_protect": 0,
            "language": "c" if unit == "sleh" else "assembler-with-cpp"}


def admit_pacga_stage(journal, stage_path, kernel_build, original_members):
    """Independently bind both ordinary-arm64 objects before any provider build."""
    from arm64_lowering import pacga
    from route_a_pacga_probe import run as execution
    path = regular(stage_path)
    stage_generation = execution.file_identity(path)
    stage_identity = journal.protect(path)
    stage_bytes = path.read_bytes()
    require(sha(stage_bytes) == stage_generation["sha256"] == stage_identity["sha256"],
            "PACGA stage report changed before it was read")
    stage = json.loads(stage_bytes)
    require(stage.get("schema") == "route-a-pacga-stage-v2" and stage.get("compile_passed") is True
            and type(stage.get("compile_exit_code")) is int and stage["compile_exit_code"] == 0
            and stage.get("abi") == pacga.ABI, "PACGA stage did not successfully compile the selected v2 ABI")
    units = stage["translation_units"]
    require(set(units) == {"sleh", "locore"}, "PACGA stage requires exactly both translation units")
    timeout = stage["compile_timeout_seconds"]
    require(type(timeout) is int and 1 <= timeout <= 900, "PACGA compile timeout differs from the reviewed bounds")
    implementation = pacga.implementation()
    require(stage.get("implementation") == implementation and stage.get("xnu_commit") == pacga.XNU_COMMIT
            and stage.get("descriptor_hex") == pacga.descriptor().hex(), "PACGA stage source/ABI implementation identity differs")
    frozen, tools = stage["frozen"], stage["tools"]
    require(set(tools) == {"clang"} and tools["clang"]["binary"]["sha256"] == PINS["compiler"],
            "PACGA stage compiler differs from the pinned kernel compiler")
    kb, output = Path(kernel_build).resolve(), path.parent
    xnu = kb / ".cache/xnu-work"
    prepared_pins = dict(zip(PACGA_SOURCES, (PACGA_PINS["source"], PACGA_PINS["locore_source"],
                                           PACGA_PINS["exception_asm_source"])))
    require(stage["prepared_sources"] == prepared_pins, "PACGA prepared source identities differ")
    expected_paths = {"helper": output / "source/osfmk/arm64/route_a_pacga_qarma5.h",
                      "abi_header": output / "source/osfmk/arm64/route_a_pacga_abi.h",
                      "patch": output / "runtime.patch"}
    expected_paths.update({"source:" + name: output / "source" / name for name in PACGA_SOURCES})
    expected_paths.update({"prepared:" + name: xnu / name for name in PACGA_SOURCES})
    expected_paths.update(assym=kb / ASSYM_REL, genassym=xnu / "osfmk/arm64/genassym.c")
    # Protect generated semantic inputs before reading them. A later first-time
    # protection must never adopt changed dependency/configuration receipts.
    guarded = [path, *(xnu / name for name in PACGA_SOURCES), kb / ASSYM_REL]
    guarded.extend(ROOT / name for name in ("scripts/build_route_a_pacga.py", "scripts/route_a_pacga_probe/run.py",
                                            "scripts/arm64_lowering/pacga.py", pacga.HEADER, pacga.ABI_HEADER, pacga.PATCH))
    for unit in ("sleh", "locore"):
        expected_paths.update({"recipe:" + unit: kb / Path(RECIPE_REL).with_name(unit + ".o.json"),
                               "object:" + unit: output / (unit + ".o"),
                               "configuration:" + unit: output / (unit + ".macros.txt")})
        guarded.extend(expected_paths[key + ":" + unit] for key in ("recipe", "object", "configuration"))
        guarded.extend(output / (unit + suffix) for suffix in (".d", ".discovered.d", ".dependencies.json"))
    guarded_generations = {str(path): stage_generation}
    for item in guarded:
        original = execution.file_identity(item)
        require(guarded_generations.setdefault(str(item), original) == original,
                "PACGA guarded input generation changed before admission")
        journal.protect(item)
    for key, item in expected_paths.items():
        require(frozen[key]["path"] == str(item), "PACGA frozen path differs: " + key)
    for key, relative in (("helper", pacga.HEADER), ("abi_header", pacga.ABI_HEADER), ("patch", pacga.PATCH)):
        require(frozen[key]["sha256"] == stage[key + "_sha256"] == implementation["sources"][relative],
                "PACGA staged helper/ABI/patch differs from its implementation identity")
    for key, relative in (("stage", "scripts/build_route_a_pacga.py"), ("execution", "scripts/route_a_pacga_probe/run.py")):
        require(frozen[key]["sha256"] == PACGA_PINS[key + "_driver"], "PACGA stage used an unreviewed producer validation source")
        pin(ROOT / relative, PACGA_PINS[key + "_driver"])
        journal.protect(ROOT / relative)
    for relative in (pacga.HEADER, pacga.ABI_HEADER, pacga.PATCH, "scripts/arm64_lowering/pacga.py"):
        journal.protect(ROOT / relative)
    try:
        execution.verify_tools(tools, hashes=True)
        execution.verify_files(frozen, hashes=True)
    except ValueError as error:
        raise BuildError("PACGA stage identity changed: " + str(error)) from error
    originals = {name: pin(xnu / name, digest) for name, digest in prepared_pins.items()}
    rebuilt = apply_pacga_patch(originals, pin(expected_paths["patch"], implementation["sources"][pacga.PATCH]))
    require(stage["staged_sources"] == {name: sha(raw) for name, raw in rebuilt.items()},
            "PACGA staged source identities do not reproduce the reviewed patch")
    for name, raw in rebuilt.items():
        require(pin(expected_paths["source:" + name], sha(raw)) == raw
                and frozen["source:" + name]["sha256"] == sha(raw),
                "PACGA staged source does not reproduce the pinned source and exact patch")
    for name, digest in prepared_pins.items():
        require(frozen["prepared:" + name]["sha256"] == digest, "PACGA prepared source generation identity differs")
    for key in ("assym", "genassym"):
        pin(expected_paths[key], PACGA_PINS[key])
        require(frozen[key]["sha256"] == PACGA_PINS[key], "PACGA retained assembly provenance differs")
    commands = stage["commands"]
    names = ["compiler-version", *[unit + suffix for unit in ("sleh", "locore")
                                   for suffix in ("-discover-headers", "-config", "-compile")]]
    require([item.get("name") for item in commands] == names, "PACGA stage command sequence differs")
    for command in commands:
        require(command.get("status") == "finished" and type(command.get("exit_code")) is int
                and command["exit_code"] == 0 and command.get("cleanup", {}).get("group_absent") is True
                and command["cleanup"].get("direct_child_reaped") is True,
                "PACGA stage has an unsuccessful or unreaped command")
    require(commands[0]["arguments"] == [tools["clang"]["invocation"], "--version"]
            and commands[0]["directory"] == str(output) and commands[0].get("timeout_seconds") == 60,
            "PACGA compiler version receipt differs")
    dependencies, admitted = {}, {}
    overlay_paths = {item for key, item in expected_paths.items()
                     if key.startswith("source:") or key in ("helper", "abi_header")}
    for position, unit in enumerate(("sleh", "locore")):
        record, relative = units[unit], PACGA_SOURCES[position]
        require(type(record.get("compile_exit_code")) is int and record["compile_exit_code"] == 0,
                "PACGA translation unit lacks a successful compile exit")
        source, staged = xnu / relative, expected_paths["source:" + relative]
        recipe_path = expected_paths["recipe:" + unit]
        recipe_pin = PACGA_PINS["recipe" if unit == "sleh" else "locore_recipe"]
        recipe = json.loads(pin(recipe_path, recipe_pin).decode().rstrip().removesuffix(","))
        require(record["source_file"] == relative and record["recipe_sha256"] == frozen["recipe:" + unit]["sha256"] == recipe_pin
                and recipe["file"] == str(source) and Path(recipe["directory"]).resolve() == recipe_path.parent,
                "PACGA translation unit is not based on the pinned retained recipe/source")
        arguments = list(recipe["arguments"])
        require(arguments.count(str(source)) == 1 and arguments.count("-o") == 1 and arguments.count("-c") == 1
                and arguments[0] == tools["clang"]["invocation"]
                and arguments[arguments.index("-o") + 1] == recipe["output"],
                "pinned PACGA recipe compiler/source/output is ambiguous")
        if unit == "locore":
            language = [value[2:] for value in arguments if value.startswith("-x") and value != "-x"]
            language += [arguments[i + 1] for i, value in enumerate(arguments[:-1]) if value == "-x"]
            require(language == ["assembler-with-cpp"], "PACGA locore recipe lacks the fixed assembly language")
        # The retained locore recipe records a temporary .s output. Its previous
        # link member is still the unique locore.o beside that fixed recipe.
        name = unit + ".o"
        previous = journal.protect(recipe_path.parent / name)
        require(record["previous_object"] == {"name": name, "sha256": previous["sha256"]}
                and sum(item == previous for item in original_members) == 1
                and sum(Path(item["path"]).name == name for item in original_members) == 1,
                "PACGA previous object is not the unique pinned platform " + name)
        obj = expected_paths["object:" + unit]
        raw = regular(obj).read_bytes()
        require(record["object"] == {"name": name, "bytes": len(raw), "sha256": sha(raw), "cpu_type": "arm64", "cpu_subtype": 0}
                and frozen["object:" + unit]["sha256"] == sha(raw), "PACGA replacement object identity differs")
        try:
            metadata = loader.platform_link.macho(raw, 1)
        except loader.platform_link.LinkError as error:
            raise BuildError("PACGA object is not an admissible ordinary-arm64 object: " + str(error)) from error
        descriptors = [section for section in metadata["sections"] if section["name"] == "__unixnu_pacga"]
        if unit == "sleh":
            require(len(descriptors) == 1 and descriptors[0]["segment"] == "__DATA_CONST"
                    and not (descriptors[0]["flags"] & 0x80000000)
                    and raw[descriptors[0]["offset"]:descriptors[0]["offset"] + descriptors[0]["size"]] == pacga.descriptor(),
                    "PACGA sleh object lacks the exact retained implementation descriptor")
        else:
            require(not descriptors, "PACGA locore object duplicates the implementation descriptor")
        arguments[arguments.index(str(source))] = str(staged)
        arguments[arguments.index("-o") + 1] = str(obj)
        arguments[1:1] = ["-I", str(output / "source/osfmk")]
        arguments += ["-march=armv8-a", "-DCONFIG_ROUTE_A_PACGA_SVC=1",
                      '-DROUTE_A_PACGA_IMPLEMENTATION_SHA256="' + implementation["sha256"] + '"']
        if unit == "sleh":
            arguments += ["-mgeneral-regs-only"]
        arguments += ["-MD", "-MF", str(output / (unit + ".d"))]
        if unit == "sleh":
            arguments += ["-Werror=implicit-function-declaration", "-Werror=incompatible-function-pointer-types", "-Werror=return-type"]
        discovery = list(arguments)
        discovery[discovery.index("-MD")] = "-M"
        discovery[discovery.index("-MF") + 1] = str(output / (unit + ".discovered.d"))
        discovery[discovery.index("-o") + 1] = str(output / (unit + ".discovered.stdout"))
        configuration = list(arguments)
        configuration.remove("-c"); configuration.remove("-MD")
        at = configuration.index("-MF"); del configuration[at:at + 2]
        configuration[configuration.index("-o") + 1] = str(output / (unit + ".macros.txt"))
        configuration += ["-E", "-dM"]
        require(record["arguments"] == arguments and record["directory"] == recipe["directory"],
                "PACGA compile argv differs from the pinned recipe and reviewed overlay flags")
        for command, expected, deadline in zip(commands[1 + 3 * position:4 + 3 * position],
                                                (discovery, configuration, arguments), (300, 300, timeout)):
            require(command["arguments"] == expected and command["directory"] == recipe["directory"]
                    and type(command.get("timeout_seconds")) is int and command["timeout_seconds"] == deadline,
                    "PACGA discovery/configuration/compile receipt differs")
        macros = expected_paths["configuration:" + unit].read_bytes()
        require(record["configuration"] == pacga_configuration(macros, unit)
                and frozen["configuration:" + unit]["sha256"] == sha(macros), "PACGA configuration publication differs")
        closure = record["header_closure"]
        declared = execution.dependency_paths(output / (unit + ".discovered.d"), recipe["directory"])
        actual = execution.dependency_paths(output / (unit + ".d"), recipe["directory"])
        require(declared == actual == {Path(item) for item in closure}
                and record["dependency_count"] == len(closure) and staged in declared,
                "PACGA actual dependency closure differs")
        required = ({staged, expected_paths["helper"], expected_paths["abi_header"]} if unit == "sleh" else
                    {staged, expected_paths["source:" + PACGA_SOURCES[2]], expected_paths["abi_header"], kb / ASSYM_REL})
        require(required <= declared and (xnu / PACGA_SOURCES[2]) not in declared
                and all(not item.is_relative_to(output / "source") or item in overlay_paths for item in declared),
                "PACGA dependencies omit the reviewed overlay or contain an unreviewed shadow header")
        for item, identity in closure.items():
            require(identity["path"] == item and frozen.get("dependency:" + item) == identity
                    and dependencies.setdefault(item, identity) == identity, "PACGA shared dependency generation differs")
        publication = output / (unit + ".dependencies.json")
        raw = publication.read_bytes()
        require(sha(raw) == record["dependencies_sha256"]
                and json.loads(raw) == {item: identity["sha256"] for item, identity in closure.items()},
                "PACGA dependency publication differs")
        admitted[unit] = {"previous_object": previous, "object": journal.protect(obj)}
    require(set(frozen) == set(expected_paths) | {"stage", "execution"} | {"dependency:" + item for item in dependencies},
            "PACGA frozen input inventory differs")
    for record in frozen.values():
        journal.protect(record["path"])
    journal.protect(tools["clang"]["invocation"], tool=True)
    for item in guarded:
        journal.protect(item)
    require(journal.protect(path) == stage_identity and pacga.implementation() == implementation,
            "PACGA report or implementation changed during admission")
    try:
        execution.verify_files(frozen, hashes=True)
        execution.verify_tools(tools, hashes=True)
        execution.verify_files(guarded_generations, hashes=True)
    except ValueError as error:
        raise BuildError("PACGA stage identity changed during admission: " + str(error)) from error
    return {"stage_report": stage_identity, "kernel_build": str(kb), "implementation": implementation,
            "translation_units": admitted, "validation_sources": {key: frozen[key]["sha256"] for key in ("stage", "execution")},
            "dependency_count": len(dependencies), "runtime_boot_verified": False}


def write_link_filelist(journal, plan, bootstrap, archive, pacga_overlay=None):
    members = list(plan["original_members"])
    substitutions = []
    replacements = [("prng_random.o", journal.protect(bootstrap), None)]
    if pacga_overlay is not None:
        units = pacga_overlay["translation_units"]
        require(set(units) == {"sleh", "locore"}, "PACGA link substitution requires exactly both translation units")
        replacements.extend((name + ".o", units[name]["object"], units[name]["previous_object"])
                            for name in ("sleh", "locore"))
    for name, replacement, previous in replacements:
        indices = [index for index, item in enumerate(members) if Path(item["path"]).name == name]
        require(len(indices) == 1, name + " replacement is not unique")
        index = indices[0]
        require(previous is None or members[index] == previous, "PACGA replacement targets a different original object")
        substitutions.append({"index": index, "kind": "bootstrap" if name == "prng_random.o" else "pacga",
                              "old": members[index], "new": replacement})
        members[index] = replacement
    path = journal.out / "platform.filelist"
    path.write_text("".join(item["path"] + "\n" for item in members))
    return {"schema": "route-a-corecrypto-ordered-link-v1", "baseline_report": plan["baseline_report"],
            "baseline_filelist": plan["baseline_filelist"], "original_members": plan["original_members"],
            "substitutions": substitutions, "ordered_members": members, "filelist": journal.protect(path),
            "provider_archive": journal.protect(archive)}


def verify_link_contract(report, directory, protected, checked_input):
    contract = report["link_contract"]
    require(contract["schema"] == "route-a-corecrypto-ordered-link-v1", "missing ordered link contract")
    baseline_path = regular(contract["baseline_report"]["path"])
    require(checked_input(baseline_path) == contract["baseline_report"], "baseline report identity differs")
    baseline = json.loads(pin(baseline_path, PINS["platform_report"]))
    inventory = baseline["protected_input_inventory"]
    require(checked_input(Path(inventory["path"])) == inventory, "pinned platform inventory identity differs")
    declared = json.loads(pin(inventory["path"], inventory["sha256"]))
    journal = Journal(directory)
    for item in declared:
        record = checked_input(Path(item["path"]))
        require(all(record[key] == item[key] for key in ("size", "sha256")), "pinned platform input changed")
        journal.records[record["path"]] = record
    plan = platform_link_inputs(journal, baseline, baseline_path)
    require(contract["baseline_filelist"] == plan["baseline_filelist"]
            and contract["original_members"] == plan["original_members"], "baseline ordered link members differ")
    overlay = report.get("pacga_overlay")
    if overlay is not None:
        selection = admit_pacga_stage(journal, overlay["stage_report"]["path"], overlay["kernel_build"], plan["original_members"])
        require(selection == overlay, "PACGA admission differs from the build receipt")
        from arm64_lowering import pacga
        require(report["pacga_runtime"] == pacga.runtime_kernel(report["kernel"]["path"]),
                "sealed kernel no longer binds the admitted PACGA runtime")
    for path, record in journal.records.items():
        require(checked_input(Path(path)) == record, "link provenance input is not protected by this build")
    members = list(plan["original_members"])
    expected = [("bootstrap", "prng_random.o", report["bootstrap"])]
    if overlay is not None:
        expected.extend(("pacga", name + ".o", overlay["translation_units"][name]["object"])
                        for name in ("sleh", "locore"))
    substitutions = []
    for kind, name, replacement in expected:
        indices = [index for index, item in enumerate(members) if Path(item["path"]).name == name]
        require(len(indices) == 1, "link substitution is not unique")
        index = indices[0]
        require(checked_input(Path(replacement["path"])) == replacement, "replacement object identity differs")
        substitutions.append({"index": index, "kind": kind, "old": members[index], "new": replacement})
        members[index] = replacement
    require(contract["substitutions"] == substitutions and contract["ordered_members"] == members,
            "generated ordered link members or permitted substitutions differ")
    path = regular(contract["filelist"]["path"])
    require(path == directory / "platform.filelist" and checked_input(path) == contract["filelist"]
            and path.read_bytes() == "".join(item["path"] + "\n" for item in members).encode(),
            "generated filelist does not match the exact ordered link contract")
    require(contract["provider_archive"] == report["archive"] == checked_input(Path(report["archive"]["path"])),
            "provider archive link input differs")
    commands = [command for command in report["commands"] if "-filelist" in command["argv"]]
    require(len(commands) == 1, "build lacks one unambiguous kernel link command")
    argv = commands[0]["argv"]
    require(argv.count("-filelist") == 1 and argv[argv.index("-filelist") + 1] == str(path)
            and argv.count(report["archive"]["path"]) == 1
            and argv.count("-o") == 1 and argv[argv.index("-o") + 1] == contract["unsealed_kernel"]["path"],
            "kernel link command does not consume the declared list/archive or produce its unsealed kernel")
    expected_argv = list(plan["argv"])
    expected_argv[expected_argv.index("-filelist") + 1] = str(path)
    expected_argv[expected_argv.index("-o") + 1] = contract["unsealed_kernel"]["path"]
    maps = [index for index, value in enumerate(expected_argv) if value.startswith("-Wl,-map,")]
    require(len(maps) == 1, "pinned platform link map is ambiguous")
    expected_argv[maps[0]] = "-Wl,-map," + str(directory / "platform.map")
    expected_argv += ["-Wl,-oso_prefix," + str(directory) + "/", report["archive"]["path"]]
    require(argv == expected_argv and commands[0]["cwd"] == plan["cwd"],
            "kernel link argv differs from the pinned recipe's permitted output substitutions")
    normalized = normalize_build_paths(contract, directory)
    # Raw hashes bind the actual file on disk, but paths inside this generated
    # list vary across output roots. Only this derived list is compared by its
    # independently reconstructed ordered member identities.
    normalized["filelist"] = {"path": normalize_build_paths(str(path), directory),
                              "ordered_members": normalize_build_paths(members, directory)}
    return normalized


def verify_abi_and_seal(report, directory):
    abi_path = regular(report["abi_receipt"]["path"])
    require(abi_path == directory / "abi.json" and loader.identity(abi_path) == report["abi_receipt"],
            "ABI report artifact changed")
    abi = json.loads(abi_path.read_bytes())
    require(abi == report["abi"] and abi.get("matches") is True and abi.get("mismatches") == []
            and set(abi["records"]) == set(ABI_RECORDS), "complete matching ABI receipt is missing")
    layouts = {}
    for side in ("provider", "consumer"):
        path = regular(directory / ("abi-" + side + ".stdout"))
        record = report["abi_outputs"][side]
        require(loader.identity(path) == record, "ABI compiler output changed")
        commands = [command for command in report["commands"] if command.get("stdout") == record]
        require(len(commands) == 1 and "-fdump-record-layouts-complete" in commands[0]["argv"]
                and "-fsyntax-only" in commands[0]["argv"], "ABI layout output lacks its compiler invocation")
        layouts[side] = record_layouts(path.read_text())
        require(set(layouts[side]) == set(ABI_RECORDS)
                and all(sha(text.encode()) == abi["records"][name][side] for name, text in layouts[side].items()),
                "ABI record digests do not match actual compiler layouts")
    require(layouts["provider"] == layouts["consumer"], "provider and consumer ABI layouts differ")
    seal_path = regular(report["seal_receipt"]["path"])
    unsealed = regular(report["link_contract"]["unsealed_kernel"]["path"])
    require(seal_path == directory / "seal.json" and loader.identity(seal_path) == report["seal_receipt"]
            and json.loads(seal_path.read_bytes()) == report["seal"]
            and unsealed == directory / "kernel.unsealed.macho"
            and loader.identity(unsealed) == report["link_contract"]["unsealed_kernel"],
            "seal or unsealed link artifact changed")
    sealed, expected = seal_kernel(unsealed.read_bytes())
    require(expected == report["seal"] and sealed == Path(report["kernel"]["path"]).read_bytes(),
            "sealed kernel does not reproduce the fixed static_if and POST HMAC procedure")
    return {"abi": abi, "seal": expected}


def build(args):
    out = fresh(args.output)
    journal = Journal(out)
    report = {"schema": "route-a-corecrypto-build-v1", "status": "failed", "build_verified": False,
              "runtime_provider_verified": False, "os_boot_verified": False, "tb371fc_kernel_qualified": False,
              "started_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "scope": "source provider and original glue against retained, identified XNU/platform objects"}
    try:
        kb = Path(args.kernel_build).resolve()
        compiler = Path(args.compiler).absolute()
        require(loader.platform_link.tool_identity(compiler)["sha256"] == PINS["compiler"], "compiler byte identity changed")
        archive = regular(args.source_archive)
        baseline_path = regular(args.platform_report)
        baseline = json.loads(pin(baseline_path, PINS["platform_report"]))
        journal.protect(archive); journal.protect(baseline_path)
        candidate = journal.protect(baseline["candidate"]["path"])
        require(all(candidate[key] == baseline["candidate"][key] for key in ("size", "sha256")), "baseline candidate changed")
        inventory = baseline["protected_input_inventory"]
        pin(inventory["path"], inventory["sha256"])
        journal.protect(inventory["path"])
        for item in json.loads(Path(inventory["path"]).read_bytes()):
            current = journal.protect(item["path"], tool=item.get("kind") == "tool")
            require(current["sha256"] == item["sha256"] and current["size"] == item["size"], "retained baseline input changed")
        link_plan = platform_link_inputs(journal, baseline, baseline_path)
        pacga_overlay = None
        if getattr(args, "pacga_stage_report", None) is not None:
            pacga_overlay = admit_pacga_stage(journal, args.pacga_stage_report, kb, link_plan["original_members"])
            report["pacga_overlay"] = pacga_overlay
        scripts = (Path(__file__), Path(loader.__file__), Path(loader.platform_link.__file__),
                   Path(loader.platform_link.toolchain.__file__))
        for path in (*scripts, loader.CONFIG, Path(sys.executable).resolve()):
            journal.protect(path)
        for path in GLUE.iterdir():
            if path.is_file(): journal.protect(path)
        frozen = out / "driver-source"; frozen.mkdir()
        for path in (*scripts, loader.CONFIG):
            shutil.copy2(path, frozen / path.name)
        pbx_path = kb / "scripts/pbxproj.py"; pin(pbx_path, PINS["pbxproj"]); journal.protect(pbx_path)
        source = extract_source(archive, out)
        source_paths = target_sources(source, module(pbx_path, "pinned_corecrypto_pbx"))
        for path in source.rglob("*"):
            if path.is_file(): journal.protect(path)
        # Freeze declared SDK/source headers before compilation, including resolved
        # framework symlinks. System host C headers are identified separately in scope.
        header_roots = (kb / ".cache/fakeroot", kb / ".cache/xnu-work", kb / "build/xnu/ios-obj")
        journal.headers(header_roots)
        resource_dir = journal.execute([str(compiler), "--no-default-config", "-print-resource-dir"],
                                       "compiler-resource-dir").decode().strip()
        resource = regular(Path(resource_dir) / "include/stddef.h").parent
        journal.headers((resource,))
        journal.protect(kb / "build/xnu/ios-obj/san/kasan-denylist-arm64")
        glue = out / "glue"; shutil.copytree(GLUE, glue)
        pin(glue / "namespace.h", PINS["namespace"])
        provider = pin(source / "corecrypto_kext/corecrypto_kext.c", PINS["provider"])
        bootstrap, report["bootstrap_reconstruction"] = reconstruct_bootstrap(journal, kb)
        report["bridge"] = prepare_overlay(provider, bootstrap, glue)
        for path in glue.iterdir():
            if path.is_file(): journal.protect(path)
        command = provider_command(compiler, kb, source, out)
        for flag in command:
            if flag.startswith("-I"):
                directory = Path(flag[2:])
                if directory.is_dir():
                    for path in directory.glob("*.h"):
                        if path.is_file():
                            journal.protect(path.resolve())
                            if path.absolute() != path.resolve(): journal.protect(path.absolute(), tool=True)
        recipe_path = kb / RECIPE_REL
        recipe = json.loads(pin(recipe_path, PINS["bootstrap_recipe"]).decode().strip().rstrip(","))
        journal.protect(recipe_path)
        bootstrap_out = out / "bootstrap"; bootstrap_out.mkdir()
        bootstrap_command = replay_bootstrap(recipe, kb, glue / "prng_random.c", bootstrap_out)
        provider_tu = command + ["-c", str(glue / "corecrypto_kext.c"), "-o", str(out / "abi-provider.o")]
        report["abi"] = abi_check(journal, provider_tu, bootstrap_command, out)
        report["abi_receipt"] = journal.protect(out / "abi.json")
        report["abi_outputs"] = {side: loader.identity(out / ("abi-" + side + ".stdout"))
                                 for side in ("provider", "consumer")}
        report["bootstrap_dependencies"] = journal.compile(bootstrap_command, "bootstrap", cwd=out, timeout=90)
        loader.platform_link.macho((bootstrap_out / "prng_random.o").read_bytes(), 1)
        objects = out / "objects"; objects.mkdir()
        entries = []
        with (out / "objects.jsonl").open("x", buffering=1) as receipt:
            for index, path in enumerate(source_paths):
                relative = str(path.relative_to(source))
                obj = objects / (sha(relative.encode())[:16] + "-" + path.stem + ".o")
                actual = glue / "corecrypto_kext.c" if relative == "corecrypto_kext/corecrypto_kext.c" else path
                dependencies = journal.compile(command + ["-c", str(actual), "-o", str(obj)], f"object-{index:03d}", timeout=60)
                loader.platform_link.macho(obj.read_bytes(), 1)
                entry = {"source": relative, "source_sha256": sha(actual.read_bytes()), "object": loader.identity(obj),
                         "dependencies": dependencies}
                entries.append(entry); receipt.write(json.dumps(entry) + "\n")
                if index % 50 == 0: print(f"provider C sources: {index + 1}/529", flush=True)
        built_archive = out / "libcorecrypto_kernel_noasm.a"
        journal.execute([str(args.ar), "rcsD", str(built_archive), *[e["object"]["path"] for e in entries]], "archive")
        raw_names = journal.execute([str(args.nm), "--extern-only", "--defined-only", str(built_archive)], "archive-names").decode()
        defined = {line.split()[-1] for line in raw_names.splitlines() if len(line.split()) == 3}
        original_names = {s["name"] for s in loader.strict_kernel(Path(baseline["candidate"]["path"]).read_bytes())["metadata"]["symbols"]["defined_external"]}
        require(not defined & original_names, "provider archive still collides with kernel definitions")
        namespace = re.findall(r"^#define (\w+) (\w+)$", (glue / "namespace.h").read_text(), re.M)
        require(len(namespace) == 64 and all("_" + new in defined and "_" + old not in defined for old, new in namespace), "namespace export contract differs")
        spec = baseline["commands"][-1]
        argv = list(spec["argv"])
        at = argv.index("-filelist") + 1
        report["link_contract"] = write_link_filelist(
            journal, link_plan, bootstrap_out / "prng_random.o", built_archive, pacga_overlay)
        argv[at] = report["link_contract"]["filelist"]["path"]
        linked = out / "kernel.unsealed.macho"; argv[argv.index("-o") + 1] = str(linked)
        map_args = [i for i, value in enumerate(argv) if value.startswith("-Wl,-map,")]
        require(len(map_args) == 1, "link map output is ambiguous")
        argv[map_args[0]] = "-Wl,-map," + str(out / "platform.map")
        # ld64 debug-map object paths are metadata too. Strip only this new
        # output prefix; retained input object paths stay exactly as declared.
        argv.append("-Wl,-oso_prefix," + str(out) + "/")
        argv.append(str(built_archive))
        temporary = out / "tmp"; temporary.mkdir()
        environment = dict(baseline["environment"], TMPDIR=str(temporary))
        require(journal.recheck()["unchanged"], "protected link inputs changed before linking")
        journal.execute(argv, "link", cwd=Path(spec["cwd"]), env=environment, timeout=180)
        report["link_contract"]["unsealed_kernel"] = journal.protect(linked)
        data, seal = seal_kernel(linked.read_bytes())
        kernel = out / "kernel.macho"; kernel.write_bytes(data); save(out / "seal.json", seal)
        report["seal_receipt"] = journal.protect(out / "seal.json")
        if pacga_overlay is not None:
            from arm64_lowering import pacga
            report["pacga_runtime"] = pacga.runtime_kernel(kernel)
        strict = loader.strict_kernel(data)
        config = json.loads(loader.CONFIG.read_text())
        symbols = loader.check_entry_symbols(strict, config, data)
        assym = kb / ASSYM_REL; loader.verify_bytes(assym.read_bytes(), config["prepared_xnu"]["assym"], "assym")
        journal.protect(assym)
        sources = loader.public_sources(config, Path(args.loader_sources))
        for item in sources.values(): journal.protect(item["path"])
        host = out / "loader"
        journal.protect(args.cc, tool=True)
        load_kernel(journal, sources, host, Path(args.cc), kernel, data, strict, symbols, assym.read_text())
        report.update(status="provider_built_linked_loaded", build_verified=True, source_revision=SOURCE_REVISION,
                      source_archive=loader.identity(archive), compiled_c_sources=len(entries),
                      namespace=namespace, archive=loader.identity(built_archive), kernel=loader.identity(kernel),
                      loaded_image=loader.identity(host / "kernel.load.bin"), loader_report=loader.identity(host / "report.json"),
                      seal=seal, bootstrap=loader.identity(bootstrap_out / "prng_random.o"),
                      object_manifest=loader.identity(out / "objects.jsonl"),
                      deterministic_environment={"SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH, "ZERO_AR_DATE": "1", "TZ": "UTC",
                                                 "compiler_paths": "fixed source/debug prefix maps and compilation directory",
                                                 "linker_paths": "oso_prefix removes only this fresh output directory"},
                      qualification_scope="build/type/layout/load only; actual POST and table consumers require runtime probe")
    except Exception as exc:
        report.update(status="failed", build_verified=False, error=f"{type(exc).__name__}: {exc}")
    finally:
        report["inputs"] = list(journal.records.values())
        report["input_recheck"] = journal.recheck()
        if not report["input_recheck"]["unchanged"]:
            report.update(status="failed", build_verified=False, error="declared inputs changed during build")
        report["commands"] = journal.commands
        report["finished_at_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save(out / "report.json", report)
    return report


def normalize_build_paths(value, directory):
    """Normalize only this build's output prefix in a recorded command contract."""
    if isinstance(value, str):
        prefix = str(directory)
        if value == prefix:
            return "<BUILD>"
        return "<BUILD>/" + value[len(prefix) + 1:] if value.startswith(prefix + "/") else value
    if isinstance(value, list):
        return [normalize_build_paths(item, directory) for item in value]
    if isinstance(value, dict):
        return {key: normalize_build_paths(item, directory) for key, item in value.items()}
    return value


def normalize_build_argv(argv, directory):
    """Normalize path operands only in the driver's known joined-path flags."""
    result = []
    for arg in argv:
        for flag in ("-ffile-prefix-map=", "-fdebug-prefix-map=", "-fmacro-prefix-map="):
            if arg.startswith(flag):
                source, separator, replacement = arg[len(flag):].partition("=")
                require(separator, "prefix-map option lacks its replacement")
                result.append(flag + normalize_build_paths(source, directory) + "=" + replacement)
                break
        else:
            for flag in ("-I", "-fdebug-compilation-dir=", "-Wl,-map,", "-Wl,-oso_prefix,"):
                if arg.startswith(flag):
                    result.append(flag + normalize_build_paths(arg[len(flag):], directory))
                    break
            else:
                result.append(normalize_build_paths(arg, directory))
    return result


def verify_compile_receipts(report, directory, objects):
    """Bind successful stages and every compile to protected inputs and own outputs."""
    inputs = report.get("inputs", [])
    require(isinstance(inputs, list) and all(isinstance(item, dict) and isinstance(item.get("path"), str)
                                           for item in inputs), "missing build input identities")
    protected = {item["path"]: item for item in inputs}
    require(len(protected) == len(inputs), "duplicate build input identity")
    expected = {}
    for item in objects:
        relative = Path(item["source"])
        require(not relative.is_absolute() and ".." not in relative.parts
                and str(relative) == item["source"], "invalid provider source path")
        source = directory / ("glue/corecrypto_kext.c" if item["source"] == "corecrypto_kext/corecrypto_kext.c"
                              else str(Path(SOURCE_ROOT) / relative))
        output = str(regular(item["object"]["path"]))
        require(output not in expected, "multiple provider sources name the same object")
        expected[output] = (source, item["source_sha256"], item["dependencies"])
    bootstrap = str(regular(report["bootstrap"]["path"]))
    require(bootstrap not in expected and len(expected) == 529, "bootstrap/provider output sets overlap")
    source = directory / "glue/prng_random.c"
    expected[bootstrap] = (source, protected.get(str(source), {}).get("sha256"), report["bootstrap_dependencies"])
    commands, stages, checked_inputs = {}, [], {}
    def checked_input(path):
        key = str(path)
        if key not in checked_inputs:
            require(key in protected and Path(key).is_absolute(), "build dependency is not a protected absolute input")
            actual = (loader.platform_link.tool_identity(path) if protected[key].get("kind") == "tool"
                      else loader.identity(regular(path)))
            require(actual == protected[key], "protected build input changed")
            checked_inputs[key] = actual
        return checked_inputs[key]
    require(isinstance(report.get("commands"), list), "missing compile command receipts")
    for command in report["commands"]:
        argv = command.get("argv", [])
        require(isinstance(argv, list) and argv and all(isinstance(arg, str) for arg in argv),
                "invalid command argv")
        require(type(command.get("exit")) is int and command["exit"] == 0 and command.get("reaped") is True,
                "build stage did not succeed and reap its owned process")
        cleanup = command.get("cleanup", {})
        require(isinstance(cleanup, dict) and command.get("group_absent_after_wait") is True
                and cleanup.get("group_absent") is True and cleanup.get("direct_child_reaped") is True
                and type(cleanup.get("direct_exit_code")) is int and cleanup["direct_exit_code"] == 0,
                "build stage did not finish and reap its owned process group")
        require(command.get("teardown_errors") == [], "build stage has command teardown errors")
        require(isinstance(command.get("cwd"), str) and isinstance(command.get("environment"), dict),
                "build stage lacks its working directory or environment")
        tool = checked_input(Path(argv[0]))
        require(tool.get("kind") == "tool", "invoked tool has no protected tool identity")
        contract = {"argv": normalize_build_argv(argv, directory), "cwd": command["cwd"],
                    "environment": command["environment"], "tool": tool}
        stages.append(normalize_build_paths(contract, directory))
        if "-c" not in argv:
            continue
        require(tool["sha256"] == PINS["compiler"], "compile tool differs from the fixed compiler")
        require(argv.count("-c") == 1 and argv.count("-o") == 1
                and argv.index("-o") + 1 < len(argv) and not any(arg.startswith("@") for arg in argv),
                "compile needs one explicit source/output operation, without response files")
        output = regular(argv[argv.index("-o") + 1])
        require(directory in output.parents and str(output) in expected,
                "compile output is not a declared object in this build directory")
        key = str(output.relative_to(directory))
        require(key not in commands, "duplicate compile output receipt")
        source, source_sha256, dependencies = expected[str(output)]
        source = regular(source)
        source_record = checked_input(source)
        require(argv.count(str(source)) == 1 and source_record == protected.get(str(source))
                and source_record["sha256"] == source_sha256,
                "compile source does not match this build's protected input")
        require(argv.count("-MF") == 1 and argv.index("-MF") + 1 < len(argv), "compile dependency output is not explicit")
        dependency_path = regular(dependencies["dependency_file"]["path"])
        require(directory in dependency_path.parents and argv[argv.index("-MF") + 1] == str(dependency_path)
                and loader.identity(dependency_path) == dependencies["dependency_file"], "dependency receipt/output identity differs")
        dependency_text = dependency_path.read_text().replace("\\\n", " ")
        require(":" in dependency_text, "dependency file lacks its target")
        target_text, input_text = dependency_text.split(":", 1)
        require(shlex.split(target_text) == [str(output)], "dependency target is not the declared compile output")
        words = shlex.split(input_text)
        require(words and all(Path(word).is_absolute() for word in words)
                and dependencies["input_count"] == len(words), "dependency input count/path contract differs")
        dependency_paths = sorted({str(Path(word).resolve()) for word in words})
        require(str(source) in dependency_paths, "dependency file omits the compiled source")
        dependency_inputs = [checked_input(Path(path)) for path in dependency_paths]
        commands[key] = normalize_build_paths(dict(contract, dependencies=dependency_inputs), directory)
    require(len(commands) == 530 and set(commands) == {str(Path(path).relative_to(directory)) for path in expected},
            "compile receipts do not cover every provider and bootstrap object exactly once")
    link_contract = verify_link_contract(report, directory, protected, checked_input)
    generated_filelist = report["link_contract"]["filelist"]["path"]
    normalized_inputs = {}
    for path in protected:
        actual = checked_input(Path(path))
        normalized_inputs[normalize_build_paths(path, directory)] = (
            {"kind": "derived-ordered-filelist", **link_contract["filelist"]} if path == generated_filelist
            else normalize_build_paths(actual, directory))
    require(len(normalized_inputs) == len(protected), "normalized input paths are ambiguous")
    return {"compiles": commands, "stages": stages, "protected_inputs": normalized_inputs, "link_contract": link_contract}


def compare_builds(first_path, second_path):
    """Compare two independently executed build receipts and their current bytes."""
    first_path, second_path = regular(first_path), regular(second_path)
    require(first_path.parent != second_path.parent, "reproducibility needs two distinct output directories")
    reports = [json.loads(path.read_text()) for path in (first_path, second_path)]
    artifacts, compile_contracts, qualifications = [], [], []
    for path, report in zip((first_path, second_path), reports):
        require(report.get("schema") == "route-a-corecrypto-build-v1" and report.get("build_verified") is True
                and report.get("input_recheck", {}).get("unchanged") is True, "build receipt did not pass")
        require(report.get("source_revision") == SOURCE_REVISION and report.get("compiled_c_sources") == 529,
                "build source revision or compiled source count differs")
        source_archive = report["source_archive"]
        require(source_archive["sha256"] == PINS["archive"]
                and loader.identity(regular(source_archive["path"])) == source_archive,
                "fixed source archive identity differs")
        manifest = report["object_manifest"]
        require(loader.identity(regular(manifest["path"])) == manifest, "object manifest changed")
        objects = [json.loads(line) for line in Path(manifest["path"]).read_text().splitlines()]
        require(len(objects) == 529 and len({o["source"] for o in objects}) == 529, "incomplete object manifest")
        records = {"provider:" + item["source"]: item["object"] for item in objects}
        records.update({key: report[key] for key in ("archive", "bootstrap", "kernel", "loaded_image")})
        for record in records.values():
            artifact = regular(record["path"])
            require(path.parent in artifact.parents and loader.identity(artifact) == record,
                    "build artifact is changed or not in its own independent output directory")
        qualifications.append(verify_abi_and_seal(report, path.parent))
        compile_contracts.append(verify_compile_receipts(report, path.parent, objects))
        artifacts.append(records)
    require(qualifications[0] == qualifications[1], "independent ABI or seal contracts differ")
    require(compile_contracts[0] == compile_contracts[1],
            "independent build stages, tools, dependencies or protected inputs differ")
    left_sources = {o["source"]: o["source_sha256"] for o in
                    map(json.loads, Path(reports[0]["object_manifest"]["path"]).read_text().splitlines())}
    right_sources = {o["source"]: o["source_sha256"] for o in
                     map(json.loads, Path(reports[1]["object_manifest"]["path"]).read_text().splitlines())}
    require(left_sources == right_sources and reports[0]["source_archive"]["sha256"] == reports[1]["source_archive"]["sha256"]
            and reports[0]["deterministic_environment"] == reports[1]["deterministic_environment"],
            "reproduction source or deterministic environment differs")
    require(artifacts[0].keys() == artifacts[1].keys(), "build artifact sets differ")
    differences = [key for key in artifacts[0] if any(artifacts[0][key][field] != artifacts[1][key][field]
                                                    for field in ("size", "sha256"))]
    return {"schema": "route-a-corecrypto-reproduction-v1", "verified": not differences,
            "reports": [loader.identity(first_path), loader.identity(second_path)],
            "checked_artifacts": len(artifacts[0]), "mismatches": differences,
            "scope": "529 independently compiled provider objects, bootstrap object, deterministic archive, ordered link inputs, replayed ABI/seal contracts, sealed kernel and loaded bytes"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compare-builds", type=Path, nargs=2, metavar=("FIRST_REPORT", "SECOND_REPORT"))
    for option in ("source-archive", "kernel-build", "compiler", "platform-report", "loader-sources", "output"):
        parser.add_argument("--" + option, type=Path)
    parser.add_argument("--pacga-stage-report", type=Path, help="explicit successful PACGA sleh.o stage; substituted before link and sealing")
    parser.add_argument("--ar", type=Path, default=Path("/usr/bin/llvm-ar"))
    parser.add_argument("--nm", type=Path, default=Path("/usr/bin/llvm-nm"))
    parser.add_argument("--cc", type=Path, default=Path("/usr/bin/cc"))
    args = parser.parse_args()
    if args.compare_builds:
        require(args.output is not None and args.pacga_stage_report is None,
                "comparison needs a fresh --output and derives PACGA identity only from its build receipts")
        out = fresh(args.output)
        report = compare_builds(*args.compare_builds); save(out / "report.json", report)
        print(json.dumps(report), flush=True)
        return 0 if report["verified"] else 2
    require(all(getattr(args, name.replace("-", "_")) is not None for name in
                ("source-archive", "kernel-build", "compiler", "platform-report", "loader-sources", "output")),
            "build requires all six explicit input/output options")
    def interrupted(number, frame):
        raise BuildError(f"build interrupted by signal {number}")
    for number in (signal.SIGTERM, signal.SIGINT): signal.signal(number, interrupted)
    report = build(args)
    print(json.dumps({k: report[k] for k in ("status", "build_verified")}), flush=True)
    return 0 if report["build_verified"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
