#!/usr/bin/env python3
"""Audit and stage native arm64e-to-arm64 compatibility experiments.

This creates research inputs for a matching XNU/dyld port, never a flash image.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import plistlib
import struct
import sys
import tempfile

from arm64_lowering.macho import MachOError, UnsupportedMachO
from arm64_lowering.pipeline import audit_userland, load_rewriter, rewrite_userland


ROOT = Path(__file__).resolve().parents[1]


def target_catalog():
    return json.loads((ROOT / "configs/route-a-targets.json").read_text())


def target_record(name, manifest=None):
    catalog = target_catalog()
    target = dict(catalog["targets"][name])
    target["source_revision"] = catalog["upstream_revision"]
    target["manifest_verified"] = False
    target["binary_membership_verified"] = False
    if manifest:
        raw = manifest.read_bytes()
        build = plistlib.loads(raw)
        if (build.get("ProductVersion"), build.get("ProductBuildVersion")) != (target["version"], target["build"]):
            raise ValueError("BuildManifest does not match the selected target")
        if target["product"] not in build.get("SupportedProductTypes", []):
            raise ValueError("BuildManifest does not contain the selected product")
        if not any(i.get("Info", {}).get("DeviceClass") == target["device_class"]
                   for i in build.get("BuildIdentities", [])):
            raise ValueError("BuildManifest does not contain the selected device class")
        target.update(manifest_verified=True, manifest_sha256=hashlib.sha256(raw).hexdigest())
    return target


def write_json(path, report):
    content = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if path:
        with path.open("x") as handle:
            handle.write(content)
    else:
        print(content, end="")


def _remove_owned(path, identity):
    """Rollback only a file whose device/inode belongs to this transaction."""
    try:
        stat = path.lstat()
        if (stat.st_dev, stat.st_ino) == identity:
            path.unlink()
    except FileNotFoundError:
        pass


@contextmanager
def staged_new_outputs(output, report):
    """Prepare both destinations before rewriting, then publish without overwrite.

    Creating temporary files tests the actual parent-directory permissions.
    Hard links publish complete files with no-replace semantics. The report is
    published first, so a binary is never published before its report. Ordinary
    failures roll back files created here, including a partially published pair;
    two independently chosen paths cannot be an atomic pair across a power loss.
    """
    staged, published = [], []
    try:
        for target in (report, output):
            if target.exists() or target.is_symlink():
                raise ValueError(f"refusing to replace an existing destination: {target}")
            descriptor, name = tempfile.mkstemp(prefix=f".{target.name}.route-a-", dir=target.parent)
            stat = os.fstat(descriptor)
            os.close(descriptor)
            staged.append((Path(name), target, (stat.st_dev, stat.st_ino)))
        yield staged[1][0], staged[0][0]
        for temporary, target, identity in staged:
            os.link(temporary, target, follow_symlinks=False)
            published.append((target, identity))
    except BaseException:
        for target, identity in reversed(published):
            _remove_owned(target, identity)
        raise
    finally:
        for temporary, _, identity in staged:
            _remove_owned(temporary, identity)


def add_trust_entry(report, paths):
    report["owner_trust_bundle_installed"] = False
    if not paths:
        report["owner_trust_entry_ready"] = False
        return
    engine = load_rewriter()
    entries = {}
    sources = []
    for path in paths:
        container = path.read_bytes()
        kind, raw = engine.im4p_payload(container)
        # Pinned zeta make-zeta-trust-bundle.py uses this same allowlist:
        # trst is a static cache; trcs is a cryptex cache. Both carry v2 entries.
        if kind not in ("trst", "trcs"):
            raise ValueError(f"unexpected trust-cache IM4P type: {kind}")
        entries.update(engine.trust_cache_entries(raw))
        sources.append(dict(name=path.name, im4p_type=kind, bytes=len(container),
                            sha256=hashlib.sha256(container).hexdigest()))
    attributes = entries.get(bytes.fromhex(report["original_cdhash"]))
    if attributes is None:
        raise ValueError("original image is absent from the provided Apple trust caches")
    report["trust_cache_entry"] = dict(
        cdhash=report["cdhash"], hash_type=attributes[0], flags=attributes[1],
        constraint_category=attributes[2], copied_from_original=True)
    report["owner_trust_entry_ready"] = True
    report["trust_cache_inputs"] = sources


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("targets", help="show pinned experimental OS targets")
    for name in ("audit", "rewrite"):
        command = commands.add_parser(name)
        command.add_argument("--input", type=Path, required=True)
        command.add_argument("--profile", choices=("ipados27", "macos27"), required=True)
        command.add_argument("--build-manifest", type=Path)
        command.add_argument("--report", type=Path, required=name == "rewrite")
        if name == "rewrite":
            command.add_argument("--output", type=Path, required=True)
            command.add_argument("--plain-pointer-abi", action="store_true", required=True)
            command.add_argument("--platform-identifier", type=int)
            command.add_argument("--hardened-runtime", action=argparse.BooleanOptionalAction, default=None)
            command.add_argument("--apple-trust-cache", type=Path, action="append", default=[])
    args = parser.parse_args(argv)
    if args.command == "targets":
        write_json(None, target_catalog())
        return 0
    target = target_record(args.profile, args.build_manifest)
    if args.report and args.report.exists():
        raise ValueError("refusing to replace an existing report")
    if args.command == "rewrite":
        if args.output.exists() or args.output.resolve() in (args.input.resolve(), args.report.resolve()):
            raise ValueError("rewrite needs a new output separate from input and report")
    if args.command == "audit":
        data = args.input.read_bytes()
        try:
            report = audit_userland(data)
        except UnsupportedMachO as error:
            report = dict(schema="route-a-userland-audit-v1", format=error.format,
                          input_sha256=hashlib.sha256(data).hexdigest(), input_bytes=len(data),
                          blockers=[str(error)], preflight_status="blocked", os_boot_verified=False,
                          scan_is_code_proof=False, target_isa_audited=False)
        report["target"] = target
        write_json(args.report, report)
        return 2 if report["preflight_status"] == "blocked" else 0
    with staged_new_outputs(args.output, args.report) as (output_stage, report_stage):
        data = args.input.read_bytes()
        output, report = rewrite_userland(
            data, plain_pointers=args.plain_pointer_abi,
            platform_identifier=args.platform_identifier, hardened_runtime=args.hardened_runtime)
        add_trust_entry(report, args.apple_trust_cache)
        report.update(target=target, input_name=args.input.name, output_name=args.output.name)
        output_stage.write_bytes(output)
        report_stage.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({key: report[key] for key in (
        "instruction_edits", "output_sha256", "cdhash", "os_boot_verified")}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error, ImportError, KeyError, IndexError) as error:
        print(f"route-a: {error}", file=sys.stderr)
        raise SystemExit(2)
