#!/usr/bin/env python3
"""Prepare four pinned XNU files and verify the Route A kernel patch round trip.

This downloads public source only. It neither builds a kernel nor runs device
commands. Original XNU license headers are retained in the prepared source.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SOURCE_RECORD = ROOT / "upstream/route-a-kernel-sources.json"
EXPECTED_FILES = {
    "osfmk/vm/vm_shared_region.c",
    "osfmk/vm/vm_shared_region_internal.h",
    "osfmk/vm/vm_shared_region_pager.c",
    "osfmk/vm/vm_dyld_pager.c",
}


class PreparationError(ValueError):
    """The pinned inputs or patch states did not match their recorded values."""


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PreparationError(message)


def raw_url(repository: str, commit: str, path: str) -> str:
    require(re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is not None,
            "unexpected source repository")
    require(re.fullmatch(r"[0-9a-f]{40}", commit) is not None, "source revision is not pinned")
    relative = Path(path)
    require(not relative.is_absolute() and ".." not in relative.parts, "unsafe source path")
    return repository.replace("https://github.com/", "https://raw.githubusercontent.com/") + "/" + commit + "/" + path


def verify_bytes(data: bytes, entry: dict, label: str) -> None:
    require(type(entry["bytes"]) is int and 0 < entry["bytes"] <= 2 * 1024 * 1024,
            "invalid source size: " + label)
    require(len(data) == entry["bytes"] and digest(data) == entry["sha256"],
            "source size or digest differs: " + label)


def prepare(output: Path, record: dict, record_digest: str, local_patch: Path) -> dict:
    """The caller has exclusively created output; leave diagnostics on failure."""
    tree = output / "tree"
    tree.mkdir()
    report = {
        "schema_version": 1,
        "status": "incomplete",
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_record_sha256": record_digest,
        "xnu_commit": record["xnu"]["commit"],
        "prepared_dir": str(tree),
        "downloads": [],
        "commands": [],
        "states": [],
        "local_patch": record["local_patch"],
        "full_kernel_compiled": False,
        "hardware_boot_tested": False,
    }
    headers = {}

    def fetch(url: str, entry: dict, destination: Path) -> bytes:
        require(type(entry["bytes"]) is int and 0 < entry["bytes"] <= 2 * 1024 * 1024,
                "invalid source size: " + url)
        with urllib.request.urlopen(url, timeout=45) as response:
            data = response.read(entry["bytes"] + 1)
        verify_bytes(data, entry, url)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        report["downloads"].append({"url": url, "bytes": len(data), "sha256": digest(data)})
        return data

    def command(*args: str) -> None:
        argv = ["git", "-C", str(tree), *args]
        result = subprocess.run(argv, capture_output=True, text=True)
        report["commands"].append({"argv": argv, "exit_code": result.returncode})
        if result.returncode:
            raise PreparationError("git command failed: " + " ".join(args) + "\n" + result.stderr.strip())

    def check_state(field: str) -> None:
        observed = {}
        for entry in record["xnu"]["files"]:
            data = (tree / entry["path"]).read_bytes()
            observed[entry["path"]] = digest(data)
            require(observed[entry["path"]] == entry[field], "tree differs: " + entry["path"] + " / " + field)
            require(data.startswith(headers[entry["path"]]), "original license header changed: " + entry["path"])
        report["states"].append({"name": field, "file_sha256": observed})

    def apply(patch: Path, reverse: bool = False) -> None:
        args = ["apply"]
        if reverse:
            args.append("--reverse")
        command(*args, "--check", str(patch))
        command(*args, str(patch))

    try:
        # Apply the exact bytes verified here, even if the checkout later changes.
        local_bytes = local_patch.read_bytes()
        verify_bytes(local_bytes, record["local_patch"], str(local_patch))
        local_patch = output / "route-a-plain-auth-12377.patch"
        local_patch.write_bytes(local_bytes)
        xnu = record["xnu"]
        for entry in xnu["files"]:
            url = raw_url(xnu["repository"], xnu["commit"], entry["path"])
            require(url == entry["url"], "source URL does not match its pin")
            data = fetch(url, entry, tree / entry["path"])
            first_comment = re.match(rb"/\*.*?\*/", data, re.S)
            require(first_comment is not None and b"License" in first_comment.group(),
                    "original license header missing: " + entry["path"])
            headers[entry["path"]] = first_comment.group()
        prerequisite = next(item for item in record["upstream_patches"] if item["role"] == "required prerequisite")
        main_patch = output / "main-4k-slide.patch"
        fetch(raw_url(prerequisite["repository"], prerequisite["commit"], prerequisite["path"]),
              prerequisite, main_patch)
        license_entry = record["upstream_license_copy"]
        license_path = (ROOT / license_entry["path"]).resolve()
        require(license_path.is_relative_to(ROOT), "unsafe upstream license path")
        license_bytes = license_path.read_bytes()
        require(digest(license_bytes) == license_entry["sha256"], "upstream license copy differs")
        (output / "UPSTREAM-LICENSE").write_bytes(license_bytes)

        command("init", "-q")
        check_state("sha256")
        apply(main_patch)
        check_state("after_prerequisite_sha256")
        apply(local_patch)
        check_state("after_plain_auth_sha256")
        apply(local_patch, reverse=True)
        check_state("after_prerequisite_sha256")
        apply(main_patch, reverse=True)
        check_state("sha256")
        apply(main_patch)
        check_state("after_prerequisite_sha256")
        apply(local_patch)
        check_state("after_plain_auth_sha256")
        report.update(status="prepared", apply_and_reverse_round_trip=True, original_license_headers_preserved=True)
        return report
    except Exception as error:
        report.update(status="failed", error=str(error))
        raise
    finally:
        (output / "verification.json").write_text(json.dumps(report, indent=2) + "\n")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, metavar="NEW_DIR",
                        help="new directory outside this repository; never overwritten")
    args = parser.parse_args(argv)
    output = args.output.absolute()
    try:
        require(not output.resolve().is_relative_to(ROOT), "output must be outside the public source repository")
        record_raw = SOURCE_RECORD.read_bytes()
        record = json.loads(record_raw)
        require(record["schema_version"] == 1, "unsupported source record schema")
        files = record["xnu"]["files"]
        require(len(files) == 4 and {entry["path"] for entry in files} == EXPECTED_FILES,
                "source record must select exactly the four expected files")
        require(sum(item["role"] == "required prerequisite" for item in record["upstream_patches"]) == 1,
                "source record must select exactly one prerequisite patch")
        local_patch = (ROOT / record["local_patch"]["path"]).resolve()
        require(local_patch.is_relative_to(ROOT) and local_patch.suffix == ".patch", "unsafe local patch path")
        verify_bytes(local_patch.read_bytes(), record["local_patch"], str(local_patch))
        # mkdir is exclusive even if another process races the existence check.
        output.mkdir(parents=True, exist_ok=False)
        report = prepare(output, record, digest(record_raw), local_patch)
    except (OSError, ValueError, KeyError, StopIteration) as error:
        print("ERROR: " + str(error), file=sys.stderr)
        return 1
    print("PASS: apply/reverse/reapply; pinned file digests and license headers match")
    print("prepared_dir=" + report["prepared_dir"])
    print("verification=" + str(output / "verification.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
