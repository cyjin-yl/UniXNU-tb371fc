"""Bind cache code proofs to exact inputs and admit only complete conversions.

The CFG analysis is a development tool, not a proof of whole-OS correctness.
This module prevents its partial or stale output from becoming an apparently
complete transformed cache. Inputs, rules, inventory and result arrays are
all content-bound; each proposed replacement is independently recomputed.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import shutil
import struct
import subprocess

import capstone
import numpy as np

from . import pacga

SCHEMA = "route-a-cache-proof-v1"
GRADES = ("unwind", "pointer", "landing", "stub", "call", "start", "gap")
_SCRIPTS = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode()


def _digest(value):
    return hashlib.sha256(value).hexdigest()


def _integer(value, label):
    require(type(value) is int and value >= 0, f"invalid {label}")
    return value


def _result_path(work, name):
    require(isinstance(name, str) and Path(name).name == name and name.endswith(".npz"),
            "proof result must be a local .npz filename")
    path = Path(work) / name
    require(path.is_file() and not path.is_symlink(), f"missing or symlinked proof result: {name}")
    return path


def source_manifest(cache):
    """Exact ordered main/subcache set, independent of their containing directory."""
    require(bool(cache.files), "empty cache file set")
    files, names, uuids = [], set(), set()
    for index, item in enumerate(cache.files):
        name, data = item.path.name, item.data
        require(name not in names, "duplicate cache filename")
        require(len(data) >= 0x68, f"truncated cache UUID: {name}")
        uuid = bytes(data[0x58:0x68]).hex()
        require(uuid != "00" * 16 and uuid not in uuids, "missing or duplicate cache UUID")
        names.add(name)
        uuids.add(uuid)
        files.append(dict(index=index, name=name, size=len(data), uuid=uuid, sha256=_digest(data)))
    images = [dict(address=hex(int(address)), path=path) for address, path in cache.images]
    require(len({entry["path"] for entry in images}) == len(images), "duplicate cache image path")
    return dict(schema="route-a-cache-input-v1", files=files, images=images)


def rules_manifest(*, pacga_policy="reject", pacga_kernel=None):
    """Reject proofs from a different decoder, CFG algorithm or lowering policy."""
    names = (
        "arm64_lowering/instructions.py", "arm64_lowering/proof.py",
        "arm64_lowering/pacga.py", "arm64_lowering/runtime/pacga_qarma5.h",
        "../patches/route-a-pacga-svc-12377.patch",
        "arm64_lowering/closure_receipts.py",
        "route_a_zeta/zeta_userland_pauth.py", "route_a_zeta/zeta_userland_code.py",
        "route_a_zeta/zeta_dyld_cache.py", "route_a_zeta/prove-zeta-dyld-cache.py",
        "route_a_zeta/zeta_closure.py",
    )
    llvm = shutil.which("llvm-mc")
    llvm_version = None
    if llvm:
        try:
            llvm_version = subprocess.run([llvm, "--version"], check=True, capture_output=True,
                                          text=True, timeout=5).stdout.strip()
        except (OSError, subprocess.SubprocessError) as error:
            raise ValueError(f"cannot identify llvm-mc decoder: {error}") from error
        require(bool(llvm_version), "llvm-mc version output is empty")
    runtime = pacga.runtime_binding(pacga_policy, pacga_kernel)
    return dict(abi="plain-pointers-v1", pacga_policy=pacga_policy, pacga_runtime=runtime,
                decoders=dict(capstone=capstone.__version__, capstone_library=list(capstone.cs_version()),
                              numpy=np.__version__, llvm_mc=llvm_version),
                sources={name: _digest((_SCRIPTS / name).read_bytes()) for name in names})


def expected_inventory(cache):
    """Compute all code-bearing images and stub islands from the input itself."""
    from route_a_zeta import zeta_dyld_cache as dc

    images, islands = {}, []
    for address, path in cache.images:
        image = dc.Image(cache, address, path)
        sections = image.instruction_sections()
        if not sections:
            continue
        require(path not in images, "duplicate code-bearing image")
        images[path] = dict(address=hex(address), file=sections[0]["file"],
                            regions=[dict(address=s["addr"], offset=s["offset"], size=s["size"])
                                     for s in sections])
    for index, item in enumerate(cache.files):
        for address, size, fileoff, _, _, flags, maxprot, _ in item.slid:
            if not flags & 8:
                continue
            require(size > 0 and maxprot & 4, "invalid executable stub island")
            islands.append(dict(address=hex(address), size=size, file=index,
                                regions=[dict(address=address, offset=fileoff, size=size)]))
    require(len({entry["address"] for entry in islands}) == len(islands), "duplicate stub island")
    islands.sort(key=lambda entry: int(entry["address"], 16))
    return dict(images=images, islands=islands)


def _entries(summary):
    require(isinstance(summary.get("images"), dict) and isinstance(summary.get("islands"), list),
            "missing proof image/island lists")
    entries = list(summary["images"].values()) + summary["islands"]
    require(all(isinstance(entry, dict) for entry in entries), "invalid proof entry")
    return entries


def seal_summary(cache, summary, work_dir, *, partial=False,
                 pacga_policy="reject", pacga_kernel=None):
    """Attach reproducible bindings to a proof, including intentionally partial reports.

    Sealing a report does not approve it. validate_summary performs admission.
    """
    result = deepcopy(summary)
    result["schema"] = SCHEMA
    result["complete"] = not bool(partial)
    result["source_manifest"] = source_manifest(cache)
    result["source_manifest_sha256"] = _digest(_canonical(result["source_manifest"]))
    result["rules"] = rules_manifest(pacga_policy=pacga_policy, pacga_kernel=pacga_kernel)
    result["inventory"] = expected_inventory(cache)
    blobs = {}
    for entry in _entries(result):
        name = entry.get("result_file")
        require(name not in blobs, "proof entries share a result file")
        raw = _result_path(work_dir, name).read_bytes()
        blobs[name] = dict(bytes=len(raw), sha256=_digest(raw))
    result["results"] = blobs
    return result


def _candidate_census(cache, file_index, geometry, entry, edits, kept, pacga_policy="reject"):
    """Account for every non-hint PAuth word, independently of result counts.

    A kept word needs an actual hardened jump-table dispatch in the source.
    Re-decoding only those small dispatch windows prevents an omitted edit
    from being relabeled as table data without structural evidence.
    """
    from route_a_zeta import zeta_userland_pauth as pauth
    from route_a_zeta import zeta_userland_code as code

    data = cache.files[file_index].data
    expected = []
    for region in geometry["regions"]:
        start, size = region["offset"], region["size"]
        require(start % 4 == 0 and size % 4 == 0 and start + size <= len(data), "invalid inventory code region")
        words = np.frombuffer(data, dtype="<u4", offset=start, count=size // 4)
        expected.extend(int(start + 4 * index) for index in pauth.candidate_indices(words, pacga_policy=pacga_policy))
    supplied = [int(offset) for offset in edits[:, 1]] + [int(offset) for offset in kept[:, 1]]
    require(len(set(supplied)) == len(supplied), "two proof edits/data claims share a word")
    require(len(set(expected)) == len(expected), "overlapping instruction inventory")
    require(sorted(supplied) == sorted(expected), "proof does not account for every PAuth candidate")
    require(entry.get("kept", {}) == ({"table": len(kept)} if len(kept) else {}), "kept-data counts differ")
    dispatches = entry.get("table_dispatches", [])
    require(isinstance(dispatches, list) and all(type(pc) is int and pc >= 0 for pc in dispatches)
            and len(set(dispatches)) == len(dispatches), "invalid jump-table dispatch list")
    if not len(kept):
        return

    def translate(address, size):
        index, offset, room = cache.locate(address)
        require(index == file_index and size >= 0 and room >= size, "jump table leaves its cache mapping")
        return offset

    ranges = []
    for pc in dispatches:
        region = next((r for r in geometry["regions"] if r["address"] <= pc < r["address"] + r["size"]), None)
        require(region is not None and pc % 4 == 0, "jump-table dispatch is outside image code")
        start = max(region["address"], pc - 128)
        section = dict(addr=start, offset=translate(start, pc + 4 - start), size=pc + 4 - start)
        decoded = code.decode(data, [section])
        table = code.jump_table(decoded, data, translate, pc)
        require(table is not None, "kept data lacks a valid hardened jump-table dispatch")
        ranges.append((table["table"], table["table"] + table["entries"] * 4))
    for address, offset, word in kept:
        address, offset, word = int(address), int(offset), int(word)
        require(offset % 4 == 0 and offset + 4 <= len(data) and word <= 0xffffffff, "invalid kept data word")
        require(any(r["address"] <= address and address + 4 <= r["address"] + r["size"] and
                    offset == r["offset"] + address - r["address"] for r in geometry["regions"]),
                "kept data address differs from instruction inventory")
        require(any(start <= address and address + 4 <= end and (address - start) % 4 == 0 for start, end in ranges),
                "kept PAuth candidate is not in a decoded jump table")
        require(struct.unpack_from("<I", data, offset)[0] == word, "kept data word differs from input")


def validate_summary(cache, summary, work_dir, *, pacga_policy="reject", pacga_kernel=None):
    """Return validated {cache file index: [offset, before, after] uint64 arrays}.

    Any unknown, missing, partial, stale or unlowerable result raises ValueError
    before a transformed output directory is created by the cache rewriter.
    """
    from route_a_zeta import zeta_userland_pauth as pauth

    require(isinstance(summary, dict), "invalid proof summary")
    require(summary.get("schema") == SCHEMA, "unsupported or unbound proof schema")
    require(summary.get("complete") is True, "partial proof cannot authorize a complete cache rewrite")
    manifest = source_manifest(cache)
    require(summary.get("source_manifest") == manifest, "proof input file set/content/UUID differs")
    require(summary.get("source_manifest_sha256") == _digest(_canonical(manifest)),
            "proof source manifest digest differs")
    require(summary.get("rules") == rules_manifest(
                pacga_policy=pacga_policy, pacga_kernel=pacga_kernel),
            "proof lowering/analysis/runtime rules differ")
    inventory = expected_inventory(cache)
    require(summary.get("inventory") == inventory, "proof inventory differs from cache input")
    entries = _entries(summary)
    require(set(summary["images"]) == set(inventory["images"]), "proof does not cover every code-bearing image")
    by_address = {entry.get("address"): entry for entry in summary["islands"]}
    require(len(by_address) == len(summary["islands"]), "duplicate island proof")
    require(set(by_address) == {entry["address"] for entry in inventory["islands"]},
            "proof does not cover every stub island")
    bound = [(summary["images"][path], geometry) for path, geometry in inventory["images"].items()]
    bound += [(by_address[item["address"]], item) for item in inventory["islands"]]
    result_names = [entry.get("result_file") for entry in entries]
    require(all(isinstance(name, str) for name in result_names) and len(set(result_names)) == len(result_names),
            "invalid or duplicate proof result names")
    require(isinstance(summary.get("results"), dict) and set(summary["results"]) == set(result_names),
            "proof result digest set differs")
    totals = summary.get("totals", {})
    require(isinstance(totals, dict), "invalid proof totals")
    require(totals.get("unproven", 0) == 0 and totals.get("unlowerable", 0) == 0,
            "proof contains unproven or unlowerable instructions")
    by_file, edit_count, grades = {}, 0, Counter()
    for entry, geometry in bound:
        file_index = _integer(entry.get("file"), "cache file index")
        require(file_index == geometry["file"] and file_index < len(cache.files), "wrong proof file owner")
        require(entry.get("unlowerable") == [] and entry.get("unproven_count") == 0,
                "entry contains unproven or unlowerable instructions")
        name = entry["result_file"]
        raw = _result_path(work_dir, name).read_bytes()
        require(summary["results"][name] == dict(bytes=len(raw), sha256=_digest(raw)),
                f"proof result digest differs: {name}")
        try:
            with np.load(io.BytesIO(raw), allow_pickle=False) as archive:
                table = archive["edits"]
                unproven = archive["unproven"]
                kept = archive["kept_data"]
        except (OSError, KeyError, TypeError, ValueError) as error:
            raise ValueError(f"invalid proof result {name}: {error}") from error
        require(table.dtype == np.dtype("uint64") and table.ndim == 2 and table.shape[1] == 5,
                "invalid edit array layout")
        require(unproven.dtype == np.dtype("uint64") and unproven.shape == (0, 2),
                "proof array contains unproven words")
        require(kept.dtype == np.dtype("uint64") and kept.ndim == 2 and kept.shape[1] == 3,
                "invalid kept-data array layout")
        require(_integer(entry.get("edit_count"), "edit count") == len(table), "proof edit count differs")
        _candidate_census(cache, file_index, geometry, entry, table, kept, pacga_policy)
        edit_count += len(table)
        if not len(table):
            require(entry.get("edits_by_evidence", {}) == {}, "empty proof has evidence counts")
            continue
        addresses, offsets, originals, replacements, evidence = table.T
        require(bool((offsets % 4 == 0).all()) and bool((evidence < len(GRADES)).all()),
                "unaligned edit or invalid evidence grade")
        require(bool((originals <= 0xffffffff).all()) and bool((replacements <= 0xffffffff).all()),
                "instruction does not fit 32 bits")
        data = cache.files[file_index].data
        signature_offset = cache.files[file_index].signature[0]
        require(signature_offset >= 4 and bool((offsets <= min(len(data), signature_offset) - 4).all()),
                "edit lies outside code or inside signature")
        inside = np.zeros(len(table), dtype=bool)
        for region in geometry["regions"]:
            start, length, address = region["offset"], region["size"], region["address"]
            if length < 4:
                continue
            in_range = (offsets >= start) & (offsets <= start + length - 4)
            inside |= in_range & (addresses == np.uint64(address) + offsets - np.uint64(start))
        require(bool(inside.all()), "edit is outside its image/island instruction regions")
        words = np.frombuffer(data, dtype="<u4", count=len(data) // 4)
        require(bool((words[(offsets // 4).astype(np.int64)] == originals).all()),
                "original instruction differs from proof")
        unique, inverse = np.unique(originals, return_inverse=True)
        computed = []
        for word in unique:
            lowered = pauth.lower(int(word), pacga_policy=pacga_policy)
            require(lowered is not None, f"edit has no admitted lowering: {int(word):#x}")
            computed.append(lowered[1])
        require(bool((np.array(computed, dtype=np.uint64)[inverse] == replacements).all()),
                "replacement differs from current lowering rule")
        counts = Counter(GRADES[int(grade)] for grade in evidence)
        require(entry.get("edits_by_evidence") == dict(counts), "entry evidence counts differ")
        grades.update(counts)
        by_file.setdefault(file_index, []).append(table[:, 1:4])
    require(_integer(totals.get("edits"), "total edit count") == edit_count, "proof total edit count differs")
    require({key: value for key, value in totals.items() if key.startswith("edits:")} ==
            {"edits:" + key: value for key, value in grades.items()}, "proof total evidence counts differ")
    result = {}
    for index, parts in by_file.items():
        table = np.concatenate(parts)
        require(len(np.unique(table[:, 0])) == len(table), "two proof edits share a word")
        result[index] = table
    from arm64_lowering.closure_receipts import validate_closure_receipts
    validate_closure_receipts(cache, summary, work_dir)
    return result
