"""Replay the persisted closure transcript without executing the CFG solver.

This is a provenance/consistency check, not an authentication mechanism or a
second independent proof of the CFG. All evidence still needs a trusted,
immutable producer and input snapshot.
"""
from collections import defaultdict
from hashlib import sha256, file_digest
from pathlib import Path
import bisect
import json

import numpy as np

from arm64_lowering.proof import require, _canonical, _digest, _result_path


def receipt_set_digest(work):
    work = Path(work)
    paths = sorted((*work.glob("*.started.json"), *work.glob("*.done.json")))
    hashes = {}
    for path in paths:
        require(path.is_file() and not path.is_symlink(), "invalid closure receipt path")
        hashes[path.name] = _digest(path.read_bytes())
    return _digest(_canonical(hashes)), set(hashes)


def validate_closure_receipts(cache, summary, work):
    work = Path(work)
    c = summary.get("closure")
    require(isinstance(c, dict) and c.get("converged") is True and c.get("partial") is False,
            "missing complete closure transcript")
    require(type(c.get("round_count")) is int and 0 <= c["round_count"] <= 128,
            "invalid closure round count")
    digest, actual_files = receipt_set_digest(work)
    require(c.get("receipt_set_sha256") == digest, "closure receipt set digest differs")
    input_sha = summary["source_manifest_sha256"]
    rules_sha = _digest(_canonical(summary["rules"]))
    for name, expected in (("initial-input.json", summary["source_manifest"]),
                           ("initial-rules.json", summary["rules"])):
        p = work / name
        require(p.is_file() and not p.is_symlink(), "missing initial closure identity")
        require(json.loads(p.read_bytes()) == expected, "initial closure identity differs")
    require(not (work / "partial.json").exists(), "partial closure receipt present")
    consumed = set()

    def read(name):
        p = work / name
        require(name in actual_files and name not in consumed, "missing or repeated closure receipt")
        consumed.add(name)
        record = json.loads(p.read_bytes())
        require(isinstance(record, dict), "invalid closure receipt")
        return record

    # Match the driver's inventory order, including non-code image acknowledgments.
    inv = summary["inventory"]
    owners = {}
    ranges = []
    for i, (addr, path) in enumerate(cache.images):
        geom = inv["images"].get(path)
        owners[i] = (addr, path, False, geom, summary["images"].get(path))
    # Driver enumerates islands in file/slid order, not sorted address order.
    islands = {v["address"]: v for v in inv["islands"]}
    final_islands = {v["address"]: v for v in summary["islands"]}
    i = len(owners)
    for item in cache.files:
        for addr, size, _, _, _, flags, _, _ in item.slid:
            if flags & 8:
                owners[i] = (addr, f"island-{addr:x}", True, islands[hex(addr)],
                             final_islands[hex(addr)])
                i += 1
    for i, (_, _, _, geom, _) in owners.items():
        if geom:
            ranges.extend((r["address"], r["address"] + r["size"], i) for r in geom["regions"])
    ranges.sort()
    for n, (a, b, _) in enumerate(ranges):
        require(a < b and a % 4 == b % 4 == 0 and
                (n == 0 or ranges[n-1][1] <= a), "invalid closure executable ownership")
    starts = [a for a, _, _ in ranges]

    def job(i, roots):
        addr, path, island, geom, _ = owners[i]
        rd = _digest(_canonical(sorted(roots))) if roots else None
        stem = path if island else sha256(path.encode()).hexdigest()[:16]
        stem += ".calls-" + rd if roots else ".own"
        start = read(stem + ".started.json")
        expected = dict(index=i, path=path, address=addr, phase="calls" if roots else "own",
                        input_sha256=input_sha, rules_sha256=rules_sha, called_roots_sha256=rd)
        require(all(start.get(k) == v for k, v in expected.items()), "closure job identity differs")
        require(type(start.get("pid")) is int and start["pid"] > 0 and
                type(start.get("start_ns")) is int and start["start_ns"] > 0 and
                set(start) == set(expected) | {"pid", "start_ns"}, "invalid closure job start")
        done = read(stem + ".done.json")
        require(set(done) == set(start) | {"result", "artifact"} and
                all(done[k] == v for k, v in start.items()), "closure job completion differs")
        result, artifact = done["result"], done["artifact"]
        if not geom:
            require(result is None and artifact is None, "non-code owner has closure artifact")
            return None, set()
        require(isinstance(result, dict) and isinstance(artifact, dict), "missing closure job artifact")
        name = stem + ".npz"
        require(result.get("result_file") == name and
                result.get("reproven_with_calls") is bool(roots), "closure job result identity differs")
        p = _result_path(work, name)
        with p.open("rb") as f:
            actual = dict(name=name, bytes=p.stat().st_size, sha256=file_digest(f, "sha256").hexdigest())
        require(artifact == actual, "closure job artifact digest differs")
        try:
            with np.load(p, allow_pickle=False) as data:
                reached = data["reached"]
        except (OSError, KeyError, TypeError, ValueError) as e:
            raise ValueError("invalid closure edge artifact") from e
        require(reached.dtype == np.dtype("uint64") and reached.ndim == 1,
                "invalid closure edge array")
        values = reached.tolist()
        require(values == sorted(set(values)), "duplicate or unordered closure edges")
        return result, set(values)

    results, edges, roots = {}, {}, defaultdict(set)
    for i in owners:
        r, e = job(i, ())
        if r is not None:
            results[i], edges[i] = r, e
    frontier = set().union(*edges.values()) if edges else set()
    rounds = []
    while frontier:
        changed = set()
        for target in frontier:
            n = bisect.bisect_right(starts, target) - 1
            require(target % 4 == 0 and n >= 0 and target < ranges[n][1],
                    "closure edge outside executable ownership")
            i = ranges[n][2]
            require(i in results, "closure edge targets missing owner")
            if target not in roots[i]:
                roots[i].add(target)
                changed.add(i)
        if not changed:
            break
        require(len(rounds) < c["round_count"], "closure transcript ends before fixed point")
        label = f"closure-{len(rounds)+1:03d}"
        expected = dict(round=label, input_sha256=input_sha, rules_sha256=rules_sha,
                        jobs=[dict(index=i, roots_sha256=_digest(_canonical(sorted(roots[i]))),
                                   roots_count=len(roots[i])) for i in sorted(changed)])
        require(read(label + ".started.json") == expected, "closure round roots differ")
        frontier = set()
        names = {}
        for i in sorted(changed):
            r, e = job(i, roots[i])
            require(r is not None and edges[i] <= e, "closure accepted edges retracted")
            frontier.update(e - edges[i])
            results[i], edges[i] = r, e
            names[str(i)] = r["result_file"]
        expected["results"] = names
        require(read(label + ".done.json") == expected, "closure round result set differs")
        rounds.append(expected)
    require(len(rounds) == c["round_count"] and c.get("rounds_sha256") == _digest(_canonical(rounds)),
            "closure round transcript differs")
    require(c.get("final_roots_sha256") == _digest(_canonical({str(i): sorted(r) for i,r in roots.items()})),
            "closure final roots differ")
    for i, result in results.items():
        addr, _, island, geom, final = owners[i]
        if island:
            result = dict(result, address=hex(addr), size=geom["size"])
        require(result == final, "closure final result differs")
    require(consumed == actual_files, "unexpected closure receipts")
