#!/usr/bin/env python3
"""Independent GNU assembler encoding oracle; imports no lowering implementation.

python3 verify_fixture.py --fixture route_a_instruction_vectors.json --out results

The fixture is synthetic. This checks its original encodings and independently
written replacement assembly. It does not prove the plain-pointer ABI contract,
authentication equivalence, rejection policy, or a complete ISA's compatibility.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import struct
import subprocess


HINT_NUMBERS = {
    "pacia1716": 8, "pacib1716": 10, "autia1716": 12, "autib1716": 14,
    "paciaz": 24, "paciasp": 25, "pacibz": 26, "pacibsp": 27,
    "autiaz": 28, "autiasp": 29, "autibz": 30, "autibsp": 31,
    "xpaclri": 7,
}
NOP_MNEMONICS = {
    "pacia", "pacib", "pacda", "pacdb", "autia", "autib", "autda", "autdb",
    "paciza", "pacizb", "pacdza", "pacdzb", "autiza", "autizb", "autdza", "autdzb",
    "xpaci", "xpacd",
}


def replacement_assembly(assembly):
    mnemonic, *tail = assembly.split(None, 1)
    if mnemonic in HINT_NUMBERS:
        return "hint #" + str(HINT_NUMBERS[mnemonic])
    if mnemonic in NOP_MNEMONICS:
        return "nop"
    if mnemonic in {"braa", "brab", "braaz", "brabz"}:
        return "br " + tail[0].split(",", 1)[0].strip()
    if mnemonic in {"blraa", "blrab", "blraaz", "blrabz"}:
        return "blr " + tail[0].split(",", 1)[0].strip()
    if mnemonic in {"retaa", "retab"}:
        return "ret"
    if mnemonic in {"ldraa", "ldrab"}:
        # All non-rejected loads in this fixed fixture are zero/positive and
        # non-writeback. Runtime probes and decoder tests cover other offsets.
        return "ldr " + tail[0]
    raise ValueError("No independent replacement assembly for: " + assembly)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def assemble(output, name, instructions, architecture):
    source = output / (name + ".s")
    obj = output / (name + ".o")
    binary = output / (name + ".bin")
    source.write_text(".text\n" + "\n".join(instructions) + "\n")
    commands = [
        ["aarch64-linux-gnu-as", "-march=" + architecture, "-o", str(obj), str(source)],
        ["aarch64-linux-gnu-objcopy", "-O", "binary", "--only-section=.text", str(obj), str(binary)],
    ]
    for command in commands:
        subprocess.run(command, check=True, capture_output=True, text=True, timeout=10)
    data = binary.read_bytes()
    if len(data) != len(instructions) * 4:
        raise ValueError("Unexpected .text size for " + name)
    return [f"{word:08x}" for (word,) in struct.iter_unpack("<I", data)], {
        "assembly_sha256": sha256(source.read_bytes()),
        "binary_sha256": sha256(data),
        "instruction_count": len(instructions),
        "architecture": architecture,
        "commands": commands,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    fixture_bytes = args.fixture.read_bytes()
    fixture = json.loads(fixture_bytes)
    vectors = fixture["vectors"]
    if len(vectors) != 54:
        raise ValueError("This review expects the fixed 54-vector fixture")
    args.out.mkdir(parents=True, exist_ok=True)
    original_words, original_artifacts = assemble(
        args.out, "original", [v["assembly"] for v in vectors], "armv8.3-a")
    replacements = [(index, replacement_assembly(v["assembly"]))
                    for index, v in enumerate(vectors) if "replacement" in v]
    replacement_words, replacement_artifacts = assemble(
        args.out, "replacement", [asm for _, asm in replacements], "armv8-a")
    replacement_results = {index: (asm, word)
                           for (index, asm), word in zip(replacements, replacement_words)}
    rows = []
    for index, (vector, actual_word) in enumerate(zip(vectors, original_words)):
        row = {
            "index": index,
            "assembly": vector["assembly"],
            "expected_word": vector["word"],
            "assembled_word": actual_word,
            "input_matches": vector["word"] == actual_word,
            "checks": ["input_encoding"],
        }
        if "replacement" in vector:
            assembly, replacement = replacement_results[index]
            row.update(replacement_assembly=assembly,
                       replacement_expected_word=vector["replacement"],
                       replacement_assembled_word=replacement,
                       replacement_matches=vector["replacement"] == replacement)
            row["checks"].append("replacement_encoding_armv8_a")
        else:
            row.update(rejection_expected=vector["reject"],
                       rejection_policy_checked_by_assembler=False)
        row["status"] = "passed" if row["input_matches"] and row.get("replacement_matches", True) else "failed"
        rows.append(row)
    report = {
        "schema_version": 1,
        "kind": "route-a-independent-assembler-oracle",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "Encoding agreement only; no lowering implementation is imported or executed.",
        "fixture_sha256": sha256(fixture_bytes),
        "fixture_provenance": fixture["provenance"],
        "runner_sha256": None,
        "host": platform.platform(),
        "assembler_version": subprocess.check_output(["aarch64-linux-gnu-as", "--version"], text=True).strip(),
        "objcopy_version": subprocess.check_output(["aarch64-linux-gnu-objcopy", "--version"], text=True).splitlines()[0],
        "original_artifacts": original_artifacts,
        "replacement_artifacts": replacement_artifacts,
        "vectors": rows,
        "input_encoding_passed": sum(row["input_matches"] for row in rows),
        "input_encoding_total": len(rows),
        "replacement_encoding_passed": sum(row.get("replacement_matches", False) for row in rows),
        "replacement_encoding_total": len(replacements),
        "rejected_vectors_input_only": len(rows) - len(replacements),
        "passed": sum(row["status"] == "passed" for row in rows),
        "total": len(rows),
        "status": "passed" if all(row["status"] == "passed" for row in rows) else "failed",
    }
    # -c execution intentionally writes no runner into the remote container.
    # The caller may set this source hash when transferring the exact script.
    report["runner_sha256"] = globals().get("ORACLE_RUNNER_SHA256")
    (args.out / "oracle-result.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
