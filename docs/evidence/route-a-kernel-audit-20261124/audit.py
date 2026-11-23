#!/usr/bin/env python3
"""Read-only scoped encoding audit of one fixed generic XNU candidate."""
from collections import Counter, defaultdict
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
import bisect
import hashlib
import json
import os
import struct
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parent
CANDIDATE = Path("/work/route-a-continue-20261123/kernel-build/build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/mach.development.bcm2837.unstripped")
EXPECTED_SHA = "a58cdeedb9b7a4c152867c3487f28658a3799b0158f5046bbad6d2d58e741469"
EXPECTED_BYTES = 21905888
sys.dont_write_bytecode = True


def sha(path):
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def save(path, value, exclusive=False):
    with path.open("x" if exclusive else "w") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def execute(args, label):
    result = subprocess.run([str(arg) for arg in args], capture_output=True, timeout=60)
    stdout, stderr = ROOT / (label + ".stdout"), ROOT / (label + ".stderr")
    stdout.write_bytes(result.stdout)
    stderr.write_bytes(result.stderr)
    record = {"command": [str(arg) for arg in args], "exit_code": result.returncode,
              "stdout": stdout.name, "stdout_sha256": sha(stdout),
              "stderr": stderr.name, "stderr_sha256": sha(stderr)}
    report["commands"].append(record)
    if result.returncode:
        raise RuntimeError(label + ": " + result.stderr.decode("utf-8", "replace")[-4000:])
    return result.stdout


state = {"status": "running", "pid": os.getpid(), "started": time.time()}
save(ROOT / "state.json", state, exclusive=True)
report = {"schema_version": 1, "status": "running", "scope": "original Armv8.3 PAuth and exact POE2 TCHANGE encodings in declared instruction-section candidate ranges",
          "commands": [], "input_path": str(CANDIDATE),
          "whole_instruction_set_verified": False, "candidate_ranges_are_code_proof": False,
          "complete_board_qualification": False, "os_boot_verified": False,
          "reachability_proven": False, "rewritten": False}
exit_code = 1
with (ROOT / "audit.log").open("x") as log, redirect_stdout(log), redirect_stderr(log):
    try:
        manifest = json.loads((ROOT / "source-manifest.json").read_text())
        for name, meta in manifest["files"].items():
            assert sha(ROOT / name) == meta["sha256"], ("audit source changed", name)
        report["audit_source_manifest_sha256"] = sha(ROOT / "source-manifest.json")
        report["audit_source_commit"] = manifest["source_commit"]
        sys.path.insert(0, str(ROOT / "classifiers"))
        from macho import parse_macho, INSTRUCTIONS
        from ptrauth import describe
        from poe2 import poe2_instruction
        import capstone
        decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        report["tools"] = {"python": {"path": sys.executable, "realpath": str(Path(sys.executable).resolve()), "sha256": sha(Path(sys.executable)), "version": sys.version},
                           "capstone": {"version": capstone.__version__, "core_version": list(capstone.cs_version()),
                                        "module_path": capstone.__file__, "module_sha256": sha(Path(capstone.__file__))}}
        native = Path(capstone._cs._name)
        if native.is_file():
            report["tools"]["capstone"]["native_library"] = {"path": str(native), "sha256": sha(native)}
        nm, objdump = Path("/usr/bin/llvm-nm-19"), Path("/usr/bin/llvm-objdump-19")
        for label, path in (("llvm-nm", nm), ("llvm-objdump", objdump)):
            version = execute([path, "--version"], label + ".version").decode("utf-8", "replace")
            report["tools"][label] = {"path": str(path), "realpath": str(path.resolve()), "sha256": sha(path), "version": version}
        data = CANDIDATE.read_bytes()
        before = hashlib.sha256(data).hexdigest()
        assert before == EXPECTED_SHA and len(data) == EXPECTED_BYTES, "candidate identity mismatch"
        noctf = Path(str(CANDIDATE) + ".noctf")
        noctf_before = sha(noctf)
        assert noctf_before == EXPECTED_SHA and noctf.stat().st_size == EXPECTED_BYTES, "noctf differs"
        report["input_bytes"] = len(data)
        report["input_sha256_before"] = before
        report["noctf_sha256_before"] = noctf_before
        header = list(struct.unpack_from("<8I", data))
        report["macho_header_words"] = header
        report["ordinary_arm64_mh_execute"] = header[:4] == [0xFEEDFACF, 0x0100000C, 0, 2]
        execute([objdump, "--macho", "--private-headers", CANDIDATE], "macho-private-headers")
        undefined = execute([nm, "--undefined-only", "--format=posix", CANDIDATE], "undefined-symbols")
        lines = [line for line in undefined.decode("utf-8", "replace").splitlines() if line.strip()]
        report["undefined_symbols"] = {"count": len(lines), "first_50": lines[:50], "truncated": len(lines) > 50,
                                       "full_output": "undefined-symbols.stdout", "output_sha256": hashlib.sha256(undefined).hexdigest()}
        image = parse_macho(data)
        save(ROOT / "geometry.json", image.to_dict(), exclusive=True)
        report["geometry_sha256"] = sha(ROOT / "geometry.json")
        report["parser_blockers"], report["parser_warnings"] = image.blockers, image.warnings
        assert image.can_scan_candidates, "Mach-O geometry has scan blockers"
        report["executable_sections"] = [
            {"segment": seg.name, "name": sec.name, "address": hex(sec.addr), "file_offset": hex(sec.offset),
             "size": sec.size, "flags": hex(sec.flags), "declared_instructions": bool(sec.flags & INSTRUCTIONS)}
            for seg in image.segments if seg.initprot & 4 for sec in seg.sections]
        report["candidate_range_count"] = len(image.candidate_ranges)
        report["candidate_bytes"] = sum(region.size for region in image.candidate_ranges)
        report["data_in_code_entry_count"] = len(image.data_in_code)
        report["excluded_data_bytes"] = sum(end - start for start, end in image.excluded_data_ranges)
        sections = image.sections
        section_numbers = {(sec.segment, sec.name, sec.offset): index + 1 for index, sec in enumerate(sections)}
        symbols = defaultdict(list)
        at = 32
        load_commands = []
        for _ in range(header[4]):
            command, size = struct.unpack_from("<II", data, at)
            load_commands.append(hex(command))
            if command == 2:
                symoff, nsyms, stroff, strsize = struct.unpack_from("<4I", data, at + 8)
                report["symbol_table_entries"] = nsyms
                strings = data[stroff:stroff + strsize]
                for index in range(nsyms):
                    string, kind, section, desc, address = struct.unpack_from("<IBBHQ", data, symoff + 16 * index)
                    if kind & 0xE0 or kind & 0xE != 0xE or not 0 < section <= len(sections) or string >= len(strings):
                        continue
                    end = strings.find(b"\0", string)
                    if end < 0:
                        continue
                    sec = sections[section - 1]
                    if sec.addr <= address < sec.addr + sec.size:
                        symbols[section].append((address, strings[string:end].decode("utf-8", "replace")))
            at += size
        report["load_commands"] = load_commands
        symbol_values = {}
        for section in symbols:
            symbols[section].sort()
            symbol_values[section] = [entry[0] for entry in symbols[section]]
        counts = {"compatible_pauth_hint": Counter(), "nonhint_pauth": Counter(), "poe2_tchange": Counter()}
        samples = {key: [] for key in counts}
        scanned = 0
        state.update(stage="scanning_candidate_ranges", undefined_symbol_count=len(lines))
        save(ROOT / "state.json", state)
        with (ROOT / "encoding-findings.jsonl").open("x") as output:
            for region in image.candidate_ranges:
                section = next((index + 1 for index, sec in enumerate(sections)
                                if sec.segment == region.segment and sec.name == region.section
                                and sec.offset <= region.offset < sec.offset + sec.size), 0)
                for offset in range(region.offset, region.end, 4):
                    scanned += 1
                    word = struct.unpack_from("<I", data, offset)[0]
                    info = describe(word)
                    poe2 = poe2_instruction(word)
                    if info is None and poe2 is None:
                        continue
                    address = region.vmaddr + offset - region.offset
                    if info is not None:
                        category = "compatible_pauth_hint" if info["family"] == "hint" else "nonhint_pauth"
                        mnemonic, family = info["mnemonic"], info["family"]
                    else:
                        category, mnemonic, family = "poe2_tchange", poe2[0], "permission_overlay_transition"
                    disassembly = list(decoder.disasm_lite(data[offset:offset + 4], address))
                    entry = {"category": category, "mnemonic": mnemonic, "family": family,
                             "word": f"0x{word:08x}", "address": hex(address), "file_offset": hex(offset),
                             "segment": region.segment, "section": region.section,
                             "pure_instruction_section": region.pure_instructions,
                             "capstone": None if not disassembly else {"mnemonic": disassembly[0][2], "operands": disassembly[0][3]},
                             "reachable_instruction_proven": False}
                    if section in symbols:
                        index = bisect.bisect_right(symbol_values[section], address) - 1
                        if index >= 0:
                            symbol_address, name = symbols[section][index]
                            entry["nearest_defined_section_symbol"] = {"name": name, "address": hex(symbol_address), "distance": address - symbol_address,
                                                                      "is_function_or_reachability_proof": False}
                    counts[category][mnemonic] += 1
                    if len(samples[category]) < 12:
                        samples[category].append(entry)
                    output.write(json.dumps(entry, sort_keys=True) + "\n")
        report["scanned_candidate_words"] = scanned
        report["counts"] = {category: dict(counter) for category, counter in counts.items()}
        report["totals"] = {category: sum(counter.values()) for category, counter in counts.items()}
        report["samples"] = samples
        report["encoding_findings_sha256"] = sha(ROOT / "encoding-findings.jsonl")
        report["not_matched_by_scoped_rules"] = scanned - sum(report["totals"].values())
        report["limitations"] = [
            "This is a bounded encoding census, not a full A77 instruction-feature audit.",
            "Only instruction-flagged sections are scanned; LC_DATA_IN_CODE bytes are excluded.",
            "Literal pools without LC_DATA_IN_CODE markings may still be inside candidate ranges.",
            "A word matching a rule, a Capstone decode or a nearby symbol does not prove execution or reachability.",
            "The PAuth classifier covers the original Armv8.3 families, not every later extension.",
            "POE2 coverage is the project's exact TCHANGEF/TCHANGEB forms only.",
            "No patching, loader, board-device, full-archive-closure or boot qualification was performed."
        ]
        report["limited_checks_passed"] = (report["ordinary_arm64_mh_execute"] and not lines
                                           and not report["totals"]["nonhint_pauth"] and not report["totals"]["poe2_tchange"])
        report["status"] = "completed" if report["limited_checks_passed"] else "completed_with_findings"
        exit_code = 0
    except BaseException as exc:
        report.update(status="failed", error_type=type(exc).__name__, error=str(exc))
        traceback.print_exc()
    finally:
        try:
            report["input_sha256_after"] = sha(CANDIDATE)
            report["noctf_sha256_after"] = sha(Path(str(CANDIDATE) + ".noctf"))
            report["candidate_unchanged"] = report.get("input_sha256_before") == report["input_sha256_after"] == EXPECTED_SHA
            report["noctf_unchanged"] = report.get("noctf_sha256_before") == report["noctf_sha256_after"] == EXPECTED_SHA
            if not report["candidate_unchanged"] or not report["noctf_unchanged"]:
                report["status"], exit_code = "failed", 1
        except BaseException as exc:
            report.update(status="failed", final_identity_error=str(exc))
            exit_code = 1
    print(json.dumps({"status": report["status"], "totals": report.get("totals"), "undefined_symbols": report.get("undefined_symbols"),
                      "candidate_unchanged": report.get("candidate_unchanged")}), flush=True)
report["log_sha256"] = sha(ROOT / "audit.log")
report["finished"] = time.time()
save(ROOT / "audit.json", report, exclusive=True)
state.update(status=report["status"], finished=report["finished"], exit_code=exit_code, audit_sha256=sha(ROOT / "audit.json"))
save(ROOT / "state.json", state)
print(json.dumps(state))
raise SystemExit(exit_code)
