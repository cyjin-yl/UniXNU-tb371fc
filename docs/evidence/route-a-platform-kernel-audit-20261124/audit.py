#!/usr/bin/env python3
"""Audit one identity-bound platform-link candidate with the retained limited rules.

No lowering, binary editing, reachability proof, complete ISA or boot claim.
Run using the existing Capstone 5.0.6 environment: python -I audit.py ...
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from contextlib import redirect_stdout, redirect_stderr
import bisect
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import time
import traceback

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
CLASSIFIERS = {
    "macho": "50539d0e8c9aac8c324adcd1cbb55ceae7049ac1dcaa41864120607bf78124cb",
    "ptrauth": "593d7981bb3bc85033748aaae8bae014ad65d1efe23f9dd39e1d225635953a2d",
    "poe2": "0aa872f2a8c95456723c5e49b22847dd9132a11a68c2ba0a18bbc250cc613915",
}
BASELINE_SHA256 = "a58cdeedb9b7a4c152867c3487f28658a3799b0158f5046bbad6d2d58e741469"
LIMITATIONS = [
    "Only the retained original Armv8.3 PAuth families and exact POE2 TCHANGEF/TCHANGEB forms are classified.",
    "Instruction-section candidate ranges are not proof that their bytes are executed instructions.",
    "LC_DATA_IN_CODE byte ranges and every partially overlapping AArch64 word are excluded.",
    "Unmarked literal pools may remain in candidate ranges; matched words require interpretation, not automatic rewriting.",
    "A Capstone decode or nearby section symbol is not a reachability or function-boundary proof.",
    "Unmatched words are outside these rules, not evidence of Cortex-A77 compatibility.",
    "No system-register, full instruction-feature, loader, device, sleep/resume or OS-boot qualification is supplied.",
    "Before/after reads refer to the same single candidate, not two independently built artifacts.",
]


class AuditError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise AuditError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def identity(path):
    path = Path(path)
    require(path.is_absolute() and path.is_file(), f"missing absolute input: {path}")
    return {"path": str(path), "realpath": str(path.resolve(strict=True)),
            "symlink_target": os.readlink(path) if path.is_symlink() else None,
            "size": path.stat().st_size, "sha256": sha(path)}


def save(path, value, exclusive=True):
    with path.open("x" if exclusive else "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, ensure_ascii=True)
        stream.write("\n")


def recheck(records):
    changes = []
    for before in records:
        try:
            after = identity(Path(before["path"]))
            if before != after:
                changes.append({"before": before, "after": after})
        except (AuditError, OSError) as exc:
            changes.append({"before": before, "error": str(exc)})
    return {"unchanged": bool(records) and not changes, "checked_file_count": len(records), "changes": changes}


def load_classifiers():
    manifest_path = ROOT / "source-manifest.json"
    manifest_id = identity(manifest_path)
    manifest = json.loads(manifest_path.read_text())
    files = manifest.get("files", {})
    expected = {"audit.py", *(f"classifiers/{name}.py" for name in CLASSIFIERS)}
    require(manifest.get("schema_version") == 1 and set(files) == expected, "unexpected audit source manifest")
    inputs, modules = [manifest_id], {}
    for name, record in files.items():
        current = identity(ROOT / name)
        require(current["sha256"] == record.get("sha256") and current["size"] == record.get("size"),
                f"audit source identity changed: {name}")
        inputs.append(current)
    for name, expected_hash in CLASSIFIERS.items():
        path = ROOT / "classifiers" / (name + ".py")
        require(files["classifiers/" + name + ".py"]["sha256"] == expected_hash,
                f"classifier differs from the retained fixed rules: {name}")
        spec = importlib.util.spec_from_file_location("platform_audit_" + name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        modules[name] = module
    return manifest, modules, inputs


def validate_link_report(path, expected_sha, candidate, expected_candidate_sha, expected_bytes):
    record = identity(path)
    require(record["sha256"] == expected_sha, "platform link report digest mismatch")
    report = json.loads(path.read_text())
    require(report.get("status") == "platform_link_compatible" and report.get("platform_link_compatible") is True and
            report.get("scope") == "isolated-platform-link-compatibility" and report.get("baseline_reproduced") is True,
            "platform link report is not a successful isolated compatibility result")
    require(report.get("baseline", {}).get("sha256") == BASELINE_SHA256, "platform link did not reproduce the fixed baseline")
    checked = report.get("protected_inputs_recheck", {})
    require(checked.get("unchanged") is True and checked.get("checked_file_count", 0) > 0 and checked.get("changes") == [],
            "platform link report does not retain an unchanged-input receipt")
    output = report.get("candidate", {})
    require(output.get("path") == str(candidate) and output.get("sha256") == expected_candidate_sha and
            output.get("size") == expected_bytes, "platform report candidate path/SHA/size binding differs")
    return record, {"status": report["status"], "candidate": {key: output[key] for key in ("path", "sha256", "size")},
                    "baseline_sha256": BASELINE_SHA256, "kernel_callback_linked": report.get("kernel_callback_linked"),
                    "protected_inputs_recheck": checked}


def data_exclusion(image, instruction_flag):
    # The retained parser exports (offset, LENGTH), after merging overlaps.
    # These lengths differ from the whole words omitted from candidate ranges.
    ranges = [{"file_offset": offset, "length": length} for offset, length in image.excluded_data_ranges]
    exact = sum(item["length"] for item in ranges)
    declared = sum(section.size for section in image.sections if section.flags & instruction_flag)
    candidates = sum(region.size for region in image.candidate_ranges)
    omitted = declared - candidates
    require(exact >= 0 and omitted >= exact and candidates > 0, "invalid or empty instruction candidate accounting")
    return {"data_in_code_entry_count": len(image.data_in_code),
            "data_in_code_declared_bytes_before_overlap_merge": sum(length for _, length, _ in image.data_in_code),
            "excluded_data_ranges_representation": "file offset and byte length; merged, not start/end",
            "excluded_data_ranges": ranges, "excluded_data_bytes": exact,
            "instruction_section_bytes": declared, "candidate_bytes": candidates,
            "excluded_candidate_word_bytes": omitted, "alignment_expansion_bytes": omitted - exact,
            "accounting_correction": "sum(length) replaces the old audit's sum(length - offset); old evidence was not edited"}


def defined_symbols(data, image):
    symbols, at = defaultdict(list), 32
    for _ in range(image.ncmds):
        command, size = struct.unpack_from("<II", data, at)
        if command == 2:
            symoff, count, stroff, strsize = struct.unpack_from("<4I", data, at + 8)
            strings = data[stroff:stroff + strsize]
            for index in range(count):
                string, kind, section, desc, address = struct.unpack_from("<IBBHQ", data, symoff + 16 * index)
                if kind & 0xE0 or (kind & 0xE) != 0xE or not 0 < section <= len(image.sections):
                    continue
                require(string < strsize, "defined symbol string index is invalid")
                end = strings.find(b"\0", string)
                require(end >= 0, "defined symbol name is unterminated")
                sec = image.sections[section - 1]
                if sec.addr <= address < sec.addr + sec.size:
                    symbols[section].append((address, strings[string:end].decode("utf-8", "backslashreplace")))
        at += size
    for values in symbols.values():
        values.sort()
    return symbols


def scan(data, image, classifiers, decoder, findings_path):
    categories = ("compatible_pauth_hint", "nonhint_pauth", "poe2_tchange")
    counts, samples = {key: Counter() for key in categories}, {key: [] for key in categories}
    symbols = defined_symbols(data, image)
    symbol_values = {section: [entry[0] for entry in values] for section, values in symbols.items()}
    scanned = 0
    with findings_path.open("x", encoding="utf-8") as output:
        for region in image.candidate_ranges:
            require(region.offset % 4 == region.size % 4 == 0, "unaligned candidate range")
            sections = [(index + 1, sec) for index, sec in enumerate(image.sections)
                        if sec.segment == region.segment and sec.name == region.section and
                        sec.offset <= region.offset and region.end <= sec.offset + sec.size]
            require(len(sections) == 1, "candidate range is not uniquely contained in its declared section")
            section = sections[0][0]
            for offset in range(region.offset, region.end, 4):
                scanned += 1
                word = struct.unpack_from("<I", data, offset)[0]
                info, poe2 = classifiers["ptrauth"].describe(word), classifiers["poe2"].poe2_instruction(word)
                require(not (info is not None and poe2 is not None), "scoped classifiers overlap")
                if info is None and poe2 is None:
                    continue
                if info is not None:
                    category = "compatible_pauth_hint" if info["family"] == "hint" else "nonhint_pauth"
                    mnemonic, family = info["mnemonic"], info["family"]
                else:
                    category, mnemonic, family = "poe2_tchange", poe2[0], "permission_overlay_transition"
                address = region.vmaddr + offset - region.offset
                decoded = list(decoder.disasm_lite(data[offset:offset + 4], address))
                entry = {"category": category, "mnemonic": mnemonic, "family": family,
                         "word": f"0x{word:08x}", "address": hex(address), "file_offset": hex(offset),
                         "segment": region.segment, "section": region.section,
                         "pure_instruction_section": region.pure_instructions, "reachable_instruction_proven": False,
                         "capstone": None if not decoded else {"mnemonic": decoded[0][2], "operands": decoded[0][3]}}
                if section in symbols:
                    index = bisect.bisect_right(symbol_values[section], address) - 1
                    if index >= 0:
                        location, name = symbols[section][index]
                        entry["nearest_defined_section_symbol"] = {"name": name, "address": hex(location),
                            "distance": address - location, "is_function_or_reachability_proof": False}
                counts[category][mnemonic] += 1
                if len(samples[category]) < 12:
                    samples[category].append(entry)
                output.write(json.dumps(entry, sort_keys=True, ensure_ascii=True) + "\n")
    totals = {category: sum(values.values()) for category, values in counts.items()}
    return {"scanned_candidate_words": scanned, "counts": {key: dict(values) for key, values in counts.items()},
            "totals": totals, "samples": samples, "not_matched_by_scoped_rules": scanned - sum(totals.values()),
            "encoding_findings": identity(findings_path)}


def execute(argv, label, output, report):
    item = {"argv": [str(arg) for arg in argv], "cwd": str(output), "status": "running"}
    report["commands"].append(item)
    try:
        result = subprocess.run(item["argv"], cwd=output, env={"PATH": os.defpath, "LC_ALL": "C", "TMPDIR": str(output / "tmp")},
                                capture_output=True, timeout=60)
        item.update(status="completed", exit_code=result.returncode)
        stdout, stderr = result.stdout, result.stderr
    except subprocess.TimeoutExpired as exc:
        stdout, stderr = exc.stdout or b"", exc.stderr or b""
        item.update(status="timed_out", exit_code=None)
    for name, value in (("stdout", stdout), ("stderr", stderr)):
        path = output / (label + "." + name)
        with path.open("xb") as stream:
            stream.write(value)
        item[name] = identity(path)
    require(item.get("exit_code") == 0, f"{label} failed; raw output retained")
    return stdout


def run(args):
    candidate, link_report = args.candidate.absolute(), args.link_report.absolute()
    require(not candidate.is_symlink() and not link_report.is_symlink(), "candidate/report leaf aliases are not accepted")
    require(candidate.is_file() and link_report.is_file(), "candidate or link report is missing")
    require(re.fullmatch(r"[0-9a-f]{64}", args.expected_sha256) and args.expected_bytes > 0 and
            re.fullmatch(r"[0-9a-f]{64}", args.expected_link_report_sha256), "invalid pinned SHA/size")
    output = args.report_dir
    require(not output.exists() and not output.is_symlink(), "report directory must be new; retain earlier attempts")
    output = output.resolve()
    for protected in (candidate.parent.resolve(), link_report.parent.resolve(), ROOT):
        require(not output.is_relative_to(protected) and not protected.is_relative_to(output), "report directory overlaps protected inputs")
    output.mkdir(parents=True)
    (output / "tmp").mkdir()
    state = {"status": "running", "pid": os.getpid(), "started": time.time()}
    save(output / "state.json", state)
    report = {"schema_version": 2, "status": "running", "scope": "retained PAuth and exact POE2 encoding census of one platform-link candidate",
              "audited_binary_artifact_count": 1, "candidate_path": str(candidate),
              "expected_candidate_sha256": args.expected_sha256, "expected_candidate_bytes": args.expected_bytes,
              "commands": [], "limited_checks_passed": False, "whole_instruction_set_verified": False,
              "candidate_ranges_are_code_proof": False, "complete_board_qualification": False,
              "os_boot_verified": False, "sleep_resume_verified": False, "reachability_proven": False,
              "rewritten": False, "limitations": LIMITATIONS}
    protected, exit_code = [], 1
    with (output / "audit.log").open("x", encoding="utf-8") as log, redirect_stdout(log), redirect_stderr(log):
        try:
            manifest, classifiers, sources = load_classifiers()
            protected.extend(sources)
            report["source_manifest"] = sources[0]
            report["classifier_source_commit"] = manifest["classifier_source_commit"]
            link_id, binding = validate_link_report(link_report, args.expected_link_report_sha256,
                                                    candidate, args.expected_sha256, args.expected_bytes)
            protected.append(link_id)
            report["platform_link_report"], report["platform_link_binding"] = link_id, binding
            before = identity(candidate)
            protected.append(before)
            report["candidate_identity_before"] = before
            require(before["sha256"] == args.expected_sha256 and before["size"] == args.expected_bytes, "candidate identity mismatch")
            data = candidate.read_bytes()
            require(len(data) == args.expected_bytes and digest(data) == args.expected_sha256, "candidate changed while being read")
            header = list(struct.unpack_from("<8I", data))
            report["macho_header_words"] = header
            require(header[:4] == [0xFEEDFACF, 0x0100000C, 0, 2], "candidate is not an ordinary ARM64 MH_EXECUTE")
            report["ordinary_arm64_mh_execute"] = True
            image = classifiers["macho"].parse_macho(data)
            save(output / "geometry.json", image.to_dict())
            report["geometry"] = identity(output / "geometry.json")
            report["parser_blockers"], report["parser_warnings"] = image.blockers, image.warnings
            require(image.can_scan_candidates, "Mach-O geometry has scan blockers")
            report.update(data_exclusion(image, classifiers["macho"].INSTRUCTIONS))
            report["candidate_range_count"] = len(image.candidate_ranges)
            report["executable_sections"] = [{"segment": seg.name, "name": sec.name, "address": hex(sec.addr),
                "file_offset": hex(sec.offset), "size": sec.size, "flags": hex(sec.flags),
                "declared_instructions": bool(sec.flags & classifiers["macho"].INSTRUCTIONS)}
                for seg in image.segments if seg.initprot & 4 for sec in seg.sections]
            import capstone
            require(capstone.__version__ == "5.0.6", "use the recorded Capstone 5.0.6 environment")
            decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
            tools = {"python": identity(Path(sys.executable).absolute()),
                     "capstone_module": identity(Path(capstone.__file__).absolute()),
                     "capstone_native_library": identity(Path(capstone._cs._name).absolute()),
                     "llvm-nm": identity(args.nm.absolute()), "llvm-objdump": identity(args.objdump.absolute())}
            protected.extend(tools.values())
            report["tools"] = tools
            report["python_execution"] = {"version": sys.version, "isolated": sys.flags.isolated, "optimize": sys.flags.optimize}
            report["capstone_version"] = {"python": capstone.__version__, "core": list(capstone.cs_version())}
            for name in ("llvm-nm", "llvm-objdump"):
                execute([tools[name]["path"], "--version"], name + ".version", output, report)
            execute([args.objdump, "--macho", "--private-headers", candidate], "macho-private-headers", output, report)
            undefined = execute([args.nm, "--undefined-only", "--format=posix", candidate], "undefined-symbols", output, report)
            lines = [line for line in undefined.decode("utf-8", "backslashreplace").splitlines() if line.strip()]
            report["undefined_symbols"] = {"count": len(lines), "first_50": lines[:50], "truncated": len(lines) > 50,
                                            "raw_output": identity(output / "undefined-symbols.stdout")}
            state["stage"] = "scanning_candidate_ranges"
            save(output / "state.json", state, exclusive=False)
            report.update(scan(data, image, classifiers, decoder, output / "encoding-findings.jsonl"))
            require(report["scanned_candidate_words"] * 4 == report["candidate_bytes"], "candidate scan was incomplete")
            report["limited_checks_passed"] = not lines and not report["totals"]["nonhint_pauth"] and not report["totals"]["poe2_tchange"]
            report["status"] = "completed" if report["limited_checks_passed"] else "completed_with_findings"
            exit_code = 0 if report["limited_checks_passed"] else 2
        except BaseException as exc:
            report.update(status="failed", error_type=type(exc).__name__, error=str(exc), limited_checks_passed=False)
            traceback.print_exc()
        finally:
            checked = recheck(protected)
            report["protected_inputs_recheck"] = checked
            try:
                after = identity(candidate)
                report["candidate_identity_after"] = after
                report["candidate_unchanged"] = after == report.get("candidate_identity_before")
            except (AuditError, OSError) as exc:
                report.update(candidate_unchanged=False, final_identity_error=str(exc))
            if not checked["unchanged"] or not report["candidate_unchanged"]:
                report.update(status="failed", limited_checks_passed=False)
                exit_code = 1
            print(json.dumps({"status": report["status"], "totals": report.get("totals"),
                              "candidate_unchanged": report["candidate_unchanged"]}, ensure_ascii=True))
    report["log"], report["finished"] = identity(output / "audit.log"), time.time()
    save(output / "audit.json", report)
    state.update(status=report["status"], finished=report["finished"], exit_code=exit_code, audit=identity(output / "audit.json"))
    save(output / "state.json", state, exclusive=False)
    return state


def main(argv=None):
    try:
        require(sys.flags.isolated == 1 and sys.flags.optimize == 0, "run with python -I and without -O/-OO")
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--candidate", type=Path, required=True)
        parser.add_argument("--expected-sha256", required=True)
        parser.add_argument("--expected-bytes", type=int, required=True)
        parser.add_argument("--link-report", type=Path, required=True)
        parser.add_argument("--expected-link-report-sha256", required=True)
        parser.add_argument("--report-dir", type=Path, required=True)
        parser.add_argument("--nm", type=Path, default=Path("/usr/bin/llvm-nm-19"))
        parser.add_argument("--objdump", type=Path, default=Path("/usr/bin/llvm-objdump-19"))
        state = run(parser.parse_args(argv))
        print(json.dumps(state, ensure_ascii=True))
        return state["exit_code"]
    except (AuditError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
