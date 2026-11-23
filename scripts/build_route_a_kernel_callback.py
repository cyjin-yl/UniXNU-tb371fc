#!/usr/bin/env python3
"""Compile the source-bound XNU CPU sleep callback in a new external directory.

Only the three upstream cpu.c hunks are selected. This command preserves the
actual C compilation ABI and warnings; it never replaces an existing object,
links a kernel, enables platform-sleep, or qualifies sleep/wakeup behavior.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_route_a_platform as platform

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/route-a-kernel-callback.json"
HOOK = "_arm64_platform_sleep_hook"
SLEEP = "_ml_arm_sleep"
RESUME = "_arm_init_cpu"
SOURCE_RELATIVE = ".cache/xnu-work/osfmk/arm64/cpu.c"
SELECTED_HUNKS = ["cpu.c:hook-definition", "cpu.c:boot-cpu-dispatch-and-resume",
                  "cpu.c:secondary-cpu-dispatch"]
C_FLAGS = (platform.STANDALONE_FLAGS - {"-xc++", "--driver-mode=g++", "-std=gnu++2b",
           "-fsized-deallocation", "-fapple-kext"}) | {"-xc"}
CallbackError = platform.PlatformError
require = platform.require
identity = platform.file_identity
save_json = platform.save_json
sha256_file = platform.sha256_file


def replay_recipe(record: dict, kernel: Path, source: Path, output: Path) -> tuple[list[str], dict]:
    """Replay the reviewed C grammar without changing any warning/ABI option.

    This pure function also lets the independent linker reconstruct every
    expected argument. Relative include directories retain their original
    meaning while the compiler runs in the new output directory.
    """
    argv = record["arguments"]
    require(isinstance(argv, list) and len(argv) > 1 and all(isinstance(v, str) and v for v in argv),
            "invalid C compilation arguments")
    require(all("\0" not in v and not v.startswith("@") for v in argv), "response files are not permitted")
    cwd = Path(record["directory"])
    original = Path(record["file"])
    require(cwd.is_absolute() and cwd.resolve().is_relative_to(kernel.resolve()), "C recipe cwd escapes kernel")
    require(original.is_absolute() and original.resolve() == (kernel / SOURCE_RELATIVE).resolve(),
            "C recipe does not compile the actual arm64 cpu.c")
    require(record.get("output") == "cpu.o" and Path(argv[0]).is_absolute(), "unexpected C recipe compiler/output")
    require(source.is_absolute() and output.is_absolute(), "isolated paths must be absolute")
    obj, dep, mj = output / "cpu.o", output / "dependencies.d", output / "compiler-record.json"
    result, changes = [argv[0], "--no-default-config"], []
    counts = {key: 0 for key in ("source", "output", "language", "compile", "arch", "cpu", "minos", "target")}
    index = 1
    while index < len(argv):
        arg = argv[index]

        def following():
            require(index + 1 < len(argv), f"missing C recipe value after {arg}")
            return argv[index + 1]

        if arg == record["file"]:
            counts["source"] += 1
            result.append(str(source))
        elif arg == "-o":
            require(following() == "cpu.o", "C recipe -o differs from its output field")
            result.extend((arg, str(obj)))
            changes.append({"flag": arg, "original": following(), "replacement": str(obj)})
            counts["output"] += 1
            index += 1
        elif arg.startswith(("-Wp,", "-Wa,", "-Wl,")):
            raise CallbackError(f"unreviewed compiler passthrough: {arg}")
        elif arg.startswith("-W"):
            result.append(arg)  # Preserve spelling, ordering and duplicates.
        elif arg == "-Xclang":
            warning = following()
            require(warning.startswith("-W") and not warning.startswith(("-Wp,", "-Wa,", "-Wl,")),
                    "unreviewed -Xclang option")
            result.extend((arg, warning))
            index += 1
        elif arg in ("-MD", "-MMD", "-MP"):
            changes.append({"flag": arg, "replacement": "explicit isolated -MD/-MF/-MT"})
        elif any(arg.startswith(flag) for flag in ("-MF", "-MJ", "-MT", "-MQ")):
            flag = arg[:3]
            value = following() if arg == flag else arg[3:]
            require(bool(value), f"empty {flag} value")
            replacement = mj if flag == "-MJ" else dep if flag == "-MF" else obj
            changes.append({"flag": flag, "original": value, "replacement": str(replacement)})
            if flag == "-MJ":
                require("-MJ" not in result, "multiple -MJ outputs")
                result.extend((flag, str(mj)))
            index += arg == flag
        elif arg in ("-arch", "-target", "--target"):
            value = following()
            if arg == "-arch":
                require(value == "arm64", "C recipe architecture changed")
                counts["arch"] += 1
            else:
                require(re.fullmatch(r"arm64-apple-ios27\.0(?:\.0)?", value), "C recipe target changed")
                counts["target"] += 1
            result.extend((arg, value))
            index += 1
        elif arg.startswith("--target="):
            require(re.fullmatch(r"--target=arm64-apple-ios27\.0(?:\.0)?", arg), "C recipe target changed")
            counts["target"] += 1
            result.append(arg)
        elif arg.startswith("-mcpu="):
            require(arg == "-mcpu=generic", "C recipe CPU changed")
            counts["cpu"] += 1
            result.append(arg)
        elif arg.startswith("-mios-version-min="):
            require(arg in ("-mios-version-min=27.0", "-mios-version-min=27.0.0"), "C recipe minos changed")
            counts["minos"] += 1
            result.append(arg)
        elif arg == "-mllvm":
            require(following() == "-disable-atexit-based-global-dtor-lowering", "unreviewed LLVM option")
            result.extend((arg, following()))
            index += 1
        elif arg in ("-D", "-U", "-I", "-include"):
            value = following()
            require(not value.startswith(("-", "@")), f"invalid {arg} value")
            if arg == "-I":
                path = Path(value) if Path(value).is_absolute() else cwd / value
                require(path.resolve().is_relative_to(kernel.resolve()), "C include directory escapes kernel")
                if not Path(value).is_absolute():
                    changes.append({"flag": arg, "original": value, "replacement": str(path)})
                    value = str(path)
            elif arg == "-include":
                require(value == "meta_features.h", "unreviewed forced C header")
            elif arg == "-D":
                require(value.split("=", 1)[0] not in ("__arm64e__", "__PTRAUTH__", "HAS_NATIVE_PAC"),
                        "C recipe enables pointer authentication")
            result.extend((arg, value))
            index += 1
        elif arg.startswith("-fsanitize-ignorelist="):
            path = Path(arg.split("=", 1)[1])
            require(path.is_absolute() and path.resolve().is_relative_to(kernel.resolve()), "C ignorelist escapes kernel")
            result.append(arg)
        elif arg in C_FLAGS:
            counts["language"] += arg == "-xc"
            counts["compile"] += arg == "-c"
            result.append(arg)
        else:
            raise CallbackError(f"unreviewed C compiler argument: {arg}")
        index += 1
    require(all(counts[key] == 1 for key in counts if key != "target") and counts["target"] >= 1,
            f"incomplete C source/target/output contract: {counts}")
    warnings = [arg for arg in argv if arg.startswith("-W")]
    require(warnings == [arg for arg in result if arg.startswith("-W")], "C recipe warnings changed")
    result.extend(("-MD", "-MF", str(dep), "-MT", str(obj)))
    return result, {"isolated_outputs_and_paths": changes, "warning_arguments": warnings,
                    "warnings_preserved_exactly": True, "added_no_default_config": True,
                    "added_dependency_inventory": str(dep), "original_cwd": str(cwd),
                    "execution_cwd": str(output), "abi_options_changed": False}


def verify_patch(path: Path, spec: dict) -> dict:
    entry = identity(path)
    require(entry["sha256"] == spec["sha256"], "callback patch identity changed")
    text = path.read_text()
    start = text.index("diff --git ")
    diff = text[start:]
    require(hashlib.sha256(diff.encode()).hexdigest() == spec["selected_diff_sha256"], "selected upstream hunks changed")
    require(re.findall(r"^diff --git (.+)$", diff, re.M) == ["a/osfmk/arm64/cpu.c b/osfmk/arm64/cpu.c"] and
            re.findall(r"^--- (.+)$", diff, re.M) == ["a/osfmk/arm64/cpu.c"] and
            re.findall(r"^\+\+\+ (.+)$", diff, re.M) == ["b/osfmk/arm64/cpu.c"] and
            len(re.findall(r"^@@ ", diff, re.M)) == 3, "patch must contain only the three cpu.c hunks")
    require(not any(line.startswith("-") and not line.startswith("--- ") for line in diff.splitlines()),
            "callback selection must not remove original source")
    return entry


def patch_context_matches(before: str, patch: str) -> list[dict]:
    """Locate each complete old-side context exactly once; offsets are explicit."""
    lines, source, result = patch.splitlines(keepends=True), before.splitlines(keepends=True), []
    starts = [index for index, line in enumerate(lines) if line.startswith("@@ ")]
    require(len(starts) == 3, "expected three callback hunks")
    previous_end = 0
    for number, begin in enumerate(starts):
        match = re.fullmatch(r"@@ -(\d+),(\d+) \+(\d+),(\d+) @@.*\n?", lines[begin])
        require(match is not None, "malformed callback hunk header")
        end = starts[number + 1] if number + 1 < len(starts) else len(lines)
        body = [line for line in lines[begin + 1:end] if line.rstrip("\r\n")]
        require(all(line[0] in " +" for line in body), "callback hunk is not a pure insertion")
        old = [line[1:] for line in body if line.startswith(" ")]
        require(len(old) == int(match[2]) and len(body) == int(match[4]), "callback hunk counts differ")
        positions = [index for index in range(len(source) - len(old) + 1) if source[index:index + len(old)] == old]
        require(len(positions) == 1 and positions[0] >= previous_end,
                "callback old context is missing, ambiguous or out of order")
        actual, expected = positions[0] + 1, int(match[1])
        result.append({"hunk": SELECTED_HUNKS[number], "upstream_old_line": expected,
                       "actual_old_line": actual, "line_offset": actual - expected,
                       "complete_context_lines": len(old), "fuzz": 0})
        previous_end = positions[0] + len(old)
    return result


def object_layout(data: bytes) -> tuple[dict, dict, list[dict], list[dict]]:
    """Bound the object's section, symbol and relocation records; no rewriting."""
    header, symbols = platform.macho(data, 1)
    sections, relocations, all_symbols = [], [], []
    pos, symtab = 32, None
    for _ in range(header["header_words"][4]):
        command, size = struct.unpack_from("<II", data, pos)
        if command == 0x19:
            require(size >= 72, "truncated object segment")
            count = struct.unpack_from("<I", data, pos + 64)[0]
            require(size == 72 + count * 80, "invalid object section table")
            for index in range(count):
                values = struct.unpack_from("<16s16sQQ8I", data, pos + 72 + index * 80)
                name, segment = (value.split(b"\0", 1)[0].decode("ascii") for value in values[:2])
                address, length, offset, align, reloff, nreloc, flags = values[2:9]
                zerofill = flags & 0xff in (1, 0xc, 0x12)
                require(zerofill or offset + length <= len(data), "object section exceeds file")
                require(reloff + nreloc * 8 <= len(data), "object relocations exceed file")
                sections.append({"index": len(sections) + 1, "name": name, "segment": segment,
                                 "address": address, "size": length, "offset": offset, "flags": flags,
                                 "alignment": align, "reloff": reloff, "nreloc": nreloc, "zero_fill": zerofill})
        elif command == 2:
            symtab = struct.unpack_from("<4I", data, pos + 8)
        pos += size
    require(symtab is not None and sections, "object lacks sections or symbols")
    symoff, count, stroff, strsize = symtab
    strings = data[stroff:stroff + strsize]
    for index in range(count):
        string, typ, section, desc, value = struct.unpack_from("<IBBHQ", data, symoff + index * 16)
        end = strings.find(b"\0", string)
        require(0 <= string < strsize and end >= string, "invalid relocation symbol string")
        all_symbols.append({"name": strings[string:end].decode(), "n_type": typ, "n_sect": section,
                            "n_desc": desc, "value": value})
    for section in sections:
        for index in range(section["nreloc"]):
            offset, bits = struct.unpack_from("<II", data, section["reloff"] + 8 * index)
            require(not offset & 0x80000000 and offset < section["size"], "invalid/scattered ARM64 object relocation")
            symbol_index, external = bits & 0xffffff, bool(bits & (1 << 27))
            require(not external or symbol_index < len(all_symbols), "relocation symbol exceeds table")
            relocations.append({"section": section["index"], "address": section["address"] + offset,
                                "section_offset": offset, "type": bits >> 28, "pcrel": bool(bits & (1 << 24)),
                                "length": (bits >> 25) & 3, "external": external, "symbol_index": symbol_index,
                                "symbol": all_symbols[symbol_index]["name"] if external else None})
    return header, symbols, sections, relocations


def decoder_identity() -> tuple[object, dict]:
    import capstone
    require(capstone.__version__ == "5.0.6", "use the recorded Capstone 5.0.6 environment")
    decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    native = Path(capstone._cs._name)
    require(native.is_file(), "Capstone native library cannot be bound")
    return decoder, {"version": capstone.__version__, "core_version": list(capstone.cs_version()),
                     "module": identity(Path(capstone.__file__)), "native_library": identity(native),
                     "python": {**identity(Path(sys.executable)), "version": sys.version}}


def callback_evidence(data: bytes, symbols: dict, sections: list[dict], relocations: list[dict], decoder) -> dict:
    """Recognize bounded emitted call sequences, not a complete CFG or ISA.

    Unknown optimizer shapes fail with the object/disassembly retained. Do not
    replace this gate with counts of unrelated BLR opcodes or symbol names.
    """
    records = symbols["records"]
    definitions = [item for item in records if item["name"] == HOOK and item["n_type"] == 0xf]
    require(len(definitions) == 1 and not definitions[0]["n_desc"] & 0xc0, "hook is not one strong section definition")
    hook = definitions[0]
    require(0 < hook["n_sect"] <= len(sections), "hook section index is invalid")
    hook_section = sections[hook["n_sect"] - 1]
    require(hook["value"] % 8 == 0 and hook_section["address"] <= hook["value"] and
            hook["value"] + 8 <= hook_section["address"] + hook_section["size"] and
            not hook_section["flags"] & 0x80000400, "hook is not aligned data storage")
    if not hook_section["zero_fill"]:
        off = hook_section["offset"] + hook["value"] - hook_section["address"]
        require(data[off:off + 8] == b"\0" * 8, "hook initial value is not NULL")
    functions = [item for item in records if item["name"] == SLEEP and item["n_type"] == 0xf]
    require(len(functions) == 1 and 0 < functions[0]["n_sect"] <= len(sections), "missing strong ml_arm_sleep definition")
    function = functions[0]
    section = sections[function["n_sect"] - 1]
    require(section["flags"] & 0x80000400 and not section["zero_fill"], "ml_arm_sleep is not instruction-section data")
    start = function["value"]
    end = min([section["address"] + section["size"]] + [item["value"] for item in records
              if item["n_type"] & 0xe == 0xe and item["n_sect"] == function["n_sect"]
              and item["name"].startswith("_") and item["value"] > start])
    offset = section["offset"] + start - section["address"]
    require(section["address"] <= start < end <= section["address"] + section["size"] and
            start % 4 == end % 4 == 0 and 0 < end - start <= 65536, "invalid bounded ml_arm_sleep range")
    instructions = list(decoder.disasm(data[offset:offset + end - start], start))
    require(len(instructions) * 4 == end - start and all(ins.size == 4 for ins in instructions),
            "decoder did not cover the bounded ml_arm_sleep bytes")
    reloc = {item["address"]: item for item in relocations if item["section"] == section["index"]
             and start <= item["address"] < end}

    def reg(ins, number):
        name = ins.reg_name(number)
        return "x" + name[1:] if re.fullmatch(r"[wx]\d+", name) else name

    def writes(ins, name):
        return name in {reg(ins, value) for value in ins.regs_access()[1]}

    def last_write(before, name, window=24, minimum=0):
        for index in range(before - 1, max(minimum - 1, before - window - 1), -1):
            ins = instructions[index]
            if ins.mnemonic in ("bl", "blr", "b", "br", "ret"):
                return None
            if writes(ins, name):
                return index
        return None

    def constant(before, name, minimum=0):
        index = last_write(before, name, minimum=minimum)
        if index is None:
            return None
        ins = instructions[index]
        if ins.mnemonic in ("mov", "movz") and len(ins.operands) == 2:
            operand = ins.operands[1]
            if operand.type == 2:  # ARM64_OP_IMM
                return operand.imm
            if operand.type == 1 and ins.reg_name(operand.reg) in ("wzr", "xzr"):
                return 0
        return None

    def taken_tail(call_index, target):
        # The observed secondary dispatch is a forward CBNZ edge to a detached
        # MOV/BLR tail. Do not infer register values from the intervening block's
        # physical bytes, and do not generalize this into a control-flow proof.
        candidates = []
        for guard_index, guard in enumerate(instructions[:call_index]):
            if (guard.mnemonic == "cbnz" and len(guard.operands) == 2
                    and guard.operands[0].type == 1
                    and guard.reg_name(guard.operands[0].reg) == target
                    and guard.operands[1].type == 2):
                address = guard.operands[1].imm
                if guard.address < address < instructions[call_index].address and (address - start) % 4 == 0:
                    tail_index = (address - start) // 4
                    if 0 < call_index - tail_index <= 8:
                        candidates.append((guard_index, tail_index))
        if not candidates:
            return None
        require(len(candidates) == 1, "tail callback has ambiguous CBNZ guards")
        guard_index, tail_index = candidates[0]
        guard = instructions[guard_index]
        load_index = last_write(guard_index, target)
        require(load_index == guard_index - 1 and load_index > 0,
                "tail hook guard does not immediately follow its pointer load")
        load = instructions[load_index]
        require(load.mnemonic == "ldr" and len(load.operands) == 2 and load.operands[0].type == 1
                and load.reg_name(load.operands[0].reg) == target,
                "tail guard does not test the actual 64-bit hook load")
        for item in instructions[tail_index:call_index]:
            require(item.mnemonic in ("mov", "movz", "nop") and not writes(item, target),
                    "unreviewed tail instruction or hook-register clobber")
        predecessor = instructions[tail_index - 1]
        require(predecessor.mnemonic in ("b", "ret"), "tail block has an unreviewed fallthrough entry")
        incoming = []
        for item in instructions:
            direct = item.mnemonic in ("b", "bl", "cbz", "cbnz", "tbz", "tbnz") or item.mnemonic.startswith("b.")
            reference = reloc.get(item.address)
            # An external BRANCH26 relocation does not encode a local target.
            external_branch = (item.mnemonic in ("b", "bl") and reference and reference["external"]
                               and reference["type"] == 2 and reference["pcrel"] and reference["length"] == 2)
            if direct and not external_branch:
                if item.operands and item.operands[-1].type == 2:
                    address = item.operands[-1].imm
                    if instructions[tail_index].address <= address <= instructions[call_index].address:
                        incoming.append(item.address)
        require(incoming == [guard.address], "tail block has another explicit local incoming edge")
        return {"load_index": load_index, "guard_index": guard_index, "tail_index": tail_index,
                "control_flow_shape": "cbnz-taken-tail-block", "guard_taken_target": hex(guard.operands[1].imm),
                "tail_entry_predecessor": {"address": hex(predecessor.address), "instruction": predecessor.mnemonic},
                "local_direct_incoming": [hex(address) for address in incoming]}

    calls = []
    for index, ins in enumerate(instructions):
        if ins.mnemonic != "blr" or len(ins.operands) != 1 or ins.operands[0].type != 1:
            continue
        target = reg(ins, ins.operands[0].reg)
        load_index = last_write(index, target)
        tail = None
        if load_index is None or reloc.get(instructions[load_index].address, {}).get("symbol") != HOOK:
            tail = taken_tail(index, target)
            if tail is None:
                continue
            load_index = tail["load_index"]
        load = instructions[load_index]
        reference = reloc.get(load.address)
        if load.mnemonic != "ldr" or reference is None or reference["symbol"] != HOOK or reference["type"] != 4:
            continue
        require(reference["external"] and reference["length"] == 2 and len(load.operands) == 2
                and load.operands[1].type == 3, "unsupported hook load relocation")
        base = reg(load, load.operands[1].mem.base)
        page_index = last_write(load_index, base)
        require(page_index is not None, "hook load has no bounded page definition")
        if tail:
            require(page_index == load_index - 1, "tail hook load does not immediately follow its page definition")
        page = instructions[page_index]
        page_reloc = reloc.get(page.address)
        require(page.mnemonic == "adrp" and page_reloc is not None and page_reloc["symbol"] == HOOK
                and page_reloc["type"] == 3 and page_reloc["pcrel"] and page_reloc["length"] == 2,
                "hook address is not backed by its actual ADRP relocation")
        if tail:
            guards = [instructions[tail["guard_index"]]]
            argument = constant(index, "x0", minimum=tail["tail_index"])
            require(argument == 0, "secondary tail callback lacks a path-local FALSE argument")
            flow = {key: value for key, value in tail.items() if not key.endswith("_index")}
        else:
            guards = [item for item in instructions[load_index + 1:index]
                      if item.mnemonic == "cbz" and len(item.operands) == 2 and item.operands[0].type == 1
                      and reg(item, item.operands[0].reg) == target and item.operands[1].type == 2
                      and not load.address <= item.operands[1].imm <= ins.address]
            require(guards, "hook call has no bounded NULL-skipping CBZ guard")
            argument = constant(index, "x0")
            flow = {"control_flow_shape": "cbz-fallthrough"}
        require(argument in (0, 1), "hook call argument is not a bounded TRUE/FALSE constant")
        calls.append({"instruction": "blr", "address": hex(ins.address),
                      "file_offset": offset + ins.address - start, "argument_value": argument,
                      "target_register": target, "null_guard_address": hex(guards[-1].address),
                      "pointer_load": {"address": hex(load.address), "relocation": reference},
                      "pointer_page": {"address": hex(page.address), "relocation": page_reloc},
                      "instruction_index": index, **flow})
    require(len(calls) == 2 and sorted(item["argument_value"] for item in calls) == [0, 1],
            "expected two relocation-backed hook calls with FALSE and TRUE arguments")
    boot = next(item for item in calls if item["argument_value"] == 1)
    resumes = []
    for index in range(boot["instruction_index"] + 1, min(len(instructions), boot["instruction_index"] + 13)):
        ins = instructions[index]
        reference = reloc.get(ins.address)
        if ins.mnemonic == "bl" and reference and reference["symbol"] == RESUME and reference["type"] == 2:
            require(reference["pcrel"] and reference["length"] == 2 and constant(index, "x1") == 0,
                    "resume call lacks its actual branch relocation or zero second argument")
            resumes.append({"symbol": RESUME, "instruction": "bl", "address": hex(ins.address),
                            "file_offset": offset + ins.address - start, "second_argument": 0,
                            "after_boot_dispatch": True, "relocation": reference})
            break
        require(ins.mnemonic not in ("bl", "blr", "b", "br", "ret", "cbz", "cbnz") and
                not ins.mnemonic.startswith("b."), "unreviewed control flow between boot callback and resume")
    require(len(resumes) == 1, "boot callback does not have a bounded arm_init_cpu resume call")
    return {"passed": True, "scope": "bounded emitted callback sequences and relocations in ml_arm_sleep",
            "hook_definition": {**hook, "section": hook_section, "null_initial_value_verified": True},
            "function": {"name": SLEEP, "address": hex(start), "end": hex(end), "file_offset": offset,
                         "size": end - start, "sha256": hashlib.sha256(data[offset:offset + end - start]).hexdigest(),
                         "boundary_basis": "defined-section symbol to next underscore symbol/section end"},
            "dispatch_calls": calls, "resume_call": resumes[0],
            "instructions": [{"address": hex(ins.address), "bytes": bytes(ins.bytes).hex(),
                              "mnemonic": ins.mnemonic, "operands": ins.op_str} for ins in instructions],
            "full_control_flow_proven": False, "full_instruction_set_audited": False,
            "runtime_path_execution_verified": False, "sleep_resume_verified": False}


def recheck(report: dict, protected: list[dict]):
    platform.recheck_inputs(report, protected)
    checks = report["protected_input_rechecks"]
    report["protected_inputs_recheck"] = {"unchanged": report["protected_inputs_unchanged"],
                                           "checked_file_count": len(checks),
                                           "changes": [item for item in checks if not item["unchanged"]]}
    if not report["protected_inputs_unchanged"]:
        report["kernel_callback_built"] = False


def build(args) -> dict:
    config, config_id = platform.verified_json(CONFIG)
    require(config.get("schema_version") == 1 and config.get("scope") == "arm64-platform-sleep-cpu-replacement" and
            config["provenance"]["selected_hunks"] == SELECTED_HUNKS, "unsupported callback configuration")
    kernel, toolwork = args.kernel_dir.resolve(), args.toolchain_work.resolve()
    require(kernel.is_dir() and toolwork.is_dir(), "kernel/toolchain workspace is missing")
    prefix_hint = Path(json.loads((toolwork / "host-tools-state.json").read_text())["environment"]["UNIXNU_TOOLCHAIN"])
    require(prefix_hint.is_absolute(), "toolchain prefix must be absolute")
    output = platform.new_output(args.output, [kernel, toolwork, prefix_hint])
    report = {"schema_version": 1, "scope": config["scope"], "status": "validating", "output": str(output),
              "driver": identity(Path(__file__).resolve()), "config": config_id, "commands": [],
              "provenance": config["provenance"], "kernel_callback_built": False,
              "protected_inputs_unchanged": None, "platform_sleep_bootarg_enabled": False,
              "complete_sleep_patch_applied": False, "sleep_resume_verified": False,
              "board_wake_sources_verified": False, "full_instruction_set_audited": False,
              "runtime_path_execution_verified": False, "tb371fc_kernel_qualified": False,
              "provider_kernel_link_verified": False, "os_boot_verified": False}
    save_json(output / "report.json", report)
    try:
        with ExitStack() as locks:
            for path in (kernel / ".route-a/build.lock", toolwork / "build.lock", toolwork / "host-tools.lock"):
                handle = locks.enter_context(path.open("rb"))
                try:
                    fcntl.flock(handle, fcntl.LOCK_SH | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise CallbackError(f"input build/installation is active: {path}") from exc
            kernel_id, recipe, prefix, states, _ = platform.verify_inputs(kernel, toolwork, config)
            protected = [config_id, report["driver"], kernel_id, kernel_id["build_report"], kernel_id["recipe"],
                         kernel_id["compiler"], kernel_id["original_recipe_object"], states["clang"], states["host_tools"]]
            locks.callback(recheck, report, protected)
            support = []
            for spec in config["support_files"]:
                entry = identity(platform.child(ROOT, spec["path"]))
                require(entry["sha256"] == spec["sha256"], f"callback support changed: {spec['path']}")
                support.append(entry)
                protected.append(entry)
            report["support_files"] = support
            baseline = config["baseline"]
            original_source = platform.child(kernel, baseline["recipe_source"])
            before = identity(original_source)
            require(before["sha256"] == baseline["recipe_source_sha256"] and before["size"] == baseline["recipe_source_size"],
                    "actual prepared cpu.c changed")
            protected.append(before)
            original_object = kernel_id["original_recipe_object"]
            require(Path(original_object["path"]).resolve() == platform.child(kernel, baseline["original_object_path"]).resolve()
                    and original_object["sha256"] == baseline["original_object_sha256"]
                    and original_object["size"] == baseline["original_object_size"], "original cpu.o identity changed")
            require(not re.search(rb'^\s*#\s*include\s*"', original_source.read_bytes(), re.M),
                    "quoted source-relative headers need a separately reviewed snapshot layout")
            patch = verify_patch(platform.child(ROOT, config["patch"]["path"]), config["patch"])
            protected.append(patch)
            report["patch_context_matches"] = patch_context_matches(original_source.read_text(), Path(patch["path"]).read_text())
            license_spec = config["provenance"]["license"]
            license_entry = identity(platform.child(ROOT, license_spec["local_copy"]))
            require(license_entry["sha256"] == license_spec["sha256"], "fixed upstream license text changed")
            report["license"] = license_entry
            protected.append(license_entry)
            report.update(kernel=kernel_id, original_object=original_object, compiler=kernel_id["compiler"],
                          patch=patch, source={"before": before}, toolchain_states=states)
            for name in ("inputs", "source", "replacement", "tmp"):
                (output / name).mkdir()
            for name, entry in (("original-cpu.c", before), ("original-compile-record.json", kernel_id["recipe"]),
                                ("callback-config.json", config_id), ("callback.patch", patch),
                                ("upstream-license.txt", license_entry),
                                ("kernel-build-report.json", kernel_id["build_report"]),
                                ("clang-state.json", states["clang"]), ("host-tools-state.json", states["host_tools"])):
                shutil.copyfile(entry["path"], output / "inputs" / name)
            source = output / "source/osfmk/arm64/cpu.c"
            source.parent.mkdir(parents=True)
            shutil.copyfile(original_source, source)
            env = {"PATH": os.pathsep.join((str(Path(recipe["arguments"][0]).parent), os.defpath)), "LC_ALL": "C",
                   "TMPDIR": str(output / "tmp"), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
            report["environment"] = env
            execution = platform.Execution(output, report, env)
            git = shutil.which("git", path=os.defpath)
            require(git is not None, "git apply is required")
            report["patch_tool"] = identity(Path(git))
            protected.append(report["patch_tool"])
            for label, extra in (("patch-check", ["--check"]), ("patch-apply", [])):
                result = execution.run(label, [git, "apply", "--whitespace=error-all", *extra,
                                               output / "inputs/callback.patch"], output / "source")
                require(result["exit_code"] == 0, f"{label} failed; original cpu.c is unchanged")
            after = identity(source)
            require(after["sha256"] == config["patch"]["result_source_sha256"] and
                    after["size"] == config["patch"]["result_source_size"], "patched cpu.c differs from the reviewed selection")
            protected.append(after)
            report["source"]["after"] = after
            argv, changes = replay_recipe(recipe, kernel, source, output / "replacement")
            replay = {"directory": str(output / "replacement"), "file": str(source),
                      "output": str(output / "replacement/cpu.o"), "arguments": argv}
            replay_path = output / "replacement/replay-compile-record.json"
            save_json(replay_path, replay)
            report["compile_record"] = {"original": kernel_id["recipe"], "replay": identity(replay_path)}
            report["recipe_changes"] = changes
            report["status"] = "compiling_callback"
            compiled = execution.run("cpu-compile", argv, output / "replacement")
            report["compile"] = compiled
            obj = output / "replacement/cpu.o"
            if obj.is_file():
                report["replacement_object"] = identity(obj)
            require(compiled["exit_code"] == 0 and obj.is_file(), "callback compilation failed; all diagnostics are retained")
            report["status"] = "checking_generated_callback"
            raw = obj.read_bytes()
            header, symbols, sections, relocations = object_layout(raw)
            symbol_path, reloc_path = output / "replacement/symbols.json", output / "replacement/relocations.json"
            save_json(symbol_path, symbols)
            save_json(reloc_path, {"sections": sections, "relocations": relocations})
            report["replacement_object"].update(macho=header, symbols=identity(symbol_path), relocations=identity(reloc_path))
            dep_path = output / "replacement/dependencies.json"
            deps = platform.dependencies(output / "replacement/dependencies.d", output / "replacement", [kernel, prefix, output / "source"])
            save_json(dep_path, deps)
            report["dependencies"] = identity(dep_path)
            protected.extend(deps)
            objdump = Path(args.objdump or "/usr/bin/llvm-objdump-19").absolute()
            require(objdump.is_file() and os.access(objdump, os.X_OK), "existing llvm-objdump is required")
            report["objdump"] = identity(objdump)
            protected.append(report["objdump"])
            for label, command in (("objdump-version", [objdump, "--version"]),
                                    ("cpu-disassembly", [objdump, "--disassemble", "--reloc", obj])):
                result = execution.run(label, command, output)
                require(result["exit_code"] == 0, f"{label} failed")
            report["disassembly"] = identity(output / "logs/cpu-disassembly.stdout")
            decoder, decoder_id = decoder_identity()
            report["decoder"] = decoder_id
            protected.extend([decoder_id["module"], decoder_id["native_library"], decoder_id["python"]])
            evidence = callback_evidence(raw, symbols, sections, relocations, decoder)
            evidence["object_sha256"] = sha256_file(obj)
            evidence["source_sha256"] = after["sha256"]
            evidence["disassembly"] = report["disassembly"]
            evidence_path = output / "callback-evidence.json"
            save_json(evidence_path, evidence)
            report["callback_evidence"] = identity(evidence_path)
            report.update(status="kernel_callback_built", kernel_callback_built=True)
    except (Exception, KeyboardInterrupt) as exc:
        report.update(failed_stage=report["status"], status="failed", kernel_callback_built=False,
                      error=str(exc), error_type=type(exc).__name__)
    finally:
        report["finished_at_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        save_json(output / "report.json", report)
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-dir", type=Path, required=True)
    parser.add_argument("--toolchain-work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new external attempt; never reused")
    parser.add_argument("--objdump", help="existing LLVM objdump, default /usr/bin/llvm-objdump-19")
    args = parser.parse_args(argv)
    try:
        report = build(args)
    except (CallbackError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"status": report["status"], "report": str(Path(report["output"]) / "report.json"),
                      "error": report.get("error")}, indent=2))
    return 0 if report["status"] == "kernel_callback_built" else 2


if __name__ == "__main__":
    raise SystemExit(main())
