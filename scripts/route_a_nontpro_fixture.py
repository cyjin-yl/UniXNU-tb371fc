"""Synthetic inputs for executing fixed real dyld functions at EL0.

Only fixture bytes and expected results are synthesized. Dyld code is immutable.
No fixture result proves universal reachability or an actual XNU syscall.
"""
from __future__ import annotations

import struct

from audit_route_a_nontpro import require

DYLD_BASE = 0x48000000
INPUT_BASE = 0x49000000
TABLE_BASE = 0x4a000000
COMMPAGE_PA = 0x4a010000
COMMPAGE_VA = 0x0000000fffffc000
BOOT_BASE = 0x40080000
COMPLETED = BOOT_BASE + 0x2100
UNEXPECTED = BOOT_BASE + 0x2224
MODEL_STATE = BOOT_BASE + 0x2300
INPUT_SIZE = 1 << 20
RESULTS_OFFSET = 0x2000
DATA_OFFSET = 0x4000
MAX_CASES = 64


class Arena:
    def __init__(self):
        self.data = bytearray(INPUT_SIZE)
        self.cursor = DATA_OFFSET

    def allocate(self, data, alignment=8):
        require(alignment in (1, 8, 16), "invalid fixture alignment")
        at = (self.cursor + alignment - 1) & -alignment
        require(at + len(data) <= INPUT_SIZE, "fixture input exceeds bound")
        self.data[at:at + len(data)] = data
        self.cursor = at + len(data)
        return INPUT_BASE + at

    def string(self, text):
        require(isinstance(text, str) and "\0" not in text, "fixture string contains NUL")
        encoded = text.encode("ascii")
        require(len(encoded) <= 512, "fixture string exceeds bound")
        return self.allocate(encoded + b"\0", 1)

    def vector(self, entries):
        require(len(entries) <= 64, "fixture vector exceeds bound")
        pointers = [self.string(s) for s in entries]
        address = self.allocate(struct.pack("<" + "Q" * (len(pointers) + 1), *pointers, 0))
        return address, pointers

    def block(self, argv, environment, apple):
        args = [self.string(s) for s in argv]
        env = [self.string(s) for s in environment]
        entries = [self.string(s) for s in apple]
        values = [DYLD_BASE, len(args), *args, 0, *env, 0, *entries, 0]
        address = self.allocate(struct.pack("<" + "Q" * len(values), *values))
        apple_address = address + 8 * (len(args) + len(env) + 4)
        return address, apple_address


def page_tables():
    """39-bit TTBR0: identity RAM + one RO user commpage alias."""
    result = bytearray(3 * 4096)
    # Normal-memory AF, inner-shareable, EL0/EL1 read/write identity block.
    struct.pack_into("<Q", result, 1 * 8, 0x40000000 | 1 | (1 << 10) | (3 << 8) | (1 << 6))
    require(COMMPAGE_VA >> 30 == 63 and COMMPAGE_VA >> 21 & 511 == 511 and
            COMMPAGE_VA >> 12 & 511 == 508, "commpage translation geometry changed")
    struct.pack_into("<Q", result, 63 * 8, TABLE_BASE + 4096 | 3)
    struct.pack_into("<Q", result, 4096 + 511 * 8, TABLE_BASE + 8192 | 3)
    struct.pack_into("<Q", result, 8192 + 508 * 8,
                     COMMPAGE_PA | 3 | (1 << 10) | (3 << 8) | (3 << 6) | (1 << 53) | (1 << 54))
    return bytes(result)


def build_cases():
    arena, cases = Arena(), []
    def add(name, target, args, expected, observation=None, model_calls=0):
        require(len(args) == 4 and len(cases) < MAX_CASES, "bad fixture descriptor")
        cases.append({"name": name, "target": hex(target), "arguments": [hex(a) for a in args],
                      "expected": {k: hex(v) for k, v in expected.items()},
                      "observation": observation, "expected_syscall38_model_calls": model_calls})
    for name, argv, env, apple in (
        ("walker-empty", [], [], []),
        ("walker-full-vectors", ["program", "argument"], ["A=1", "B=2"],
         ["executable_path=/fixture", "security_config=0x0", "guard=0x123", "pfz=0x0"])):
        block, expected = arena.block(argv, env, apple)
        add(name, 0x6e38, [block, 0, 0, 0], {"x0": expected, "x1": len(apple)})
    lookups = (
        ("lookup-null-vector", None, "dyld_hw_tpro", None),
        ("lookup-empty-vector", [], "dyld_hw_tpro", None),
        ("lookup-absent", ["executable_path=/fixture", "security_config=0x0"], "dyld_hw_tpro", None),
        ("lookup-prefixes-and-bare-key", ["dyld_hw_tpro_pagers=0", "dyld_hw_tpro_extra=1", "dyld_hw_tpro"],
         "dyld_hw_tpro", None),
        ("lookup-first-value-zero", ["dyld_hw_tpro=0", "security_config=0x0"], "dyld_hw_tpro", 0),
        ("lookup-middle-empty-value", ["executable_path=/fixture", "dyld_hw_tpro=", "pfz=0x0"], "dyld_hw_tpro", 1),
        ("lookup-last-value-one", ["executable_path=/fixture", "security_config=0x0", "dyld_hw_tpro=1"], "dyld_hw_tpro", 2),
        ("lookup-duplicate-first-wins", ["dyld_hw_tpro=0", "dyld_hw_tpro=1"], "dyld_hw_tpro", 0),
        ("lookup-pager-key", ["executable_path=/fixture", "dyld_hw_tpro_pagers=0"], "dyld_hw_tpro_pagers", 1),
    )
    for name, entries, key, match in lookups:
        vector, pointers = arena.vector(entries) if entries is not None else (0, [])
        key_ptr = arena.string(key)
        expected = pointers[match] + len(key) + 1 if match is not None else 0
        add(name, 0x6e78, [vector, key_ptr, 0, 0], {"x0": expected})
    constructors = (
        ("manager-no-tpro-keys", ["executable_path=/fixture", "security_config=0x0"], 0, 0),
        ("manager-zero-still-enables", ["executable_path=/fixture", "dyld_hw_tpro=0"], 1, 0),
        ("manager-empty-still-enables", ["dyld_hw_tpro=", "security_config=0x0"], 1, 0),
        ("manager-prefix-does-not-enable", ["dyld_hw_tpro_pagers=1", "dyld_hw_tpro_extra=1"], 0, 0),
        ("manager-sec-transition-separate", ["executable_path=/fixture", "has_sec_transition=1"], 0, 1),
    )
    env, _ = arena.vector([])
    for name, entries, hardware, sec in constructors:
        apple, _ = arena.vector(entries)
        obj = arena.allocate(bytes([0xa5]) * 0x58, 16)
        expected = bytearray(0x58)
        expected[0x20], expected[0x22] = hardware, sec
        expected[0x23:0x28] = bytes([0xa5]) * 5  # C++ padding is not initialized.
        add(name, 0x713c, [obj, env, apple, 0], {"x0": obj},
            {"address": hex(obj), "size": 0x58, "expected_hex": expected.hex()}, model_calls=1)
    for name, entries in (
        ("default-stack-empty-vector", []),
        ("default-stack-absent-key", ["executable_path=/fixture", "dyld_hw_tpro_pagers=0"]),
    ):
        apple, _ = arena.vector(entries)
        configuration = bytearray(0x100)
        struct.pack_into("<Q", configuration, 0xd0, apple)
        obj = arena.allocate(configuration, 16)
        add(name, 0x21264, [obj, 0, 0, 0], {"x0": 0})
    obj = arena.allocate(bytes([0xa5]) * 64, 16)
    add("protected-stack-disabled", 0x3cb2c, [obj, 0, 0, 0], {"x0": obj},
        {"address": hex(obj), "size": 64, "expected_hex": bytes(64).hex()})
    obj = arena.allocate(bytes(64), 16)
    add("empty-protected-stack-not-in-use", 0x32020, [obj, 0, 0, 0], {"x0": 0})
    descriptor = INPUT_BASE + 64
    struct.pack_into("<3Q", arena.data, 0, len(cases), descriptor, INPUT_BASE + RESULTS_OFFSET)
    for index, case in enumerate(cases):
        struct.pack_into("<5Q", arena.data, 64 + index * 40,
                         DYLD_BASE + int(case["target"], 16), *[int(v, 16) for v in case["arguments"]])
    return bytes(arena.data), cases


def check_results(cases, result_bytes, observations, model_calls):
    """Retain each raw result before comparison. A partial read is a failure."""
    require(len(result_bytes) == 16 * len(cases), "truncated fixture result array")
    require(len(observations) == len(cases), "missing case observation")
    verified = True
    for i, case in enumerate(cases):
        x0, x1 = struct.unpack_from("<2Q", result_bytes, i * 16)
        case["observed"] = {"x0": hex(x0), "x1": hex(x1)}
        case["registers_match"] = all(case["observed"][k] == v for k, v in case["expected"].items())
        observation = case["observation"]
        case["object_matches"] = True
        if observation:
            raw = observations[i]
            case["observed_object_hex"] = raw.hex()
            case["object_matches"] = len(raw) == observation["size"] and raw.hex() == observation["expected_hex"]
        case["verified"] = case["registers_match"] and case["object_matches"]
        verified &= case["verified"]
    return verified and model_calls == sum(c["expected_syscall38_model_calls"] for c in cases)


def decode_model_state(raw):
    """The fixture captured raw SVC state before accepting its synthetic model."""
    require(len(raw) >= 64, "truncated model header")
    attempts, accepted, esr, elr, far, level = struct.unpack_from("<6Q", raw)
    require(attempts <= MAX_CASES and accepted <= attempts, "invalid model counters")
    require(len(raw) == 64 + attempts * 256, "truncated or surplus model records")
    result = {"attempts": attempts, "accepted": accepted,
              "unexpected": {"esr": hex(esr), "elr": hex(elr), "far": hex(far), "current_el": hex(level)},
              "records": [], "actual_xnu_dispatch_verified": False}
    for i in range(attempts):
        values = struct.unpack_from("<19Q", raw, 64 + i * 256)
        service, syndrome, pc, saved = values[8], values[10], values[11], values[13]
        signed_service = service - (1 << 64) if service & (1 << 63) else service
        record = {"arguments": {f"x{j}": hex(values[j]) for j in range(8)},
                  "x16": hex(service), "x16_signed": signed_service, "x30": hex(values[9]),
                  "esr": hex(syndrome), "elr": hex(pc), "sp_el0": hex(values[12]),
                  "spsr_before": hex(saved), "output_pointer": hex(values[14]),
                  "output_byte_before": values[15],
                  "synthetic_reply": {"x0": hex(values[16]), "x1": hex(values[17]),
                                      "spsr": hex(values[18])}}
        record["matches_declared_model"] = (
            service == 38 and syndrome >> 26 == 0x15 and syndrome & 0xffff == 0x80 and
            pc == DYLD_BASE + 0xa9d8 and values[9] == DYLD_BASE + 0xa9c4 and
            saved & 0x1f == 0 and values[:3] == (0, 0, 0) and
            0x4b000000 <= values[3] <= 0x4b00fff8 and values[3] % 8 == 0 and
            0x4b000000 <= values[14] < 0x4b010000 and values[15] == 0 and
            values[16:18] == (45, 0) and values[18] == saved | (1 << 29))
        result["records"].append(record)
    result["synthetic_model_verified"] = accepted == attempts and all(
        r["matches_declared_model"] for r in result["records"]) and not any((esr, elr, far, level))
    return result
