"""PACGA ABI encoding, real C state semantics, and fail-closed pipeline gates.

All images and keys here are synthetic. The C is extracted from the production
patch and includes the production helper. A separate QEMU probe compares the
software result with architected PACGA; neither test is a Darwin boot claim.
"""
from pathlib import Path
import hashlib
import io
import json
import os
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from arm64_lowering import pacga
from arm64_lowering.instructions import lower
from arm64_lowering.pipeline import rewrite_userland
from arm64_lowering.proof import validate_summary
from route_a_zeta import zeta_userland_pauth as pauth
from route_a_zeta import zeta_dyld_cache as dc
from test_route_a_pipeline import signed_fixture
from test_route_a_proof import cache_bytes, module


def synthetic_kernel():
    """A parser fixture carrying a descriptor; deliberately not a real kernel."""
    base = 0xFFFFFFF007004000
    data = bytearray(0x3000)
    commands = []
    for name, vmaddr, fileoff, size, prot, section, section_at, section_size, flags in (
        ("__TEXT", base, 0, 0x2000, 5, "__text", 0x1000, 4, 0x80000400),
        ("__DATA_CONST", base + 0x2000, 0x2000, 0x1000, 1,
         "__unixnu_pacga", 0x2000, len(pacga.descriptor()), 0),
    ):
        command = struct.pack("<2I16s4Q4I", 0x19, 152, name.encode(), vmaddr, size,
                              fileoff, size, prot, prot, 1, 0)
        command += struct.pack("<16s16s2Q8I", section.encode(), name.encode(),
                               vmaddr + section_at - fileoff, section_size, section_at,
                               0, 0, 0, flags, 0, 0, 0)
        commands.append(command)
    struct.pack_into("<8I", data, 0, 0xFEEDFACF, 0x0100000C, 0, 2, 2, 304, 0, 0)
    data[32:336] = b"".join(commands)
    struct.pack_into("<I", data, 0x1000, 0xD65F03C0)
    descriptor = pacga.descriptor()
    data[0x2000:0x2000 + len(descriptor)] = descriptor
    return bytes(data)


def added_function(name, result_type):
    added = "\n".join(line[1:] for line in (ROOT / pacga.PATCH).read_text().splitlines()
                      if line.startswith("+") and not line.startswith("+++"))
    signature = "static " + result_type + "\n" + name + "("
    if added.count(signature) != 1:
        raise AssertionError("production function extraction is ambiguous: " + name)
    start = added.index(signature)
    cursor = added.index("{", start)
    depth = 1
    end = cursor + 1
    while depth:
        depth += (added[end] == "{") - (added[end] == "}")
        end += 1
    return added[start:end]


HOST_PREAMBLE = r"""
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
/* Pinned XNU arm_saved_state64 layout; the real translation unit is also
 * compiled by build_route_a_pacga.py against its actual XNU headers. */
typedef struct {
    uint64_t x[29], fp, lr, sp, pc;
    uint32_t cpsr, reserved;
    uint64_t far, esr;
} arm_saved_state64_t;
typedef struct { arm_saved_state64_t state; } arm_saved_state_t;
static arm_saved_state64_t *saved_state64(arm_saved_state_t *s) { return &s->state; }
_Static_assert(offsetof(arm_saved_state64_t, fp) == 29 * 8, "fp layout");
_Static_assert(offsetof(arm_saved_state64_t, lr) == 30 * 8, "lr layout");
_Static_assert(offsetof(arm_saved_state64_t, sp) == 31 * 8, "sp layout");
_Static_assert(sizeof(arm_saved_state64_t) == 288, "state layout");
static struct route_a_pacga_key route_a_pacga_boot_key;
static uint32_t route_a_pacga_ready;
static const struct route_a_pacga_key public_key = {
    .lo=UINT64_C(0xec2802d4e0a488e9), .hi=UINT64_C(0x84be85ce9804e94b)
};
static jmp_buf panic_target;
static int expecting_panic, generation_failure, random_calls;
static _Noreturn void panic(const char *message, ...) {
    if (expecting_panic) longjmp(panic_target, 1);
    fprintf(stderr, "unexpected panic: %s\n", message);
    exit(2);
}
static void read_random(void *destination, unsigned count) {
    if (count != 16) panic("wrong random request");
    ++random_calls;
    memcpy(destination, &public_key, count);
    if (generation_failure) panic("injected unavailable generator");
}
"""

HOST_MAIN = r"""
static int bootstrap_panics(void) {
    expecting_panic = 1;
    if (setjmp(panic_target) == 0) {
        route_a_pacga_bootstrap();
        expecting_panic = 0;
        return 0;
    }
    expecting_panic = 0;
    return 1;
}
static int unready_panics(void) {
    arm_saved_state_t state = {0};
    expecting_panic = 1;
    if (setjmp(panic_target) == 0) {
        (void)route_a_pacga_svc(&state, UINT64_C(0x56008000));
        expecting_panic = 0;
        return 0;
    }
    expecting_panic = 0;
    return 1;
}
int main(void) {
    uint64_t full = route_a_qarma5(UINT64_C(0xfb623599da6e8127),
                                  UINT64_C(0x477d469dec0b8762), &public_key);
    if (full != UINT64_C(0xc003b93999b33765)) {
        fprintf(stderr, "QARMA paper vector differs: %016llx\n",
                (unsigned long long)full); return 1;
    }
    if (route_a_pacga_signature(UINT64_C(0xfb623599da6e8127),
                               UINT64_C(0x477d469dec0b8762), &public_key)
        != UINT64_C(0xc003b93900000000)) return 2;
    if (!unready_panics() || route_a_pacga_ready || random_calls) return 3;
    generation_failure = 1;
    if (!bootstrap_panics() || route_a_pacga_ready || random_calls != 1) return 4;
    generation_failure = 0;
    route_a_pacga_bootstrap();
    if (route_a_pacga_ready != 1 || random_calls != 2 ||
        memcmp(&route_a_pacga_boot_key, &public_key, sizeof(public_key))) return 5;
    if (!bootstrap_panics() || random_calls != 2) return 6;

    arm_saved_state_t original;
    memset(&original, 0xA5, sizeof(original));
    uint64_t registers[32];
    for (unsigned i = 0; i < 32; ++i) {
        registers[i] = UINT64_C(0xFEDCBA9876543210) ^
                       ((uint64_t)i * UINT64_C(0x0102040810204081));
        memcpy((uint8_t *)&original.state + 8 * i, &registers[i], 8);
    }
    /* Host probe reads the entire SP value, including these unaligned low bits. */
    registers[31] = original.state.sp = UINT64_C(0x123456789ABCDEF3);
    original.state.pc = UINT64_C(0x1020304050607084);
    original.state.cpsr = UINT32_C(0xA0000000);
    original.state.reserved = 0; /* Actual SPILL_REGISTERS entry reset. */
    unsigned cases = 0;
    for (unsigned n = 0; n < 32; ++n) {
        for (unsigned m = 0; m < 32; ++m) {
            uint64_t value = n == 31 ? 0 : registers[n];
            uint64_t result = route_a_pacga_signature(value, registers[m], &public_key);
            for (unsigned d = 0; d < 32; ++d) {
                arm_saved_state_t state = original, expected = original;
                if (d != 31) memcpy((uint8_t *)&expected.state + 8 * d, &result, 8);
                expected.state.reserved = ROUTE_A_PACGA_RETURN_TAG;
                uint64_t esr = UINT64_C(0x56008000) | d | ((uint64_t)n << 5) | ((uint64_t)m << 10);
                if (!route_a_pacga_svc(&state, esr) ||
                    memcmp(&state, &expected, sizeof(state))) {
                    fprintf(stderr, "saved state differs d=%u n=%u m=%u\n", d,n,m); return 7;
                }
                ++cases;
            }
        }
    }
    const uint32_t outside[] = {0, 0x80, 0x7fff, 0x18000};
    for (unsigned i = 0; i < sizeof(outside)/sizeof(outside[0]); ++i) {
        arm_saved_state_t state = original;
        if (route_a_pacga_svc(&state, UINT64_C(0x56000000) | outside[i]) ||
            memcmp(&state, &original, sizeof(state))) return 8;
    }
    const uint32_t invalid_modes[] = {1, 4, 5, 0x10, 0x1f};
    for (unsigned i = 0; i < sizeof(invalid_modes)/sizeof(invalid_modes[0]); ++i) {
        arm_saved_state_t state = original;
        state.state.cpsr |= invalid_modes[i];
        arm_saved_state_t before = state;
        if (route_a_pacga_svc(&state, UINT64_C(0x56008000)) ||
            memcmp(&state, &before, sizeof(state))) return 9;
    }
    const uint32_t invalid_ec[] = {0, 0x11, 0x20, 0x24, 0x3f};
    for (unsigned i = 0; i < sizeof(invalid_ec)/sizeof(invalid_ec[0]); ++i) {
        arm_saved_state_t state = original;
        if (route_a_pacga_svc(&state, ((uint64_t)invalid_ec[i] << 26) | 0x8000) ||
            memcmp(&state, &original, sizeof(state))) return 10;
    }
    printf("{\"register_cases\":%u,\"paper_vector\":true,\"key_failures\":true,"
           "\"outside_dispatch_cases\":4,\"undefined_behavior_sanitizer\":true}\n", cases);
    return 0;
}
"""


class PacgaTests(unittest.TestCase):
    def test_encoding_is_bijective_for_every_register_form_and_default_stays_reject(self):
        for n in range(32):
            for m in range(32):
                for d in range(32):
                    word = 0x9AC03000 | d | n << 5 | m << 16
                    lowered = lower(word, plain_pointers=True, pacga_policy=pacga.ABI)
                    expected = 0xD4000001 | ((0x8000 | d | n << 5 | m << 10) << 5)
                    self.assertEqual(lowered, ("PACGA", expected))
                    self.assertEqual(pacga.decode(expected), word)
        with self.assertRaisesRegex(ValueError, "separate_abi"):
            lower(0x9AC23020, plain_pointers=True)
        with self.assertRaisesRegex(ValueError, "plain_pointer"):
            lower(0x9AC23020, pacga_policy=pacga.ABI)
        with self.assertRaisesRegex(ValueError, "policy"):
            lower(0x9AC23020, plain_pointers=True, pacga_policy="zero")

    def test_source_svc_namespace_is_censused_and_never_silently_reinterpreted(self):
        words = np.array([0xD4100001, 0xD4001001, 0x9AC23020], dtype=np.uint32)
        self.assertEqual(pauth.candidate_indices(words).tolist(), [2])
        self.assertEqual(pauth.candidate_indices(words, pacga_policy=pacga.ABI).tolist(), [0, 2])
        with self.assertRaisesRegex(ValueError, "namespace"):
            pauth.lower(int(words[0]), pacga_policy=pacga.ABI)

    def test_exclusive_reservation_propagates_through_branches_and_table_targets(self):
        insns = {
            0: ("ldaxr", "x0, [x1]"), 4: ("cbz", "x2, #0x14"),
            8: ("pacga", "x0, x0, x2"), 12: ("stlxr", "w3, x0, [x1]"),
            16: ("b", "#0"), 20: ("clrex", ""), 24: ("pacga", "x0, x0, x2"),
            28: ("ret", ""),
            32: ("ldxr", "x0, [x1]"), 36: ("br", "x16"),
            40: ("pacga", "x0, x0, x2"), 44: ("ret", ""),
        }
        tables = [dict(dispatch=36, targets=[40])]
        result = pacga.exclusive_analysis(insns, insns, tables)
        self.assertEqual(result["pacga"], {8, 40})
        self.assertEqual(result["escapes"], [
            dict(va="0x2c", reason="unsupported exclusive-state escape: return with live reservation")])
        self.assertEqual(pacga.exclusive_analysis(
            insns, {24: "pointer", 28: "pointer"}, tables), dict(pacga=set(), escapes=[]))

    def test_live_reservation_is_not_dropped_at_calls_or_unresolved_owner_boundaries(self):
        # A direct call can run PACGA in the callee and still return to a caller
        # whose store-exclusive depends on the old reservation. It is not a
        # closed-state root for this extra admission check.
        insns = {
            0: ("ldaxr", "x0, [x1]"), 4: ("bl", "#0x14"),
            8: ("pacga", "x0, x0, x2"), 12: ("stlxr", "w3, x0, [x1]"),
            16: ("ret", ""), 20: ("pacga", "x0, x0, x2"), 24: ("ret", ""),
            32: ("ldxr", "x0, [x1]"), 36: ("blr", "x3"),
            40: ("stxr", "w4, x0, [x1]"), 44: ("ret", ""),
            48: ("ldxr", "x0, [x1]"), 52: ("br", "x16"),
            64: ("ldaxr", "x0, [x1]"), 68: ("ret", ""),
            80: ("ldxr", "x0, [x1]"), 84: ("b", "#0x1000"),
            96: ("ldaxr", "x0, [x1]"),
        }
        result = pacga.exclusive_analysis(insns, insns, [])
        self.assertEqual(result["pacga"], {8})
        self.assertEqual([int(e["va"], 16) for e in result["escapes"]], [4, 36, 52, 68, 84, 96])
        self.assertEqual(result["escapes"][0]["target"], "0x14")
        self.assertEqual(result["escapes"][-2]["target"], "0x1000")
        self.assertEqual(result["escapes"][-1]["target"], "0x64")
        self.assertTrue(all("unsupported exclusive-state escape" in e["reason"]
                            for e in result["escapes"]))

    def test_existing_exceptions_and_clrex_end_the_reservation(self):
        for terminator in ("stxr", "stlxr", "stxp", "stlxp", "clrex",
                           "svc", "hvc", "smc", "brk", "udf", "hlt"):
            with self.subTest(terminator=terminator):
                insns = {0: ("ldxr", "x0, [x1]"), 4: (terminator, ""),
                         8: ("pacga", "x0, x1, x2"), 12: ("ret", "")}
                self.assertEqual(pacga.exclusive_analysis(insns, insns, []),
                                 dict(pacga=set(), escapes=[]))

    def test_production_c_matches_known_answer_and_preserves_complete_saved_state(self):
        compiler = shutil.which("cc") or shutil.which("clang")
        self.assertIsNotNone(compiler, "the PACGA C contract test requires a C compiler")
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "probe.c"
            executable = Path(tmp) / "probe"
            code = ("#include " + json.dumps(str(ROOT / pacga.HEADER)) + "\n"
                    + "#include " + json.dumps(str(ROOT / pacga.ABI_HEADER)) + "\n" + HOST_PREAMBLE)
            code += "\n".join(added_function(name, kind) for name, kind in (
                ("route_a_pacga_bootstrap", "void"),
                ("route_a_pacga_register", "uint64_t"),
                ("route_a_pacga_svc", "bool"),
            ))
            source.write_text(code + HOST_MAIN)
            command = [compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                       "-fsanitize=undefined", "-fno-sanitize-recover=all", str(source), "-o", str(executable)]
            compiled = subprocess.run(command, capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            ran = subprocess.run([str(executable)], capture_output=True, text=True, timeout=60)
            self.assertEqual(ran.returncode, 0, ran.stderr)
            result = json.loads(ran.stdout)
            self.assertEqual(result["register_cases"], 32768)
            self.assertTrue(result["paper_vector"] and result["key_failures"])
            self.assertEqual(result["outside_dispatch_cases"], 4)
            self.assertEqual(ran.stderr, "")

    def test_production_bootstrap_requires_the_kernel_random_declaration(self):
        # The existing state harness defines its random-provider double before
        # the extracted functions. This separate compile probe has no such
        # definition: production includes must expose the public XNU API.
        # Declaration/gates: ac9718fb:bsd/sys/{random.h,appleapiopts.h}.
        # These small API fixtures do not represent the complete XNU headers;
        # build_route_a_pacga.py still compiles the entire real sleh translation unit.
        compiler = shutil.which("cc") or shutil.which("clang")
        self.assertIsNotNone(compiler, "the bootstrap declaration test requires a C compiler")
        includes = "\n".join(line[1:] for line in (ROOT / pacga.PATCH).read_text().splitlines()
                             if line.startswith("+#include "))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            headers = {
                "arm64/route_a_pacga_qarma5.h": (ROOT / pacga.HEADER).read_text(),
                "arm64/route_a_pacga_abi.h": (ROOT / pacga.ABI_HEADER).read_text(),
                "kern/startup.h": "/* The extracted function has no STARTUP registration. */\n",
                "libkern/crypto/rand.h": "/* This API does not declare read_random. */\n",
                "sys/appleapiopts.h": "#ifndef __APPLE_API_STRICT_CONFORMANCE\n#define __APPLE_API_UNSTABLE\n#endif\n",
                "sys/random.h": "#include <sys/appleapiopts.h>\n"
                                "#if defined(KERNEL) && defined(__APPLE_API_UNSTABLE)\n"
                                "void read_random(void *buffer, u_int numBytes);\n#endif\n",
            }
            for name, content in headers.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            prefix = "#include <stdint.h>\n#include <stddef.h>\ntypedef unsigned int u_int;\n"
            body = "\nstatic struct route_a_pacga_key route_a_pacga_boot_key;\n"
            body += "static uint32_t route_a_pacga_ready;\nvoid panic(const char *, ...);\n"
            body += added_function("route_a_pacga_bootstrap", "void")
            body += "\nvoid declaration_probe(void) { route_a_pacga_bootstrap(); }\n"
            source = root / "declaration.c"
            for label, selected, defines, succeeds in (
                ("formal-kernel-header", includes, ["-DKERNEL=1"], True),
                ("previous-wrong-header", includes.replace("<sys/random.h>", "<libkern/crypto/rand.h>"),
                 ["-DKERNEL=1"], False),
                ("kernel-api-hidden", includes, ["-DKERNEL=1", "-D__APPLE_API_STRICT_CONFORMANCE=1"], False),
            ):
                with self.subTest(label=label):
                    source.write_text(prefix + selected + body)
                    command = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-fsyntax-only",
                               "-I", str(root), *defines, str(source)]
                    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
                    if succeeds:
                        self.assertEqual(result.returncode, 0, result.stderr)
                    else:
                        self.assertNotEqual(result.returncode, 0, "undeclared read_random was accepted")
                        self.assertIn("read_random", result.stderr)
                        self.assertRegex(result.stderr, "implicit|undeclared")

    def test_runtime_identity_is_explicit_and_bound_to_the_entire_linked_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            kernel = Path(tmp) / "synthetic-kernel"
            kernel.write_bytes(synthetic_kernel())
            binding = pacga.runtime_binding(pacga.ABI, kernel)
            self.assertEqual(binding["kernel"]["sha256"], hashlib.sha256(kernel.read_bytes()).hexdigest())
            self.assertFalse(binding["runtime_boot_verified"])
            with self.assertRaisesRegex(ValueError, "matching runtime kernel"):
                pacga.runtime_binding(pacga.ABI)
            with self.assertRaisesRegex(ValueError, "explicit"):
                pacga.runtime_binding("reject", kernel)
            changed = bytearray(kernel.read_bytes())
            changed[0x2000 + 40] ^= 1
            kernel.write_bytes(changed)
            with self.assertRaisesRegex(ValueError, "identity differs"):
                pacga.runtime_binding(pacga.ABI, kernel)

    def test_standalone_pipeline_requires_runtime_and_preserves_equal_width_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            kernel = Path(tmp) / "synthetic-kernel"
            kernel.write_bytes(synthetic_kernel())
            original = signed_fixture((0x9AC23020, 0xD65F0FFF))
            with self.assertRaisesRegex(ValueError, "matching runtime kernel"):
                rewrite_userland(original, plain_pointers=True, pacga_policy=pacga.ABI)
            output, report = rewrite_userland(original, plain_pointers=True,
                                             pacga_policy=pacga.ABI, pacga_kernel=kernel)
            self.assertEqual(len(output), len(original))
            self.assertEqual(struct.unpack_from("<2I", output, 0x400), (0xD4110401, 0xD65F03C0))
            self.assertEqual(output[0x500:0x510], original[0x500:0x510])
            self.assertEqual(report["instruction_counts"]["pacga"], 1)
            self.assertEqual(report["pacga_runtime"]["kernel"]["sha256"],
                             hashlib.sha256(kernel.read_bytes()).hexdigest())
            for words, reason in (
                ((0xD4100001, 0xD65F03C0), "namespace"),
                ((0xC85FFC20, 0x9AC23020, 0xC802FC20, 0xD65F03C0), "reservation"),
                # PACGA is only in the callee: source at BL must still refuse.
                ((0xC85FFC20, 0x94000004, 0xC802FC20, 0xD65F03C0,
                  0xD503201F, 0x9AC23020, 0xD65F03C0), "exclusive-state escape"),
                ((0xC85FFC20, 0xD65F03C0), "exclusive-state escape"),
            ):
                with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason):
                    rewrite_userland(signed_fixture(words), plain_pointers=True,
                                     pacga_policy=pacga.ABI, pacga_kernel=kernel)

    def test_actual_cache_driver_and_admission_bind_policy_runtime_and_receipts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kernel = root / "synthetic-kernel"
            kernel.write_bytes(synthetic_kernel())
            data = cache_bytes()
            section = 0x1000 + 104
            struct.pack_into("<Q", data, section + 40, 8)
            struct.pack_into("<I", data, section + 64, 0x80000408)  # structural stub entry
            struct.pack_into("<I", data, section + 72, 8)
            struct.pack_into("<2I", data, 0x1100, 0x9AC23020, 0xD65F0FFF)
            cache_path = root / "cache"
            cache_path.write_bytes(data)
            work = root / "proof"
            driver = module("prove-zeta-dyld-cache")
            # ProcessPool serializes real worker functions by module identity.
            # Keep the dynamically loaded CLI registered for the entire run.
            with mock.patch.dict(sys.modules, {driver.__name__: driver}):
                self.assertEqual(driver.main(["--cache", str(cache_path), "--work", str(work), "--jobs", "1",
                                              "--pacga-policy", pacga.ABI, "--pacga-kernel", str(kernel)]), 0)
            summary = json.loads((work / "summary.json").read_text())
            cache = dc.Cache(cache_path)
            try:
                with self.assertRaisesRegex(ValueError, "rules differ"):
                    validate_summary(cache, summary, work)
                edits = validate_summary(cache, summary, work, pacga_policy=pacga.ABI, pacga_kernel=kernel)
                self.assertEqual(edits[0].tolist(),
                                 [[0x1100, 0x9AC23020, 0xD4110401], [0x1104, 0xD65F0FFF, 0xD65F03C0]])
                changed = bytearray(kernel.read_bytes())
                struct.pack_into("<I", changed, 0x1000, 0xD503201F)
                kernel.write_bytes(changed)
                with self.assertRaisesRegex(ValueError, "rules differ"):
                    validate_summary(cache, summary, work, pacga_policy=pacga.ABI, pacga_kernel=kernel)
            finally:
                for member in cache.files:
                    member.close()
            self.assertFalse(driver.STATE)


    def test_cache_records_live_call_as_unlowerable_even_when_call_is_not_a_pac_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            kernel = root / "synthetic-kernel"
            kernel.write_bytes(synthetic_kernel())
            data = cache_bytes()
            words = (0xC85FFC20, 0x94000004, 0xC802FC20, 0xD65F03C0,
                     0xD503201F, 0x9AC23020, 0xD65F03C0)
            section = 0x1000 + 104
            struct.pack_into("<Q", data, section + 40, 4 * len(words))
            struct.pack_into("<I", data, section + 64, 0x80000408)
            struct.pack_into("<I", data, section + 72, 4 * len(words))
            struct.pack_into("<" + "I" * len(words), data, 0x1100, *words)
            cache_path = root / "cache"
            cache_path.write_bytes(data)
            work = root / "proof"
            driver = module("prove-zeta-dyld-cache")
            # ProcessPool serializes real worker functions by module identity.
            # Keep the dynamically loaded CLI registered for the entire run.
            with mock.patch.dict(sys.modules, {driver.__name__: driver}):
                self.assertEqual(driver.main(["--cache", str(cache_path), "--work", str(work), "--jobs", "1",
                                              "--pacga-policy", pacga.ABI, "--pacga-kernel", str(kernel)]), 1)
            summary = json.loads((work / "summary.json").read_text())
            blocked = [item for entry in summary["images"].values() for item in entry["unlowerable"]]
            self.assertEqual(len(blocked), 1)
            self.assertEqual(blocked[0]["word"], "0x94000004")
            self.assertIn("call with live reservation", blocked[0]["reason"])
            cache = dc.Cache(cache_path)
            try:
                with self.assertRaisesRegex(ValueError, "unlowerable"):
                    validate_summary(cache, summary, work, pacga_policy=pacga.ABI, pacga_kernel=kernel)
            finally:
                for member in cache.files:
                    member.close()
            self.assertFalse(driver.STATE)


    def test_probe_runner_timeout_and_signal_reap_owned_descendants(self):
        from route_a_pacga_probe import run as runner
        child = (
            "import os,signal,subprocess,sys,time\n"
            "from pathlib import Path\n"
            "grandchild=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])\n"
            "Path(sys.argv[2]).write_text(str(grandchild.pid))\n"
            "if sys.argv[1]=='signal': os.kill(os.getppid(),signal.SIGTERM)\n"
            "time.sleep(60)\n"
        )
        for mode in ("timeout", "signal"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                identity = runner.tool_identity(sys.executable)
                manifest = dict(complete=False, tools=dict(python=identity), frozen={}, commands=[])
                expected_error = subprocess.TimeoutExpired if mode == "timeout" else InterruptedError
                with runner.owned_children(), self.assertRaises(expected_error):
                    runner.execute([identity["invocation"], "-c", child, mode, str(root / "descendant.pid")],
                                   root, "controlled-" + mode, manifest, timeout=2)
                self.assertTrue((root / "descendant.pid").is_file())
                descendant = int((root / "descendant.pid").read_text())
                receipt = manifest["commands"][0]
                self.assertTrue(receipt["cleanup"]["group_absent"])
                self.assertTrue(receipt["cleanup"]["direct_child_reaped"])
                self.assertIn(descendant, [item["pid"] for item in receipt["cleanup"]["reaped_descendants"]])
                with self.assertRaises(ProcessLookupError):
                    os.killpg(receipt["pid"], 0)
                with self.assertRaises(ChildProcessError):
                    os.waitpid(descendant, os.WNOHANG)
                disk = json.loads((root / "report.json").read_text())
                self.assertFalse(disk["complete"])
                self.assertEqual(disk["commands"][0]["cleanup"], receipt["cleanup"])


    def test_probe_tools_preserve_multicall_invocation_and_reject_retargeting(self):
        from route_a_pacga_probe import run as runner
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "instrumented-driver"
            real.write_text('#!/bin/sh\nprintf "%s\\n" "$0"\n')
            real.chmod(0o755)
            alias = root / "ld.lld"
            alias.symlink_to(real.name)
            identity = runner.tool_identity(alias)
            self.assertEqual(identity["invocation"], str(alias))
            self.assertEqual(identity["realpath"], str(real))
            manifest = dict(complete=False, tools=dict(lld=identity), frozen={}, commands=[])
            with runner.owned_children():
                output = runner.execute([identity["invocation"]], root, "multicall", manifest)
            self.assertEqual(output.strip(), str(alias))
            other = root / "different-driver"
            other.write_bytes(real.read_bytes())
            other.chmod(0o755)
            alias.unlink()
            alias.symlink_to(other.name)
            with self.assertRaisesRegex(ValueError, "invocation changed"):
                runner.verify_tools(manifest["tools"])

    def test_failed_final_probe_report_cannot_remain_complete(self):
        from route_a_pacga_probe import run as runner
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "new-probe"
            args = SimpleNamespace(output=output, clang=sys.executable, lld=sys.executable,
                                   qemu=sys.executable, timeout=1)

            def synthetic_execute(command, directory, name, manifest, **_options):
                # Only the publication failure path is under test. No compiler,
                # executable ELF or QEMU is run by this injected environment.
                if "-o" in command:
                    (directory / command[command.index("-o") + 1]).write_bytes(b"synthetic fixture")
                if "-MF" in command:
                    source = directory / command[command.index("-c") + 1]
                    (directory / command[command.index("-MF") + 1]).write_text(
                        "fixture.o: " + shlex.quote(str(source)) + "\n")
                if name == "qemu-version":
                    return "QEMU emulator version 8.2.2 (synthetic publication fixture)\n"
                if name.startswith("qemu-"):
                    native = name == "qemu-native"
                    result = dict(schema="route-a-pacga-el0-probe-v1", cases=1024, native=native,
                                  ordinary_fallback=not native, result_fold="0000000000000000",
                                  production_return_gate=True, marker_lifecycle=True,
                                  isar1="0000000001000000" if native else "0000000000000000")
                    result.update({field: True for field in
                                   ("paper_vector", "gpr", "pc_lr_sp", "nzcv", "simd", "fpcr_fpsr")})
                    return "PACGA-PROBE " + json.dumps(result) + "\n"
                return "synthetic tool response\n"

            original_write = Path.write_text

            def fail_complete_receipt(path, text, *arguments, **keywords):
                if path.name == "report.json" and json.loads(text).get("complete") is True:
                    raise OSError("injected final report write failure")
                return original_write(path, text, *arguments, **keywords)

            with mock.patch.object(runner, "execute", synthetic_execute), \
                    mock.patch.object(Path, "write_text", fail_complete_receipt), \
                    self.assertRaisesRegex(OSError, "injected final report"):
                runner.run(args)
            report = json.loads((output / "report.json").read_text())
            self.assertIs(report["complete"], False)
            self.assertEqual(report["error"], "OSError")
            self.assertIn("injected final report", report["message"])


    def test_probe_dependency_closure_binds_resource_headers_and_rejects_drift(self):
        from route_a_pacga_probe import run as runner
        for failure in (None, "changed-resource-header", "undeclared-header"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                output = root / "probe"
                output.mkdir()
                source = output / "probe.c"
                source.write_text("/* synthetic compile dependency fixture */\n")
                resource = root / "resource" / "stdint.h"
                resource.parent.mkdir()
                resource.write_text("/* first resource-header generation */\n")
                extra = root / "extra.h"
                extra.write_text("/* undeclared compiler input */\n")
                manifest = dict(tools={}, frozen={"source": runner.file_identity(source)}, commands=[])
                command = [sys.executable, "-c", str(source), "-o", str(output / "probe.o")]

                def synthetic_execute(arguments, directory, name, receipt, **_options):
                    # No compiler runs: inject dependency output into the real
                    # closure-binding and final identity verification paths.
                    discovery = "-M" in arguments
                    dependencies = [source, resource]
                    if not discovery and failure == "changed-resource-header":
                        resource.write_text("/* a different compiler resource */\n")
                    if not discovery and failure == "undeclared-header":
                        dependencies.append(extra)
                    Path(arguments[arguments.index("-MF") + 1]).write_text(
                        "fixture.o: " + shlex.join(str(path) for path in dependencies) + "\n")
                    if not discovery:
                        Path(arguments[arguments.index("-o") + 1]).write_bytes(b"synthetic object")
                    receipt["commands"].append(dict(name=name, exit_code=0))
                    return ""

                with mock.patch.object(runner, "execute", synthetic_execute):
                    if failure is None:
                        records = runner.compile_with_dependencies(command, output, "compile", manifest)
                        self.assertIn(str(resource), records)
                        self.assertEqual(records[str(resource)], runner.file_identity(resource))
                        self.assertTrue(manifest["compilations"]["compile"]["complete"])
                    else:
                        with self.assertRaisesRegex(ValueError, "bound file changed|dependencies differ"):
                            runner.compile_with_dependencies(command, output, "compile", manifest)
                        self.assertFalse(manifest["compilations"]["compile"]["complete"])
                self.assertEqual([entry["name"] for entry in manifest["commands"]],
                                 ["compile-discover-headers", "compile"])

    def test_oracle_cpu_version_selection_and_guest_features_fail_closed(self):
        from route_a_pacga_probe import run as runner
        for version in ("8.2.0", "8.2.2", "9.2.4"):
            record = runner.oracle_cpu("QEMU emulator version " + version + " (distribution)\n")
            self.assertNotIn("pauth-qarma5", record["cpu"])
            self.assertIn("pauth-qarma3=off,pauth-impdef=off", record["cpu"])
        for version in ("10.0.0", "10.1.2"):
            self.assertIn("pauth-qarma5=on", runner.oracle_cpu("QEMU emulator version " + version)["cpu"])
        for version in ("QEMU emulator version 8.1.5", "unknown", "QEMU emulator version 10.0"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                runner.oracle_cpu(version)
        runner.verify_pauth_features({"isar1": "0000000001000000"}, native=True)
        runner.verify_pauth_features({"isar1": "0000000000000000"}, native=False)
        for value, native in (("0000000010000000", True), ("0000000000000000", True),
                              ("0000000001000000", False), ("0000000000000010", False),
                              ("1000000", True), (None, True)):
            with self.subTest(value=value, native=native), self.assertRaises(ValueError):
                runner.verify_pauth_features({"isar1": value}, native=native)

    def test_stage_compile_timeout_cli_defaults_and_boundary_values_are_forwarded(self):
        import build_route_a_pacga as stage
        result = dict(abi=pacga.ABI, compile_passed=True,
                      translation_units={unit: {"object": {}} for unit in ("sleh", "locore")},
                      kernel_linked=False, runtime_boot_verified=False)
        for value, expected in ((None, 300), ("1", 1), ("900", 900)):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                output = root / "not-created"
                argv = ["--xnu-work", str(root / "xnu"), "--recipe", str(root / "sleh.json"),
                        "--locore-recipe", str(root / "locore.json"), "--output", str(output),
                        "--expected-sleh-sha256", "0" * 64, "--expected-locore-sha256", "1" * 64,
                        "--expected-exception-asm-sha256", "2" * 64]
                if value is not None:
                    argv += ["--compile-timeout", value]
                with mock.patch.object(stage, "prepare", return_value=result) as prepare, \
                        mock.patch.object(sys, "stdout", io.StringIO()):
                    self.assertEqual(stage.main(argv), 0)
                prepare.assert_called_once_with(root / "xnu", root / "sleh.json", output, "0" * 64,
                    locore_recipe=root / "locore.json", expected_locore="1" * 64,
                    expected_exception_asm="2" * 64, compile_timeout=expected)
                self.assertFalse(output.exists())

    def test_invalid_stage_timeout_is_rejected_before_output_or_child_creation(self):
        import build_route_a_pacga as stage
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "not-created"
            argv = ["--xnu-work", str(root / "xnu"), "--recipe", str(root / "sleh.json"),
                    "--locore-recipe", str(root / "locore.json"), "--output", str(output),
                    "--expected-sleh-sha256", "0" * 64, "--expected-locore-sha256", "1" * 64,
                    "--expected-exception-asm-sha256", "2" * 64]
            with mock.patch.object(stage, "prepare", side_effect=AssertionError("invalid CLI reached prepare")):
                for value in ("0", "-1", "901", "1.5", "inf", "nan", "abc"):
                    with self.subTest(cli=value), mock.patch.object(sys, "stderr", io.StringIO()):
                        with self.assertRaises(SystemExit) as caught:
                            stage.main(argv + ["--compile-timeout", value])
                        self.assertEqual(caught.exception.code, 2)
                        self.assertFalse(output.exists())
            with mock.patch.object(stage, "run", side_effect=AssertionError("invalid API spawned a command")), \
                    mock.patch.object(stage, "execute", side_effect=AssertionError("invalid API spawned a compiler")):
                for value in (0, -1, 901, 1.5, True, False, "300", None):
                    with self.subTest(api=value), self.assertRaisesRegex(ValueError, "compile timeout"):
                        stage.prepare(root / "xnu", root / "sleh.json", output, "0" * 64,
                            locore_recipe=root / "locore.json", expected_locore="1" * 64,
                            expected_exception_asm="2" * 64, compile_timeout=value)
                    self.assertFalse(output.exists())

    def test_stage_postcompile_failures_leave_a_failed_terminal_receipt(self):
        import build_route_a_pacga as stage
        original_write, original_tools = Path.write_text, stage.verify_tools
        cases = [(None, None), (None, 1), (None, 900)]
        cases += [(failure, None) for failure in
                  ("locore-compile", "object-header", "dependencies-write", "prepared-source",
                   "shared-dependency", "configuration", "tool-recheck", "final-report")]
        for failure, compile_timeout in cases:
            with self.subTest(failure=failure, timeout=compile_timeout), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                xnu, work, output = root / "xnu", root / "build", root / "stage"
                work.mkdir()
                prepared = {}
                for relative in stage.SOURCES:
                    source = xnu / relative
                    source.parent.mkdir(parents=True, exist_ok=True)
                    # This fixture tests publication/error boundaries only.
                    # Production assembly execution has separate extracted-gate tests.
                    source.write_text("/* synthetic publication source: " + relative + " */\n")
                    prepared[relative] = hashlib.sha256(source.read_bytes()).hexdigest()
                (xnu / "osfmk/arm64/genassym.c").write_text("/* provenance fixture */\n")
                assym = work / "assym.s"
                assym.write_text("#define SS64_CPSR 272\n#define SS64_X18 152\n")
                resource = work / "shared-resource.h"
                resource.write_text("/* original resource generation */\n")
                recipes = {}
                for unit, relative in stage.UNITS.items():
                    previous = work / (unit + ".o")
                    previous.write_bytes(b"retained platform " + unit.encode())
                    temporary = str(work / "temporary-locore.s") if unit == "locore" else unit + ".o"
                    arguments = [sys.executable]
                    if unit == "locore":
                        arguments.append("-xassembler-with-cpp")
                    arguments += ["-c", str(xnu / relative), "-o", temporary]
                    recipe = work / (unit + ".o.json")
                    recipe.write_text(json.dumps(dict(file=str(xnu / relative), directory=str(work),
                                                       output=temporary, arguments=arguments)) + ",\n")
                    recipes[unit] = recipe
                options = dict(locore_recipe=recipes["locore"], expected_locore=prepared[stage.LOCORE],
                               expected_exception_asm=prepared[stage.EXCEPTION_ASM])
                if compile_timeout is not None:
                    options["compile_timeout"] = compile_timeout
                command_timeouts = {}

                def synthetic_run(arguments, *, cwd):
                    return pacga.XNU_COMMIT + "\n" if "rev-parse" in arguments else ""

                def synthetic_execute(arguments, directory, name, manifest, **kw):
                    command_timeouts[name] = kw.get("timeout", 60)
                    manifest["commands"].append(dict(name=name, exit_code=0,
                                                      timeout_seconds=kw.get("timeout", 60)))
                    if name == "compiler-version":
                        return "synthetic compiler publication fixture\n"
                    unit = name.split("-", 1)[0]
                    if name.endswith("-config"):
                        macros = "#define CONFIG_ROUTE_A_PACGA_SVC 1\n"
                        macros += "#define __ARM_KERNEL_PROTECT__ " + (
                            "1" if failure == "configuration" and unit == "locore" else "0") + "\n"
                        if unit == "locore":
                            macros += "#define __ASSEMBLER__ 1\n"
                        Path(arguments[arguments.index("-o") + 1]).write_text(macros)
                        return ""
                    dependencies = [directory / "source" / stage.UNITS[unit],
                                    directory / "source/osfmk/arm64/route_a_pacga_abi.h", resource]
                    dependencies += ([directory / "source/osfmk/arm64/route_a_pacga_qarma5.h"]
                                     if unit == "sleh" else [directory / "source" / stage.EXCEPTION_ASM, assym])
                    if failure == "shared-dependency" and name == "locore-discover-headers":
                        resource.write_text("/* substituted resource generation */\n")
                    Path(arguments[arguments.index("-MF") + 1]).write_text(
                        unit + ".o: " + shlex.join(str(path) for path in dependencies) + "\n")
                    if name.endswith("-compile"):
                        if failure == "locore-compile" and unit == "locore":
                            manifest["commands"][-1]["exit_code"] = 1
                            raise ValueError("injected locore compile failure")
                        header = struct.pack("<4I", 0xFEEDFACF, 0x0100000C, 0, 1)
                        Path(arguments[arguments.index("-o") + 1]).write_bytes(
                            b"invalid object!\n" if failure == "object-header" and unit == "locore"
                            else header + b"fixture")
                        if failure == "prepared-source" and unit == "locore":
                            (xnu / stage.LOCORE).write_bytes(b"changed prepared source")
                    return ""

                def controlled_write(path, text, *arguments, **keywords):
                    if failure == "dependencies-write" and path.name == "locore.dependencies.json":
                        raise OSError("injected dependencies publication failure")
                    if failure == "final-report" and path.name == "stage-report.json" and json.loads(text).get("compile_passed"):
                        raise OSError("injected final stage report failure")
                    return original_write(path, text, *arguments, **keywords)

                def controlled_tools(records, **options):
                    if failure == "tool-recheck":
                        raise ValueError("injected tool identity failure")
                    return original_tools(records, **options)

                with mock.patch.object(stage, "run", synthetic_run), \
                        mock.patch.object(stage, "execute", synthetic_execute), \
                        mock.patch.object(stage, "verify_tools", controlled_tools), \
                        mock.patch.object(Path, "write_text", controlled_write):
                    if failure is None:
                        result = stage.prepare(xnu, recipes["sleh"], output, prepared[stage.SOURCE], **options)
                        self.assertTrue(result["compile_passed"])
                    else:
                        with self.assertRaises((ValueError, OSError)):
                            stage.prepare(xnu, recipes["sleh"], output, prepared[stage.SOURCE], **options)
                report = json.loads((output / "stage-report.json").read_text())
                self.assertEqual(report["schema"], "route-a-pacga-stage-v2")
                self.assertIs(report["compile_passed"], failure is None)
                self.assertFalse(report["kernel_linked"])
                self.assertFalse(report["runtime_boot_verified"])
                self.assertEqual(set(report["translation_units"]), {"sleh", "locore"})
                self.assertIn("object", report["translation_units"]["sleh"])
                selected_timeout = 300 if compile_timeout is None else compile_timeout
                self.assertEqual(report["compile_timeout_seconds"], selected_timeout)
                self.assertEqual(command_timeouts["sleh-compile"], selected_timeout)
                if "locore-compile" in command_timeouts:
                    self.assertEqual(command_timeouts["locore-compile"], selected_timeout)
                if failure is None:
                    self.assertEqual(report["compile_exit_code"], 0)
                    self.assertEqual(command_timeouts, {
                        "compiler-version": 60, "sleh-discover-headers": 300, "sleh-config": 300,
                        "sleh-compile": selected_timeout, "locore-discover-headers": 300,
                        "locore-config": 300, "locore-compile": selected_timeout})
                    self.assertEqual(report["translation_units"]["locore"]["previous_object"]["name"], "locore.o")
                else:
                    self.assertIn("error", report)
                    self.assertIn("message", report)
                if failure in ("locore-compile", "configuration", "shared-dependency"):
                    self.assertNotIn("object", report["translation_units"]["locore"])

    def test_stage_recipe_binds_compact_assembly_and_uses_the_retained_object(self):
        import build_route_a_pacga as stage
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "locore.s"
            source.write_text("/* retained assembly recipe fixture */\n")
            (root / "locore.o").write_bytes(b"original platform object")
            path = root / "locore.o.json"
            recipe = dict(file=str(source), directory=str(root), output="/tmp/locore-temporary.s",
                          arguments=[sys.executable, "-xassembler-with-cpp", str(source),
                                     "-o", "/tmp/locore-temporary.s", "-c"])
            path.write_text(json.dumps(recipe) + ",\n")
            parsed, identity, previous = stage.recipe_for(path, source, "locore")
            self.assertEqual(parsed, recipe)
            self.assertEqual(previous, root / "locore.o")
            self.assertEqual(identity["sha256"], stage.sha(path))
            recipe["arguments"][1] = "-xassembler"
            path.write_text(json.dumps(recipe))
            with self.assertRaisesRegex(ValueError, "assembler-with-cpp"):
                stage.recipe_for(path, source, "locore")

    def test_actual_cpp_configuration_and_required_overlay_dependencies_fail_closed(self):
        import build_route_a_pacga as stage
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            macros = root / "macros.txt"
            base = "#define CONFIG_ROUTE_A_PACGA_SVC 1\n"
            for suffix, unit, accepts in (
                ("", "sleh", True), ("#define __ARM_KERNEL_PROTECT__ 0\n", "sleh", True),
                ("#define __ASSEMBLER__ 1\n", "locore", True),
                ("#define __ARM_KERNEL_PROTECT__ 1\n", "sleh", False),
                ("#define __ARM_KERNEL_PROTECT__ (1)\n", "sleh", False),
                ("#define CONFIG_ROUTE_A_PACGA_SVC 0\n", "sleh", False),
                ("#define __ASSEMBLER__ 1\n", "sleh", False),
                ("", "locore", False), ("#define __arm64e__ 1\n", "sleh", False),
            ):
                with self.subTest(suffix=suffix, unit=unit):
                    macros.write_text(base + suffix)
                    if accepts:
                        self.assertEqual(stage.read_configuration(macros, unit)["arm_kernel_protect"], 0)
                    else:
                        with self.assertRaises(ValueError):
                            stage.read_configuration(macros, unit)
            tree, xnu, assym = root / "overlay/source", root / "xnu", root / "assym.s"
            source = tree / stage.LOCORE
            required = {source, tree / stage.EXCEPTION_ASM,
                        tree / "osfmk/arm64/route_a_pacga_abi.h", assym}
            stage.validate_closure(required, source, tree, xnu, "locore", assym)
            for bad in (required - {assym}, required - {tree / stage.EXCEPTION_ASM},
                        required | {xnu / stage.EXCEPTION_ASM}, required | {tree / "osfmk/arm64/proc_reg.h"}):
                with self.assertRaises(ValueError):
                    stage.validate_closure(bad, source, tree, xnu, "locore", assym)

    def test_production_assembly_extraction_includes_the_original_fallback_and_reset(self):
        from route_a_pacga_probe import run as runner
        patch = (ROOT / pacga.PATCH).read_text()
        reset = runner.assembly_from_patch(patch, "ENTRY_RESET")
        gate = runner.assembly_from_patch(patch, "RETURN_GATE")
        self.assertIn("wzr, [x0, SS64_CPSR + ROUTE_A_PACGA_CPSR_BYTES]", reset)
        self.assertIn("wzr, [sp, SS64_CPSR + ROUTE_A_PACGA_CPSR_BYTES]", gate)
        self.assertIn("MACHDEP_TPIDR_FLAG_PRESERVE_X18_SHIFT", gate)
        self.assertIn("ldr\t\tx18, [sp, SS64_X18]", gate)
        self.assertNotIn("SS64_ESR", gate)
        for name in ("ENTRY_RESET", "RETURN_GATE"):
            broken = patch.replace("ROUTE_A_PACGA_" + name + "_BEGIN", "REMOVED", 1)
            with self.assertRaisesRegex(ValueError, "markers"):
                runner.assembly_from_patch(broken, name)

    def test_production_kernel_protect_and_private_layout_guards_are_effective(self):
        compiler = shutil.which("cc") or shutil.which("clang")
        self.assertIsNotNone(compiler)
        added = "\n".join(line[1:] for line in (ROOT / pacga.PATCH).read_text().splitlines()
                          if line.startswith("+") and not line.startswith("+++"))
        first = added.index("_Static_assert(sizeof(((arm_saved_state64_t *)0)->cpsr)")
        last = added.index("/* Public identity only:", first)
        assertions = added[first:last]
        prefix = ('#include <stddef.h>\n#include <stdint.h>\n#include "' + str(ROOT / pacga.ABI_HEADER) + '"\n'
                  '#define PSR64_MODE_MASK 0x1f\n#define ESR_EC_SVC_64 0x15\n#define ESR_EC_SHIFT 26\n')
        structure = ("typedef struct { uint64_t x[29], fp, lr, sp, pc; "
                     "uint32_t cpsr, reserved; uint64_t far, esr; } arm_saved_state64_t;\n")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "guards.c"
            for label, body, defines, accepts in (
                ("supported", structure, ["-DCONFIG_ROUTE_A_PACGA_SVC=1"], True),
                ("protected-rejected", structure, ["-DCONFIG_ROUTE_A_PACGA_SVC=1", "-D__ARM_KERNEL_PROTECT__=1"], False),
                ("disabled-unchanged", structure, ["-DCONFIG_ROUTE_A_PACGA_SVC=0", "-D__ARM_KERNEL_PROTECT__=1"], True),
                ("wrong-padding-width", structure.replace("cpsr, reserved", "cpsr; uint16_t reserved"), [], False),
                ("wrong-padding-position", structure.replace("cpsr, reserved", "cpsr, inserted, reserved"), [], False),
            ):
                with self.subTest(label=label):
                    path.write_text(prefix + body + assertions)
                    result = subprocess.run([compiler, "-std=c11", "-Werror", "-fsyntax-only",
                                             *defines, str(path)], capture_output=True, text=True, timeout=60)
                    self.assertEqual(result.returncode == 0, accepts, result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
