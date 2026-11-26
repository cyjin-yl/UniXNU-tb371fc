"""PACGA ABI encoding, real C state semantics, and fail-closed pipeline gates.

All images and keys here are synthetic. The C is extracted from the production
patch and includes the production helper. A separate QEMU probe compares the
software result with architected PACGA; neither test is a Darwin boot claim.
"""
from pathlib import Path
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

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
    unsigned cases = 0;
    for (unsigned n = 0; n < 32; ++n) {
        for (unsigned m = 0; m < 32; ++m) {
            uint64_t value = n == 31 ? 0 : registers[n];
            uint64_t result = route_a_pacga_signature(value, registers[m], &public_key);
            for (unsigned d = 0; d < 32; ++d) {
                arm_saved_state_t state = original, expected = original;
                if (d != 31) memcpy((uint8_t *)&expected.state + 8 * d, &result, 8);
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
            code = "#include " + json.dumps(str(ROOT / pacga.HEADER)) + "\n" + HOST_PREAMBLE
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
                identity = runner.file_identity(sys.executable)
                manifest = dict(complete=False, tools=dict(python=identity), frozen={}, commands=[])
                expected_error = subprocess.TimeoutExpired if mode == "timeout" else InterruptedError
                with runner.owned_children(), self.assertRaises(expected_error):
                    runner.execute([identity["path"], "-c", child, mode, str(root / "descendant.pid")],
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
