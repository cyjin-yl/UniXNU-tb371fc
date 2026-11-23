"""Compile the actual fileset panic helper before/after the Route A patch.

The small original helper below is from UniXNU 8542980d, file
patches/xnu-12377/fileset-unmapped-call.patch (BSD-2-Clause-Patent).
Copyright (c) 2026, UniXNU contributors. All rights reserved.
License terms are retained in the repository's LICENSE.

These are real Clang target checks, not a complete XNU build or execution test.
Set ROUTE_A_FILESET_CLANG to select the verified custom compiler explicitly.
"""
from pathlib import Path
import os
import re
import shutil
import struct
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "patches/route-a-fileset-unmapped-ptrauth.patch"
ORIGINAL = r'''typedef __UINT64_TYPE__ uint64_t;
__attribute__((noreturn, format(printf, 1, 2)))
void panic(const char *, ...);

__attribute__((noinline, noreturn, used))
void
unixnu_fileset_unmapped(uint64_t arg0, uint64_t arg1)
{
	panic("fileset: original component called an unmapped kernel function from %p (x0 0x%llx x1 0x%llx)",
	    __builtin_ptrauth_strip(__builtin_return_address(0), 0), arg0, arg1);
}
'''


class FilesetPtrauthCompileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        chosen = os.environ.get("ROUTE_A_FILESET_CLANG")
        cls.clang = shutil.which(chosen) if chosen else next(
            (path for name in ("clang-24", "clang-23", "clang-22", "clang-21",
                               "clang-20", "clang-19", "clang")
             if (path := shutil.which(name))), None)
        if not cls.clang:
            raise unittest.SkipTest("Clang unavailable; fileset target compilation was not verified")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="route-a-fileset-")
        self.addCleanup(self.temp.cleanup)
        self.tree = Path(self.temp.name)
        self.source = self.tree / "osfmk/kern/debug.c"
        self.source.parent.mkdir(parents=True)
        self.source.write_text(ORIGINAL)

    def apply_fix(self):
        for args in (("--check",), ()):
            result = subprocess.run(["git", "apply", *args, str(PATCH)], cwd=self.tree,
                                    text=True, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)

    def compile(self, name, *, target="arm64-apple-ios27.0", march="armv8-a", cpu="generic",
                extra=(), kind="ir", success=True, feature_checks=""):
        source = self.tree / (name + ".c")
        source.write_text(feature_checks + "\n" + self.source.read_text())
        extension, mode = {"ir": ("ll", ("-S", "-emit-llvm")),
                           "object": ("o", ("-c",)),
                           "assembly": ("s", ("-S",))}[kind]
        output = self.tree / (name + "." + extension)
        args = [self.clang, "-target", target, "-mcpu=" + cpu, "-march=" + march, "-ffreestanding",
                "-O1", "-Werror", "-fno-stack-protector", "-fno-discard-value-names",
                *extra, *mode, str(source), "-o", str(output)]
        result = subprocess.run(args, text=True, capture_output=True, timeout=30)
        if success:
            self.assertEqual(result.returncode, 0, repr(args) + "\n" + result.stderr)
            return output.read_bytes() if kind == "object" else output.read_text()
        self.assertNotEqual(result.returncode, 0, "unconditional strip unexpectedly compiled")
        return result.stderr

    def assert_panic_contract(self, ir):
        # LLVM 24 overloads the pointer result; older LLVM spells it without .p0.
        self.assertRegex(ir, r"call[^\n]*@llvm\.returnaddress(?:\.p0)?\(i32 0\)")
        self.assertRegex(ir, r"call[^\n]*@panic\([^\n]*i64[^\n]*%arg0[^\n]*i64[^\n]*%arg1")
        self.assertIn("unreachable", ir)
        self.assertIn("fileset: original component called an unmapped kernel function", ir)

    def test_original_helper_fails_on_plain_arm64(self):
        error = self.compile("original", success=False)
        self.assertRegex(error, r"does not support pointer authentication|unknown builtin.*__builtin_ptrauth_strip")

    def test_plain_arm64_has_no_pauth_and_keeps_panic(self):
        self.apply_fix()
        checks = ("#if __has_feature(ptrauth_calls) || __has_feature(ptrauth_intrinsics) || defined(__PTRAUTH__)\n"
                  "#error plain test unexpectedly has pointer authentication\n#endif\n")
        ir = self.compile("plain-ir", feature_checks=checks)
        self.assert_panic_contract(ir)
        self.assertNotIn("llvm.ptrauth.", ir)
        assembly = self.compile("plain-asm", kind="assembly", feature_checks=checks)
        # XPACLRI is HINT #7 on pre-PAuth CPUs; XPACI/XPACD require PAuth.
        # Match instruction lines only, not comments or the panic string.
        self.assertNotRegex(assembly, r"(?m)^\s*(?:paci\w*|auti\w*|xpaci|xpacd|pacga|retaa|retab|braa\w*|brab\w*|blraa\w*|blrab\w*)\b")
        obj = self.compile("plain-object", kind="object", feature_checks=checks)
        self.assertEqual(struct.unpack_from("<4I", obj), (0xFEEDFACF, 0x0100000C, 0, 1))

    def test_arm64e_keeps_strip_with_original_key(self):
        self.apply_fix()
        checks = ("#if !__has_feature(ptrauth_calls) || !( __has_feature(ptrauth_intrinsics) || defined(__PTRAUTH__) )\n"
                  "#error arm64e test must retain pointer authentication\n#endif\n")
        ir = self.compile("arm64e-ir", target="arm64e-apple-ios27.0", march="armv8.3-a", cpu="apple-a12",
                          feature_checks=checks)
        self.assert_panic_contract(ir)
        self.assertRegex(ir, r"call[^\n]*@llvm\.ptrauth\.strip\(i64[^\n]*, i32 0\)")
        obj = self.compile("arm64e-object", target="arm64e-apple-ios27.0", march="armv8.3-a", cpu="apple-a12",
                           kind="object", feature_checks=checks)
        magic, cpu, subtype, filetype = struct.unpack_from("<4I", obj)
        self.assertEqual((magic, cpu, subtype & 0xFFFFFF, filetype), (0xFEEDFACF, 0x0100000C, 2, 1))

    def test_explicit_intrinsics_without_pauth_calls_keep_strip(self):
        self.apply_fix()
        checks = ("#if __has_feature(ptrauth_calls) || !( __has_feature(ptrauth_intrinsics) || defined(__PTRAUTH__) )\n"
                  "#error this test needs intrinsics without the arm64e call ABI\n#endif\n")
        ir = self.compile("intrinsics-ir", march="armv8.3-a", extra=("-fptrauth-intrinsics",),
                          feature_checks=checks)
        self.assert_panic_contract(ir)
        self.assertRegex(ir, r"call[^\n]*@llvm\.ptrauth\.strip\(i64[^\n]*, i32 0\)")


if __name__ == "__main__":
    unittest.main()
