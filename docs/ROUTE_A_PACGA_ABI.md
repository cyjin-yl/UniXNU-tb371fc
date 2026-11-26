# PACGA software ABI for ordinary ARM64

This is an **opt-in implementation candidate**, not a completed system conversion
or boot result. Default lowering still rejects PACGA. The ABI, source patch,
rewriter policy and target kernel must be selected together. A kernel carrying a
descriptor is a build artifact; its descriptor alone does not attest to a boot.

## Why PACGA needs its own operation

PACGA signs two arbitrary 64-bit values. It is not a pointer-normalization
instruction. LLVM describes generic signatures as keyed data signatures whose
producer and consumer recompute the same value; the numeric signature and
algorithm are implementation dependent.
[LLVM API](https://github.com/llvm/llvm-project/blob/main/clang/lib/Headers/ptrauth.h)
and [LLVM intrinsic](https://github.com/llvm/llvm-project/blob/main/llvm/docs/PointerAuth.md)
are the interface references.

The earlier full-cache diagnostic recorded 728 PACGA candidates: Foundation 336,
CoreGraphics 212, CoreFoundation 101, JavaScriptCore 70, libobjc 7, and
libsystem_trace 2. This is a diagnostic inventory, not evidence that every
producer and consumer has been admitted by the newer closure proof. The observed
register forms included 489 destination/modifier aliases, 173 destination/source
aliases, and five XZR source operands. The supplied image set had no observed SP
modifier or XZR destination, but the implementation covers those architectural
forms as well.

Representative uses include chained signatures followed by comparisons, stored
high-bit fields, and string hashes ending in a shift by 32. Apple's public
[objc4 named-class table implementation](https://github.com/apple-oss-distributions/objc4/blob/fb265098298302243cd7eeaa1f63f0ba7786dd9a/runtime/objc-runtime-new.mm)
computes its generic hash for a runtime-allocated table; its
[preoptimized-cache disguise](https://github.com/apple-oss-distributions/objc4/blob/fb265098298302243cd7eeaa1f63f0ba7786dd9a/runtime/objc-cache.mm)
also creates and checks a signature at runtime. These examples explain why
constant results and register-dependent ad hoc hashes are inadmissible.

## Value and key contract

`qarma5-svc-v1` computes QARMA-64-5 using the Arm S-box, a 64-bit data value, a
64-bit modifier, and a 128-bit key. It returns bits 63:32 of the block result in
bits 63:32 and clears bits 31:0. The implementation follows the published
[QARMA specification and test vector](https://eprint.iacr.org/2016/444).
[QEMU's architected implementation](https://github.com/qemu/qemu/blob/v9.2.0/target/arm/tcg/pauth_helper.c)
is an independent execution oracle; its source is not linked or copied into
this runtime.

One key is generated per kernel boot with XNU `read_random`, after the source
provider finishes POST and `register_and_init_prng` at SYSCTL/LAST. The new
initializer runs at EARLY_BOOT/FIRST. Key bytes remain in kernel memory and are
not included in descriptors, stage reports or public evidence. The ready flag
is published only after the random request returns; premature use and duplicate
initialization panic. There is no fixed key or early-random fallback.

The boot scope makes recomputation consistent across threads, fork and exec.
It is a deliberate new ordinary-ARM64 ABI choice. It does **not** reproduce
Apple's hardware algorithm, key values, process isolation, pointer authentication
or signature values from an earlier execution. Every interacting producer and
consumer must use this ABI. Previously persisted/imported signatures, unconverted
code, and JIT-emitted PACGA are not automatically qualified by this implementation.

The ordering and saved-state references are pinned XNU 12377.121.6:
[startup stages](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/osfmk/kern/startup.h),
[random provider](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/osfmk/prng/prng_random.c),
[saved state](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/osfmk/mach/arm/thread_status.h),
and [exception dispatch](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/osfmk/arm64/sleh.c).

## Four-byte instruction and exception contract

A proven instruction `PACGA Xd, Xn, Xm|SP` becomes one SVC:

```text
immediate = 0x8000 | d | (n << 5) | (m << 10)
word      = 0xd4000001 | (immediate << 5)
```

The allocated immediate range is 0x8000–0xffff. Values outside it retain XNU's
ordinary SVC dispatcher. The source census includes preexisting words in this
reserved namespace, so executable or unresolved collisions block conversion;
table data still requires the existing structural data proof.

The handler is reached only after XNU validates an AArch64 EL0 SVC. It runs
before `handle_svc`, syscall tracing, syscall-number lookup and errno handling.
Both operands are captured before writing any destination:

| Register field | Register 0–30 | Register 31 |
| --- | --- | --- |
| `Rn` data | Full register value | Zero |
| `Rm` modifier | Full register value | Full user SP |
| `Rd` destination | Replace only that register | Discard result |

Every other general register, SP, saved PC and CPSR/NZCV is preserved. LR or FP
changes only when it is explicitly the destination. The saved SVC PC already
points to the following instruction, so the handler does not increment it.

An exception may clear the local exclusive monitor. The new proof policy
therefore rejects PACGA reachable inside a live load-exclusive/store-exclusive
region. The check follows both conditional edges and proven jump-table targets;
store-exclusive, CLREX and an existing exception end a path. A call does **not**
clear the tracked reservation. A live call, return, unknown indirect branch or
edge outside the proven instruction owner is an explicit
`unsupported exclusive-state escape` blocker. Call fallthrough remains live,
so `ldaxr → bl → pacga → stlxr` cannot evade the check. The cache result records
the escaping instruction and reason even when it is not itself a PAC candidate;
the standalone rewriter rejects the escape before making edits.

Accepting cross-call reservations would require an interprocedural state proof
over every affected caller and return path. Starting the callee as a closed-state
root is insufficient. All executable code in a process must participate in this
admission contract; converting one module does not qualify an unexamined caller
or JIT. The software trap also changes timing and exception visibility; the
tests do not claim cycle-accurate instruction emulation.

## Build, bind and rewrite

The source patch is [route-a-pacga-svc-12377.patch](../patches/route-a-pacga-svc-12377.patch);
the portable helper is [pacga_qarma5.h](../scripts/arm64_lowering/runtime/pacga_qarma5.h).
The existing kernel preparer and default link remain unchanged.

[build_route_a_pacga.py](../scripts/build_route_a_pacga.py) requires a fixed XNU
worktree, the actual `sleh.o.json` recipe and the reviewed prepared `sleh.c`
digest. It copies only that translation unit into a new overlay, applies the
patch there, and compiles with ordinary Armv8-A and general registers only.
It records the original and replacement object digests, compile command,
dependencies, helper identity and provider prerequisite. Run the command inside
the isolated CT through the host's `agent-heavy` gate.

```sh
python3 scripts/build_route_a_pacga.py \
  --xnu-work /absolute/path/to/prepared-xnu \
  --recipe /absolute/path/to/sleh.o.json \
  --expected-sleh-sha256 REVIEWED_PREPARED_SHA256 \
  --output /absolute/path/to/new-pacga-stage
```

The resulting object must be explicitly included in the reviewed kernel link
alongside the working random provider. Only `sleh.o` and the new helper are in
this overlay; the stage does not silently change another component.

The linked kernel retains a non-secret `__DATA_CONST,__unixnu_pacga` descriptor.
It binds the exact helper, patch and ABI contract. The validator checks its
geometry, ordinary-arm64 architecture and identity, and hashes the entire
linked kernel. The same binding appears in proof rules and the conversion
report. The descriptor relies on a trusted build producer; it is not a signature
or a proof of kernel execution.

```sh
python3 scripts/route_a_zeta/prove-zeta-dyld-cache.py \
  --cache /absolute/path/to/original-cache --work /absolute/path/to/new-proof \
  --jobs 1 --pacga-policy qarma5-svc-v1 \
  --pacga-kernel /absolute/path/to/linked-matching-kernel
```

The cache rewriter and standalone `route_a.py rewrite` take the same two PACGA
options. Missing/mismatched runtime, stale rules or input, unresolved code/data,
namespace collisions, active exclusive reservations or unsupported escapes, incomplete closure and
partial receipts remain blockers. Existing proof arrays cannot be reused under
the new policy. All original signature-page, FIPS and trust-input checks remain.

## Validation boundaries

The committed tests are synthetic and operate on the actual new C and Python
code. They cover the published full-block known answer and PACGA truncation,
all 32,768 register combinations, aliasing, XZR versus SP, Rd31 discard,
preservation of the whole saved state, readiness/failure behavior, ordinary SVC
fallback, reserved-namespace rejection, exclusive-window rejection, and the
actual cache-driver/receipt/admission path.

The separate [QEMU probe](../scripts/route_a_pacga_probe/run.py) builds two
freestanding ELF fixtures from the actual helper and the new handler bodies
extracted from the production patch. One runs original PACGA at EL0 on
`max,pauth-qarma5=on,pauth-qarma3=off,pauth-impdef=off`; the other runs the
replacement SVC on `cortex-a57`. The guest checks the generic-authentication
feature fields as well as the result. QEMU 10 defaults to its implementation
defined algorithm unless QARMA5 is selected explicitly
([fixed QEMU documentation](https://github.com/qemu/qemu/blob/v10.0.0/docs/system/arm/cpu-features.rst)).

Both fixtures use 1,024 public deterministic vectors, including the paper's
known answer and every register index. They compare the delivered GPRs, PC, LR,
SP, NZCV, V0–V31, FPCR and FPSR. The SVC fixture also checks that an ordinary
immediate returns false from the new handler and reaches its fixture dispatcher.
The ELF startup and exception vectors are test infrastructure; they do not
substitute for an XNU runtime test. Public test keys are never used by the
production initializer.

```sh
python3 -m unittest discover -s tests -p test_route_a_pacga.py -v
python3 scripts/route_a_pacga_probe/run.py --output /absolute/path/to/new-probe
```

Run the compiler and QEMU jobs through the required host `agent-heavy` gate and
the agreed resource window. The probe binds the actual clang, explicitly selected lld and QEMU executable
hashes and file generations before and after execution. Its staged sources,
objects and ELF files are read-only and checked at each invocation and at
completion. It retains commands, hashes, logs and a complete-or-failed report.
On Linux it uses one owned process group per command and a local child subreaper
to terminate and reap descendants after completion, timeout, SIGINT, SIGTERM or
SIGHUP; cleanup results are recorded. SIGKILL and host loss cannot run a finalizer
and do not produce a completed report. The real `sleh.o` stage shares this
bounded compiler execution helper. Neither tool creates a persistent VM.

Execution status for this implementation candidate is **pending**. The host
tests, a real `sleh.c` translation-unit compile, the QEMU probe, a linked
candidate with the provider/key startup order verified, fresh full-cache proof,
and a Darwin process execution are distinct gates. Until their execution reports
are available, this page does not mark them as passed and does not claim TB371FC
or OS boot success.
