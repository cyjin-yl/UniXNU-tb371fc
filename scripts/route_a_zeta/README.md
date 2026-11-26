# Pinned zeta conversion research tools

These Python sources originate from [none24smu/UniXNU-zeta](https://github.com/none24smu/UniXNU-zeta)
at commit `eb489285a1d9153872f00c93ebb519a269b249b5`. The original BSD-2-Clause-Patent
license is retained in `LICENSE`; each original file's SHA-256 and size are recorded
in `upstream/route-a-sources.json`. The hashes identify upstream inputs, not these
adapted files. No source from the unlicensed Bergamota converter was copied.

## Local changes

- The PAuth adapter invokes `arm64_lowering.instructions.lower` with the explicit
  plain-pointer ABI contract. It rejects PACGA by default, unsupported loads and
  other unadmitted forms. An explicit [QARMA5 / SVC ABI candidate](../../docs/ROUTE_A_PACGA_ABI.md)
  requires a matching runtime kernel, source SVC namespace census and live
  exclusive-state admission. Its execution validation is pending. Hint-space
  encodings remain unchanged. No pointer authentication is provided by this policy.
- The cache prover produces a `route-a-cache-proof-v1` manifest containing SHA-256,
  UUID and byte size for the complete ordered main/subcache set, the source image
  inventory, hashes of the analysis and lowering source files, decoder versions
  (Capstone, its native library, NumPy and `llvm-mc`, or explicit null if absent),
  and each NPZ result.
- The cache rewriter validates that manifest before creating its output directory.
  It requires all code-bearing images and stub islands, rejects partial `--only`
  results and any unproven/unlowerable candidates, recomputes every replacement,
  checks offsets and originals, and performs a full PAuth candidate census.
  Candidates retained as data must belong to a jump table reconstructed from a
  hardened dispatch in the source. Omitted or duplicate candidates are rejected.
- `--only` and runs with unproven/unlowerable instructions return status 1 while
  retaining their diagnostic output. Such reports cannot authorize a rewrite.
- The cache reader validates header/table bounds, subcache suffixes and UUIDs,
  mapping ownership, image load commands, and version-5 slide-chain page bounds.
  Other cache header/slide layouts need separate support; they are rejected.
- Standalone and tree rewriting use the strict local Mach-O parser. Each edit is
  checked against its code/data boundaries. CodeDirectory platform/runtime fields
  are preserved unless explicitly overridden with `--platform-identifier` and
  `--hardened-runtime` / `--no-hardened-runtime`. The platform byte is not an OS
  version selector. Upstream's forced 26-era signing policy is not the default.
- Standalone signing reads the same validated CodeDirectory layout as the
  independent page verifier. Versioned headers through `0x20600` and a consistent
  effective `codeLimit64` are supported. Nonzero scatter, pre-encryption and
  linkage fields need other signing rules and are rejected. The inherited signer
  still requires 4 KiB SHA-256 code pages and an ad-hoc signature.

The single-image Python entry point is:

```python
rewritten, report = rewrite(original, platform_identifier=None, hardened_runtime=None)
```

The cache manifest API is in `arm64_lowering.proof`:

```python
sealed = seal_summary(cache, summary, work_dir, partial=False)
edits_by_file = validate_summary(cache, sealed, work_dir)
```

`edits_by_file[index]` is a NumPy `uint64` array with columns
`[file_offset, original_word, replacement_word]`. The sealed NPZ arrays contain
`edits` (N×5: VA, file offset, original, replacement, evidence grade), `unproven`
(N×2: VA, word), and `kept_data` (N×3: VA, file offset, word); the upstream `reached`
array is retained for diagnostics.

## POE2 decoding and the ISA boundary

The CFG decoder explicitly recognizes the four `TCHANGEF` / `TCHANGEB` register
and immediate forms from `FEAT_S1POE2`. Capstone 5.0.6 and the older LLVM fallback
can leave these words undecoded, which rejects a strict tentative walk through
an otherwise declared function and propagates that rejection to its callers.
Recognition checks the exact fixed bits, register fields, seven-bit immediate
and `NB` bit. It grants no roots: function starts, unwind information, entry
points and the existing strict control-flow checks still determine admission.
Reserved neighboring encodings remain undecoded, and no address whitelist is
used. The regression fixtures contain original synthetic code only.

Encoding vectors come from LLVM's
[arm-poe2.s](https://github.com/llvm/llvm-project/blob/main/llvm/test/MC/AArch64/arm-poe2.s),
git blob `dbed9ba599067923194b15c63e365c8a4f2d38e6`.
The normal fall-through classification follows LLVM's TableGen model:
`TCHANGERegInst` / `TCHANGEImmInst` inherit `I`, `EncodedI`, `AArch64Inst`, then
`Instruction`, without overriding the default false branch, call, return,
barrier or terminator flags. The four definitions add the `HasS1POE2` predicate.
The inspected primary sources at commit
`8ac298779c251819b6bab7739464547ee014aabd`, retrieved on 2026-11-23, are:

| Source | Content SHA-256 |
| --- | --- |
| [AArch64InstrFormats.td](https://github.com/llvm/llvm-project/blob/8ac298779c251819b6bab7739464547ee014aabd/llvm/lib/Target/AArch64/AArch64InstrFormats.td) | `78245fff9e98387145b679cc48fe4ea04ebe602e5d6f91ed2916314bb7c28ed8` |
| [AArch64InstrInfo.td](https://github.com/llvm/llvm-project/blob/8ac298779c251819b6bab7739464547ee014aabd/llvm/lib/Target/AArch64/AArch64InstrInfo.td) | `865d28d1cbbf0787078beca33ab109c5e29dc811a635230cfce29ee322fd4173` |
| [Target.td](https://github.com/llvm/llvm-project/blob/8ac298779c251819b6bab7739464547ee014aabd/llvm/include/llvm/Target/Target.td) | `0455f3fb04aa22ed1949a693c6e4577a77591768569e46fb3f2f364dde26f2b9` |

This is implementation-level evidence for CFG discovery. Arm's
[ESR_EL1 specification](https://support.arm.com/documentation/111107/2026-09/AArch64-Registers/ESR-EL1--Exception-Syndrome-Register--EL1-)
also identifies the four forms in Illegal TIndex Change exceptions. The decoder
does not claim that the instructions cannot trap or that their permission-state
effects are emulated.

Every recognized POE2 word is retained unchanged. The standalone rewrite report
lists each proven site under `retained_isa_requirements`, with the feature name,
mnemonic counts, VA, file offset and original word. It records
`instructions_unchanged: true`, `native_on_a77: false` and
`runtime_dispatch_verified: false`. `target_isa_audited` remains false. Correct
runtime dispatch for every retained site, or a separate semantic implementation,
must be established before native execution on A77. This targeted inventory also
leaves the complete remaining ISA audit to a separate pass.

## Scope and dependencies

Python, NumPy and Capstone are required. The inherited CFG decoder invokes
`llvm-mc` for instruction words Capstone cannot decode; those words being decoded
does not establish their availability on Cortex-A77. Unknown A77 ISA requirements,
loader/fixup contracts, dynamic/JIT code, trust policy and whole-system behavior
remain separate work. The ad-hoc signer supports the upstream's narrow SHA-256
CodeDirectory layout, not every possible signing format.

These tools emit local research artifacts. A passing PAuth proof is not a
whole-ISA compatibility proof, a cryptographically authenticated attestation, a
boot result, or evidence that iPadOS 27/macOS 27 can start on TB371FC. Do not deploy
outputs before the independent ISA, loader, kernel and hardware gates pass.
