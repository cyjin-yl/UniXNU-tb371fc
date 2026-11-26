# Conditional disabled ProtectedStack contract

This analyzer composes the complete, byte-pinned default policy, RuntimeState and
ProtectedStack constructors, MM setter and stack query in the original 24A446
standalone dyld. The exact Process policy call/store is bound to its complete
containing function's byte hash; the containing function is not claimed closed.
Its result is a conditional leaf contract. It does not prove the caller's actual
control flow, all later writers, shared-cache handoff, lowering or runtime boot.

The relevant invariant after publication has a nonnull protected-stack pointer:

```
MM.hardware byte +0x20 == 0
MM.protected_stack pointer +0x30 == runtime object +0x4f8
bytes [runtime +0x4f8, runtime +0x538) == zero
stack query on that same pointer returns zero
```

Checking only `MM.hardware == 0` is insufficient: the nonnull protected-stack
path is evaluated before the ordinary hardware-flag path in several wrappers.
The zero stack fields make the observed query's equality short circuit bypass
the thread-ID read and pointer-authentication path.

## What the source binds

The production entry first requires the exact standalone input SHA256 and size,
then verifies each complete function byte extent and the `dyld_hw_tpro` key.
It reuses the existing explicit-instruction abstract interpreter. The checker
records both its own source hash and the imported interpreter's source hash.

| Phase | Complete byte range | Conditional postcondition |
|---|---|---|
| Default policy | `0x21264..0x212f0` | Key absence returns zero |
| Process policy publication | Complete owner `0x1fd80..0x202d4`; local edge `0x1ffdc..0x1ffe8` | Returned zero is stored at Process +0x101, or Config +0x111 |
| Runtime constructor | `0x3c4a8..0x3c7e8` | Reads the same Config +0x111 and calls the stack constructor at runtime +0x4f8 |
| Nested stack constructor | `0x3cb2c..0x3cb68` | Disabled argument leaves all 64 bytes zero and skips enable |
| MM setter | `0x3ccf0..0x3ccf8` | The MM points to the same runtime subobject |
| Stack query | `0x32020..0x320c8` | The installed zero object returns false |

Each phase consumes the previous phase's abstract memory. A fresh object or a
similar offset cannot substitute for the actual pointer carried through the
composition. A known return value cannot hide an opaque nested call: every
unknown callee, unknown alias write, exception alternative or unsupported effect
keeps the leaf contract open, even if later stores restore the observed bytes.

Every decoded memory access must also fit a named live extent: the fresh stack,
the 0x340-byte Config, the 0x538-byte RuntimeState or the 0x58-byte global MM.
An unknown address or out-of-range access remains unresolved even when the read
value is unused or a later store restores the tracked fields.

## Caller binding remains separate

The constructor's real call in `RuntimeState` loads its boolean from
`ProcessConfig +0x111`; it does not load the MM hardware byte. The checked local
edge calls default policy at `0x1ffe0` and stores its return byte at `0x1ffe4`.
The Process subobject begins at Config +0x10. The complete RuntimeState
constructor then reads Config +0x111 at `0x3c7cc` and calls the nested constructor
at `0x3c7d4`, with its object pointer derived by adding 0x4f8.

The intervening Process/ProcessConfig callers have other calls and branches.
They still need effect contracts to preserve this field and the config identity.
The runtime object identity must also be traced through the actual setup caller
to the MM setter. The local store binding does not cover these surrounding paths.

This module's current sequence is an explicit assumption. Its premises also
name policy-config/apple-vector identity, allocation lifetimes, global MM
identity, the initial MM hardware-zero fact, ordinary call behavior and the
absence of intervening writers. Those premises are never marked discharged by
runtime. `caller_trace_bound`, `entry_coverage_complete`, `all_writers_covered`,
`cached_handoff_verified`, `all_a01_hazards_closed` and
`runtime_execution_observed` remain false in every report.

The synthetic tests exercise the composition's failure boundaries. They are
independently constructed instruction sequences and do not execute target code
or replace validation of the complete pinned functions.

## Restricted PAuth effect model

The runtime constructor contains two exact data-signing forms, PACDA X16,X17
(`0xdac10a30`) and PACDB X17,X16 (`0xdac10e11`). Under a separately reported
normal-execution premise the model kills both scratch registers and NZCV,
preserving memory. It computes no authentication value. Other encodings, other
function owners, missing premises and authentication instructions are not
silently accepted. The base MM interpreter retains its previous behavior.

Arm's primary instruction reference describes these data-signing operations in
sections D2.123 and D2.124; the architecture register documentation separately
describes possible PAuth traps. This conditional effect model does not discharge
those trap conditions or prove that the lowering preserves the same effects.

- [Arm Instruction Set Reference Guide, D2.123/D2.124](https://documentation-service.arm.com/static/6245c734b059dc5ff9a8bdab)
- [Arm SCR_EL3 API trap control](https://support.arm.com/documentation/ddi0601/2026-03/AArch64-Registers/SCR-EL3--Secure-Configuration-Register)

## Reproduction

Run in the approved development container, under the shared heavy-job gate:

```sh
python3 -m unittest discover -s tests -p test_route_a_nontpro_stack.py -v
python3 scripts/audit_route_a_nontpro_stack.py \
  --input /path/to/the/original/24A446/usr/lib/dyld \
  --output /new/private/disabled-stack-conditional.json \
  --conditional-sequence
```

The output path must not already exist. Omitting `--conditional-sequence` leaves
the required premises unset and returns an unresolved report. This is static
analysis of original userland bytes, with no target instruction execution.
