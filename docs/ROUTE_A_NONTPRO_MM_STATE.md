# Conditional MM bootstrap state analysis

`scripts/audit_route_a_nontpro_state.py` adds a bounded abstract analysis of one
primary standalone `MemoryManager::init` call. It binds the original 24A446 dyld
identity, complete function byte hashes and the two lookup strings. It does not
execute dyld instructions or publish an A01 completion receipt.

The supported context follows the constructor at `0x713c`, init at `0x6f50`, and
its cold function at `0x4c988`. Byte-level stores distinguish the hardware byte
at `+0x20`, the security-transition byte at `+0x22`, and the protected-stack
pointer at `+0x30`. Overlapping stores preserve only the unaffected bytes. A
pointer stored in memory retains its object identity only while all eight bytes
still belong to that pointer.

The constructor's stores cover `+0x30` with zero. Under the explicit absent-key
lookup premise, the hardware byte remains zero. The interpreter checks the
resulting branches at `0x6fa8` and `0x4c9a8`; the expected local successors are
`0x70f8` and `0x4cb04`. Complete primary-function hashes bind the census of
16 local TPRO hazards. A missing or altered byte sequence, unsupported reachable
instruction, incomplete context, or possible path to a hazard cannot produce
the conditional exclusion result.

## Read-only static invocation

Run in the admitted development environment, with the existing resource gate:

```sh
python3 scripts/audit_route_a_nontpro_state.py \
  --input /absolute/path/to/original/24A446/dyld \
  --output /absolute/new/path/mm-conditional.json \
  --conditional-bootstrap
```

The output path must be new. Omitting `--conditional-bootstrap` leaves the
context premises unassumed and the result unresolved. Supplying it records all
assumptions, including complete readable input vectors, absence of both keys,
a fresh disjoint stack, the initial flag, ordinary call/return behavior, the
pinned lookup's read-only effect, and a bounded syscall-38 output effect. The
option does not establish those premises in XNU or in a running process.

## What remains open

Unknown calls clear memory facts, caller-saved values and flags. Their
ordinary-return continuations are explored conservatively to cover the local
function frames. The output lists the unresolved callee sites and arguments;
it does not claim that callees cannot invoke another entry or mutate the MM.
Unknown alias writes and pointer escape discard all affected knowledge. Only
explicitly supported operand forms are interpreted; shifted comparisons and
unmodeled SIMD aliases are rejected rather than silently preserving facts.

`conditional_local_exclusion` means the 16 hazards in these function frames
are excluded under the listed premises. It leaves all-entry coverage, nested
callee closure, post-call object invariants, cache handoff and runtime execution
unverified. It does not close the remaining startup, callback, API, protected
stack, or private-cache groups, and does not turn a 236-site census into a boot
proof. Ordinary VM protection and later global-object publication need their
own byte-bound contracts and input evidence.

`tests/test_route_a_nontpro_state.py` uses only independently assembled synthetic
instruction words. It covers partial writes, pointer identity, unknown calls,
NZCV invalidation, escape, arithmetic bounds, unsupported operand forms,
resource bounds, and the conditional leaf models. Actual execution counts and
the static report belong in a separate run receipt; no test pass or runtime
result is asserted by this document.
