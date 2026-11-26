# Observing the PACGA random-key startup sequence

The CoreCrypto runtime probe selects these observations only when its input
build explicitly admits the PACGA overlay and the actual linked kernel carries
the matching descriptor. The complete kernel digest and implementation must
match the build receipt. A descriptor-bearing kernel with an omitted overlay
does not silently fall back to the provider-only probe.

## Actual observations required

After the real provider POST returns successfully, the probe stops at the
unique direct BL from the source-bound PACGA bootstrap to read_random. It
checks that the complete provider table and PRNG have been published, that
the bootstrap has not already set its ready flag, and that the call arguments
identify exactly the declared 16-byte boot-key storage.

It then observes the unchanged instruction immediately following that BL,
with ready still zero. At the later real XNU crypto consumer it requires
ready to have become one. The key-initialization gate is granted only after
the call, return and subsequent publication have all been observed. Any
later probe failure or input change revokes that gate along with the existing
provider qualification flags.

The negative POST run requires ready to remain zero at both the rejected
POST return and the actual provider panic. It retains the existing checks
that no crypto table, PRNG or consumer success has been published.

The source ordering follows the fixed XNU startup definitions: SYSCTL occurs
before EARLY_BOOT, the PACGA bootstrap uses EARLY_BOOT/FIRST, and the real
vm_map_store_crypto_init consumer uses EARLY_BOOT/MIDDLE. Those declarations
select the expected observations; source order alone does not pass a runtime
gate.

- [Fixed XNU startup phases](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/osfmk/kern/startup.h)
- [Fixed XNU crypto consumer](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/osfmk/vm/vm_map_store.c)

## Narrow debugger reads

After the entry stub, observation stops request individual registers through
RSP p packets after validating QEMU's exact AArch64 register XML. Every stop
first checks PC and CPSR against its declared instruction and exception level.
Only the semantic arguments or return value required at that stop are then
read. The read_random return requests PC and CPSR only. The key's address and
extent are declared, but its memory bytes are never requested.
The key range must be disjoint from every declared state cell and provider
table, including same-address symbol aliases. Every actual observer memory
request checks this range again. A bounded panic-string window that reaches
the key is recorded as excluded without sending a memory request.

The observer does not request a bulk g packet or retain unsolicited register
fields from a stop reply. A BLR consumer call reads only the single target
register named by the actual caller instruction. Panic observations retain
only the existing bounded semantic arguments and static strings.

## Scope of a successful result

The new flags are pacga_key_initialization_verified for a positive run and
pacga_negative_post_unpublished_verified for the negative run. They describe
the source-bound startup sequence and its failure boundary. They do not
measure entropy quality or establish a user-mode exception round trip.

The PACGA SVC round-trip, userland execution, complete real-cache proof, OS
boot and physical-device qualification remain separate false gates. The
existing build descriptor's runtime_boot_verified flag is not rewritten.

The additional tests use independent instruction, register-packet and state
fixtures to reject wrong arguments, premature readiness, missing call/return
events, invalid register replies, same-address key aliases, overlapping
memory requests and descriptor/receipt disagreement. They
do not execute a guest or substitute for these actual runtime observations.
