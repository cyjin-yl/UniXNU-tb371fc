# Notices and licensing

This is an independent TB371FC device port assembled from UniXNU and community implementations.
It is not an official Lenovo or Apple project.

The root LICENSE is the UniXNU BSD-2-Clause-Patent license. It applies to port integration code
unless a file or component specifies another license. Existing copyright and SPDX notices
are preserved. Imported components keep their own licenses:

- Adreno650, AdrenoMetal, ArmSmmu4K, QcomGeniSpi, ShengHidInput and the imported Novatek protocol:
  use the LICENSE inside the corresponding directory and each file's SPDX notice.
- TB371FC GPU/display glue and common Adreno PM4/HFI source: BSD-2-Clause-Patent where marked.
- PlatformPower helpers: MIT where marked.
- RootLog common code: BSD-2-Clause where marked; license text is in LICENSES/.

The V129 allocation policy is adapted from UniXNU/Adreno740; the file remains subject to
its original MIT license. The Metal frontend and its Pipa translator patches retain their
upstream licensing. The source lock and UPSTREAM.md identify the corresponding projects.

Apple operating-system files, original Apple binary components, device firmware blobs,
private device dumps and credentials are not included. External inputs must be obtained
separately and are not relicensed by this repository.

## Route A additions

The native-lowering and original validation code added by the Route A branch is
covered by the repository's default BSD-2-Clause-Patent license unless a file or
component states otherwise. The adapted zeta tooling retains its upstream license
in `scripts/route_a_zeta/LICENSE`; source revisions and original hashes are in
`upstream/route-a-sources.json`.

`patches/route-a-go-apfs-type4.patch` adapts the Apache-2.0-licensed go-apfs project.
The patch, including its new decompressor and synthetic tests, is distributed
under Apache-2.0; the full license is in
`upstream/route-a-extraction/go-apfs-LICENSE`. The external ipsw extraction tool is
MIT-licensed; its license and pinned build provenance are retained in that same
directory. No Apple restore-image contents are included.

The XNU patch `patches/route-a-plain-auth-12377.patch` preserves the modified
files' original APSL-2.0 / OSREFERENCE notices and adds dated modification notes.
It is not a relicensing of those XNU files. The exact upstream files, adaptations
and validation scope are listed in `upstream/route-a-kernel-sources.json` and
`docs/ROUTE_A_PLAIN_AUTH_PATCH.md`.

The context-only PAN adaptation in `patches/route-a-native-arm-pan-12377.patch`
preserves the five additions from UniXNU's `native-arm-pan.patch` at commit
`8542980d02b4d2cc5c32ee3542de1760b2562aac` (BSD-2-Clause-Patent).
Only the surrounding patch context is rebased after excluding native-PAC
support. Existing XNU file notices remain unchanged. Original and adapted
patch digests are recorded in `configs/kernel-route-a-ipados27.json`.
