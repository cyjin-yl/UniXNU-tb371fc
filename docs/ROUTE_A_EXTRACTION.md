# Ranged extraction of the iPadOS 27 audit inputs

This is a small extension to a pinned upstream extraction tool. It adds bounded
decmpfs type 4 (zlib resource fork) support to the `go-apfs` streaming reader used
by `ipsw extract --ranged`. The existing non-streaming upstream implementation
already documents the format in `types/decmpfs.go`.

## Sources and licenses

| Component | Pin | License |
| --- | --- | --- |
| `blacktop/ipsw` | `v3.1.750`, commit `26b65938cf4c9479cb5627d2d479492a1dcdd13e` | MIT |
| `blacktop/go-apfs` | `v1.0.32`, commit `19d39e62ed62f3fefd6c00811c9358eadab30dfc` | Apache-2.0 |
| Go compiler used | `go1.27.4`, Linux amd64 | Go upstream distribution |

The original license texts and source archive SHA-256 values are in `upstream/route-a-extraction/`. Paths in the commands are relative to the repository root unless stated otherwise.
`scripts/route_a_extraction/main.go` is a small MIT-licensed front end that calls the pinned
`extract.Search` implementation with ranged mode enabled. The front end avoids
building unrelated command-line features; it does not replace the upstream ZIP,
AEA, DMG, or APFS parsers.

## Patch behavior and limits

`patches/route-a-go-apfs-type4.patch` has SHA-256:

`737657c209bd92fd761107e6bf85d2fbda7e0e56d163c227a90f977a77b1c5ba`

The extension accepts decoded files of at most 64 MiB. It validates the resource
data interval, mixed-endian block table, expected number of 64 KiB chunks,
nonoverlapping block intervals, compressed block sizes, zlib checksum, and exact
decoded size. A short or invalid chunk fails extraction. The upstream atomic
file writer publishes a file only after the entire logical file was decoded.

The tests cover a two-chunk resource with one zlib chunk and one stored chunk,
including a read across their boundary. Eight malformed fixtures exercise an
out-of-file resource declaration, wrong block count, block inside the table,
overlapping blocks, out-of-file block, oversized compressed block, invalid zlib
checksum, and short stored chunk. All passed before the successful real-input extraction recorded in the provenance JSON.

## Rebuilding

Use the exact source commits above and apply `patches/route-a-go-apfs-type4.patch` in the
`go-apfs` source root with `git apply`. Run:

```sh
go test -p 4 -run '^TestRouteAZlibResource' -v .
```

In the pinned `ipsw` source tree, use `go mod edit` to replace
`github.com/blacktop/go-apfs` with the patched source directory. Copy
`scripts/route_a_extraction/main.go` to `route_a_extract/main.go`, then build with Go 1.27
and a working C compiler:

```sh
CGO_ENABLED=1 go build -p 4 -trimpath -ldflags '-s -w' \
  -o ipsw-route-a-extract ./route_a_extract
```

The normal Linux build requires no filesystem mount. The recorded experiment
used an isolated container and a compiler extracted into its work directory.

## Extraction command

Set `ROUTE_A_IPSW_URL` to the official Apple CDN URL recorded in
`docs/evidence/route-a-extraction-20261123.json`. For the tested iPadOS 27.0.1 build `24A446`, the
selected board is `j820ap` (product `iPad17,3`) and the OS component is
`043-68950-668.dmg.aea`.

```sh
./ipsw-route-a-extract \
  --url "$ROUTE_A_IPSW_URL" \
  --device j820ap --dmg fs \
  --pattern '^/?(sbin/launchd|usr/lib/dyld|System/Library/CoreServices/SystemVersion[.]plist)$' \
  --output original
```

Keep HTTPS certificate validation enabled. An explicit `SSL_CERT_FILE` can point
to the environment's trusted public CA bundle when required.

The regex is anchored so the upstream reader can skip unrelated directories.
Ranged mode reads the required parts of the stored ZIP member; it does not
download the full IPSW or disk image. Preserve its output, log, source pins,
tool binary hash, and file hashes together. Verify the original Mach-O
CodeDirectory code pages before rewriting. Extraction and static transformation
are separate from demonstrating an iPadOS boot.

## Successful run on 2026-11-23

The final extraction returned exit code 0 and `complete: true` at 08:50:25 UTC.
Both files are little-endian, thin ARM64 Mach-O files with raw CPU subtype
`0x80000002` (ARM64E with feature bits). The extracted SystemVersion metadata
reports version `27.0.1` and build `24A446`.

| Input | Bytes | SHA-256 |
| --- | ---: | --- |
| `sbin/launchd` | 639376 | `c640246d38aaeb2d2372aff1e5aa0de59dec267f53c0dfc155f7837e717af68b` |
| `usr/lib/dyld` | 1447088 | `ab9887ed96c9c08ad68d4c6a5c27e8289fb0c9e55ec3e134547292a1ec579608` |

The OS image range reader logged 72 HTTP requests and 10,952,263 downloaded
bytes against an IPSW of 11,654,176,243 bytes. This counter excludes the initial
ZIP directory and manifest reads and any public FCS key request; it is not an
exact total for all network traffic. The full firmware archive was not saved.

The built extractor SHA-256 was
`0d75d5a58bbe4e5a2f650d8836ea7137171b48443564676504f59beab1c7e18a`.
See `docs/evidence/route-a-extraction-20261123.json`, `build-minimal-status.json`, and
`original-extract-stdout.json` / `original-extract-stderr.log` for the exact
source URL, commands, pins, times, and paths. This source bundle records the
extraction; the subsequent Mach-O audit and transformation have their own
reports.

No Apple executable or disk image is included in this source bundle.
