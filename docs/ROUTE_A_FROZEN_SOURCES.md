# Verify frozen source inputs

A clean preparation receipt describes the tree at preparation time. Before a
later build, verify the bytes that the build will actually consume. The
read-only verifier accepts the existing tracked-source-inventory.json list
format; a versioned envelope with schema route-a-frozen-source-manifest-v1 and
files containing that same list is also supported.

Each entry has exactly five fields: path, mode (100644, 100755 or 120000),
git_blob (SHA1), bytes and sha256. Callers must supply the independently retained
manifest SHA256, commit and tree identities. The manifest belongs outside the
source root.

Example, with values from the caller's fixed preparation receipt:

~~~sh
python3 -B scripts/route_a_checks/frozen_sources.py \
  --root /absolute/path/to/frozen-source \
  --manifest /absolute/path/to/tracked-source-inventory.json \
  --manifest-sha256 "$MANIFEST_SHA256" \
  --head "$SOURCE_COMMIT" \
  --tree "$SOURCE_TREE" \
  --timeout 120
~~~

Exit 0 requires complete=true in the JSON result. Other results must not start
a compiler. The command itself never starts a compiler, creates an output
directory, acquires/releases a heavy lease or claims kernel/runtime success.

## What is checked

- The manifest's exact digest and schema, bounded file count and byte lengths.
- HEAD, committed tree entries and all stage-zero index entries, using Git
  metadata queries. No git status, index refresh, checkout or filter is run.
  Ambient Git directory/index overrides and global/system Git configuration
  are not inherited by these queries.
- Every declared file's type, Git owner-execute bit, byte length, Git blob SHA1
  and SHA256. Reading a regular file uses no-follow descriptors and compares
  its device/inode/mode/size/mtime/ctime before and after the read.
- The exact file and directory set, including empty directories and ignored
  files. Only the root .git entry is excluded from filesystem enumeration;
  Git still reads its own metadata. Generated files therefore belong outside
  the frozen source root, and Python should run with -B.
- Symlink text is hashed as a Git blob. Resolution uses the verified manifest
  and link texts, rather than opening a target outside it. Relative links may
  end at declared files or directories. Absolute paths, root escapes, .git
  targets, dangling targets, loops and directory type substitutions fail.
- Git metadata, directory/file generations and the manifest are checked again
  before a successful result is emitted. The absolute ancestor chain is opened
  again from / with O_DIRECTORY and O_NOFOLLOW, checking each directory's
  device/inode/mode identity. Ancestor timestamps are not frozen, because an
  unrelated sibling output does not change this source tree.

This is a Linux, SHA1-Git-repository checker using /usr/bin/git. Submodules and
other Git object formats are rejected. It verifies source content, not the
absence of Git ignored files in an arbitrary build tree: the intended input
is a small, isolated source checkout with all outputs elsewhere.

## Bounds and use in a build supervisor

The maximum manifest is 8 MiB, with 10,000 files, 32 MiB per file and 256 MiB
total declared source bytes. Git metadata output is capped at 8 MiB and each
Git query has a 30-second ceiling inside the overall deadline (at most 180
seconds). A timed-out Git child is killed and reaped; an unresolved cleanup is
a failure. Unexpected filesystem entries fail immediately without traversing
their contents.

Filesystem I/O can remain blocked inside the kernel. The verifier checks the
monotonic deadline after each read and cannot turn a late return into success,
but it does not claim that a Python deadline forcibly terminates uninterruptible
I/O. Run it within the existing bounded experiment supervisor; only that owner
may reconcile process termination and the heavy lease. A nonzero CLI exit is
also not evidence that its descendants are absent. In particular,
git_cleanup_unresolved retains the owned child's PID, start ticks, PGID and SID
in error.cleanup_observation (plus the last available observation). The outer
supervisor must keep its lease until it independently reconciles those
identities and its own complete descendant registry. It must not infer cleanup
from this verifier's exit status alone.

A successful check is a snapshot, not a write lock or a future immutability
guarantee. The owner must keep the source isolated throughout the build and
repeat verification afterward, along with the actual compiler dependency/input
checks. This verifier does not replace the XNU/header/tool identity or compile
receipt checks.
