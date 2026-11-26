# Read-only lab terminal verification

A successful compiler receipt and an exhausted timeout are different from an
observed end to all owned work. The A01 wrapper once retried indefinitely because
it read the environment of every container process, including unrelated old
zombies with protected metadata.

The scripts/route_a_checks/lab_processes.py command verifies the existing
seven-recipe A01 success profile. Supply the original host envelope's boot ID and
independently recorded SHA256 values for the plan, bootstrap, terminal receipt,
controller and owned-process helper. Run it in the same container/PID namespace:

    python3 -B scripts/route_a_checks/lab_processes.py \
      --scope /absolute/path/to/original/output \
      --boot-id ORIGINAL_BOOT_ID \
      --plan-sha256 PLAN_SHA256 \
      --bootstrap-sha256 BOOTSTRAP_SHA256 \
      --receipt-sha256 RECEIPT_SHA256 \
      --controller-sha256 CONTROLLER_SHA256 \
      --owned-processes-sha256 OWNED_PROCESSES_SHA256

The source directory must be the output path plus -source. The verifier checks
all 23 phase ledgers, hashes/counts, bootstrap payload and controller identity,
unchanged evidence and parent-directory identities, and two complete process snapshots. Owned
identities, process groups and sessions block completion even when their
metadata cannot be read. Older unrelated processes need no environment access.
An unrelated zombie is nonexecuting only after two stable thread enumerations,
with a final thread-identity recheck; a live or newly created thread still blocks. Unclassified active processes with
inaccessible metadata remain inconclusive.

The command prints JSON and returns 0 only when owned_scope_terminal_verified is
true; otherwise it returns 2. It never prints process environments or command
lines, writes evidence, signals processes or releases a lease. The result
describes the fixed original experiment; it is not XNU boot evidence. There is
no missing/partial-receipt or deadline-only fallback.

An operator resolving a defective host supervisor must separately bind its exact
identity, prevent further probe creation, verify it has no descendants, retain a
new recovery record, and let the existing lease guardian observe that
supervisor's actual exit. Historical receipts and lock inodes remain unchanged.
