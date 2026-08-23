# ADR-0006: OpenOCD configuration execution requires an exact launch confirmation

- Status: accepted
- Date: 2026-08-23

## Context

The host-only OpenOCD checkpoint established executable identity and canonical
top-level configuration inputs without executing Tcl. The next checkpoint must
start a real server to allocate endpoints and prove Tcl readiness. A `.cfg`
file is executable Tcl, not declarative board metadata: it may source files,
access adapters and targets, reset or write a device, or execute host commands.
Therefore a lifecycle that sends only `version` and `shutdown` cannot honestly
be classified as read-only or reversible based only on those two tool-added
commands.

Long-running OpenOCD also creates operational hazards. Dynamic ports must not be
published before they are usable, stdout and stderr must be drained without
unbounded memory, and every timeout or protocol failure must terminate the
complete descendant tree. A parent PID kill alone is insufficient on Windows
or Unix.

## Decision

1. Server launch is split into `openocd server plan` and `openocd server test`.
   Test recomputes the plan and requires its exact `confirm_digest` before any
   configuration Tcl is executed.
2. The execution plan is classified `R2_DEVICE_WRITE`. It discloses that target
   writes and arbitrary host commands are possible from configuration even
   though the launcher itself never adds reset, flash, or target-control Tcl.
3. Confirmation binds schema and operation identity, exact executable path,
   executable SHA-256 and recognized version, ordered top-level config hashes,
   ordered search directory paths, lifecycle deadlines, and server policy.
4. Confirmation does not claim to bind search directory contents, transitive
   sources, environment-dependent Tcl, or configuration semantics. These
   limitations are first-class structured fields in both plan and result.
5. The launcher accepts no arbitrary command option. It fixes loopback binding,
   GDB/Tcl port zero, disabled telnet, canonical search/config arguments, null
   stdin, and independently piped stdout/stderr.
6. Readiness requires both announced dynamic ports and a framed Tcl `version`
   response identifying OpenOCD. Tcl messages use terminator byte `0x1a` and a
   64 KiB response bound.
7. Shutdown sends framed Tcl `shutdown`, observes a successful parent exit, and
   then enforces descendant termination. Windows uses a Job Object assigned
   while the child is suspended; Unix uses a new process group.
8. Output is drained concurrently, forwarded to stderr, completely hashed, and
   bounded for retention, line size, and queued events. Any loss or incomplete
   drain makes the lifecycle incomplete.
9. This checkpoint enables server launch, Tcl RPC, and a dynamic GDB endpoint.
   It does not enable GDB/MI, target operations, state-preservation claims, or
   flash through OpenOCD.

## Consequences

- An Agent cannot accidentally cross from inspection into configuration
  execution with one unreviewed command.
- The digest detects changes to the selected executable, top-level configs,
  ordering, paths, and deadlines between plan and execution.
- A correct digest is explicit authorization, not proof that arbitrary Tcl is
  benign. Users must trust the selected distribution and all sourced content.
- Server crash and timeout handling has one cross-platform process-tree owner;
  callers do not need to discover or clean up OpenOCD descendants themselves.
- The next OpenOCD checkpoint can add a managed GDB/MI client against the proven
  dynamic endpoint without implementing a partial GDB remote protocol client.
