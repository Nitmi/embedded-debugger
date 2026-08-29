# ADR-0016: Confirm one temporary OpenOCD hardware-breakpoint roundtrip

- Status: accepted
- Date: 2026-08-29

## Context

The existing OpenOCD checkpoints prove host tools, server lifecycle, remote
attach/detach, selected registers, bounded memory, and bounded stack output.
Agents can invoke GDB or OpenOCD directly, but a general command channel does
not provide a stable policy for breakpoint kind, address interpretation,
cleanup proof, target restoration, or failure evidence.

GDB/MI `-break-insert -h` requests a hardware-assisted breakpoint and returns
a structured `bkpt` tuple. `-break-delete` returning `done` proves only that the
delete command was accepted. A subsequent `-break-list` can provide an empty
`BreakpointTable`, but that table is GDB bookkeeping rather than an independent
read of a target's physical comparator registers.

Cleanup also has a subtle state boundary. GDB detach and GDB exit, including
configuration-defined OpenOCD detach handlers, may resume a target. Omitting an
additional Tcl `resume` after failure therefore does not prove that the target
remained halted.

## Decision

1. Add independent `openocd breakpoint plan/test` commands. Reuse the exact
   OpenOCD/GDB/profile/configuration/target inputs without changing accepted
   session, register, memory, stack, target, or reset digests.
2. Require one exact nonzero numeric address and validate zero before host-file
   inspection. Do not accept a symbol, expression, source location, requested
   slot, condition, command list, or arbitrary GDB input.
3. Fix the successful MI sequence to version, remote select,
   `-break-insert -h *0x<address>`, `-break-delete 1`, `-break-list`, detach,
   and exit with tokens 1 through 7.
4. Do not intentionally continue the target while the breakpoint exists and do
   not request or claim a breakpoint hit.
5. Accept insertion only when exactly one `bkpt` tuple reports number 1,
   `type="hw breakpoint"`, `disp="keep"`, `enabled="y"`, the exact address,
   and `times="0"`. Reject pending, multi-location, software, conditional,
   scripted, malformed, duplicate, unknown, or extra data.
6. Require deletion to be followed by an exact zero-row, six-column canonical
   `BreakpointTable` with an empty body. Parse the official named nonempty body
   shape so residual entries fail explicitly.
7. Restore the successful running-origin target only after the empty GDB table
   is proven. Keep physical comparator cleanup independently unverified.
8. After a breakpoint-exchange failure following remote connection and before
   normal detach, attempt fixed token-8 delete, token-9 list, token-10 detach,
   then bounded process exit and OpenOCD cleanup. Every GDB failure records a
   point-in-time target observation.
9. Do not send an additional OpenOCD Tcl resume after GDB failure. Explicitly
   report that detach, exit, or configured handlers may still resume the
   target; require manual recovery authority and prohibit automatic retries.
10. Bind the fixed success/failure protocols, exact address, strict parsers,
    restoration and failure policies, effects, confirmation boundary,
    identities, and deadlines in a new `R2_DEVICE_WRITE` digest. Keep runtime
    adapter identity, dynamic port, comparator capacity, and physical comparator
    state unbound.

## Consequences

- Agents gain a useful, deterministic breakpoint smoke test without receiving
  persistent breakpoint ownership or general GDB execution control.
- The empty-table proof is stronger than trusting `-break-delete` alone but is
  deliberately not presented as physical comparator readback.
- A failed operation may leave target state indeterminate even when GDB cleanup
  looks complete. Evidence remains useful, but recovery is a separate action.
- Physical qualification requires two identical host-only plans, independent
  confirmation of the fresh digest, one non-retried execution, complete process
  cleanup, target-state checks, and an external liveness check where available.

## Validation

Controlled regressions cover the official insertion and breakpoint-table
shapes, unsafe response rejection, deterministic address-bound digests, stale
confirmation rejection, a successful two-process roundtrip, and malformed
insertion cleanup without an additional Tcl resume. No physical target
acceptance is claimed by this ADR.

## References

- [GDB/MI breakpoint commands](https://www.sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI-Breakpoint-Commands.html)
- [GDB/MI breakpoint information](https://sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI-Breakpoint-Information.html)
- [ADR-0008: Confirmed OpenOCD and GDB session](0008-confirmed-openocd-gdb-session.md)
- [ADR-0013: Bounded OpenOCD stack snapshots](0013-confirmed-openocd-stack-snapshot.md)
