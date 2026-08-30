# ADR-0018: Confirm one bounded OpenOCD hardware-watchpoint hit

- Status: accepted; physical validation failed and protocol amendment pending
- Date: 2026-08-29

## Context

ADR-0017 deliberately stops after hardware classification and deletion. That
workflow does not resume the target while the watchpoint is installed, so it
cannot prove that a target accepted the comparator, that the selected width is
usable, or that GDB can attribute a real stop to the requested watchpoint.

A hit workflow crosses a stronger execution-control boundary. GDB/MI reports
`-exec-continue` with `^running` and later emits an asynchronous `*stopped`
record. The stop can be unrelated to the requested watchpoint, and a target may
remain running when the wait expires. A client that discards asynchronous
records, accepts only the stop reason, retries automatically, or deletes before
interrupting a running target cannot make a reliable cleanup claim.

GDB assigns distinct stop reasons and tuple names to hardware read and access
watchpoints: `read-watchpoint-trigger` with `hw-rwpt`, and
`access-watchpoint-trigger` with `hw-awpt`. Read hits report one `value` field;
access hits report either `new` or `old` plus `new`. The stop frame address is
the strongest bounded runtime provenance available without loading symbols or
claiming target firmware identity.

## Decision

1. Add independent `openocd watchpoint hit plan/test` commands. Keep the
   classification-only digest and behavior unchanged.
2. Reuse the exact numeric RAM range, alignment, declared-region, generated C
   expression, and hardware-only `read`/`access` policies from ADR-0017.
3. Require a nonzero, nonempty, bounded expected-PC half-open interval and an
   explicit bounded hit timeout. Treat the interval as user-confirmed runtime
   provenance, not proof of executable memory or firmware identity.
4. Before remote attachment, issue fixed MI commands enabling asynchronous
   execution and forcing all-stop mode. Then connect, select C, insert and
   classify the watchpoint, and execute exactly one `-exec-continue --all`.
5. Correlate the continue result and asynchronous records without assuming
   their relative ordering. Allow repeated `*running` records, but require the
   exact continue token on the single accepted `*stopped` record.
6. Accept a hit only when its reason, `hw-rwpt`/`hw-awpt` tuple, watchpoint
   number, expression, value tuple shape, and frame address match the confirmed
   policy. Reject unrelated stops, scope loss, exit, signals, extra stop fields,
   malformed frames, wrong tokens, and out-of-range PCs.
7. After the stop, require the canonical one-row watchpoint table with
   `times=1`, then delete number 1 and require the canonical empty table before
   detach and exit.
8. Use a distinct fixed failure protocol. If execution may still be running,
   attempt exactly one `-exec-interrupt --all`, correlate its result and the
   continue-token stop, then attempt delete, empty-table verification, and
   detach. Do not retry the continue, hit, interrupt, or physical operation.
9. On a verified-success path, retain the existing bounded OpenOCD running-state
   restoration check and fixed Tcl resume fallback. On every GDB failure, send
   no additional Tcl resume and report target state as point-in-time evidence
   that may require separately authorized recovery.
10. Bind the exact MI protocol, cleanup protocol, RAM and PC ranges, mode,
    timeout, strict parsing policy, tools, configuration, target name, effects,
    and lifecycle deadlines in a new `R2_DEVICE_WRITE` digest. Leave runtime
    adapter identity, dynamic port, RAM/executable semantics, firmware identity,
    and physical comparator readback explicitly unbound.

## Consequences

- Agents can qualify one real hardware-watchpoint hit without receiving an
  arbitrary GDB command channel or persistent execution-control session.
- A successful report is materially stronger than classification alone: it
  proves one GDB-attributed hit and post-hit bookkeeping cleanup for the exact
  confirmed run.
- The expected PC interval prevents an unrelated access elsewhere in the
  program from being silently accepted, but it does not attest the firmware
  image running on the target.
- Timeout and malformed-output paths may still leave device state indeterminate
  if interrupt, delete, detach, or configuration handlers fail. Recovery stays
  separate and is never automatic.
- Every physical run requires two identical host-only plans and a fresh exact
  confirmation digest.

## Validation

Host-only controlled GDB/OpenOCD fixtures must cover a successful immediate hit,
stop-before-result ordering, repeated running notifications, wrong reason or PC,
timeout interruption, fixed cleanup, deterministic digests, stale confirmation,
and preflight rejection before any hardware process starts. Physical target
acceptance is recorded only after a separately confirmed, non-retried run.

The first separately confirmed physical attempt on 2026-08-30 was not accepted.
It timed out because the confirmed address came from an `a1` register snapshot,
while local disassembly placed the incremented loop value at `a1 + 128`. The run
also showed that Espressif GDB 17.1 emits a tokenless asynchronous SIGINT stop
after `-exec-interrupt --all`. The fixtures had emitted token 8 on asynchronous
stops, so they did not model this real behavior.

Before another physical attempt, items 5 and 8 require a bounded amendment:
correlate a tokenless stop, or the matching token if one is present, only while
the one continue is outstanding; retain the complete hit tuple/reason/PC checks
on the success path and the fixed post-interrupt SIGINT check on the cleanup
path; and reject competing stops or nonmatching tokens. The watched address must
also be re-derived without treating the stack pointer as the variable address.
Implementation, fixtures,
plans, and digest must all be revised before fresh confirmation. Recovery of the
point-in-time halted target remains separately authorized.

## References

- [GDB/MI asynchronous records](https://sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI-Async-Records.html)
- [GDB/MI program execution](https://www.sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI-Program-Execution.html)
- [GDB/MI breakpoint and watchpoint commands](https://www.sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI-Breakpoint-Commands.html)
- [GDB asynchronous and all-stop modes](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Asynchronous-and-non_002dstop-modes.html)
- [ADR-0017: Temporary hardware watchpoint](0017-confirmed-openocd-hardware-watchpoint-roundtrip.md)
