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
   single accepted `*stopped` record to be tokenless or carry the exact
   continue token while the one continue operation is outstanding. Reject a
   nonmatching token or competing stop.
6. Accept a hit only when its reason, `hw-rwpt`/`hw-awpt` tuple, watchpoint
   number, expression, value tuple shape, and frame address match the confirmed
   policy. Reject unrelated stops, scope loss, exit, signals, extra stop fields,
   malformed frames, wrong tokens, and out-of-range PCs.
7. After the stop, require the canonical one-row watchpoint table with
   `times=1`, then delete number 1 and require the canonical empty table before
   detach and exit.
8. Use a distinct fixed failure protocol. If execution may still be running,
   attempt exactly one `-exec-interrupt --all`, correlate its result and the
   single tokenless-or-matching-token `signal-received`/`SIGINT` stop, then
   attempt delete, empty-table verification, and detach. Do not retry the
   continue, hit, interrupt, or physical operation.
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
It timed out because the confirmed address came directly from a historical
`a1` register snapshot rather than a current variable address. The run also
showed that Espressif GDB 17.1 emits a tokenless asynchronous SIGINT stop after
`-exec-interrupt --all`; synthetic fixtures had emitted token 8 instead.

The host-only amendment now implements items 5 and 8: a tokenless stop, or the
matching token if present, is correlated only inside the one fixed continue
lifecycle; competing and nonmatching stops fail closed; the success path keeps
the complete hit tuple/reason/PC checks; and cleanup additionally requires the
fixed SIGINT reason and signal. Controlled fixtures use tokenless records while
matching-token compatibility and rejection paths have direct regressions.

The address audit also corrected the earlier preliminary `a1 + 128` reading.
In local ELF SHA-256
`676a89d78556f07500fcbe50a17c046c27d9d6e1e425ed9732c6f257a09f7b20`,
the concrete `heartbeat` DIE is `DW_OP_fbreg: 160`, and `main` uses
`DW_OP_reg1 (a1)` as its frame base. Disassembly shows `a1 + 128` as a
loop-carried temporary and writes the source-level assignment to `a1 + 160` at
`0x420128CD`. This proves only the static frame-relative relation for that ELF.
The 2026-08-24 `a1=0x3FCDB550` snapshot was taken at another PC and time, so
even the arithmetic historical candidate `0x3FCDB5F0` is not a current address.
No new physical hit plan may treat it as one; runtime frame and firmware
identity evidence, revised plans, and fresh confirmation remain required.

## References

- [GDB/MI asynchronous records](https://sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI-Async-Records.html)
- [GDB/MI program execution](https://www.sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI-Program-Execution.html)
- [GDB/MI breakpoint and watchpoint commands](https://www.sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI-Breakpoint-Commands.html)
- [GDB asynchronous and all-stop modes](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Asynchronous-and-non_002dstop-modes.html)
- [ADR-0017: Temporary hardware watchpoint](0017-confirmed-openocd-hardware-watchpoint-roundtrip.md)
