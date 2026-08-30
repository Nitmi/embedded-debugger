# ADR-0011: Confirm selected OpenOCD register snapshots as a fixed MI exchange

- Status: accepted
- Date: 2026-08-24

## Context

The accepted combined OpenOCD/GDB session proves tool interoperability,
running-origin attachment, cleanup, and target restoration, but it sends no
explicit target-data request. Agents need actual debugger data next. Exposing
arbitrary GDB/MI would make the confirmation digest unable to describe the
operation and would immediately create symbol, memory, execution-control,
monitor, and flash command surfaces.

GDB assigns target-specific register numbers at runtime. A confirmed list of
names therefore cannot safely be converted to hard-coded indices during host
planning. GDB/MI already defines structured register-name inventory and
selected-value commands, including an option to skip unavailable values. A
safe wrapper must resolve names from the live inventory, parse nested MI values
structurally, reject partial output, and restore the running origin after GDB
attachment.

## Decision

1. Add independent `openocd registers plan/test` commands. Do not change the
   accepted `openocd session`, `openocd target`, or `openocd reset` protocols or
   confirmation inputs.
2. Accept 1..=64 explicitly repeated register names. Restrict each to a bounded
   ASCII allow list, normalize to lowercase, reject case-insensitive duplicates,
   and bind the normalized order in a new digest.
3. Bind the exact OpenOCD/GDB files and versions, optional native Xtensa profile,
   top-level configuration manifests, ordered search paths, all deadlines,
   exact expected current target, fixed MI protocol, selection policy,
   restoration policy, effects, and confirmation limits.
4. Retain `R2_DEVICE_WRITE`. OpenOCD configuration and attach handlers can have
   effects beyond the explicit register read; runtime adapter identity, dynamic
   ports, transitive Tcl sources, search-tree contents, and Tcl semantics remain
   unbound.
5. Require the exact selected target to start `running`. Permit only MI tokens
   1 through 6 for version, remote connect, complete register-name inventory,
   selected hexadecimal register values, detach, and GDB exit.
6. Parse result variables with a structured MI parser. Resolve each requested
   name case-insensitively to one unique non-empty inventory entry. Construct the
   value command only from those numeric indices; no user text enters an MI
   command.
7. Require every value result to contain one requested, unique decimal register
   number and a bounded hexadecimal value. Fail on unknown, ambiguous,
   unavailable, missing, duplicate, extra, or malformed entries. Preserve the
   confirmed requested order in the report.
8. After a snapshot failure on a connected session, attempt the fixed detach
   before bounded GDB exit. Then prove the original target `running`, using only
   the accepted fixed OpenOCD resume fallback, and always clean up OpenOCD.
9. Do not automatically retry a failed physical test. Register reads are
   observational, but attachment, configuration, partial protocol completion,
   and target restoration can leave hardware outcome indeterminate.
10. Keep ELF/symbol loading, memory/stack access, breakpoints/watchpoints,
    execution control, flash, monitor input, and arbitrary MI/Tcl unavailable.

## Consequences

- Agents receive real selected register values without receiving a general GDB
  command channel.
- Planning remains host-only. Register existence is target-specific and can be
  proven only after a separately confirmed attachment.
- `--skip-unavailable` prevents GDB from failing the entire command internally,
  but the wrapper still requires all selected values and treats omission as a
  protocol failure.
- Failure evidence distinguishes target-data parsing from detach, GDB cleanup,
  target restoration, and OpenOCD cleanup.
- Controlled fixtures qualify parsing and lifecycle behavior. Each physical
  target/tool/profile combination still needs a deterministic plan, independent
  confirmation, and one acceptance run.

## Physical validation

ESP32-S3 CPU0 first passed one exact `pc/a0/a1/ps` snapshot on 2026-08-24.
On 2026-08-31, a second independently confirmed, non-retried run under digest
`a817ed1453fb2ff0e4f23d83ba07bf02c7d0fdeccba37c13913cbc939d188ba0`
returned ordered `pc=0x420129e4` and `a1=0x3fcdb550`. CPU0 started running,
the fixed fallback restored it from the post-detach halted observation to
running, both process trees exited gracefully, the dynamic ports were reusable,
and eight consecutive zero-transmit UART heartbeats followed. CPU1 examination
failed and remains outside acceptance.

The second selection supplies point-in-time frame evidence only. A local ELF
maps that PC inside `main` and gives the static `a1 + 160` relation, but runtime
ELF identity, the resulting memory address and contents, and all watchpoint
operations remain unverified and unauthorized.

## References

- [GDB/MI data manipulation commands](https://sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI-Data-Manipulation.html)
- [GDB/MI result records](https://sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI-Result-Records.html)
- [ADR-0008: Confirmed OpenOCD and GDB session](0008-confirmed-openocd-gdb-session.md)
- [ADR-0009: Confirmed OpenOCD target state roundtrip](0009-confirmed-openocd-target-state-roundtrip.md)
