# ADR-0017: Confirm temporary OpenOCD hardware-watchpoint classification

- Status: accepted
- Date: 2026-08-29

## Context

The temporary hardware-breakpoint workflow establishes a useful pattern for
strict GDB/MI mutation, cleanup, and running-state restoration. Watchpoints need
a separate contract because their expression can read target memory, their
width/alignment is target-dependent, and GDB does not give every watchpoint mode
the same hardware guarantee.

GDB defines `rwatch` and `awatch` as hardware watchpoints, while a normal
write-only `watch` can fall back to software single-stepping. GDB also documents
that resource exhaustion may not be detected until the inferior resumes. A
create/list/delete roundtrip without resume can therefore prove GDB's hardware
classification and bookkeeping cleanup, but not physical comparator allocation,
capacity, width support, hit behavior, or physical cleanup.

An arbitrary user expression would make memory access and language semantics
unbounded. Even a generated expression must be evaluated by GDB and may read
the selected target range during creation. Region semantics cannot be inferred
safely from a numeric address alone.

## Decision

1. Add independent `openocd watchpoint plan/test` commands without changing any
   accepted session, register, memory, stack, breakpoint, target, or reset
   digest.
2. Accept only modes `read` and `access`, mapped to MI
   `-break-watch -r` and `-break-watch -a`. Do not expose ordinary write-only
   watchpoints or any software fallback.
3. Require a nonzero exact numeric address, a 1/2/4/8-byte width, natural
   alignment, and complete containment in an explicit nonempty RAM region.
   Reject NVM and all invalid ranges before host-file inspection.
4. Generate only `*((char*)0x<address>)@<length>` and first issue the fixed
   `-gdb-set language c`. Bind both commands and the possible RAM read effect in
   the confirmation digest.
5. Fix success tokens 1 through 9 to version, remote select, language select,
   watchpoint insert, list, delete number 1, list, detach, and exit.
6. Require insertion to return exactly `hw-rwpt` or `hw-awpt` with number 1 and
   the exact expression. Then require one canonical table row classified as
   `read watchpoint` or `acc watchpoint`, enabled, persistent until explicit
   deletion, zero-hit, and tied to the exact expression. Reject unsupported or
   extra fields.
7. Do not intentionally continue the target while the watchpoint exists and do
   not request or claim a hit. Explicitly keep physical comparator allocation,
   capacity, width support, and hit capability unverified.
8. Require deletion to be followed by the exact canonical empty six-column GDB
   table. Treat this only as GDB bookkeeping evidence, not physical readback.
9. Restore a successful running-origin target only after classification and the
   empty table are proven. Keep the existing single fixed Tcl resume fallback
   for that verified-success path.
10. After any insertion attempt fails before normal detach, attempt fixed
    token-10 delete, token-11 list, and token-12 detach cleanup. Before insertion,
    connection or language failures attempt detach only.
11. On every GDB failure, record a point-in-time target observation and send no
    additional Tcl resume. Report that GDB detach/exit or configured handlers
    may still resume the target, require fresh recovery authority, and prohibit
    automatic retry.
12. Bind the exact range, declared RAM region, mode, protocol, parsers, cleanup,
    restoration, effects, identities, and deadlines in an independent
    `R2_DEVICE_WRITE` digest. Leave runtime adapter identity, dynamic port, RAM
    semantics, hardware resources, and physical state explicitly unbound.

## Consequences

- Agents receive a deterministic, auditable temporary watchpoint qualification
  instead of an arbitrary GDB command channel.
- The API honestly separates GDB hardware classification from actual target
  comparator allocation and hit capability.
- RAM declaration errors remain consequential because expression evaluation may
  access MMIO or another side-effectful range; callers must review that effect.
- Write-only, persistent, symbolic, conditional, and hit-executing watchpoints
  remain unavailable until they have distinct policies and evidence.
- Every physical execution requires a fresh plan and exact user confirmation.

## References

- [GDB watchpoint semantics](https://www.sourceware.org/gdb/current/onlinedocs/gdb.html/Set-Watchpoints.html)
- [GDB/MI breakpoint and watchpoint commands](https://www.sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI-Breakpoint-Commands.html)
- [GDB/MI breakpoint information](https://sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI-Breakpoint-Information.html)
- [ADR-0008: Confirmed OpenOCD and GDB session](0008-confirmed-openocd-gdb-session.md)
- [ADR-0016: Temporary hardware breakpoint](0016-confirmed-openocd-hardware-breakpoint-roundtrip.md)
