# ADR-0013: Bound OpenOCD stack snapshots without claiming bounded unwind reads

- Status: accepted
- Date: 2026-08-27

## Context

The accepted OpenOCD register and memory snapshots expose explicit target-data
commands with exact selections or address ranges. Stack inspection is different.
GDB's unwinder may read registers and target memory at addresses derived from
live register values, stack contents, and architecture rules. Limiting the
number of returned frames does not pre-bind the addresses read while producing
those frames, and corrupted unwind state can lead to an unexpected or
side-effectful target address.

GDB/MI defines `-stack-list-frames [--no-frame-filters low high]`. The bounds are
inclusive. The result uses a result-list such as
`stack=[frame={level="0",addr="0x..."}, ...]`; this differs from the value-list
shapes already handled for registers and memory. Omitting low/high requests the
entire GDB-visible stack and is not acceptable for this checkpoint. Python
frame filters are also unnecessary executable extension code.

## Decision

1. Add independent `openocd stack plan/test` commands without changing any
   accepted server, session, target, reset, register, or memory confirmation
   input.
2. Require `--max-frames` in 1..=32 and validate it before executable or
   configuration lookup. Always request the inclusive range `0..limit-1`.
3. Fix the only stack command to
   `-stack-list-frames --no-frame-filters 0 <limit-1>`. Do not accept an
   arbitrary low frame, command, expression, frame filter, argument, local, or
   value request.
4. Load no ELF or symbol file. Treat optional function/source fields as bounded
   GDB-reported metadata, require no firmware identity, and make no
   symbolization or physical call-stack completeness claim.
5. Bind the exact tool/config/profile identities, ordered search paths, exact
   target, deadlines, frame limit/range, disabled-filter policy, strict result
   policy, restoration policy, effects, and confirmation boundary in a new R2
   digest.
6. Disclose separately that returned frames are bounded while implicit unwind
   register/memory access is possible and its target addresses are not digest
   bound. Do not recast this as an address-bounded memory read.
7. Extend structured MI parsing only for the exact `stack=[frame={...}]`
   result-list grammar. Reject unnamed entries, duplicate fields, nested
   values, extra top-level variables, and malformed separators.
8. Require every frame to contain decimal `level` and a 0x-prefixed address of
   at most 64 bits. Require levels to be contiguous from zero. Accept only the
   documented scalar optional fields, each bounded to 4096 bytes with control
   characters rejected.
9. Reject empty output and more frames than confirmed. When the returned count
   equals the limit, report that additional GDB frames may exist. Always report
   physical call-stack completeness as unproven.
10. After a connected failure, attempt fixed detach before bounded GDB exit,
    then prove selected-target running restoration and clean up OpenOCD. Never
    retry a failed physical test automatically.

## Consequences

- Agents gain a useful top-of-stack snapshot without receiving a general GDB
  command channel or unbounded backtrace operation.
- A frame-count limit bounds result size and unwind depth requested from GDB,
  but it cannot guarantee which target addresses the unwinder will read.
- Unsymbolized addresses remain useful. Any later symbol-loading checkpoint
  needs a separate immutable firmware identity and confirmation digest.
- Physical qualification still requires two identical host-only plans,
  independent digest confirmation, one execution, complete cleanup, target
  restoration, and an external liveness check where available.

## References

- [GDB/MI stack manipulation](https://sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI-Stack-Manipulation.html)
- [GDB/MI frame information](https://www.sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI-Frame-Information.html)
- [ADR-0008: Confirmed OpenOCD and GDB session](0008-confirmed-openocd-gdb-session.md)
- [ADR-0012: Confirmed bounded memory snapshot](0012-confirmed-openocd-memory-snapshot.md)
