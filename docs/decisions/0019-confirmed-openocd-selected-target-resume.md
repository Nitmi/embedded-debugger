# ADR-0019: Confirm one selected-target OpenOCD resume-only recovery

- Status: accepted; physical validation pending
- Date: 2026-08-30

## Context

The failed hardware-watchpoint-hit attempt left ESP32-S3 CPU0 point-in-time
halted. Existing one-shot probe-rs core control cannot guarantee target state
after `Session::drop`, so it correctly rejects `core run` before probe
selection. Existing OpenOCD `target test` deliberately performs a complete
`running -> halted -> running` roundtrip, and `reset test` resets all defined
targets. Neither command represents authority to resume one already halted
selected target without another halt or reset.

A generic Tcl escape hatch would be difficult for an Agent to review and could
silently broaden recovery into reset, memory access, breakpoint manipulation,
or arbitrary host execution. Recovery therefore needs its own fixed protocol,
digest, state preconditions, evidence, and no-retry boundary.

## Decision

1. Add independent `openocd resume plan/test` commands. Do not alter any
   existing plan, protocol, digest, or accepted hardware capability.
2. Bind the exact OpenOCD file/version, top-level configuration manifests,
   ordered search paths, lifecycle and state deadlines, expected selected-target
   name, fixed Tcl protocol, accepted origin states, one-command maximum, and
   zero-retry policy into one `R2_DEVICE_WRITE` digest.
3. Validate target syntax and timeout before filesystem access. Recompute and
   compare the digest before configuration Tcl executes.
4. Query `target current`, require its validated name to exactly equal the
   confirmed target, and query that target's `curstate` before any control
   command.
5. Accept only `halted` or `running`. For `running`, send no control command and
   use that observation as the idempotent final-running proof. Reject any other
   state before resume.
6. For `halted`, issue at most once:
   `format {__EMBEDDED_DEBUGGER_RESUME_ONLY_V1__%d} [catch {targets <validated-current-target>; resume}]`.
   Accept only exact catch code 0 and poll the same selected target until
   `running` within the confirmed deadline.
7. Never issue halt, reset, flash, target-data, GDB/monitor,
   breakpoint/watchpoint, or arbitrary Tcl commands. Never send a second resume
   after an error and never retry the physical operation automatically.
8. Require final selected-target `running`, graceful OpenOCD shutdown, complete
   output drains, and process-tree cleanup for success. Preserve available
   initial, transition, final-state, readiness, shutdown, log, command-count,
   and retry-count evidence on every failure.
9. State the confirmation boundary conservatively. Top-level configuration is
   hashed but remains executable Tcl; transitive sources, search-tree contents,
   runtime adapter identity, dynamic ports, and non-selected target states are
   unbound. Resumed firmware may perform arbitrary firmware-defined I/O.
10. Require two identical host-only plans and fresh exact digest confirmation
    before every physical recovery. A prior natural-language authorization,
    rejected command, successful recovery, or historical digest is not standing
    authority for another attempt.

## Consequences

- An Agent can request the smallest reviewable selected-target recovery without
  receiving generic OpenOCD or GDB control.
- A running target is handled idempotently and does not receive a redundant
  resume; a halted target can receive only one resume command.
- Failure can still leave target state uncertain because configuration Tcl,
  transport loss, partial command delivery, or target behavior cannot be made
  transactional. The tool reports this evidence and stops instead of retrying.
- The result proves only a point-in-time final state for the exact selected
  target. It does not prove non-selected target state, watchpoint comparator
  cleanup, firmware identity, or external-system recovery.

## Validation

Controlled fixtures cover halted success, running idempotence, mismatched
target, unsupported initial state, command error, malformed catch envelope,
final-state failure, deterministic digests, stale confirmation, pre-filesystem
validation, lifecycle cleanup, exact command counts, and zero retries. Physical
validation requires a separately confirmed, non-retried run and independent
post-run evidence.

## References

- [OpenOCD general commands](https://openocd.org/doc/html/General-Commands.html)
- [OpenOCD Tcl RPC API](https://openocd.org/doc/html/Tcl-Scripting-API.html)
- [ADR-0009: Confirmed OpenOCD target state roundtrip](0009-confirmed-openocd-target-state-roundtrip.md)
- [ADR-0010: Confirmed OpenOCD reset recovery](0010-confirmed-openocd-reset-recovery.md)
- [ADR-0018: Confirmed OpenOCD hardware-watchpoint hit](0018-confirmed-openocd-hardware-watchpoint-hit.md)
