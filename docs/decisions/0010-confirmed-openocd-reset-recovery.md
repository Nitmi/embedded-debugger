# ADR-0010: Confirm OpenOCD reset as a global reset and selected-target recovery

- Status: accepted
- Date: 2026-08-24

## Context

The accepted direct OpenOCD target roundtrip proves fixed halt and resume on an
exact current target. Reset is a materially broader effect. OpenOCD defines
`reset halt` as resetting all defined targets, using the hardest available
mechanism, and firing configured reset events. Those event handlers are Tcl and
may affect target memory, peripherals, external I/O, or host state beyond what a
selected target's `curstate` can prove.

The Tcl RPC returns interpreter text framed by `0x1a`, not a separate command
status. For reset, observing `halted` after an error is insufficient: the reset
may have failed after partially changing the target. The first reset checkpoint
therefore needs an explicit fixed Tcl success envelope as well as state proof.

## Decision

1. Add `openocd reset plan/test` as an independent operation. Do not alter the
   accepted `openocd server`, `openocd session`, or `openocd target` protocols
   or confirmation inputs.
2. Bind the exact OpenOCD file/version, top-level configuration manifests,
   ordered search paths, lifecycle and transition deadlines, exact expected
   current-target name, fixed Tcl protocol, global reset scope, and selected
   target recovery policy into one digest.
3. Retain `R2_DEVICE_WRITE`. Search-tree contents, transitive Tcl sources,
   configuration and reset-event semantics, runtime adapter identity, dynamic
   ports, and non-selected target inventory and states remain explicitly
   unbound.
4. Require `target current` to pass the existing bounded ASCII validation,
   exactly match the confirmed name, and report `running` before reset. Reject
   mismatch or another initial state without issuing reset or resume.
5. Issue only the fixed reset RPC
   `format {__EMBEDDED_DEBUGGER_RESET_V1__%d} [catch {reset halt}]`. Accept only
   exact catch code `0`, then poll the selected target until `halted`. The fixed
   wrapper contains no user interpolation and creates no Tcl variable.
6. After every reset result, issue exactly
   `format {__EMBEDDED_DEBUGGER_RECOVERY_V1__%d} [catch {targets <validated-current-target>; resume}]`
   with a fresh deadline. Require exact catch code `0` and the selected target
   to reach `running`. Do not issue a second reset as an automatic fallback.
7. Treat the reset as global but the recovery guarantee as selected-target
   only. Do not claim observation or restoration of any non-selected target.
8. Require clean reset and recovery catch results, halted and final running
   observations, graceful OpenOCD shutdown, complete output drains, and
   process-tree cleanup for success. Preserve all available reset, recovery,
   readiness, shutdown, and log evidence on failure.
9. Do not automatically retry a failed confirmed test. Partial reset or failed
   recovery leaves target and peripheral state indeterminate and requires
   explicit inspection plus a newly reviewed plan where inputs changed.
10. Expose only fixed reset-halt, selected-target resume, and final selected
    running verification after physical acceptance. `reset init`, configurable
    reset modes, GDB/MI, target-data access, breakpoints, flash, monitor input,
    and arbitrary Tcl remain unavailable.

## Consequences

- Agents can request one reviewable reset workflow without receiving a general
  OpenOCD command channel.
- Catch-code validation distinguishes clean Tcl completion from a reset or
  recovery error that happens to leave the selected target in the expected
  state.
- The operation proves only the selected target's `running -> halted -> running`
  observations. OpenOCD may reset or leave other targets in states that the
  result neither inventories nor restores.
- Reset can clear volatile CPU and peripheral state, interrupt external I/O,
  rerun boot code, and execute configuration-defined reset handlers. A final
  selected-target `running` observation is recovery evidence, not full state
  restoration.
- Controlled OpenOCD fixtures qualify protocol and cleanup behavior. A real
  target still requires a separate exact digest confirmation and physical
  acceptance before this capability is qualified there.

## References

- [OpenOCD general reset commands](https://openocd.org/doc/html/General-Commands.html)
- [OpenOCD reset configuration](https://openocd.org/doc/html/Reset-Configuration.html)
- [OpenOCD Tcl RPC API](https://openocd.org/doc/html/Tcl-Scripting-API.html)
- [ADR-0009: Confirmed OpenOCD target state roundtrip](0009-confirmed-openocd-target-state-roundtrip.md)
