# ADR-0009: Confirm direct OpenOCD halt and run as a fixed state roundtrip

- Status: accepted
- Date: 2026-08-24

## Context

The guarded OpenOCD server proves process and Tcl RPC lifecycle, and the first
combined GDB session proves remote attach/detach interoperability. Neither
qualifies direct OpenOCD target-control commands. Phase 3 needs basic halt/run
before reset, flash, or broader GDB/MI debugging, but a one-shot halt cannot
promise a durable halted state after server teardown.

Halting a live CPU can interrupt peripheral activity and external I/O. OpenOCD
configuration is executable Tcl whose transitive sources and semantics remain
outside the confirmation boundary. The first direct-control checkpoint must
therefore remain narrow, separately confirmed, and restoration-oriented.

## Decision

1. Add `openocd target plan/test` as an independent operation. Do not change
   the already accepted `openocd server` or `openocd session` protocols and
   digests.
2. Bind the exact OpenOCD file/version, top-level configuration manifests,
   ordered search paths, lifecycle deadlines, target transition deadline,
   exact expected current-target name, fixed Tcl protocol, and target-state
   policy into one digest.
3. Retain `R2_DEVICE_WRITE`. Search-tree contents, transitive Tcl sources,
   configuration semantics, runtime adapter identity, and dynamic port numbers
   remain explicitly unbound.
4. Require the runtime `target current` name to pass the existing 128-byte
   ASCII allow list, exactly match the confirmed name, and report `running`
   before control. Reject mismatch or any other initial state without issuing
   halt or resume.
5. Permit only `targets <validated-name>; halt`, bounded polling until
   `halted`, `targets <validated-name>; resume`, bounded polling until
   `running`, and the managed server's fixed readiness/shutdown requests. No
   user Tcl or target-name interpolation outside the validated name is allowed.
6. Attempt the fixed resume after every halt result, even when halt fails or
   `halted` cannot be proven. Use a fresh transition deadline for restoration.
   Final `running` is mandatory, and failure evidence includes all available
   transition and server cleanup state.
7. Expose only selected-target observation, fixed halt/run, and verified final
   restoration after physical acceptance. Reset, GDB/MI, registers, memory,
   stack, breakpoints, watchpoints, flash, monitor commands, and arbitrary Tcl
   remain false.
8. Do not automatically retry a failed confirmed test. A timeout, server crash,
   or failed restoration can leave the target outcome indeterminate and needs
   explicit inspection and a newly reviewed plan where inputs changed.

## Consequences

- Agents can qualify direct OpenOCD halt/run without also authorizing reset,
  flash, debugger data access, or arbitrary command execution.
- The operation proves a temporary halted observation inside one managed
  server lifecycle, not a durable halted state after exit.
- The final-state invariant converges success and failure cleanup on a
  verifiable running target, while structured evidence preserves partial
  transitions for diagnosis.
- Target grouping and reviewed configuration can affect related cores or
  peripherals beyond what `curstate` proves; those residual effects remain
  disclosed rather than treated as state preservation.
- Controlled OpenOCD fixtures cover the protocol and cleanup paths without
  hardware. A real target requires a separate exact digest confirmation and
  physical acceptance before the capability is considered qualified there.

## References

- [OpenOCD general target commands](https://www.openocd.org/doc/html/General-Commands.html)
- [OpenOCD CPU configuration and target state](https://openocd.org/doc/html/CPU-Configuration.html)
- [ADR-0006: Guarded OpenOCD server lifecycle](0006-guarded-openocd-server-lifecycle.md)
- [ADR-0008: Confirmed OpenOCD and GDB session](0008-confirmed-openocd-gdb-session.md)
