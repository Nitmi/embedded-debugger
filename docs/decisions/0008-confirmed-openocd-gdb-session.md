# ADR-0008: Confirm the first OpenOCD and GDB target session as a fixed lifecycle

- Status: accepted
- Date: 2026-08-24

## Context

The managed OpenOCD server and GDB/MI host checkpoints prove each process in
isolation. They do not prove that the selected GDB can negotiate a remote
session with the selected OpenOCD configuration. Combining them crosses a
target-control boundary: OpenOCD's default `gdb-attach` event halts the current
target, while a normal GDB remote detach generally resumes it.

This first combined checkpoint needs to prove interoperability without also
introducing symbols, register or memory inspection, breakpoints, execution
commands, flash, arbitrary MI, or arbitrary monitor commands.

## Decision

1. Add `openocd session plan/test`. The plan binds the exact OpenOCD and GDB
   executable files and versions, an optional exact Espressif Xtensa target
   configuration file, ordered top-level OpenOCD configuration manifests and
   search paths, all process and target-state deadlines, the fixed MI command
   sequence, an exact expected OpenOCD current-target name, and the target
   restoration policy. Execution requires its exact combined digest.
2. Retain `R2_DEVICE_WRITE`. OpenOCD configuration is executable Tcl whose
   transitive sources, search-tree contents, and semantics are not bound, and a
   remote attach may halt the target.
3. Start the already guarded loopback-only OpenOCD server with dynamic GDB/Tcl
   ports and disabled telnet. Read the validated `target current` name and its
   `curstate` through bounded Tcl RPC. Refuse to start GDB unless that name
   exactly matches the confirmed `--expected-target` and its state is exactly
   `running`.
4. Launch GDB only as `--nx --nh --quiet --interpreter=mi2`. Remove ambient
   `XTENSA_GNU_CONFIG` unconditionally. If `--gdb-xtensa-config` was selected,
   canonicalize and hash that file during planning, bind the selection and
   identity in the digest, and set only that fixed environment variable during
   confirmed execution. The file is a native host module and is not loaded by
   planning. The entire MI exchange is fixed to `1-gdb-version`,
   `2-target-select remote 127.0.0.1:<dynamic>`, `3-target-detach`, and
   `4-gdb-exit`, requiring result classes `done`, `connected`, `done`, and
   `exit` with matching tokens.
5. After GDB cleanup, query the original current target again. If `running` is
   not proven, issue one fixed `targets <validated-name>; resume` fallback and
   poll `curstate` within the bound deadline. Success requires a final exact
   `running` observation. Failure to prove restoration is a verification
   failure and includes GDB, target restoration, OpenOCD shutdown, and bounded
   log evidence.
6. Target names are accepted for Tcl interpolation only after a 128-byte ASCII
   allow-list check. No user-provided Tcl, MI, endpoint, GDB argument, symbol,
   executable image, or monitor command is accepted.
7. Distinguish explicit tool commands from underlying connection effects.
   Remote negotiation may exchange stop state, target descriptions, memory-map
   metadata, or register state. Confirmed configuration may install an attach
   handler that probes flash or resets and halts a protected target. These are
   disclosed even though no corresponding general capability is exposed.
8. Both process trees retain the Windows Job Object / Unix process-group,
   bounded output, fail-closed protocol, graceful shutdown, and forced cleanup
   guarantees of their individual checkpoints.
9. A successful result enables only the managed server/Tcl/GDB-MI connection,
   target-state observation, attach/detach, and restoration-resume capabilities.
   All symbol, register, memory, stack, breakpoint, watchpoint, general
   execution-control, flash, and arbitrary-command capabilities remain false.

## Consequences

- The first combined acceptance is small enough to diagnose toolchain and
  remote-protocol compatibility independently of ELF and explicit target-data
  commands, while still disclosing negotiation and attach-handler effects.
- A running-origin precondition makes the normal detach behavior and the fixed
  resume fallback converge on one verifiable final state. Halted-origin sessions
  require a later policy and are rejected before GDB starts.
- A dynamically allocated runtime port cannot be part of a prior digest. The
  digest instead binds loopback-only allocation policy; the actual endpoint is
  returned in execution evidence.
- The runtime adapter/USB serial identity is not currently digest-bound by this
  OpenOCD workflow. The plan reports that limit; reviewed driver-specific
  configuration may bind a serial where the adapter supports it.
- The first physical ESP32-S3 attempt proved the failure cleanup path but not
  interoperability: generic Espressif GDB expected a 388-byte register packet
  while OpenOCD returned the ESP32-S3 608-byte layout. The target-specific
  profile produces the matching register inventory. Automated tests now bind
  and deliver that profile, clear ambient configuration, restore the target on
  protocol failure, and reject profile drift. Physical success still requires
  a new separately confirmed digest.

## References

- [GNU GDB remote target connection](https://www.sourceware.org/gdb/current/onlinedocs/gdb.html/Connecting.html)
- [GDB/MI target manipulation](https://www.sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI-Target-Manipulation.html)
- [GDB/MI result records](https://www.sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI-Result-Records.html)
- [OpenOCD CPU configuration and target state](https://openocd.org/doc/html/CPU-Configuration.html)
- [OpenOCD GDB integration](https://openocd.org/doc-release/html/GDB-and-OpenOCD.html)
- [OpenOCD general target commands](https://www.openocd.org/doc/html/General-Commands.html)
- [GDB remote packet configuration](https://www.sourceware.org/gdb/current/onlinedocs/gdb.html/Remote-Configuration.html)
- [GDB remote target descriptions](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Retrieving-Descriptions.html)
