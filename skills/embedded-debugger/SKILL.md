---
name: embedded-debugger
description: Use embedded-debugger for structured embedded flashing and debugging through probe-rs or Replay, plus confirmed OpenOCD and GDB lifecycles. Trigger when work needs exact probe selection, bounded target control, evidence, safe session cleanup, or verified debug-tool integration.
---

# Embedded Debugger

Use `embedded-debugger` as the structured debug control layer. Prefer the
`embedded_debugger_request` MCP tool when available; otherwise use the CLI and
the same versioned JSON contract. Do not replace it with ad hoc probe-rs or
OpenOCD shell parsing.

## Before hardware

1. Run `embedded-debugger doctor` and `embedded-debugger --backend probe-rs probes list --json`.
2. Select the probe by its complete selector, including serial identity. Select the exact target name; never infer either from a friendly board name.
3. For native operations, surface the returned capability matrix and `effects` before taking an R1 action. Replay is the safe path for contract tests and offline analysis.
4. When a serial console is relevant, use the `baud` skill for port identity and read-only monitoring. Keep DTR/RTS false unless the board protocol explicitly requires otherwise.

## OpenOCD and GDB host checks

Use `openocd inspect` before any OpenOCD configuration execution. Configuration
files are Tcl; crossing into `openocd server test` requires a reviewed
`openocd server plan` and its exact confirmation digest.

For direct OpenOCD halt/run qualification, run `openocd target plan` with the
exact executable, top-level config/search inputs, and exact
`--expected-target`. Surface the R2 effects, including target interruption,
partial external I/O, and unbound runtime adapter identity. Require the user to
return the exact digest before `openocd target test`. The fixed test accepts
only a running origin, proves halted, always attempts the fixed resume after
the halt result, and requires final running plus complete server cleanup. Do
not retry failure automatically. A success proves only fixed selected-target
halt/run; it does not authorize reset, GDB, register/memory/stack access,
breakpoints, flash, monitor commands, or arbitrary Tcl.

For reset, use the independent `openocd reset plan/test` workflow. Before
requesting confirmation, surface that OpenOCD resets all defined targets and
runs configuration-defined reset events, while the tool observes and recovers
only the exact selected target. The fixed test requires a running origin, exact
Tcl catch code 0 for reset and recovery, a halted selected-target observation,
one fixed catch-wrapped selected-target resume, final running, and complete
cleanup. Require the exact reset digest immediately before execution. Do not
claim non-selected target restoration, and never retry a failed reset test
automatically. Success does not authorize `reset init`, another reset mode,
GDB, target-data access, breakpoints, flash, monitor commands, or user Tcl.

Use `openocd gdb inspect --executable <PATH> --json` to prove an exact GNU GDB
file, then `openocd gdb test --executable <PATH> --json` to prove only the
fixed local MI2 version/exit lifecycle. A successful
`gdb_mi_host_process=true` does not authorize or prove a remote target session.
Do not infer symbol, register, memory, stack, breakpoint, execution-control, or
flash support while those capability fields remain false.

For the combined interoperability check, run `openocd session plan` with exact
`--openocd-executable`, `--gdb-executable`, top-level `--config`, and `--search`
inputs plus the exact OpenOCD `--expected-target` name. Surface its
`R2_DEVICE_WRITE` effects and confirmation boundary, including the unbound
runtime adapter identity, then require the user to return the exact digest
before `openocd session test`. The test requires the current target name to
match and its state to start and finish `running`; attach may halt it, detach
normally resumes it, and the tool may issue one fixed OpenOCD resume fallback
before final verification. Do not retry a lost or failed test automatically
because target outcome may be indeterminate.

For Espressif Xtensa targets, resolve the target-specific profile before
planning. Prefer the actual `xtensa-esp-elf-gdb` binary with
`--gdb-xtensa-config <exact-profile.so>` so both files are hash-bound; do not
substitute a small board launcher whose dynamically selected GDB child is not
represented by that launcher hash. Surface that the profile is native host
code loaded only during confirmed execution. Use the identical option for
plan and test. Ambient `XTENSA_GNU_CONFIG` is deliberately ignored. A missing
or changed profile requires a new plan and confirmation.

A complete combined test proves only the selected tools' fixed MI2
version/connect/detach/exit lifecycle, loopback endpoint, target-state
observation, and restoration. It does not authorize ELF or symbol loading,
explicit register/memory/stack reads, breakpoints, watchpoints, general
execution control, flash, monitor commands, or arbitrary MI/Tcl input. Still
surface the plan's implicit effects: remote negotiation may exchange target
descriptions, memory-map metadata, stop/register state, and confirmed OpenOCD
attach handlers may probe flash or reset/halt a protected target.

## Persistent session

The MCP server exposes one tool, `embedded_debugger_request`. Call it with
`operation="session.open"`, exact `probe` and `target`, then reuse the opaque
`session_id` returned in every later request. The supported operations are
`session.status`, `core.status`, `core.halt`, `core.run`, `core.continue`,
`core.continue_until_halt`, `core.step`, `breakpoints.list|set|clear|clear_all`,
`registers.read`, `memory.read`, and `session.close`.

Always close the session explicitly. The server also applies its idle lease
policy and will halt tracked breakpoint cores, clear and verify comparator
slots, run observed cores, disconnect, and emit structured expiry evidence on
stderr. A session response is scoped to the active lease; do not claim that a
halt or breakpoint survives process teardown unless a separate acceptance
result proves it.

The plugin launches the bounded MCP supervisor. If its child exits before a
tool response, treat JSON-RPC `-32001` as an indeterminate target outcome and
never repeat the operation automatically. The supervisor restores only the MCP
handshake. Any old `session_id` is stale after a restart, so inspect the error,
open a new exact probe/target lease, and recover explicitly. A retryable
`-32002` means the replacement child is still completing that private
handshake; the rejected request was not forwarded.

## Safety boundaries

- Treat halt, run, step, continue, register reads, memory reads, and breakpoint changes as R1 reversible control, not side-effect-free inspection. Report the response `effects` and warnings.
- Keep memory reads within the validated single-region limit of 4096 bytes. Do not turn an MMIO or cross-region request into a guessed read.
- Breakpoint mutation requires a halted selected core. Preserve the complete before/after slot inventory and cleanup evidence.
- Flashing is not exposed through the MCP session tool. Use the CLI `flash plan` first, require the exact confirmation digest for `flash execute`, and preserve the evidence path.
- Treat `ok=true` as a completed operation, not proof that every target-side expectation was satisfied. Inspect `complete`, state fields, verification flags, and ordered operations.

Read [mcp.md](references/mcp.md) for the MCP launch shape and request schema.
