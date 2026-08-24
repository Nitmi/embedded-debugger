---
name: embedded-debugger
description: Use embedded-debugger for structured embedded flashing and debugging through probe-rs or Replay, plus guarded OpenOCD and GDB host diagnostics. Trigger when work needs exact probe selection, bounded target control, evidence, safe session cleanup, or verified debug-tool lifecycles.
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

Use `openocd gdb inspect --executable <PATH> --json` to prove an exact GNU GDB
file, then `openocd gdb test --executable <PATH> --json` to prove only the
fixed local MI2 version/exit lifecycle. A successful
`gdb_mi_host_process=true` does not authorize or prove a remote target session.
Do not infer symbol, register, memory, stack, breakpoint, execution-control, or
flash support while those capability fields remain false.

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
