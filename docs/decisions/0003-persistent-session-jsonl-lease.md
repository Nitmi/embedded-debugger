# ADR-0003: Persistent debug sessions use a leased JSONL owner

- Status: accepted
- Date: 2026-08-14

## Context

`probe-rs` can observe and change a core reliably while its `Session` is alive,
but dropping that session may resume a halted Xtensa core or clear halting debug
on Cortex-M. A short-lived CLI therefore cannot expose a durable halt. Agents
also need one process to own the USB probe; reopening a session for every MCP
tool call recreates the teardown race and makes state continuity ambiguous.

## Decision

1. Add `session serve --target <exact-target>` as a foreground local service.
   It owns one backend instance and one active probe session at a time.
2. Use newline-delimited JSON on stdin/stdout. Every non-empty input line is
   one request and every request receives exactly one versioned response line.
   Human diagnostics and transport-cleanup notes go to stderr.
3. Requests carry `schema_version`, a bounded non-empty `request_id`, and an
   operation. `session.open` binds an exact probe selector and exact target;
   subsequent operations carry the returned opaque `session_id`.
4. A stale or foreign `session_id` is a protocol error. A second open is
   rejected while a lease is active. `server.shutdown` requires an explicit
   `session.close` first.
5. In-session `core.status`, `core.halt`, `core.run`, and `core.step` use the
   backend's explicit `control_core_in_session` boundary. `core.step` requires
   a halted origin and finishes halted after one instruction. In-session
   `registers.read` and `memory.read` reuse the bounded read contracts while
   the same backend session remains alive. Every result reports
   `state_scope="active_session"` and does not claim a post-disconnect
   guarantee.
6. `session.close` explicitly runs every core observed by the service before
   disconnecting (`run_observed_cores_before_disconnect`). EOF and transport
   errors use the same best-effort cleanup path. If cleanup fails, the response
   reports whether the session was nevertheless disconnected.
7. One-shot CLI commands retain their existing `post_disconnect_core_state`
   gate. The persistent service is the only first-class path for native
   probe-rs stateful halt/run in this milestone.

## Consequences

- CLI, future MCP, and Skills can share a small transport-neutral session owner
  instead of duplicating probe lifetime logic.
- The service is intentionally single-client and foreground in this milestone;
  process supervision, idle lease expiry, cancellation, and a multi-client
  broker remain follow-up work.
- Closing a session has an explicit running-state policy. A future backend may
  add a capability-qualified restore policy, but it must not silently claim that
  `Session::drop` preserves a halted state.
- Register and memory reads restore the original core state before returning,
  but remain R1 operations: transient halt/attach effects and non-atomic
  external I/O are exposed through structured effects and ordered operations.
- Single-instruction stepping is deliberately a persistent-session operation
  for native probe-rs targets. A one-shot step remains behind the same
  detach-safe capability gate because dropping the backend session can change
  the final halted state.
- The JSONL transport is easy to launch from an Agent and easy to replace with
  MCP stdio or a local authenticated socket without changing domain operations.
