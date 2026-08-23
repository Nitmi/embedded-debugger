# ADR-0004: Fail closed across MCP child restarts

- Status: accepted
- Date: 2026-08-23

## Context

The MCP stdio adapter owns a native debugger lease inside one foreground child
process. Idle expiry can close that lease cleanly, but a client normally keeps
the outer stdio connection open. An unexpected child exit must not strand the
Agent transport or tempt middleware to replay a target operation whose outcome
is unknown.

The [MCP lifecycle](https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle)
requires `initialize` to be the first interaction on a client-server
connection. Requiring the external client to initialize a second time on the
same stdio connection would therefore depend on non-standard client behavior.
Treating a replacement child as an implementation detail allows each new
private child connection to receive its own valid first interaction while the
supervisor remains the stable logical server seen by the client.

## Decision

1. `supervisor mcp` is a bounded stdio proxy around the existing `mcp serve`
   process. It does not own hardware behavior or define another tool schema.
2. Backend, fixture, target, idle-timeout, restart-count, and restart-delay
   configuration is validated before the first child is launched.
3. A child response is drained before exit is processed. Every request still
   awaiting a response then receives JSON-RPC error `-32001`, explicitly
   reporting that target state is indeterminate. No request is replayed.
4. After a successful initial MCP negotiation, the supervisor caches only the
   side-effect-free `initialize` request and an observed
   `notifications/initialized` notification. A replacement child receives that
   handshake with a private request ID. Its response is consumed internally.
5. External requests received during the short internal handshake are rejected
   with retryable JSON-RPC error `-32002`; they are not queued or forwarded.
6. A fresh child has no active debug lease. Requests that carry an old
   `session_id` reach the normal session owner and fail with its stable
   `PROTOCOL_ERROR`; callers must open a new lease before further control.
7. Restarts are capped at 3 by default, at most 32, with a bounded delay. A
   client-requested shutdown or stdin EOF is expected termination and is never
   restarted.

## Consequences

- Standard MCP clients keep one logical connection and do not need to perform a
  non-standard second initialize.
- Process availability improves without converting an ambiguous target action
  into at-least-once execution.
- A child crash cannot prove breakpoint cleanup, core restoration, flash
  completion, or disconnect. The next lease must inspect and recover the target
  explicitly; the supervisor never labels that state safe.
- The private handshake is the only replay exception because it negotiates the
  transport and does not call the embedded debugger tool.
- Multi-client arbitration, durable operation journals, and asynchronous
  cancellation remain separate concerns.
