# Embedded Debugger MCP Reference

## Launch

The plugin entry point is the bounded stdio supervisor. Its child owns one
backend instance and one debug lease:

```console
embedded-debugger --backend probe-rs supervisor mcp --target esp32s3 \
  --idle-timeout-ms 300000 --max-restarts 3 --restart-delay-ms 250
```

For contract tests, use Replay and its fixture:

```console
embedded-debugger --fixture examples/replay/stm32g4.json supervisor mcp \
  --idle-timeout-ms 0 --max-restarts 1 --restart-delay-ms 0
```

The plugin manifest is [`mcp.json`](../../mcp.json). Native users should edit
the exact target in that file for the connected board rather than relying on a
default target guess.

## Protocol

The server implements MCP stdio JSON-RPC with `initialize`, `ping`,
`notifications/initialized`, `tools/list`, `tools/call`, and `shutdown`.
Input lines are limited to 64 KiB; malformed or oversized lines return a
JSON-RPC `-32600` error and do not renew an active idle lease.
`tools/list` returns one tool named `embedded_debugger_request`. Its arguments
are the existing session JSON fields with an added required `operation`:

```json
{
  "operation": "session.open",
  "probe": "303a:1001:E0:72:A1:D4:1F:DC",
  "target": "esp32s3"
}
```

The tool result contains the normal versioned session envelope in both
`structuredContent` and the text content. Operation-level failures are MCP
tool results with `isError=true` and retain the stable embedded-debugger error
code. Invalid MCP method or argument shapes use JSON-RPC errors and do not
terminate the server.

The supervisor validates configuration before launch and never replays a tool
request. If the child exits before responding, JSON-RPC `-32001` marks the
target state indeterminate. The replacement child receives only the cached MCP
initialize handshake; this stays private and the external client does not
initialize twice. Calls arriving while that handshake is in progress receive
retryable `-32002` without being forwarded. A replacement child owns no lease,
so an old `session_id` returns the normal `PROTOCOL_ERROR`; open a new lease and
recover the target deliberately. Expected shutdown and stdin EOF are not
restarted.

## Session order

```text
session.open
  -> session.status / core.* / breakpoints.* / registers.read / memory.read
  -> session.close
```

Use the `session_id` from `session.open` exactly. `core.continue_until_halt`
is bounded by `timeout_ms` and `poll_interval_ms`; a successful timeout leaves
the core running and the lease usable. Idle expiry starts only after the lease
opens, resets after a valid request completes, and never interrupts a request
already in flight. The close report is the authority for breakpoint cleanup,
final observed core state, and disconnect status.

The MCP session tool intentionally does not expose flash or arbitrary memory
writes. Use the CLI plan/execute contract for flashing and keep its confirmation
digest and evidence bundle.
