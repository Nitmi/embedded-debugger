# ADR-0001: CLI-first embedded control plane

- Status: accepted
- Date: 2026-08-13

## Context

Agents can invoke probe-rs, OpenOCD, and GDB directly, but every caller then has
to rediscover output parsing, process lifecycle, target identity, concurrency,
dangerous-operation policy, evidence capture, and error recovery. An MCP-only
wrapper also makes the domain behavior difficult to reuse from a terminal or CI.

The implementation review of `Adancurusul/embedded-debugger-mcp` confirmed that
a probe-rs/OpenOCD abstraction, bounded memory access, file canonicalization,
and explicit write guards are useful. It also showed the cost of concentrating
session and domain behavior inside MCP handlers and of maintaining a partial
GDB Remote Serial Protocol client.

## Decision

Build a standalone Rust CLI and library with:

1. A versioned domain result contract shared by every interface.
2. Backend capability negotiation.
3. A first-class Replay backend from the first milestone.
4. Plan/confirm/apply semantics for target mutation.
5. Evidence capture suitable for offline inspection and regression tests.
6. MCP as an adapter over the same service layer after the CLI contract is
   exercised, not as the owner of hardware behavior.
7. OpenOCD advanced debugging through a maintained GDB/MI integration rather
   than a new partial RSP implementation.

## Consequences

- Native hardware support follows and reuses the contract and replay path.
- CLI and MCP equivalence can be tested at the service boundary.
- Failure reports can be replayed without access to the reporter's device.
- Persistent live sessions will require a long-running local service; one-shot
  CLI commands must not pretend that a process-local session survives exit.
