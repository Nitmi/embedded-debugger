# ADR-0002: Core-state guarantees follow the session lifetime

- Status: accepted
- Date: 2026-08-14

## Context

A short-lived CLI can attach, observe or change a core, verify the state, and
then drop its debugger session. Verification before teardown is not sufficient:
the backend may change execution state while detaching.

probe-rs 0.32 calls `debug_core_stop` for each core from `Session::drop`. Its
Xtensa path leaves debug mode by resuming a stopped core. Its Cortex-M default
sequence disables core debug, including halting debug. Physical ESP32-S3 testing
confirmed the consequence: a halt verified inside the session, but an
independent session immediately observed the core running again.

Leaking or forgetting a probe-rs session would retain USB resources, skip
required cleanup, and make ownership and recovery undefined. It is not an
acceptable implementation of persistent control.

## Decision

1. A successful `core status`, `core halt`, or `core run` response guarantees
   that its reported `core.state` remains valid after the command disconnects.
2. Successful live snapshot, register-read, and memory-read responses make the
   same guarantee for their reported final restored states.
3. The `post_disconnect_core_state` capability represents that guarantee and
   is required in addition to `core_status` and the action-specific capability.
   State-preserving read commands require it alongside their existing read,
   halt, and run capabilities.
4. Replay advertises the guarantee and models state across operations within one
   service/backend instance.
5. Native probe-rs does not advertise it until a backend/target pair passes both
   running-origin and halted-origin teardown acceptance.
6. Persistent native observation and halt/run use the long-running local
   `session serve` owner introduced by ADR-0003. Future CLI, Skill, and MCP
   adapters will all address the same lease through that shared contract.

## Consequences

- Unsupported native one-shot core-state and state-preserving read commands
  fail before probe selection.
- An in-session observation capability cannot be mistaken for a detach-safe
  one-shot operation.
- Agent responses never claim a durable halt that disappears during cleanup.
- Persistent-session work must define lease identity, exclusivity, expiry,
  cleanup, crash recovery, and final-state policy before exposing native
  interactive control.
