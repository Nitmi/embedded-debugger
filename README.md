# embedded-debugger

`embedded-debugger` is an agent-safe control plane for embedded flashing and
debugging. It is CLI-first: humans, scripts, CI, Skills, and MCP clients will all
use the same versioned domain contract.

The current milestone implements the contract and a deterministic Replay
backend. It proves the complete guarded flow without requiring hardware:

```text
discover -> select exact probe/target -> flash plan -> confirm digest
         -> simulated program/verify -> reset -> snapshot evidence
```

Real probe-rs and OpenOCD backends are the next milestones. Replay is a product
backend, not a throwaway mock: it will power CI, regression fixtures, issue
reports, and offline Agent analysis.

Native probe discovery is already available through probe-rs:

```console
cargo run -- --backend probe-rs probes list --json
```

This command is read-only. Native attach, flash, and debug operations remain
disabled until their session lifecycle and hardware acceptance tests land.

## Build

```console
cargo build
cargo test
```

## Quick start

Inspect the environment and validate the bundled fixture:

```console
cargo run -- doctor
cargo run -- --fixture examples/replay/stm32g4.json replay validate
cargo run -- --fixture examples/replay/stm32g4.json probes list
```

Create a flash plan for the bundled dummy firmware:

```console
cargo run -- --fixture examples/replay/stm32g4.json flash plan examples/firmware/demo.bin --json
```

Copy the returned `confirm_digest` into the execute command:

```console
cargo run -- --fixture examples/replay/stm32g4.json flash execute examples/firmware/demo.bin \
  --confirm <digest> --evidence run.evidence.json --json
```

Changing the firmware, target, or probe changes the digest. Execution rejects a
stale or incorrect confirmation before a backend write is attempted.

## Design constraints

- Successes and failures have a stable `schema_version` and `operation_id`.
- Hardware mutation requires a plan and exact confirmation digest.
- Backends advertise capabilities; callers do not infer them from backend names.
- Evidence is written atomically and referenced by SHA-256.
- Replay fixtures are validated and cannot silently opt into unsupported behavior.

See [docs/contracts.md](docs/contracts.md) and
[docs/decisions/0001-cli-first-control-plane.md](docs/decisions/0001-cli-first-control-plane.md).

## Current status

This repository is at its first development checkpoint. Replay workflows and
native probe discovery are implemented and tested. Native target mutation is
intentionally unavailable until probe-rs attach/flash lifecycle handling and a
real-hardware acceptance fixture are complete. See `CHANGELOG.md` for the exact
scope and known limitations.

## Acknowledgments

The architecture review included
[Adancurusul/embedded-debugger-mcp](https://github.com/Adancurusul/embedded-debugger-mcp),
probe-rs, OpenOCD, GDB/MI, and the existing Nitmi `baud-cli` and `blea`
projects. See `NOTICE` for the current source-reuse status.

## License

MIT
