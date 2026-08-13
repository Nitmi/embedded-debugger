# embedded-debugger

`embedded-debugger` is an agent-safe control plane for embedded flashing and
debugging. It is CLI-first: humans, scripts, CI, Skills, and MCP clients will all
use the same versioned domain contract.

The current milestone implements the contract, a deterministic Replay backend,
and a native probe-rs guarded flash workflow:

```text
discover -> select exact probe/target -> flash plan -> confirm digest
         -> sector erase/program -> read-back verify
         -> reset-and-halt -> snapshot -> resume -> evidence
```

Replay is a product backend, not a throwaway mock: it powers CI, regression
fixtures, issue reports, and offline Agent analysis. OpenOCD remains a future
fallback backend.

Native probe discovery is available through the embedded probe-rs library:

```console
cargo run -- --backend probe-rs probes list --json
```

This command is read-only and does not require the standalone `probe-rs` CLI.
The official probe-rs Espressif plugin is registered in-process, so native ESP
USB-JTAG probes and Espressif targets are visible to the embedded library too.

Test an exact probe/target connection without requesting erase, program, reset,
halt, snapshot, or arbitrary user memory access:

```console
cargo run -- --backend probe-rs probes test \
  --probe <vid:pid:serial> --target <exact-target> --json
```

The command performs one attach/disconnect lifecycle and reports the target's
conservative capability matrix as `R1_REVERSIBLE_CONTROL`.

Capture PC, SP, and LR from every enabled core while preserving each core's
original running or halted state:

```console
cargo run -- --backend probe-rs snapshot capture \
  --probe <vid:pid:serial> --target <exact-target> --json
```

This `R1_REVERSIBLE_CONTROL` command names every described core, explicitly
reports disabled cores, and returns `original_state`, the halted
`captured_state`, and the final restored `state`. It preserves the observed
core execution state and does not request a reset,
Flash operation, or arbitrary memory write. The structured `effects` field
still reports backend-managed volatile target changes: probe-rs clears hardware
breakpoints on attach, and some target debug sequences change control
registers. On ESP32-S3, the current probe-rs sequence disables multiple
watchdogs during attach/halt. This is why the command is R1 rather than R0.

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

## Native probe-rs flash

List probes and create a plan for a raw BIN image:

```console
cargo run -- --backend probe-rs probes list --json
cargo run -- --backend probe-rs flash plan firmware.bin \
  --probe <vid:pid:serial> --target STM32G431CBTx \
  --base-address 0x08000000 --json
```

Review the returned `ranges`, `erase_ranges`, `policy`, and exact identities,
then execute with the same selection and returned digest:

```console
cargo run -- --backend probe-rs flash execute firmware.bin \
  --probe <vid:pid:serial> --target STM32G431CBTx \
  --base-address 0x08000000 --confirm <digest> \
  --evidence run.evidence.json --json
```

The native workflow accepts only raw BIN data in readable boot flash. It erases
only affected sectors, restores bytes outside the image within those sectors,
does not grant full-chip erase permission, verifies by read-back, captures
PC/SP/LR while halted after reset, resumes the core, disconnects, and then
atomically publishes complete evidence. Device-write plans require a probe that
reports a non-empty hardware serial number, so reconnecting another same-model
probe cannot silently satisfy an old confirmation digest.

## Design constraints

- Successes and failures have a stable `schema_version` and `operation_id`.
- Hardware mutation requires a plan and exact confirmation digest.
- Backends advertise capabilities; callers do not infer them from backend names.
- Evidence is written atomically and referenced by SHA-256.
- Replay fixtures are validated and cannot silently opt into unsupported behavior.
- A complete evidence bundle means the debug session was also disconnected.

See [docs/contracts.md](docs/contracts.md) and
[docs/decisions/0001-cli-first-control-plane.md](docs/decisions/0001-cli-first-control-plane.md).

## Current status

Replay and native probe-rs guarded application flashing are implemented.
Native discovery and attach/disconnect have been exercised on an nRF52840 over
J-Link and an ESP32-S3 over native ESP USB-JTAG. An nRF52840 single-page guarded
write has passed exact-digest confirmation, read-back verification, unwritten
byte preservation, reset/halt/snapshot/resume, complete evidence inspection,
backup comparison, and serial runtime checks. The same preservation guarantees
also passed for a 32-byte image crossing two adjacent 4 KiB pages. Physical
probe removal returns stable unavailable errors without selecting another
connected probe or creating evidence. ESP32-S3 guarded flash remains
intentionally blocked pending format-aware ESP image planning and a verified
system-reset/post-flash policy. State-preserving multi-core live snapshots have
passed on ESP32-S3: the enabled `cpu0` was observed as
`running -> halted -> running`, while disabled `cpu1` was reported explicitly.
OpenOCD, ELF/HEX/ESP-IDF loading, RTT, persistent interactive debug sessions,
multi-core post-flash snapshots, and non-boot NVM writes are not yet exposed. See
`CHANGELOG.md` and
[docs/hardware-acceptance.md](docs/hardware-acceptance.md).

## Acknowledgments

The architecture review included
[Adancurusul/embedded-debugger-mcp](https://github.com/Adancurusul/embedded-debugger-mcp),
probe-rs, OpenOCD, GDB/MI, and the existing Nitmi `baud-cli` and `blea`
projects. See `NOTICE` for the current source-reuse status.

## License

MIT
