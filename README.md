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
conservative capability matrix as `R1_REVERSIBLE_CONTROL`. probe-rs teardown
can resume a core that was halted before attach, so callers must not treat this
diagnostic as state preserving.

Capture PC, SP, and LR from every enabled core while preserving each core's
original running or halted state:

```console
cargo run -- --fixture examples/replay/stm32g4.json snapshot capture \
  --probe replay:stlink-v3:0039002A3432510433343034 \
  --target STM32G431CBTx --json
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

The versioned core-state contract is available through `core status`,
`core halt`, and `core run`. A successful response guarantees that
`data.core.state` still describes the target after the one-shot debug session
has disconnected; `data.core.original_state`, `state_changed`, and
`effects.intentional_final_core_state_change_requested` make the transition
explicit. This guarantee is advertised separately as
`capabilities.post_disconnect_core_state`.

Replay implements and tests all three actions, including repeatable idempotent
halt/run and state continuity across later snapshot, register, and memory
operations within one service/backend instance.

Read a bounded set of registers from one core while preserving that core's
original running or halted state:

```console
cargo run -- --fixture examples/replay/stm32g4.json registers read pc sp lr \
  --probe replay:stlink-v3:0039002A3432510433343034 \
  --target STM32G431CBTx --core 0 --json
```

Names and architecture-defined aliases are matched case-insensitively. Omitting
the positional names reads the target's register inventory only when it contains
at most 64 entries; larger inventories require an explicit selection. Each
reading reports its canonical name, aliases, backend register ID, bit width,
kind, and fixed-width hexadecimal value. Floating-point values are returned as
raw register bit patterns. The command halts only the selected core when needed,
verifies restoration to its original state, and disconnects. As with live
snapshots, probe-rs attach sequences can modify volatile debug-control state, so
the result is classified as `R1_REVERSIBLE_CONTROL` and includes `effects`.
Halting can also interrupt an in-flight peripheral or log write; restoring the
core state cannot retract bytes already emitted externally.

Read a bounded byte range from target-described RAM or NVM while preserving the
selected core's original state:

```console
cargo run -- --fixture examples/replay/stm32g4.json memory read 0x20007F00 32 \
  --probe replay:stlink-v3:0039002A3432510433343034 \
  --target STM32G431CBTx --core 0 --json
```

The exact inline limit is 4096 bytes. Planning completes before probe discovery
or attach and accepts only one readable RAM or NVM region assigned to the
selected core. Zero-length, overflowing, cross-region, ambiguous, Generic/MMIO,
and larger requests return `CONFIG_INVALID`. The probe-rs backend uses exact
byte reads rather than an alignment helper that may access bytes outside the
requested range. Results include the target-described region, lowercase hex
data, SHA-256, and `running`/`halted` capture and restoration states. This is an
R1 one-shot observation: other cores and DMA remain live, and attach/halt can
still alter the volatile state disclosed in `effects`. Replay requires explicit
core-state and byte-block evidence; it never invents missing memory content.

All successful one-shot core-state, live snapshot, register-read, and
memory-read reports require `post_disconnect_core_state=true`. Native probe-rs
currently advertises the underlying in-session read/halt/run capabilities but
sets this guarantee to false, so these commands return `CAPABILITY_UNAVAILABLE`
before probe selection. probe-rs 0.32 deconfigures cores when a `Session` is
dropped; this resumes a halted Xtensa core and disables halting debug on
Cortex-M. Persistent native observation and control therefore use the
foreground JSONL session service rather than a short-lived CLI process:

```console
cargo run -- --backend probe-rs session serve --target esp32s3
```

Write one compact JSON request per stdin line. Start with `session.open` and an
exact probe/target, then use the returned `session_id` for `session.status`,
`core.status`, `core.halt`, `core.run`, and `session.close`. Finish with
`server.shutdown`. Responses are one versioned JSON object per stdout line;
diagnostics stay on stderr. Core responses are explicitly scoped to the active
session. Close and stdin EOF run every observed core before disconnecting, so a
normal client exit does not leave the target paused. See
[`docs/contracts.md`](docs/contracts.md) for the wire contract.

Exercise the target's accepted reset policy without flashing it:

```console
cargo run -- --backend probe-rs snapshot reset-capture \
  --probe <vid:pid:serial> --target <exact-target> --json
```

This command performs a system reset-and-halt, captures PC/SP/LR from every
available core, restores each core to its explicit `expected_final_state`, and
disconnects. On the accepted ESP32-S3 policy, CPU0 resumes while secondary
cores preserve the state in which the reset sequence left them. The result sets
`effects.reset_requested=true`; it never requests erase or program.

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

The executable native workflow accepts raw BIN data in readable boot flash. It
erases only affected sectors, restores bytes outside the image within those
sectors, does not grant full-chip erase permission, verifies by read-back,
captures PC/SP/LR while halted after reset, resumes the core, disconnects, and
then atomically publishes complete evidence. Device-write plans require a probe
that reports a non-empty hardware serial number, so reconnecting another
same-model probe cannot silently satisfy an old confirmation digest.

## ESP-IDF physical image planning

An ESP-IDF application ELF can be normalized into its physical bootloader,
partition-table, and application segments without attaching to the target:

```console
cargo run -- --backend probe-rs flash plan app.elf \
  --probe <vid:pid:serial> --target esp32s3 \
  --format idf --flash-size 8MB --json
```

The format and flash capacity are explicit safety inputs; `.elf` is not guessed
to mean ESP-IDF. `--chip-revision <number>` is available when image generation
depends on a silicon revision. The plan records the source hash and size,
generated byte count, each physical segment and hash, image-generation options,
write and erase ranges, exact probe/target identity, and execution readiness.
The confirmation digest binds all of those fields.

Image normalization uses the pinned espflash 4.5.0 library. The declared flash
capacity must fit the target package's boot-flash address window. The shared
execution layer can stage all physical segments in one transaction, verify each
segment independently, and publish per-segment results in evidence. Replay
exercises that full path with a single-core ESP32-C3 fixture and the complete
multi-core evidence path with an ESP32-S3 fixture.

Native execution remains target-gated. A probe-rs target must explicitly
advertise `segmented_flash` only after physical acceptance, and multi-core
targets also require a complete post-flash reset/snapshot/resume policy.
ESP32-S3 has passed both gates on native USB-JTAG: its normalized ESP-IDF plan is
executable after exact digest confirmation. Other targets continue to report
explicit blockers until their own physical acceptance is complete.

## Design constraints

- Successes and failures have a stable `schema_version` and `operation_id`.
- Hardware mutation requires a plan and exact confirmation digest.
- Backends advertise capabilities; callers do not infer them from backend names.
- Evidence is written atomically and referenced by SHA-256.
- Replay fixtures are validated and cannot silently opt into unsupported behavior.
- A complete evidence bundle means the debug session was also disconnected.

See [docs/contracts.md](docs/contracts.md),
[ADR-0001](docs/decisions/0001-cli-first-control-plane.md), and
[ADR-0002](docs/decisions/0002-core-state-follows-session-lifetime.md).

## Current status

Replay and native probe-rs guarded application flashing are implemented.
Native discovery and attach/disconnect have been exercised on an nRF52840 over
J-Link and an ESP32-S3 over native ESP USB-JTAG. An nRF52840 single-page guarded
write has passed exact-digest confirmation, read-back verification, unwritten
byte preservation, reset/halt/snapshot/resume, complete evidence inspection,
backup comparison, and serial runtime checks. The same preservation guarantees
also passed for a 32-byte image crossing two adjacent 4 KiB pages. Physical
probe removal returns stable unavailable errors without selecting another
connected probe or creating evidence. ESP-IDF ELF normalization, segmented
staging, per-segment verification, and single- and multi-core post-flash
evidence reporting now pass end-to-end Replay coverage. Native ESP execution
has now passed on ESP32-S3: exact-confirmation segmented programming, independent
per-segment verification, preservation of every byte outside the image ranges,
multi-core post-reset evidence, a full 16 MiB external readback, and serial
heartbeat checks all succeeded. System-reset snapshots also passed. Live
snapshots and bounded register and RAM/NVM reads passed running-origin ESP32-S3
exercises, including pre-attach MMIO and size rejection plus serial heartbeat
recovery, but are now native capability-gated because halted-origin teardown is
not state preserving. OpenOCD, general ELF/HEX loading, RTT, persistent interactive
debug sessions, memory writes, MMIO reads, breakpoints, other physically accepted
native segmented targets, and non-boot NVM writes are not yet exposed.
The core status/halt/run contract is complete in Replay, but all native one-shot
commands that promise a final core state remain capability-gated because
probe-rs cannot guarantee every reported execution state across session teardown.
See `CHANGELOG.md` and
[docs/hardware-acceptance.md](docs/hardware-acceptance.md).

## Acknowledgments

The architecture review included
[Adancurusul/embedded-debugger-mcp](https://github.com/Adancurusul/embedded-debugger-mcp),
probe-rs, OpenOCD, GDB/MI, and the existing Nitmi `baud-cli` and `blea`
projects. See `NOTICE` for the current source-reuse status.

## License

MIT
