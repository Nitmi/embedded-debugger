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
targets also require a complete post-flash reset/snapshot/resume policy. The
ESP32-S3 system-reset and multi-core restoration policy has passed physical
acceptance, but segmented flash has not. Its current plan therefore reports only
`SEGMENTED_FLASH_ACCEPTANCE_REQUIRED`; even the correct digest is rejected after
probe enumeration but before target attach, evidence reservation, erase,
program, or reset.

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
connected probe or creating evidence. ESP-IDF ELF normalization, segmented
staging, per-segment verification, and single- and multi-core post-flash
evidence reporting now pass end-to-end Replay coverage. Native ESP execution
remains intentionally target-gated pending physical segmented-flash acceptance.
State-preserving live snapshots and system-reset snapshots have passed on
ESP32-S3. After reset, `cpu0` is sampled while halted and resumed; `cpu1` is
available at its reset breakpoint and remains halted. A subsequent independent
live snapshot verified those final states.
OpenOCD, general ELF/HEX loading, physically accepted native ESP-IDF execution,
RTT, persistent interactive debug sessions, physically accepted native
segmented flash, and non-boot NVM writes are not yet exposed.
See `CHANGELOG.md` and
[docs/hardware-acceptance.md](docs/hardware-acceptance.md).

## Acknowledgments

The architecture review included
[Adancurusul/embedded-debugger-mcp](https://github.com/Adancurusul/embedded-debugger-mcp),
probe-rs, OpenOCD, GDB/MI, and the existing Nitmi `baud-cli` and `blea`
projects. See `NOTICE` for the current source-reuse status.

## License

MIT
