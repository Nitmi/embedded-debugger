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
fixtures, issue reports, and offline Agent analysis. The OpenOCD target backend
is being enabled in guarded checkpoints. Host inspection and a managed server
lifecycle are available:

```console
cargo run -- openocd inspect \
  --executable openocd \
  --config path/to/board.cfg \
  --search path/to/openocd/scripts \
  --json
```

`openocd inspect` resolves one exact executable, runs only `--version` with a
bounded deadline and output limit, and canonicalizes and hashes the explicitly
listed top-level configuration files. It does not execute OpenOCD configuration
Tcl, connect to a probe, allocate ports, or touch a target. The response is
therefore `scope="host_only"`, `risk="R0_READ_ONLY"`, and explicitly keeps
server launch, Tcl RPC, GDB/MI, target operations, and flash disabled. Repeating
`--config` or `--search` preserves argument order; duplicate paths and paths
containing `#` are rejected. Use `--timeout-ms` to override the 2000 ms version
deadline within 100..=30000 ms.

Executing an OpenOCD configuration is a different risk boundary because `.cfg`
files are executable Tcl. First generate a launch plan, review its disclosed
limits, and then return the exact digest:

```console
cargo run -- openocd server plan \
  --executable openocd \
  --config path/to/board.cfg \
  --search path/to/openocd/scripts \
  --json

cargo run -- openocd server test \
  --executable openocd \
  --config path/to/board.cfg \
  --search path/to/openocd/scripts \
  --confirm <confirm_digest> \
  --json
```

`server test` is conservatively `R2_DEVICE_WRITE`: configuration Tcl can access
the host and target even though the tool itself adds only loopback binding,
dynamic GDB/Tcl ports, a Tcl `version` readiness query, and `shutdown`. The
digest binds the selected executable file and version, top-level config hashes,
search directory paths, and lifecycle deadlines. It does not bind search tree
contents, transitively sourced files, or Tcl semantics. Runtime logs stay on
stderr and in bounded summaries; telnet is disabled, and the complete process
tree is isolated and cleaned up. This checkpoint exposes the dynamic GDB
endpoint but does not yet claim GDB/MI, target operations, or flash.

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
`core halt`, `core run`, `core continue`, `core continue-until-halt`, and
`core step`. A successful one-shot response guarantees that its final observed
state still describes the target after the debug session has disconnected.
Ordinary actions use `data.core`; the bounded wait uses `data.wait`. This
guarantee is advertised separately as
`capabilities.post_disconnect_core_state`.

`core run` is strict: success means the immediate verification still observed
the core running. `core continue` instead requires a halted origin, resumes
execution, and reports either an immediate running state or a new halted state
with a non-empty halt reason. This distinction matters when a breakpoint is
hit before a strict run verification can observe the transient running state.
`core continue-until-halt` extends the event-oriented form with bounded status
polling. It reports `outcome="halted"` with a reason or a successful
`outcome="timed_out"` with the core still running. Timeout and poll interval are
validated before probe selection, and timeout never pretends that a halt
occurred. In the persistent JSONL path it also leaves the lease usable.
`core step` also requires a halted origin, executes one target instruction, and
must finish halted with `halt_reason="step"`, `pc_before`, `pc_after`, and
`effects.instruction_step_requested=true`. Replay implements and tests all five
core-control actions plus the bounded wait, including repeatable idempotent
halt/run, immediate and delayed breakpoint results, timeout, the halted step
boundary, and state continuity within one backend instance.
Native probe-rs exposes the session-scoped actions, register reads, and bounded
memory reads through the foreground `session serve` owner while its exclusive
lease remains active. ESP32-S3 continue, continue-until-halt, and step are
accepted on CPU0.

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
currently advertises the underlying in-session read and execution-control
capabilities but sets this guarantee to false, so these commands return
`CAPABILITY_UNAVAILABLE` before probe selection. probe-rs 0.32 deconfigures
cores when a `Session` is dropped; this resumes a halted Xtensa core and
disables halting debug on Cortex-M. Persistent native observation and control
therefore use the foreground JSONL session service rather than a short-lived
CLI process:

```console
cargo run -- --backend probe-rs session serve --target esp32s3 \
  --idle-timeout-ms 300000
```

An active lease expires after five idle minutes by default. Set
`--idle-timeout-ms 0` to disable expiry; finite values must be
100..=86400000 ms. `session.open` and `session.status` expose the effective
`lease_policy`. The deadline starts only after a lease opens and restarts after
each structurally valid request has finished and its response has been written.
Blank, malformed, and oversized lines do not renew it. A request already in
flight is never interrupted by the lease timer.

Write one compact JSON request per stdin line. Start with `session.open` and an
exact probe/target, then use the returned `session_id` for `session.status`,
`core.status`, `core.halt`, `core.run`, `core.continue`,
`core.continue_until_halt`, `core.step`,
`breakpoints.list`, `breakpoints.set`, `breakpoints.clear`,
`breakpoints.clear_all`, `registers.read`, `memory.read`, and `session.close`.
For example:

```json
{"schema_version":"1.0","request_id":"req-registers","operation":"registers.read","session_id":"ses_<opaque>","core":0,"names":["pc","sp","lr"]}
{"schema_version":"1.0","request_id":"req-memory","operation":"memory.read","session_id":"ses_<opaque>","core":0,"address":"0x42000000","length":32}
{"schema_version":"1.0","request_id":"req-step","operation":"core.step","session_id":"ses_<opaque>","core":0}
{"schema_version":"1.0","request_id":"req-breakpoint","operation":"breakpoints.set","session_id":"ses_<opaque>","core":0,"address":"0x420129D4","slot":0}
{"schema_version":"1.0","request_id":"req-continue","operation":"core.continue","session_id":"ses_<opaque>","core":0}
{"schema_version":"1.0","request_id":"req-wait","operation":"core.continue_until_halt","session_id":"ses_<opaque>","core":0,"timeout_ms":5000,"poll_interval_ms":25}
{"schema_version":"1.0","request_id":"req-clear","operation":"breakpoints.clear","session_id":"ses_<opaque>","core":0,"slot":0}
```

`core.step` is only accepted while the selected core is halted; it preserves
that halted execution state within the active lease while advancing one
instruction and reports the R1 instruction effect. `core.continue` is also
halted-only, but unlike strict `core.run` it treats an immediate breakpoint hit
as a successful observed result instead of a protocol failure.
`core.continue_until_halt` additionally polls until a halt or its bounded
deadline. A `timed_out` response is successful, leaves the core running, and
keeps the lease usable. The current JSONL server processes one request at a
time, so this request occupies the server until it returns; a second JSONL
request cannot asynchronously cancel it.

Hardware-breakpoint capacity is negotiated from the live core during
`session.open`; ESP32-S3 CPU0 currently reports two accepted slots. Listing
returns every slot and is allowed while running. Mutations require a halted
core. Set accepts an optional slot, otherwise chooses the lowest free slot;
repeating the same address is idempotent, occupied-slot overwrites are rejected,
and clear/clear-all are also idempotent. Every result carries the complete
`before` and `after` slot inventory plus explicit verification effects.

Register and memory reads preserve the core's running or halted state within
the active lease and return structured R1 `effects` plus ordered operations.
Memory reads keep the same target-region and 4096-byte bounds as the one-shot
command. Finish with `server.shutdown`. Responses are one versioned JSON object
per stdout line; diagnostics stay on stderr. Core responses are explicitly
scoped to the active session. Close, stdin EOF, and idle expiry first halt cores
with managed breakpoints, clear and verify all of their slots, then run every
observed core and disconnect. Successful expiry emits a versioned
`session.idle_expired` lifecycle object with the complete close report on
stderr, then exits with code 0. See [`docs/contracts.md`](docs/contracts.md) for
the wire contract.

### MCP stdio adapter and supervisor

The preferred Agent entry point is a bounded supervisor around the thin MCP
adapter. The child still uses the same persistent session owner; neither layer
introduces a second hardware API or cleanup policy:

```console
embedded-debugger --backend probe-rs supervisor mcp --target esp32s3 \
  --idle-timeout-ms 300000 --max-restarts 3 --restart-delay-ms 250
```

After `initialize`, call `tools/list` and use the single
`embedded_debugger_request` tool. Its arguments are the persistent JSONL
fields with a required `operation`, so `session.open` returns the opaque
`session_id` used by later `core.*`, `breakpoints.*`, `registers.read`,
`memory.read`, and `session.close` calls. The tool returns the normal
versioned envelope in both `structuredContent` and text content; operation
failures retain the same stable error codes. Flash planning/execution and
one-shot commands remain CLI operations. Plugin manifests are provided in
`mcp.json` (Agent Plugins) and `.mcp.json` (Codex plugin validation).

On an unexpected child exit, every unanswered request receives JSON-RPC
`-32001` with an explicit indeterminate-target warning and is never replayed.
The supervisor starts a fresh child within its bounded restart budget and
privately restores only the side-effect-free MCP initialize handshake. The
external client remains on one standards-compliant lifecycle; an old
`session_id` is rejected by the fresh owner and must be replaced through a new
exact `session.open`. Requests arriving during the short private handshake get
retryable `-32002` without being forwarded. Structured restart events stay on
stderr. A hard child kill can still leave target state unknown, so restart is
availability recovery, not proof of core or breakpoint cleanup. Run `mcp serve`
directly only when a process manager already owns this lifecycle.

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
[ADR-0001](docs/decisions/0001-cli-first-control-plane.md),
[ADR-0002](docs/decisions/0002-core-state-follows-session-lifetime.md),
[ADR-0003](docs/decisions/0003-persistent-session-jsonl-lease.md), and
[ADR-0004](docs/decisions/0004-fail-closed-mcp-supervision.md), and
[ADR-0005](docs/decisions/0005-openocd-host-inspection-boundary.md), and
[ADR-0006](docs/decisions/0006-guarded-openocd-server-lifecycle.md).

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
not state preserving. OpenOCD host inspection and guarded managed-server
planning are implemented. The server launcher fixes loopback-only dynamic
endpoints, disables telnet, proves Tcl readiness, performs graceful shutdown,
bounds logs, and enforces process-tree cleanup. Its exact-confirmation Windows
lifecycle passed on ESP32-S3 native USB-JTAG, including dynamic endpoints, Tcl
version/shutdown, exit and port cleanup, probe-rs reattach, and UART heartbeat
recovery. OpenOCD reported CPU0 examination success but CPU1 examination
failure, so GDB/MI target operations, general
ELF/HEX loading, RTT, memory writes,
Generic/MMIO reads, register writes, software/symbolic/conditional breakpoints,
watchpoints, asynchronous request cancellation, durable crash recovery,
multi-client arbitration, other physically accepted native segmented targets,
and non-boot NVM writes are not yet exposed. The core
status/halt/run/continue/continue-until-halt/step contract is complete in
Replay. Its session-scoped native path, idle lease expiry, and slot-addressable
hardware breakpoints are accepted on ESP32-S3 CPU0; live attach negotiates two
comparator slots. Native one-shot
commands that promise a final core state remain capability-gated because
probe-rs cannot guarantee every reported execution state across session
teardown. The MCP stdio adapter and the `skills/embedded-debugger` Skill now
expose the same persistent session contract to Agent clients. Replay covers
the complete handshake and open/close lifecycle offline, and the same
handshake, CPU0 status, close, and shutdown path has passed a native ESP32-S3
USB-JTAG smoke run. A second native lease also passed MCP register and mapped
NVM reads, CPU0 halt/status/step/run, immediate hardware-breakpoint hit and
exact PC verification, comparator clear, complete close/disconnect, bounded
continue-until-halt event/timeout results, and supervised idle expiry cleanup.
The bounded MCP subprocess supervisor now passes Replay coverage for transparent
proxying, standards-compatible private handshake restoration, stale-session
rejection, startup validation, and restart exhaustion. The same outer-connection
recovery, stale-session rejection, new lease, complete close/disconnect, and
probe release path passed native ESP32-S3 idle-child replacement acceptance.
See `CHANGELOG.md` and
[docs/hardware-acceptance.md](docs/hardware-acceptance.md).

## Acknowledgments

The architecture review included
[Adancurusul/embedded-debugger-mcp](https://github.com/Adancurusul/embedded-debugger-mcp),
probe-rs, OpenOCD, GDB/MI, and the existing Nitmi `baud-cli` and `blea`
projects. See `NOTICE` for the current source-reuse status.

## License

MIT
