# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Added

- Versioned success and error envelopes for Agent-safe CLI automation.
- Stable error codes and exit codes.
- Backend capability model and deterministic Replay backend.
- Guarded raw BIN flash planning with digest-bound probe, target, firmware,
  write ranges, sector erase ranges, and execution policy.
- ESP-IDF ELF normalization through pinned espflash 4.5.0, including
  physical bootloader, partition-table, and application segments; per-segment
  hashes; explicit flash capacity and chip revision; target flash-window
  validation; merged sector ranges; and digest-bound execution blockers.
- Shared segmented flash staging and per-segment verification, including
  payload hash validation, one-transaction backend commit, manifest-consistent
  flash reports, and per-segment evidence. A single-core ESP32-C3 Replay fixture
  exercises the complete plan/execute/verify/reset/evidence path.
- Explicit `segmented_flash` target capability. ESP32-S3 passed target-specific
  physical acceptance; other native targets remain disabled until qualified.
- Multi-core post-flash evidence inventories with exact core indexes, explicit
  disabled-core reasons, halted capture, per-core expected-final-state
  validation, backward-compatible running defaults and single-core views, and
  Replay success/failure coverage.
- Explicit `multi_core_post_flash` capability and pre-mutation native reset
  gating. ESP32-S3 system reset and per-core restoration passed physical
  acceptance.
- Replay execution, verification, reset, snapshot capture, and atomic evidence
  publication.
- Native probe discovery through probe-rs 0.32.
- Official probe-rs Espressif plugin registration for in-process ESP target and
  native ESP USB-JTAG support.
- Explicit `probes test` attach/disconnect diagnostics with a structured risk,
  capability matrix, and complete session lifecycle.
- State-preserving `snapshot capture` for all described target cores, with
  explicit disabled-core reporting, original/captured/final states, and cleanup
  on both success and failure.
- Bounded, state-preserving `registers read` with exact core selection,
  case-insensitive architecture aliases, canonical register metadata,
  fixed-width raw hexadecimal values, a 64-register limit, Replay evidence,
  and verified restoration and disconnect on success and failure.
- Exact, state-preserving `memory read` with a 4096-byte inline limit,
  pre-attach readable RAM/NVM containment checks, Generic/MMIO and cross-region
  rejection, target region metadata, hexadecimal data and SHA-256, explicit
  Replay core/byte evidence, and probe-rs byte reads that do not widen the
  requested address range. ESP32-S3 CPU0 RAM and mapped NVM passed
  running-origin physical exercises with serial heartbeat recovery.
- Non-flashing `snapshot reset-capture` with structured reset effects, complete
  per-core post-reset observations, verified restoration, and disconnect.
- Structured R1 `effects` disclosure for backend-managed volatile target state,
  including probe-rs hardware-breakpoint clearing, ESP32-S3 watchdog changes,
  and the possibility that session teardown resumes a previously halted core.
- Versioned `core status`, `core halt`, and `core run` reports with explicit
  original/final states, idempotent Replay transitions, state continuity within
  one Replay service instance, and intentional-final-state effects. The separate
  `post_disconnect_core_state` capability prevents a one-shot command from
  claiming a state that probe-rs session teardown can change.
- Versioned `core step` support in Replay, one-shot CLI, and persistent JSONL
  sessions. Step requires a halted origin, executes one instruction, finishes
  halted, returns before/after PCs, and reports `instruction_step_requested`;
  native ESP32-S3 CPU0 passed a persistent-session PC-advance and UART-recovery
  exercise.
- Versioned `core continue` support with explicit immediate-result semantics.
  Continue requires a halted origin and may successfully report either running
  or an immediate halted result with a normalized reason, avoiding the false
  failure produced when a breakpoint is hit before strict `core run`
  verification. ESP32-S3 CPU0 passed an immediate hardware-breakpoint hit with
  exact PC evidence.
- Bounded `core continue-until-halt` CLI and `core.continue_until_halt` JSONL
  support with validated 10..=60000 ms deadlines, 10..=1000 ms polling,
  explicit `halted` versus successful `timed_out` outcomes, elapsed time and
  poll evidence, deterministic Replay event queues, and a reusable running
  lease after timeout. ESP32-S3 CPU0 passed both an exact-PC hardware-breakpoint
  hit and a 300 ms no-breakpoint timeout in one native session.
- Persistent JSONL `breakpoints.list`, `breakpoints.set`, `breakpoints.clear`,
  and `breakpoints.clear_all` with live capacity negotiation, complete indexed
  before/after slot inventories, optional explicit slot selection, lowest-free
  automatic allocation, idempotent duplicate set/clear behavior, occupied-slot
  rejection, halted-only mutations, and structured verification effects.
  ESP32-S3 CPU0 reports two physically accepted comparator slots.
- Breakpoint-aware session cleanup. A lease tracks every core on which a
  breakpoint mutation was attempted; close and EOF halt those cores, clear and
  verify every managed slot, then resume all observed cores before disconnect.
  Cleanup evidence is returned in the close report, and resume is skipped if
  explicit breakpoint cleanup cannot be verified.
- Native single-core probe-rs attach, affected-sector flash, preservation of
  unwritten sector bytes, independent read-back verification, reset-and-halt,
  PC/SP/LR snapshot, resume, and disconnect.
- Exact target package variant handling and rejection of ambiguous probe
  selectors.
- Preflight evidence-path reservation and complete evidence containing plan,
  policy, flash result, core snapshot, and operation history.
- Windows and Linux CI for formatting, linting, tests, documentation, and
  package validation.

### Known limitations

- OpenOCD and MCP adapters are not implemented.
- Native raw BIN requires an explicit base address; Replay uses the fixture
  address unless the same address is supplied. ESP-IDF ELF requires explicit
  format and flash capacity inputs and is physically accepted only on ESP32-S3.
  General ELF and Intel HEX are not accepted.
- Native flashing is limited to readable boot NVM. Multi-core segmented
  execution is physically accepted only on ESP32-S3. RTT, arbitrary
  memory writes, Generic/MMIO reads, register writes, software/symbolic/
  conditional breakpoints, watchpoints, idle lease expiry, and asynchronous
  request cancellation are not implemented. Persistent hardware breakpoints are
  physically accepted only on ESP32-S3 CPU0; native one-shot breakpoint
  commands and CPU1 breakpoint control are not exposed. Memory reads are
  limited to 4096 bytes and do not freeze other cores or DMA.
- Native probe-rs one-shot live snapshot, register read, memory read, core
  status, core halt, core run, core continue, core continue-until-halt, and core
  step are exposed only as explicit `CAPABILITY_UNAVAILABLE` results. The
  persistent JSONL owner now provides session-scoped
  status/halt/run/continue/continue-until-halt/step, hardware breakpoints, and
  bounded register and memory reads while the lease is alive. probe-rs 0.32
  teardown resumes halted Xtensa cores and disables Cortex-M halting debug, so
  the one-shot commands remain gated.
- Native attach/disconnect is verified on nRF52840/J-Link and ESP32-S3/native
  USB-JTAG. nRF52840 single-page guarded write acceptance passed, including
  exact confirmation, read-back, page preservation, post-reset snapshot,
  evidence, backup, and runtime checks. The two-page cross-sector case also
  passed. Physical probe removal consistently returns `PROBE_UNAVAILABLE`
  without falling back to another connected probe. ESP32-S3 running-origin live
  snapshots passed, while its accepted system-reset workflow left `cpu0`
  running and was independently observed to leave reset-accessible `cpu1`
  halted. The live one-shot path is now gated because halted-origin teardown is
  not safe. Its guarded three-segment ESP-IDF execution also passed exact
  confirmation, read-back, complete outside-range preservation, evidence, and
  heartbeat runtime checks.
