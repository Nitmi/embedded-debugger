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
  memory writes, Generic/MMIO reads, register writes, breakpoints, and persistent
  sessions are not implemented. Memory reads are one-shot, limited to 4096 bytes,
  and do not freeze other cores or DMA.
- Native probe-rs one-shot live snapshot, register read, memory read, core
  status, core halt, and core run are exposed only as explicit
  `CAPABILITY_UNAVAILABLE` results. probe-rs 0.32 teardown resumes halted Xtensa
  cores and disables Cortex-M halting debug, so detach-safe observation and
  durable control require a future long-running session owner.
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
