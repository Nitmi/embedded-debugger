# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Added

- Versioned success and error envelopes for Agent-safe CLI automation.
- Stable error codes and exit codes.
- Backend capability model and deterministic Replay backend.
- Guarded raw BIN flash planning with digest-bound probe, target, firmware,
  write ranges, sector erase ranges, and execution policy.
- Replay execution, verification, reset, snapshot capture, and atomic evidence
  publication.
- Native probe discovery through probe-rs 0.32.
- Official probe-rs Espressif plugin registration for in-process ESP target and
  native ESP USB-JTAG support.
- Explicit `probes test` attach/disconnect diagnostics with a structured risk,
  capability matrix, and complete session lifecycle.
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
- Only raw BIN firmware is accepted. probe-rs requires an explicit base address;
  Replay uses the fixture address unless the same address is supplied.
- Native flashing is limited to readable boot NVM on single-core targets. RTT,
  arbitrary memory/register commands, breakpoints, and persistent sessions are
  not implemented.
- Native attach/disconnect is verified on nRF52840/J-Link and ESP32-S3/native
  USB-JTAG. nRF52840 device-write acceptance is pending exact plan confirmation;
  ESP32-S3 guarded flash awaits a defined multi-core post-flash contract.
