# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Added

- Versioned success and error envelopes for Agent-safe CLI automation.
- Stable error codes and exit codes.
- Backend capability model and deterministic Replay backend.
- Guarded raw BIN flash planning with digest-bound probe, target, firmware,
  address range, verification, and reset intent.
- Replay execution, verification, reset, snapshot capture, and atomic evidence
  publication.
- Native read-only probe discovery through probe-rs 0.32.
- Windows and Linux CI for formatting, linting, tests, documentation, and
  package validation.

### Known limitations

- Native probe-rs attach, flash, debug, and RTT operations are not implemented.
- OpenOCD and MCP adapters are not implemented.
- Only raw BIN firmware is accepted; its base address comes from the Replay
  fixture.
- Hardware acceptance is pending because no debug probe was connected during
  this milestone.

