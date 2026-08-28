# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Added

- Bounded `openocd inspect` host diagnostics with exact executable resolution,
  OpenOCD identity checking, a 100..=30000 ms version deadline, 64 KiB output
  limits, canonical top-level configuration/search paths, duplicate and `#`
  rejection, 4 MiB per-file limits, SHA-256 manifests, and explicit disabled
  server/Tcl/GDB-MI/target capability fields. `doctor` now uses the same bounded
  OpenOCD version probe.
- Guarded `openocd server plan/test` with executable and top-level config
  SHA-256 confirmation, explicit unbound Tcl/source semantics, loopback-only
  dynamic GDB/Tcl endpoints, disabled telnet, framed Tcl version readiness and
  shutdown, bounded concurrent logs, and Windows Job Object / Unix process-group
  cleanup. ESP32-S3 native USB-JTAG passed the Windows lifecycle, probe-release,
  and UART-recovery checks; CPU1 examination remains unqualified and GDB/MI,
  target operations, and OpenOCD flash remain disabled.
- Host-only `openocd gdb inspect/test` with exact GNU GDB identity and executable
  hashing, fixed `mi2` with initialization files disabled, direct ASCII input,
  token-correlated `-gdb-version`/`-gdb-exit`, bounded and hashed MI output,
  fail-closed framing validation, and Windows Job Object / Unix process-group
  cleanup. Espressif GDB 17.1 passed the native Windows host lifecycle; remote
  connection and all target-facing capabilities remain disabled.
- Confirmed `openocd session plan/test` for the first combined OpenOCD + GDB
  target lifecycle. The digest binds both executable identities, OpenOCD config
  manifests/search paths, an exact expected current-target name, fixed MI2
  version/connect/detach/exit commands, deadlines, and a running-origin
  restoration policy. Execution validates the current target name/state
  through bounded Tcl, refuses a mismatched target or non-running origin,
  verifies running after detach, applies one fixed resume fallback when needed,
  and cleans both process trees on every path. It accepts no ELF, symbols,
  explicit target-data command, breakpoints, flash command, monitor input, or
  arbitrary command. Effects disclose that remote negotiation may exchange
  target descriptions, memory-map metadata, stop/register state, and that
  confirmed OpenOCD attach handlers may probe flash or reset a protected
  target. The first physical ESP32-S3 attempt failed closed on a 388-byte versus
  608-byte GDB register-layout mismatch, then restored CPU0 running, cleaned
  both processes and ports, permitted probe-rs reattach, and recovered UART
  heartbeats. Optional `--gdb-xtensa-config` now canonicalizes and hashes the
  exact Espressif target profile, binds its selection in the digest, clears any
  ambient `XTENSA_GNU_CONFIG`, and sets only the confirmed path for GDB. A
  separately confirmed profile-bound run then completed the fixed MI exchange,
  restored CPU0 to running with the fixed fallback, gracefully exited both
  processes, released both dynamic ports and the exact probe, and recovered
  UART heartbeats. The accepted scope remains the bounded attach/detach
  lifecycle; symbols, target-data commands, breakpoints, flash, and arbitrary
  commands remain disabled.
- Confirmed `openocd registers plan/test` for one ordered selection of 1..=64
  target register names. A separate digest binds the exact OpenOCD/GDB/profile
  and configuration identities, fixed six-command MI2 exchange, normalized
  register names and order, deadlines, expected current target, and running
  restoration policy. Structured MI parsing resolves names through the complete
  runtime inventory and requires one unique hexadecimal result for every
  selection. Unknown, ambiguous, unavailable, missing, duplicate, extra, or
  malformed results fail closed. Connected failure paths still attempt fixed
  detach, bounded GDB exit, selected-target running restoration, and OpenOCD
  cleanup. Controlled parser, process, restoration, digest, and CLI regressions
  pass. ELF/symbol loading, memory/stack reads, breakpoints/watchpoints, general
  execution control, flash, monitor input, and arbitrary MI/Tcl remain disabled;
  a separately confirmed ESP32-S3 CPU0 run returned ordered `pc/a0/a1/ps`, used
  the fixed resume fallback, cleaned both processes, and recovered UART
  heartbeats. CPU1 and other targets remain unqualified.
- Confirmed `openocd memory plan/test` for one exact 1..=4096-byte read inside
  an explicitly declared RAM or NVM region. Range, overflow, and containment
  checks run before host-file access. A separate digest binds the exact address,
  length, declared-region kind/bounds, concrete five-command MI2 exchange,
  complete-coverage policy, tool/config/profile identities, deadlines, target,
  effects, and restoration. Structured parsing accepts multiple GDB memory
  blocks only when `begin/offset/end/contents` describe ordered gap-free coverage
  of every requested byte; partial, inaccessible, overlapping, reordered,
  malformed, or extra results fail closed and still take fixed detach, GDB exit,
  target restoration, and OpenOCD cleanup paths. Region semantics are explicitly
  user-confirmed rather than target-map verified, so wrong declarations retain
  possible side-effectful-read risk and the operation remains R2. Memory writes,
  MMIO/unknown declarations, expressions, symbols/ELF, register/stack commands,
  breakpoints, execution control, flash, monitor input, and arbitrary MI/Tcl
  remain disabled. Controlled parser, process, digest, range, and CLI regressions
  pass. A separately confirmed, non-retried ESP32-S3 CPU0 run returned complete
  `0x42000000 + 32` coverage with the same SHA-256 as the prior probe-rs
  snapshot, used the fixed resume fallback, cleaned both process trees and
  dynamic ports, and recovered UART heartbeats. CPU1, other ranges and targets,
  and independent verification of the user-declared NVM semantics remain
  unqualified.
- Confirmed `openocd stack plan/test` for the first 1..=32 GDB-reported frames.
  Its separate digest binds the exact inclusive range, fixed
  `-stack-list-frames --no-frame-filters` command, tool/config/profile
  identities, target, deadlines, strict structured result policy, effects, and
  restoration. The parser handles the official `stack=[frame={...}]`
  result-list without string rewriting, requires contiguous levels and bounded
  hexadecimal addresses, and rejects duplicate/unknown/nested/extra or
  malformed data. No ELF, symbol, frame filter, argument, local, or value input
  is accepted. The result limit does not bind target addresses implicitly read
  by the unwinder; that possible register/memory access and side-effectful-read
  risk is explicit, and physical call-stack completeness remains unproven.
  Connected failures still attempt fixed detach, GDB exit, target restoration,
  and OpenOCD cleanup. Controlled parser, lifecycle, digest, bounds, and CLI
  regressions pass. A separately confirmed, non-retried ESP32-S3 CPU0 run with
  `--max-frames 8` returned two unsymbolized frames, used the fixed resume
  fallback, cleaned both process trees and dynamic ports, and recovered UART
  heartbeats. Implicit unwind addresses, physical call-stack completeness,
  symbols, CPU1, and any other plan remain unqualified.
- Optional SHA-256-bound offline ELF annotation for `openocd stack plan/test`
  through the separate `openocd.stack.annotated.*` contract. The outer digest
  binds the unchanged base stack digest, canonical executable ELF identity,
  fixed `object 0.39.1` / `addr2line 0.25.1` policy, return-address adjustment,
  eight-frame lookup/output limit, 64-byte build-ID limit, bounded object-table
  sizes, and external-data prohibition. GDB never receives the ELF; annotation
  runs in process only after target restoration and both managed processes
  finish. Compressed debug sections are rejected, no more than eight declined
  split-DWARF continuations are resumed per frame, split or linked debug files
  and source contents are never read, and symbol-table fallback remains within
  the exact in-memory ELF. Reports explicitly keep
  runtime firmware identity and physical call-stack completeness unverified.
  Controlled ELF, digest, CLI, and full two-process lifecycle regressions pass;
  no physical annotated-stack acceptance is claimed.
- Confirmed `openocd target plan/test` for one fixed direct-Tcl
  `running -> halted -> running` roundtrip. The digest binds exact OpenOCD and
  top-level config identities, ordered search paths, the expected current
  target, fixed halt/resume protocol, deadlines, and restoration policy. The
  test rejects a mismatched or non-running target before control, attempts the
  fixed resume after every halt result, requires final running, and preserves
  transition plus server cleanup evidence on failure. It requests no reset,
  GDB, register/memory/stack read, breakpoint, flash, monitor, or arbitrary Tcl
  command. Controlled lifecycle regressions pass. A separately confirmed
  ESP32-S3 CPU0 run proved `running -> halted -> running`, graceful shutdown,
  dynamic-port cleanup, exact probe reuse, and UART recovery; CPU1 remains
  unqualified.
- Confirmed `openocd reset plan/test` for one fixed global `reset halt` and
  selected-target recovery. The digest binds OpenOCD/config identities, exact
  selected current-target name, global reset scope, fixed reset/recovery Tcl
  `catch` envelopes, deadlines, and one selected-target resume policy.
  Execution refuses a mismatched or non-running selected target before reset,
  requires catch code 0 plus the required state after both transitions, always
  attempts the fixed recovery after any reset result, and requires complete
  server cleanup. Effects disclose that OpenOCD resets all defined targets and
  fires configuration-defined reset events; non-selected target inventory and
  final states remain unbound and unverified. Controlled regressions pass,
  including nonzero catch code, ineffective reset, and failed recovery paths.
  A separately confirmed ESP32-S3 CPU0 run proved reset/recovery catch code 0,
  `running -> halted -> running`, graceful process-tree cleanup, exact probe
  reuse, and restarted UART heartbeats. CPU1 was reset but remains unqualified.
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
- Supervised active-lease idle expiry for the foreground JSONL owner. The CLI
  defaults to 300000 ms, accepts 100..=86400000 ms, and uses 0 to disable.
  `session.open` and `session.status` expose the effective lease policy. A
  structurally valid completed request renews the lease; malformed input does
  not, and an in-flight request is never interrupted. Expiry reuses the guarded
  breakpoint/core close policy, emits a versioned `session.idle_expired` stderr
  event with complete cleanup evidence, and exits successfully. ESP32-S3 CPU0
  passed physical expiry with an active comparator, running-state restoration,
  probe release, and heartbeat recovery.
- MCP stdio JSON-RPC adapter backed by the persistent JSONL session owner,
  including `initialize`, `tools/list`, `tools/call`, bounded argument schema,
  stable embedded-debugger envelopes, and Replay subprocess coverage for the
  open/close lifecycle. Added the `embedded-debugger` Skill plus Agent Plugins
  and Codex companion manifests.
- Bounded `supervisor mcp` process recovery with startup prevalidation, a
  configurable 0..=32 restart budget and 0..=60000 ms delay, transparent MCP
  proxying, duplicate in-flight ID rejection, and structured lifecycle events.
  Unanswered requests fail once as target-state-indeterminate and are never
  replayed. A replacement child privately restores only the successful MCP
  initialize handshake, preserving the external client's single standard
  lifecycle; stale debug session IDs remain explicitly invalid. Replay covers
  normal shutdown, idle-child recovery, stale-session rejection, restart
  exhaustion, and bad-configuration fail-fast behavior. Plugin manifests now
  launch this supervisor by default.
- Native ESP32-S3 MCP stdio smoke acceptance using the exact USB-JTAG probe:
  handshake and tool discovery, persistent `session.open`, CPU0
  `core.status=running`, complete/disconnected `session.close`, and standard
  `shutdown` all passed with exit code 0 and empty stderr. This is transport
  lifecycle coverage, not a replacement for the existing operation-specific
  hardware acceptance.
- Native ESP32-S3 MCP operation acceptance in one persistent lease: running
  register and mapped-NVM reads, CPU0 halt/status/step/run, an immediate
  hardware-breakpoint hit with exact PC verification, explicit comparator
  clear, complete close/disconnect, and MCP shutdown all passed. The run did
  not flash, reset, write memory, or transmit serial data.
- Native ESP32-S3 MCP bounded-wait and idle-lease acceptance: a breakpoint wait
  returned `halted/breakpoint` with exact PC evidence, a no-event wait returned
  successful `timed_out/running` with six polls, and a separate 1500 ms idle
  lease automatically cleared an active comparator, restored CPU0 running,
  disconnected, emitted `session.idle_expired`, and exited 0.
- Native ESP32-S3 MCP supervisor acceptance on the exact USB-JTAG probe: after
  a 1500 ms active-lease idle cleanup, the child was replaced and privately
  reinitialized while the outer connection stayed open. Ping succeeded without
  a second client initialize, the old lease returned `PROTOCOL_ERROR`, a new
  lease opened with CPU0 running, close/disconnect and shutdown completed, the
  supervisor exited 0, and a subsequent exact attach/disconnect succeeded. No
  flash, reset, memory write, or breakpoint mutation was requested.
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

- OpenOCD host inspection, a confirmed managed server, GDB/MI host validation,
  a confirmed fixed remote attach/detach lifecycle, and one fixed direct CPU0
  halt/resume roundtrip are implemented; the latter is physically accepted on
  ESP32-S3. A fixed global reset-halt and selected-target recovery workflow is
  also physically accepted on ESP32-S3 CPU0. General OpenOCD target
  discovery/control, configurable reset, non-selected target restoration,
  symbol/ELF loading, register or memory inspection, breakpoints/watchpoints,
  and flashing are not. The MCP adapter
  currently exposes only the probe-rs/Replay persistent session contract;
  OpenOCD and flash planning/execution remain CLI operations.
- Native raw BIN requires an explicit base address; Replay uses the fixture
  address unless the same address is supplied. ESP-IDF ELF requires explicit
  format and flash capacity inputs and is physically accepted only on ESP32-S3.
  General ELF and Intel HEX are not accepted.
- Native flashing is limited to readable boot NVM. Multi-core segmented
  execution is physically accepted only on ESP32-S3. RTT, arbitrary
  memory writes, Generic/MMIO reads, register writes, software/symbolic/
  conditional breakpoints, watchpoints, asynchronous request cancellation, and
  durable crash recovery or multi-client arbitration are not implemented. The
  supervisor can replace an MCP child but cannot prove target cleanup after a
  hard kill. Persistent hardware
  breakpoints and idle lease expiry are physically accepted only on ESP32-S3
  CPU0; native one-shot breakpoint commands and CPU1 breakpoint control are not
  exposed. Memory reads are limited to 4096 bytes and do not freeze other cores
  or DMA.
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
