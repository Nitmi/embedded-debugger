# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Added

- Strict Intel HEX planning with `.hex`/`.ihex` auto-detection, checksum and record
  validation, sparse normalized segment manifests, overlap and address-overflow
  rejection, nRF52840 UICR labeling, readable non-boot NVM erase planning, and
  digest-bound execution gates. Intel HEX, segmented code Flash, and non-boot NVM
  writes are now independent capabilities. The nRF52840 native backend passed a
  separately confirmed physical code-Flash-only sparse HEX execution on the
  official DK after an explicitly authorized access-protection recovery. Both
  segments verified and complete post-reset evidence was published; normal
  runtime readiness and independent preservation of pre-existing unwritten bytes
  remain outside that exact run. UICR remains blocked by
  `NON_BOOT_NVM_EXECUTION_ACCEPTANCE_REQUIRED` before attach.
- A standalone dependency-free nRF52840 DK smoke firmware with a valid Cortex-M
  vector table, active-low LED1 heartbeat, fixed 115200-baud virtual-COM READY and
  HEARTBEAT records, reproducible ELF/Intel HEX build, artifact manifest, and
  bounded machine-readable hardware-test contract.
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
  17-record lookup and 16-annotation output limits, 64-byte build-ID limit,
  bounded object-table sizes, and external-data prohibition. GDB never receives
  the ELF; annotation
  runs in process only after target restoration and both managed processes
  finish. Compressed debug sections are rejected, no more than eight declined
  split-DWARF continuations are resumed per frame, split or linked debug files
  and source contents are never read, and symbol-table fallback remains within
  the exact in-memory ELF. Reports explicitly keep
  runtime firmware identity and physical call-stack completeness unverified.
  Controlled ELF, digest, CLI, and full two-process lifecycle regressions pass.
  One separately confirmed, non-retried ESP32-S3 CPU0 run resolved the top
  frame into eight bounded DWARF annotations, retained the adjusted caller as
  unresolved, restored running with the fixed fallback, cleaned both managed
  processes, proved both dynamic ports reusable, and recovered UART
  heartbeats. Runtime ELF identity, complete resolution, CPU1, implicit unwind
  addresses, and physical call-stack completeness remain unqualified.
  Host-only follow-up found that the unresolved caller belongs to zero-sized
  `STT_FUNC Reset`; fallback now permits an explicitly labeled, maximum-64-KiB
  range only to the next distinct text symbol or executable-section end in the
  same section, with structured range evidence and explicit-size symbols taking
  priority. Against the same ELF, the current parser returns all 12 top-frame
  annotations and inferred caller range `[0x40378638, 0x40378698)`. A new
  independently confirmed, non-retried ESP32-S3 CPU0 run then returned those 12
  annotations through `main`, resolved the caller as inferred `Reset` with
  structured 96-byte range evidence, restored running, gracefully cleaned both
  processes, proved both ports reusable, and recovered UART heartbeats. Runtime
  ELF identity, physical call-stack completeness, CPU1, and implicit unwind
  addresses remain unqualified.
- Confirmed `openocd breakpoint plan/test` for one temporary hardware-only
  breakpoint at an exact nonzero numeric address. Its independent R2 digest
  binds fixed `-break-insert -h`, breakpoint-1 deletion, exact empty-table
  verification, tools/config/profile, target, deadlines, effects, and
  restoration. Structured parsing requires an enabled `hw breakpoint` at the
  requested address with zero hits, accepts the official named breakpoint-table
  body grammar, and rejects software, pending, conditional, multi-location,
  malformed, extra, or residual entries. The target is never intentionally
  continued while the breakpoint exists. Breakpoint-exchange failures after
  connection and before normal detach attempt fixed delete/list/detach cleanup.
  Every GDB failure records a point-in-time target state and issues no additional
  Tcl resume; GDB detach/exit or configured detach handlers may
  still resume the target, so manual recovery may be required and failures are
  never retried automatically. Runtime adapter identity, comparator capacity,
  and physical comparator cleanup remain unbound or independently unverified.
  Controlled parser, digest, success, failure-cleanup, two-process, and CLI
  regressions pass. A separately confirmed, non-retried ESP32-S3 CPU0 run at
  `0x420129E4` installed the exact zero-hit hardware breakpoint, deleted it,
  proved the canonical GDB table empty, restored final running, gracefully
  cleaned both process trees, proved both ports reusable, and recovered eight
  consecutive UART heartbeats after retained boundary fragments. Physical
  comparator state/capacity, CPU1, hit execution, and persistent breakpoints
  remain unqualified.
- Confirmed `openocd watchpoint plan/test` for one temporary hardware-only read
  or access watchpoint over an exact, naturally aligned 1/2/4/8-byte range in a
  user-declared RAM region. Invalid, overflowing, cross-region, NVM, and
  misaligned inputs fail before tool inspection. The independent R2 digest
  binds the range, RAM declaration, mode, fixed C artificial-array expression,
  possible expression-evaluation read, nine-command MI protocol, strict
  insertion/classification parsers, delete/empty-table proof, identities,
  effects, deadlines, and restoration. Only GDB `rwatch`/`awatch` are exposed;
  write-only watchpoints are omitted because GDB may implement them with
  software stepping. Insertion must return exact `hw-rwpt`/`hw-awpt` metadata,
  and the first canonical table must contain exactly one matching
  `read watchpoint`/`acc watchpoint` row with zero hits. The target is never
  intentionally continued while the watchpoint exists. Failures after insertion
  attempt fixed delete/list/detach cleanup, record point-in-time target state,
  and issue no additional Tcl resume. GDB hardware classification does not prove
  comparator allocation; width/capacity failure may be deferred until resume.
  Empty-table cleanup likewise does not independently read physical comparator
  state. Runtime adapter identity, RAM semantics, target width/capacity,
  physical allocation/cleanup, hits, CPU1, and any later physical plan remain
  unqualified. Controlled parser, digest, success, failure-cleanup, two-process,
  and CLI regressions pass. A separately confirmed, non-retried ESP32-S3 CPU0
  `access` run over `0x3FCDB550 + 4` returned exact `hw-awpt` and
  `acc watchpoint` evidence, deleted it, proved the canonical table empty,
  restored final running, gracefully cleaned both process trees, proved both
  ports reusable, and recovered eight consecutive UART heartbeats. `read`
  mode, physical comparator allocation/cleanup, width/capacity, hit behavior,
  CPU1, and any later plan remain unqualified.
- Confirmed `openocd watchpoint hit plan/test` for one bounded real
  hardware-watchpoint event. The independent R2 digest reuses the exact
  classification plan and additionally binds asynchronous MI, all-stop mode,
  one `-exec-continue --all`, a 100..=60000 ms deadline, a user-confirmed
  half-open PC interval no larger than 1 MiB, strict token/reason/tuple/value/
  frame parsing, a required post-hit count of one, fixed cleanup, restoration,
  and a no-retry policy. Result and stop ordering may vary; repeated running
  notifications are accepted, but unrelated or malformed stops fail closed.
  Timeout or indeterminate execution attempts one fixed interrupt, then
  delete/list/detach/exit without any additional Tcl resume. Controlled
  fixtures cover immediate stop-before-result, timeout cleanup, deterministic
  plans, stale confirmation, and complete managed-process cleanup. The PC
  interval does not attest runtime firmware identity, and physical ESP32-S3
  acceptance remains pending. The first separately confirmed run timed out and
  exposed a real MI behavior mismatch: Espressif GDB emitted a tokenless SIGINT
  stop while fixtures emitted token 8. The amended protocol accepts a tokenless
  stop or exact token 8 only inside the single outstanding continue lifecycle,
  records the observed token/correlation method, rejects nonmatching and
  competing stops, and requires `signal-received`/`SIGINT` during interrupt
  cleanup. Tokenless success and timeout fixtures plus matching, nonmatching,
  competing, and signal-shape regressions pass. A follow-up ELF/DWARF audit
  identifies the demo's `heartbeat` as frame base `a1 + 160`; `a1 + 128` is a
  compiler temporary. A separately confirmed, non-retried current-frame
  snapshot returned `pc=0x420129e4` inside the local ELF's `main` range and
  `a1=0x3fcdb550`, yielding conditional arithmetic candidate `0x3fcdb5f0`.
  It restored final running, cleaned both processes and ports, and recovered
  eight UART heartbeats. Runtime ELF identity and candidate memory remain
  unverified, so no watchpoint address acceptance or standing hit authorization
  is claimed.
- Confirmed `openocd resume plan/test` for one selected-target resume-only
  recovery. Its independent R2 digest binds exact OpenOCD/config identities,
  the selected current-target name, fixed catch-wrapped Tcl protocol,
  `halted|running -> running` policy, deadlines, maximum resume count of one,
  and zero automatic retries. A halted target receives at most one resume; a
  running target receives no control command. Target mismatch, unsupported
  state, malformed/error response, or missing final-running proof fails closed
  with command-count and lifecycle evidence. The workflow requests no halt,
  reset, target-data access, GDB/monitor, breakpoint/watchpoint, flash, or
  arbitrary Tcl. Configuration Tcl effects, runtime adapter identity, and
  non-selected target states remain outside its guarantee. Controlled
  lifecycle, digest, CLI, and no-retry regressions pass; physical validation
  requires a fresh exact confirmation. One separately confirmed ESP32-S3 CPU0
  run physically accepted the running-origin idempotent branch: OpenOCD
  observed running before the conditional phase, sent zero resume commands,
  proved final running, and cleaned all processes and ports. It did not exercise
  halted-origin resume, and a zero-transmit UART check remained silent, so
  firmware liveness and heartbeat recovery remain unqualified.
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

- OpenOCD host inspection, managed server and GDB/MI validation, fixed remote
  attach/detach, direct halt/resume, global reset-halt with selected-target
  recovery, selected-register, bounded memory/stack, and offline stack-ELF
  annotation workflows are implemented and physically accepted on ESP32-S3
  CPU0 within their exact plans. One temporary numeric hardware-breakpoint
  roundtrip and one access-mode hardware-watchpoint classification/cleanup
  roundtrip also have exact-plan physical acceptance. General OpenOCD target
  discovery/control, configurable reset, non-selected target restoration, GDB
  symbol loading, persistent/software/symbolic/conditional breakpoints,
  breakpoint-hit execution, write-only/persistent watchpoints, read-mode
  physical watchpoint acceptance, physical acceptance of the bounded
  watchpoint-hit workflow, and flashing remain unqualified. The MCP adapter
  currently exposes only the probe-rs/Replay persistent session contract;
  OpenOCD and flash planning/execution remain CLI operations.
- Native raw BIN requires an explicit base address; Replay uses the fixture
  address unless the same address is supplied. ESP-IDF ELF requires explicit
  format and flash capacity inputs and is physically accepted only on ESP32-S3.
  General ELF and Intel HEX are not accepted.
- Native flashing is limited to readable boot NVM. Multi-core segmented
  execution is physically accepted only on ESP32-S3. RTT, arbitrary
  memory writes, Generic/MMIO reads, register writes, software/symbolic/
  conditional breakpoints, general/persistent watchpoints, watchpoint-hit
  execution, asynchronous request cancellation, and durable crash recovery or
  multi-client arbitration are not implemented. The
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
