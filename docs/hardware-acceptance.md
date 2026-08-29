# Hardware acceptance

Native probe-rs code is compiled and its target, address, sector, confirmation,
and error behavior is tested without hardware. A release that claims verified
device support must also complete this checklist on representative hardware.

## Preconditions

- Use a disposable or recoverable target with a known-good debug connection.
- Back up flash outside the image range when practical.
- Record the exact target name, probe selector, board revision, supply voltage,
  probe-rs version, and firmware SHA-256.
- Use a test image that emits an observable serial or GPIO result after reset.

## Acceptance flow

1. Run `doctor` and `probes list`; verify the intended probe has a unique serial.
2. Plan a small raw BIN inside boot flash and inspect `ranges`, `erase_ranges`,
   target, probe, policy, and digest.
3. Attempt execution with an incorrect digest; verify no device write occurs.
4. Execute with the exact digest and persist evidence to a new path.
5. Verify the image starts, the evidence reports read-back success, and the
   final core state is running or explains an immediate halt.
6. Read back bytes in the affected sectors but outside the image; confirm they
   were preserved.
7. Repeat with an image that crosses a sector boundary.
8. Unplug or deny access to the probe and verify structured unavailable or
   permission errors.
9. Attempt an option-byte/OTP address and a RAM address; both must be rejected
   before attach.
10. Inspect the evidence by CLI and verify its recorded plan digest and ordered
    operations match the run.

## Current result

Run on 2026-08-13 through 2026-08-17 with probe-rs 0.32.0 on Windows:

- nRF52840: J-Link `1366:1061:001050282192`, detected target
  `nRF52840_xxAA`, silicon `NRF52840_xxAA_REV2`. Product-level `probes test`
  completed attach and disconnect. The single-core guarded workflow reports all
  required flash, verify, reset, halt/run, register-read, and memory-read
  capabilities.
- ESP32-S3: native USB-JTAG `303a:1001:E0:72:A1:D4:1F:DC`, detected target
  `esp32s3`. Product-level `probes test` completed attach and disconnect.
  Before reset acceptance, the candidate `snapshot capture` completed repeated
  running-origin exercises with `cpu0` as `running -> halted -> running` and
  `cpu1` explicitly unavailable. A standalone probe-rs system reset then
  completed successfully.
  After reset, `cpu1` became accessible at its natural ROM breakpoint instead of
  remaining disabled.
- Product-level `snapshot reset-capture` then completed a non-flashing five-step
  lifecycle: attach, system reset-and-halt, all-core register capture, per-core
  restoration, and disconnect. `cpu0` was captured halted at `PC=0x40000400`,
  `SP=0`, `LR=0` and restored to its declared `running` state. `cpu1` was captured
  halted at `PC=0x400003C0`, `SP=0`, `LR=0` with breakpoint halt reason and
  preserved in its declared `halted` state. The response reported
  `reset_requested=true`, `flash_operation_requested=false`, and verified core
  restoration.
- A subsequent independent live snapshot observed that the reset workflow's
  states survived its disconnect: `cpu0` entered running at `PC=0x420969FE`,
  `SP=0x3FCDB5D0`, `LR=0x4203DAF8`, while `cpu1` entered halted at
  `PC=0x400003C0`. This accepts native ESP32-S3 `reset` and
  `multi_core_post_flash`; it does not qualify the independent live snapshot's
  own later detach as state preserving. It also does not claim all volatile
  target state is unchanged: probe-rs clears hardware breakpoints on attach,
  and its ESP32-S3 sequence disables the super, timer-group 0/1, and RTC
  watchdogs. Structured `effects` reports these R1 side effects.
- The complete 16 MiB ESP32-S3 flash was backed up before any candidate write.
  The local file is exactly 16,777,216 bytes with SHA-256
  `676e986b86f781db5ccd1abe3ff42bb446acc6c041bfbef59cba48ea7ef8f373`
  and MD5 `70428b668a219f60be1a88ef004b7b10`; an independent device-side checksum over
  `0x00000000 + 0x01000000` returned the same MD5. The current bootloader and
  partition-table slices match the rebuilt candidate, while the application
  differs and identifies as the historical `YD-ESP32 Rust Control` firmware.
- A local YD-ESP32-S3 N16R8 Rust heartbeat project was rebuilt successfully. Its
  ELF is 2,221,600 bytes with SHA-256
  `676a89d78556f07500fcbe50a17c046c27d9d6e1e425ed9732c6f257a09f7b20`.
  Physical planning normalized it into bootloader (`0x0 + 21056`), partition
  table (`0x8000 + 3072`), and application (`0x10000 + 95136`), affecting
  `0x0 + 196608` bytes.
- The exact confirmed ESP32-S3 plan
  `90098bb194bdf83175c68f854434ac21fbe89b5b5eaee9f8735037423375b482`
  programmed and independently verified all three segments, 119,264 bytes in
  total. It then reset the system, captured both cores, restored `cpu0` to
  running and `cpu1` to its reset breakpoint, disconnected, and published an
  eight-operation evidence bundle. Evidence SHA-256 is
  `d4f1b5fcb47abfb7a6cca51b08889130063061b3cbcffcd0383328fa99750509`;
  `snapshot inspect` accepted the complete bundle.
- An external espflash read recovered the complete 16 MiB after programming.
  Its SHA-256 is
  `a12e4d9b521d7fae51ef1c8f98ff4afd17c35ad36abe2a01c10d13bcd5c19439`
  and MD5 is `6924f783c06605ea55b7bb26a0f8ed2d`; a separate device-side full-flash
  checksum returned the same MD5. The three programmed ranges matched their
  planned hashes. The three preserved gaps (`0x5240 + 11712`,
  `0x8C00 + 29696`, and `0x273A0 + 35936`) matched their write-before hashes.
  Every byte from `0x30000` through the end of flash also matched the backup;
  that 16,580,608-byte region retained SHA-256
  `02a9e262a65e4b73eab6eba9e0157b251c9ba64ec5e759d40eeec276e081d4ec`.
- A 12-second `baud` monitor at 115200 with DTR/RTS false received 12 consecutive
  heartbeat records (`24..35`) and the expected blue/red/green RGB cycle. After
  an independent live snapshot restored `cpu0` from halted to running, a second
  five-second monitor received heartbeats `65..69`. No serial bytes were sent.
  Recovery was not required. This accepts native ESP32-S3 `segmented_flash`.
- The pre-gate candidate `registers read` passed on ESP32-S3 `cpu0`. An explicit
  `pc sp lr a2 ps` request resolved the Xtensa `lr` alias to canonical `a0`,
  captured all five 32-bit values while halted, and reported
  `running -> halted -> running`. Omitting names then captured the complete
  bounded 18-register Xtensa inventory with the same verified restoration and
  disconnect lifecycle. An independent live snapshot again entered and left
  `cpu0` running. Read-only `baud` monitors at 115200 with DTR/RTS false observed
  heartbeats `2875..2879` before the reads and clean consecutive heartbeats
  `2945..2951` and `2972..2976` afterward; no bytes were sent. One immediate
  post-halt sample contained partial ANSI/log prefixes followed by heartbeat
  `2918`, demonstrating that execution-state restoration cannot make an
  interrupted external log write atomic. The command now reports that generic
  R1 effect explicitly. This accepts the in-session register implementation and
  running-origin path on ESP32-S3 CPU0, but not the general one-shot product
  capability for an initially halted core.
- The pre-gate candidate `memory read` passed on ESP32-S3 `cpu0`. With a
  deliberately invalid probe selector, `0x3FF00000 + 16` (Generic/MMIO) and
  `0x3FC88000 + 4097` were both rejected as `CONFIG_INVALID`, proving region and
  4096-byte limit checks completed before probe access. The exact RAM request
  `0x3FCDB550 + 32` resolved to non-alias `SRAM1 Data bus`
  (`0x3FC88000 + 425984`), returned SHA-256
  `08262ab765506db7116f9592b9718e2522aca7915fcd5158e2338fea80afa2d6`,
  and reported `running -> halted -> running`. The mapped NVM request
  `0x42000000 + 32` resolved to alias `External instruction bus`
  (`0x42000000 + 33554432`), returned SHA-256
  `6e5c379f5b716afd7e4915e5881f62d44034c8b6ece90d8490df9f25cc6ce5af`,
  and reported the same verified restoration and disconnect lifecycle. Read-only
  `baud` monitors at 115200 with DTR/RTS false received consecutive heartbeats
  `5803..5806` before and `5861..5863` after the reads; no bytes were sent. Logs
  are under `target/hardware-acceptance/2026-08-14-esp32s3-memory-read`. This
  accepts the bounded in-session RAM/NVM implementation and running-origin path
  on ESP32-S3 CPU0; it does not accept the general one-shot product capability,
  Generic/MMIO reads, writes, unbounded output, or atomic capture against the
  still-running secondary core and DMA.
- A candidate one-shot `core halt` was deliberately rejected during ESP32-S3
  acceptance. With CPU0 heartbeats `8458..8461` as the baseline, probe-rs
  reported `running -> halted` and halt reason `request` while the session was
  alive. An independent `core status` immediately after disconnect reported
  CPU0 running, and serial heartbeats continued at `8513..8515`. Source review
  confirmed that probe-rs 0.32 `Session::drop` calls `debug_core_stop` and the
  Xtensa implementation's `leave_debug_mode` resumes a stopped core. Cortex-M
  teardown also clears halting debug, so this is not safe to infer from
  architecture or backend name.
- The resulting `post_disconnect_core_state` capability is false for native
  probe-rs and true for deterministic Replay. Native one-shot live snapshot,
  register read, memory read, status, halt, and run now return
  `CAPABILITY_UNAVAILABLE` before probe selection, including with a deliberately
  invalid selector. Invalid memory ranges continue to fail even earlier as
  `CONFIG_INVALID`. A running-state exploratory status reported CPU0
  `running -> running`; it does not qualify the command for an initially halted
  core. Read-only monitors with DTR/RTS false observed heartbeats
  `8846..8849`, `8878..8881`, `8914..8917`, `9946..9949`, and
  `11311..11314` across the final gate checks. The last two samples respectively
  followed status/halt/run and live-snapshot/register/memory rejections from the
  rebuilt binary. No bytes were sent and recovery was not required. Logs
  are under `target/hardware-acceptance/2026-08-14-esp32s3-core-control`.
  The missing long-running owner was implemented and accepted in the next
  exercise.
- The foreground `session serve` JSONL owner passed native ESP32-S3 acceptance
  on exact probe `303a:1001:E0:72:A1:D4:1F:DC`. A read-only 115200-baud baseline
  produced heartbeats `13273..13276`. Within one probe-rs session, `core.halt`
  reported CPU0 `running -> halted`; a four-second `baud` monitor then received
  zero bytes, and a later in-session `core.status` still reported halted.
  `core.run` reported `halted -> running`; the next monitor received resumed
  UART activity including heartbeat `13349` (with partial ANSI prefixes caused
  by halting during an external log write). `session.close` explicitly verified
  CPU0 `running -> running`, disconnected, and the post-close monitor received
  clean heartbeats `13354..13356`.
- The unexpected-client-exit path was exercised separately: after another
  `running -> halted`, stdin was closed without `core.run` or `session.close`.
  The service logged that it safely closed the active session using the
  then-current policy
  `run_observed_cores_before_disconnect`, exited with code 0, and the following
  monitor received heartbeats `13411..13413`. All monitors used DTR/RTS=false
  and transmitted no serial bytes. Artifacts are under
  `target/hardware-acceptance/2026-08-14-esp32s3-persistent-session`. This
  accepts native persistent CPU0 status/halt/run, explicit close, and stdio EOF
  cleanup. It does not yet accept idle expiry, multi-client arbitration, hard
  process termination, or CPU1 control.
- The same persistent owner now accepts bounded register and memory reads on
  ESP32-S3 CPU0. A read-only serial baseline produced heartbeats
  `15797..15800`. While CPU0 was running, `registers.read` returned
  `pc/sp/lr/a2/ps` and `memory.read` returned 32 mapped-NVM bytes at
  `0x42000000` with SHA-256
  `6e5c379f5b716afd7e4915e5881f62d44034c8b6ece90d8490df9f25cc6ce5af`;
  both reported `running -> halted -> running`, and the next monitor produced
  heartbeats `15870..15873`. After an explicit halt, the same reads reported
  `halted -> halted`, a four-second monitor received zero bytes, and a later
  status still reported halted. Closing the lease then explicitly verified
  `halted -> running` before disconnecting.
- A monitor adjacent to that halt/close boundary contained a partial UART log
  record, as expected when an external write is interrupted. A delayed
  seven-second read-only monitor then received complete heartbeats
  `15995..15998` after one residual partial line. All serial events record
  DTR/RTS=false and no transmitted bytes; both probes were accessible after the
  lease closed. Artifacts are under
  `target/hardware-acceptance/2026-08-14-esp32s3-persistent-reads`. This accepts
  running- and halted-origin persistent reads and explicit close recovery for
  CPU0, not cross-core/peripheral atomicity or a durable halted state after the
  lease ends.
- On 2026-08-15, the same exact ESP32-S3 probe passed persistent single-step:
  a read-only baseline at 115200 baud observed `heartbeat=902..906`; inside one
  lease, CPU0 was halted, `registers.read(pc)` captured `0x420129E4`,
  `core.step` returned `halted -> halted` with `halt_reason=step` and
  `instruction_step_requested=true`, and the next `registers.read(pc)` was
  `0x420129E7`. `core.status` remained halted, `core.run` resumed the core,
  and `session.close` verified `running -> running`. A delayed six-second
  monitor then observed complete heartbeats `961..966`. All serial monitors
  used DTR/RTS=false and transmitted no bytes; artifacts are under
  `target/hardware-acceptance/2026-08-15-esp32s3-persistent-step`. This
  accepts CPU0 single-step while halted, not running-origin step, CPU1 step,
  or a durable halted state after lease teardown.
- After `pc_before`/`pc_after` became part of the step response itself, the
  rebuilt binary passed a second self-contained exercise on the same probe.
  The read-only baseline observed complete heartbeats `3825..3829`;
  `core.step` itself reported `pc_before=0x42012A3A`,
  `pc_after=0x42012A3D`, `halted -> halted`, and
  `instruction_step_requested=true`. `core.run` and `session.close` both
  verified a running final state, the probe was accessible immediately after
  close, and the next monitor received complete heartbeats `3906..3907` after
  residual partial UART text at the halt/resume boundary. The monitor metadata
  again records DTR/RTS=false and no transmitted bytes. This directly accepts
  the versioned step response without relying on separate register reads.
- On 2026-08-15, persistent hardware-breakpoint lifecycle acceptance passed on
  the exact ESP32-S3 native USB-JTAG probe
  `303a:1001:E0:72:A1:D4:1F:DC`. Attach negotiated two hardware comparator
  slots from CPU0. While halted, slot 0 set/list/readback, duplicate set,
  clear, duplicate clear, explicit-slot set, clear-all, and close cleanup all
  returned exact full-slot before/after evidence. Mutations from a running core
  were rejected with `CONFIG_INVALID`. A breakpoint deliberately left active
  before close was halted, cleared, read back empty, and followed by a verified
  running state before disconnect. The read-only serial baseline observed
  complete heartbeats `8827..8830`; after the lifecycle it observed
  `9103..9107`. Both used 115200 baud, DTR/RTS=false, and transmitted no bytes.
- A true-hit exercise then exposed an important semantic boundary: after slot 0
  was set to a recently stepped PC, strict `core.run` returned
  `PROTOCOL_ERROR` because the core hit the breakpoint before the immediate
  running-state verification. Cleanup still cleared the comparator, restored
  runtime, and the next monitor observed `heartbeat=9429..9432`. This was used
  to add the distinct `core.continue` operation instead of weakening the strict
  `core.run` contract.
- The rebuilt `core.continue` path passed a final self-contained exercise. A
  pre-test monitor observed complete heartbeats `10364..10366`. CPU0 was halted
  and stepped, slot 0 was set to `0x420129D4`, and `core.continue` immediately
  succeeded with `halted`, `halt_reason=breakpoint`; `registers.read(pc)` matched
  `0x420129D4` exactly. A concurrent three-second read-only serial monitor
  received zero bytes while the breakpoint held. Clearing slot 0, strict
  `core.run`, and `session.close` all succeeded; close reported policy
  `halt_clear_hardware_breakpoints_run_observed_cores_before_disconnect` and one
  verified cleanup observation. The probe was immediately accessible, and the
  recovery monitor received complete heartbeats `10523..10524` after one
  expected partial boundary record. Artifacts are under
  `target/hardware-acceptance/2026-08-15-esp32s3-persistent-breakpoints`.
  This accepts session-scoped CPU0 hardware breakpoints and immediate-result
  continue semantics, not CPU1, software/symbolic/conditional breakpoints,
  watchpoints, or durable breakpoint ownership after a hard process kill.
- On 2026-08-17, bounded `core.continue_until_halt` passed both native result
  paths on the same exact ESP32-S3 probe. A read-only serial baseline observed
  complete heartbeats `174..178`. In one persistent lease, CPU0 was halted and
  stepped, slot 0 was set to the resulting `PC=0x42012A2A`, and the wait
  returned `halted`, `halt_reason=breakpoint`, `elapsed_ms=3`, and
  `poll_count=0`; `registers.read(pc)` matched the breakpoint address exactly.
  After clearing the slot, a 300 ms wait with 50 ms polling returned the
  successful outcome `timed_out`, `state=running`, `elapsed_ms=301`, and
  `poll_count=6`. The same session then reported CPU0 running, accepted a new
  halt, restored running, and closed with policy
  `halt_clear_hardware_breakpoints_run_observed_cores_before_disconnect`.
  The server exited cleanly, a new attach/disconnect probe test succeeded, and
  a six-second recovery monitor observed complete heartbeats `330..335`.
  Both monitors used 115200 baud with DTR/RTS=false and transmitted no bytes.
  Artifacts are under
  `target/hardware-acceptance/2026-08-17-esp32s3-continue-until-halt`. This
  accepts bounded halt-event and timeout semantics plus lease reuse on CPU0;
  it does not accept CPU1 or asynchronous cross-request cancellation.
- On 2026-08-17, supervised active-lease idle expiry passed on the same exact
  ESP32-S3 probe. A five-second read-only serial baseline observed complete
  heartbeats `4239..4243`. The foreground server advertised
  `idle_timeout_ms=1500` and `idle_timeout_action=close_and_exit`; CPU0 was
  halted and stepped, then slot 0 was left active at `PC=0x42012A02`. With stdin
  deliberately kept open and no close request sent, the process expired after
  1835 ms, exited with code 0, and emitted `session.idle_expired` on stderr.
  Its full close evidence preserved the active address in the before snapshot,
  verified every comparator empty afterward, restored CPU0 to running, and
  successfully disconnected. A six-second recovery monitor observed complete
  heartbeats `4441..4446`, and a subsequent exact attach/disconnect probe test
  succeeded. Both serial monitors used 115200 baud with DTR/RTS=false and
  transmitted no bytes. Artifacts are under
  `target/hardware-acceptance/2026-08-17-esp32s3-idle-expiry`. This accepts
  between-request idle cleanup on CPU0; it does not imply in-flight request
  cancellation, hard-kill recovery, or CPU1 acceptance.
- Serial baseline at 115200 baud with DTR and RTS held false: nRF `COM16`
  emitted seven `Z` bytes in three seconds; nRF `COM15` and ESP32-S3 `COM3`
  were silent. No bytes were transmitted.
- A second read-only ESP `COM3` monitor after live snapshot capture was also
  silent. It provides no runtime liveness signal, so acceptance relies on the
  debug interface's explicit original and restored core states rather than
  treating serial silence as success or failure.
- A five-second `baud` monitor after `snapshot reset-capture`, again at 115200
  with DTR and RTS held false, received zero bytes. This matches the pre-reset
  baseline for the currently installed historical firmware; no bytes were sent.
- nRF Code Flash and UICR were backed up locally. The Code Flash HEX was
  verified against the connected device. Backup SHA-256 values are
  `058569c18e01e307babbf2fdc70d5dced4a4086fa0a5aee400a7839a4a3f9605`
  and `f3e0bebcc11fb18e80b3add492052e1d9942b211506eb80a8550c4c1acc3a588`.
- The planned test image is the device's original first 256 bytes, SHA-256
  `42e14475dd22fed8c69fbec371efd84b10dcba805d29bc888de082aa6c0f5022`.
  Its plan writes `0x00000000 + 256`, affects only the first 4096-byte page,
  and preserves unwritten page bytes. The complete pre-write page SHA-256 is
  `beace458e24fbf367e831e3ab4a73e45abdbdcaff19df70e6933be00cb6e160d`.
- Wrong confirmation, RAM address `0x20000000`, and UICR address `0x10001000`
  were all rejected before a device write. A subsequent independent read
  matched the original 256-byte hash.
- The exact confirmed plan
  `4d3d3cf56af7548307f275415e78be15e67b631280d88d8882d8040ddc40f8c3`
  completed on the nRF52840. It programmed 256 bytes, independently read them
  back, reset and halted the core, captured `PC=0x00000998`,
  `SP=0x20000400`, and `LR=0xFFFFFFFF`, resumed the core, disconnected, and
  published a complete eight-operation evidence bundle.
- The evidence SHA-256 is
  `6bf2a0b5a4c3888c697d4a38f3e7114bbfc0eb1b4252a4c98080bdf387485ac3`.
  `snapshot inspect` accepted it and matched the plan digest, exact identities,
  write and erase ranges, policy, flash result, core state, and ordered
  operations.
- Independent full-page reads before and after the write both produced SHA-256
  `beace458e24fbf367e831e3ab4a73e45abdbdcaff19df70e6933be00cb6e160d`.
  All 3840 bytes outside the 256-byte image matched byte for byte. A subsequent
  device-side comparison also verified the complete Code Flash and UICR against
  their backups.
- After the reset/resume workflow, `COM16` again emitted seven `Z` bytes in
  three seconds at 115200 baud with DTR and RTS false. No bytes were sent, and
  the observable firmware behavior matched the pre-write baseline.
- The cross-page case used the device's original 32 bytes at `0x00000FF0`,
  SHA-256
  `70954de6e5d07d1ea9da686ccddf5c2da794352d7489b6e6b1bbb74807c7b5f6`.
  Its exact confirmed plan
  `e89c3c3fc1fb7726019bfb836eb004a78e48dd953e6c8ca36df7257eb588230b`
  crossed the `0x00001000` page boundary and affected exactly
  `0x00000000 + 8192` bytes.
- The cross-page run programmed and independently verified all 32 image bytes,
  captured the same post-reset `PC`, `SP`, and `LR`, resumed the target, and
  published a complete evidence bundle with SHA-256
  `59ca691efbe6148fe47c4c8f68441f724b9a218c4bb128d0a7ebbaee3ada1b61`.
- Two independent pre-write reads and the post-write read of both affected
  pages all produced SHA-256
  `95c1421ef611f952759935ffbdc474ae42fd8f20e386b453bb51f5d9a5260121`.
  The prefix outside the image, the 32-byte cross-page image, and the suffix
  outside the image each matched byte for byte. Code Flash, UICR, and the
  seven-`Z` serial runtime baseline also remained unchanged.
- With the nRF/J-Link USB physically unplugged, `baud list`, standalone
  probe-rs, and the embedded discovery path all showed that serial
  `001050282192`, `COM15`, and `COM16` had disappeared while the ESP32-S3
  remained connected. `probes test`, `flash plan`, and `flash execute` against
  the missing selector each returned exit code 4 and `PROBE_UNAVAILABLE`.
  No evidence file was created, and a subsequent ESP32-S3 attach/disconnect
  test succeeded.

The nRF single-page guarded write, read-back verification, post-reset snapshot,
page preservation, evidence inspection, backup comparison, and observable
runtime checks passed. The cross-page case also passed across two adjacent
4096-byte pages. The affected pages were physically erased and reprogrammed,
but their final byte content is identical to the write-before baselines. The
physical unplugged-probe case also passed, completing this checklist for the
nRF52840/J-Link fixture.

The ESP32-S3 three-segment guarded write, per-segment and full-flash readback,
unwritten-byte preservation, multi-core post-reset snapshot, evidence
inspection, device-side checksum, and observable heartbeat checks passed. This
completes native ESP-IDF segmented-flash acceptance for the ESP32-S3/native
USB-JTAG fixture. Bounded register and RAM/NVM reads on CPU0 passed only as
running-origin implementation exercises with pre-attach safety rejection and
post-read heartbeat recovery. They are now capability-gated for native one-shot
use until halted-origin teardown can be guaranteed.

## MCP stdio smoke acceptance (2026-08-23)

- The exact native ESP32-S3 USB-JTAG probe `303a:1001:E0:72:A1:D4:1F:DC` was
  enumerated by the embedded probe-rs backend and selected with target
  `esp32s3`.
- A real `mcp serve --idle-timeout-ms 0` subprocess completed the MCP stdio
  handshake and persistent tool lifecycle. The server advertised protocol
  version `2025-06-18` and one `embedded_debugger_request` tool.
- `session.open` returned `ok=true`, an opaque lease ID, the native capability
  matrix, and two negotiated ESP32-S3 CPU0 hardware-breakpoint slots. The
  operation remained R1 and disclosed probe-rs attach effects; no flash,
  reset, breakpoint mutation, memory write, or serial bytes were requested by
  this smoke test.
- `core.status` on CPU0 returned `ok=true`, `state="running"`, and
  `state_scope="active_session"`. `session.close` returned
  `complete=true` and `disconnected=true`; standard MCP `shutdown` then
  completed with process exit code 0 and empty stderr.

This is a transport and lifecycle acceptance, not by itself a full hardware
debugging qualification. The operation-level MCP acceptance below exercises
the currently qualified CPU0 reads, control, breakpoint, and cleanup paths.

## MCP operation acceptance (2026-08-23)

- A second native `mcp serve --idle-timeout-ms 0` run used the same exact probe
  and target in one lease (`ses_f23879060fe34588ab92b05c0f9ab2c5`). The open
  capability matrix reported `register_read=true`, `memory_read=true`,
  `step=true`, and two hardware-breakpoint slots.
- Running-origin `registers.read` returned `pc`, `sp`, and canonical `a0` for
  the requested `lr` alias, with `ok=true`. `memory.read` returned 32 bytes
  from mapped NVM at `0x42000000`, with SHA-256
  `6e5c379f5b716afd7e4915e5881f62d44034c8b6ece90d8490df9f25cc6ce5af`.
- CPU0 `core.halt` and `core.status` both reported `halted`. `core.step`
  completed in the same active session with `pc_before=0x420129F5`,
  `pc_after=0x420129F7`, `halt_reason=step`, and the explicit instruction
  effect. `core.run` and a later status restored `running`.
- After halting again, `breakpoints.set` placed slot 0 at the current
  `0x420129FD`; `breakpoints.list` returned both indexed slots. `core.continue`
  immediately stopped with `halt_reason=breakpoint`, and a follow-up register
  read matched `pc=0x420129FD` exactly. `breakpoints.clear` succeeded, followed
  by a verified running state.
- `session.close` returned `complete=true` and `disconnected=true`; MCP
  `shutdown` returned `{}`, the process exited 0, and stderr was empty. The
  run did not flash, reset, write memory, or transmit serial data.

This accepts the MCP mapping for the currently qualified ESP32-S3 CPU0
session operations: bounded register/memory reads, halt/status/run/step,
hardware breakpoints, immediate continue, and explicit cleanup. It does not
qualify CPU1 control, asynchronous cancellation, flash, or OpenOCD.

## MCP bounded wait and idle expiry acceptance (2026-08-23)

- A native MCP lease on the exact ESP32-S3 probe exercised
  `core.continue_until_halt` through both result paths. With slot 0 set at the
  current `PC=0x420129D4`, the bounded wait returned
  `outcome=halted`, `state=halted`, `halt_reason=breakpoint`,
  `elapsed_ms=4`, and `poll_count=0`; a follow-up register read matched the
  PC exactly. After clearing the comparator, a 300 ms wait with 50 ms polling
  returned the successful `outcome=timed_out`, `state=running`,
  `elapsed_ms=301`, and `poll_count=6`. The same lease remained usable for
  status and explicit close, which completed and disconnected.
- A separate native MCP subprocess used `--idle-timeout-ms 1500`, halted CPU0,
  and left slot 0 active at `0x420129FF` without sending another request. It
  exited after 1879 ms with `session.idle_expired` and
  `action=close_and_exit` on stderr. The structured close evidence reported
  `complete=true`, `disconnected=true`, slot 0 changing from
  `0x420129FF` to empty, all comparator slots empty afterward, and CPU0
  `running`; process exit code was 0.

This accepts MCP bounded wait event/timeout semantics, lease reuse after a
timeout, and supervised idle cleanup on ESP32-S3 CPU0. It does not qualify
CPU1 control, asynchronous cancellation, flash, or OpenOCD.

## MCP supervisor recovery acceptance (2026-08-23)

- The exact native ESP32-S3 USB-JTAG probe
  `303a:1001:E0:72:A1:D4:1F:DC` was selected with target `esp32s3` through
  `supervisor mcp --idle-timeout-ms 1500 --max-restarts 2
  --restart-delay-ms 100`.
- The external client completed one MCP `2025-06-18` initialize lifecycle and
  opened lease `ses_cf06ee5581014b8db9519e530b6fe971`. It then sent no
  requests for 2506 ms. The child closed the active lease on idle expiry, and
  stderr recorded `session.idle_expired`, `supervisor.child_exited`,
  `supervisor.child_restarted`, and `supervisor.child_ready` in order.
- Without a second external initialize, JSON-RPC ping request 3 succeeded. A
  status request carrying the old lease ID reached the fresh owner and returned
  the expected stable `PROTOCOL_ERROR`, proving that the supervisor did not
  fabricate lease continuity.
- A new exact lease `ses_31d13f600f2648799843651b1a520a20` then opened through
  the same external MCP connection. CPU0 status was `running`; explicit close
  returned `complete=true` and `disconnected=true`. Standard shutdown request
  8 completed and the supervisor exited with code 0.
- A subsequent exact `probes test` attach/disconnect completed successfully,
  confirming that the replacement lifecycle released the probe. The exercise
  did not flash, reset, write memory, set breakpoints, or transmit serial data.

This accepts native process replacement after a child performs its guarded idle
cleanup, private MCP handshake restoration, stale-session rejection, and a new
lease on one outer stdio connection. It deliberately does not claim hard-kill
cleanup, in-flight operation recovery, request replay, CPU1 control, or durable
target-state recovery.

## Guarded OpenOCD server lifecycle acceptance (2026-08-23)

- The connected fixture was the exact ESP32-S3 native USB-JTAG device
  `303A:1001 / E0:72:A1:D4:1F:DC`, also exposed as COM3. No OpenOCD,
  probe-rs, or embedded-debugger process was running before execution.
- The selected official Espressif executable identified itself as
  `Open On-Chip Debugger v0.12.0-esp32-20260703 (2026-07-03-13:40)`.
  Its size was 5,235,200 bytes and SHA-256 was
  `58ceca283262cd313fdb6b4ba94195b01502a15dc61b6ae0b986077449010179`.
  The top-level `board/esp32s3-builtin.cfg` was 411 bytes with SHA-256
  `62f5bb4f81cf28455bab48d158227c3f4f280dcaab0838e0472c4249e7696611`.
- `openocd server plan` was recomputed immediately before execution. Its exact
  confirmed digest was
  `c91af0e92eff4ada06c093dc46e4e92406ebff9023455eb5e3236698b8707b30`.
  The run retained the `R2_DEVICE_WRITE` classification because search-tree
  contents, transitive Tcl sources, and configuration semantics are not bound
  or statically verified.
- The managed launcher bound only `127.0.0.1`, disabled telnet, selected Tcl
  port 2961 and GDB port 2962 dynamically, and proved Tcl readiness with a
  framed `version` response in 89 ms. The exact USB-JTAG serial was logged.
- Both ESP32-S3 JTAG taps were found. OpenOCD reported CPU0 examination success,
  but CPU1 examination failed with `Unexpected OCD_ID = 00000000`. This is
  retained as a target limitation; the acceptance does not qualify CPU1,
  GDB/MI, target operations, or OpenOCD flash.
- The launcher sent framed Tcl `shutdown`. OpenOCD exited with code 0 in 10 ms;
  `graceful=true`, `forced_process_tree_kill=false`,
  `process_tree_cleanup_complete=true`, and both output streams drained without
  truncation, oversized lines, dropped events, or read errors. The complete
  stderr stream was 1,201 bytes with SHA-256
  `f3dd032bc67ad78369d39d804c41d332089696d993b7608f80100cf62581af7f`.
- Process and TCP checks found no remaining OpenOCD/probe/debugger process and
  no listener on ports 2961 or 2962. A subsequent exact native probe-rs
  attach/disconnect succeeded, proving the USB/JTAG interface was released.
- A five-second `baud` monitor immediately after OpenOCD, at 115200 with DTR and
  RTS held false and no transmitted bytes, received complete heartbeats
  `18341..18343`. The sample immediately after the probe-rs release check crossed
  a partial UART/log boundary, so a final five-second sample was taken and
  received complete heartbeats `18381..18384`. Baud preserved log and JSONL
  artifacts under
  `target/hardware-acceptance/2026-08-23-openocd-managed-lifecycle`.

This accepts the guarded OpenOCD server lifecycle on Windows for the exact
ESP32-S3/native USB-JTAG fixture: confirmation, process isolation, dynamic
endpoint discovery, Tcl readiness, graceful shutdown, descendant cleanup,
probe release, and runtime recovery all passed. It does not accept arbitrary
configuration as benign, claim target-state preservation, or enable GDB/MI,
CPU1 control, target operations, or flash.

## GDB/MI host lifecycle acceptance (2026-08-24)

- Espressif's recommended Windows x64 `xtensa-esp-elf-gdb`
  `17.1_20260402` archive was selected from the current ESP-IDF `tools.json`.
  The downloaded archive was exactly 44,820,924 bytes and matched the published
  SHA-256
  `7525ae46b39fc87568717d8f0cc3dfbcdb77b96435dd80acfce6918b0abc2b8a`.
  It was installed as a portable tool under
  `D:\Code\tools\embedded\espressif\xtensa-esp-elf-gdb\17.1_20260402`
  without changing `PATH`.
- The exact selected binary was `xtensa-esp-elf-gdb-no-python.exe`. It
  identified itself as `GNU gdb (esp-gdb) 17.1_20260402`, was 14,596,096
  bytes, and had SHA-256
  `5ce33ee35b9075251532fc8ea6f1745ce0885764689f0014ff1c3a3f42bcd71a`.
- The original 2000 ms version deadline failed closed on a cold Windows start
  at 2005 ms with no retained output. The process was terminated and drained;
  it was not accepted as available. The GDB-specific default was then calibrated
  to 10000 ms. A cold `openocd gdb inspect` passed in 2818 ms with exit code 0,
  complete 286-byte stdout, no stderr, and all remote/target capabilities false.
- `openocd gdb test` launched only
  `--nx --nh --quiet --interpreter=mi2` inside a Windows Job Object. It observed
  the startup prompt in 28 ms, accepted 13 quoted version stream records, and
  correlated `1-gdb-version` with `1^done` in 1 ms.
- The fixed `2-gdb-exit` command returned `2^exit`. GDB exited with code 0;
  shutdown took 5 ms, `graceful=true`,
  `forced_process_tree_kill=false`, and
  `process_tree_cleanup_complete=true`. Stdout contained 913 bytes with SHA-256
  `4d685e1ff6823828f172f0d392f742882881a4f290ba54a175e24bb47b3de10f`;
  stderr was empty. Neither stream was truncated, oversized, dropped, or
  incompletely drained.
- A final reproducibility run using the completed contract also passed with the
  same 13 stream records and stdout SHA-256. Normal scheduler variation changed
  startup/version/shutdown timing from 28/1/5 ms to 32/0/23 ms without changing
  any protocol, exit, or cleanup result. Its JSON stdout and protocol stderr
  are retained under
  `target/hardware-acceptance/2026-08-24-gdb-mi-host`.
- The ESP32-S3 remained physically connected during this host acceptance, but
  the command did not start OpenOCD, open a GDB remote endpoint, load an ELF,
  connect to the USB/JTAG probe, inspect a CPU, or issue any target command.
  Therefore no confirmation digest or UART recovery claim applies to this
  `R0_READ_ONLY` checkpoint.

This accepts exact GDB identity, fixed MI2 framing and token correlation,
bounded output, graceful exit, and descendant cleanup on the host. It enables
only `gdb_mi_host_process` in the GDB test result. It does not combine GDB with
OpenOCD or qualify symbols, registers, memory, stack, breakpoints, execution
control, target-state preservation, CPU1, or flash.

## Combined OpenOCD and GDB failure-path acceptance (2026-08-24)

- The user confirmed exact digest
  `8936fffb9fa9eb3a36b97e7c928e1aa2b4f0de96f00eb33cb6e97fbb3ca84aee`.
  It selected `esp32s3.cpu0`, the Espressif OpenOCD executable SHA-256
  `58ceca283262cd313fdb6b4ba94195b01502a15dc61b6ae0b986077449010179`,
  the generic no-Python GDB SHA-256
  `5ce33ee35b9075251532fc8ea6f1745ce0885764689f0014ff1c3a3f42bcd71a`,
  and `esp32s3-builtin.cfg` SHA-256
  `62f5bb4f81cf28455bab48d158227c3f4f280dcaab0838e0472c4249e7696611`.
- Before execution, COM3 was re-enumerated as `303A:1001` with serial
  `E0:72:A1:D4:1F:DC`. A 5-second, 115200-baud, DTR/RTS-false, zero-transmit
  monitor received five consecutive heartbeats `5090..5094` (206 bytes).
- The confirmed test started OpenOCD on dynamic Tcl/GDB ports 2504/2505,
  verified `esp32s3.cpu0=running`, and completed `1-gdb-version` as `1^done`.
  Remote selection then returned `2^error`: GDB expected a 388-byte `g` packet
  but OpenOCD returned 608 bytes. No detach result, symbol, ELF, breakpoint,
  explicit target-data command, flash command, or arbitrary command followed.
- The failure cleanup observed CPU0 halted, issued the fixed resume fallback,
  and proved the final exact state `esp32s3.cpu0=running`. GDB accepted
  `4-gdb-exit`, exited 0, and was not force-killed. OpenOCD accepted `shutdown`,
  exited 0, and was not force-killed. Both Job Object trees, output readers,
  and ports 2504/2505 were clean after exit.
- An exact probe-rs attach/disconnect then succeeded on
  `303a:1001:E0:72:A1:D4:1F:DC`. A second zero-transmit serial monitor received
  heartbeats `5241..5245` (204 bytes), proving observable firmware recovery.
  Evidence is retained under
  `target/hardware-acceptance/2026-08-24-openocd-gdb-session`.
- Host-only diagnosis showed 131 register-table lines for the generic GDB and
  272 for the official `xtensa-esp32s3-elf-gdb` launcher. Setting
  `XTENSA_GNU_CONFIG` to `lib/xtensa_esp32s3.so` on the exact generic GDB
  reproduced the launcher's table byte for byte; both outputs had SHA-256
  `a99bc896e736c3dd50a52e16f7a94777d1dddd0e99b227033237bd4aa1dd648c`.
  The profile file SHA-256 is
  `8bea9f0f2225db46a5ab682b257cd3590969ae4173ab2ceddde24d6e830dbee4`.

This accepts the confirmed protocol-failure cleanup, target restoration,
process/port release, probe reuse, and UART recovery paths. It does not accept
successful OpenOCD/GDB interoperability. The implementation now supports a
digest-bound `--gdb-xtensa-config`; at this failure checkpoint, a new plan and
separate confirmation were required before one further physical attempt.

## Profile-bound OpenOCD and GDB session acceptance (2026-08-24)

- The user separately confirmed the deterministic profile-bound digest
  `57acda7c2ef2654454d22dde8dad88abc43cd188be4f5978f196ac16cb2e545d`.
  It selected exact current target `esp32s3.cpu0`, OpenOCD SHA-256
  `58ceca283262cd313fdb6b4ba94195b01502a15dc61b6ae0b986077449010179`,
  GDB SHA-256
  `5ce33ee35b9075251532fc8ea6f1745ce0885764689f0014ff1c3a3f42bcd71a`,
  and `esp32s3-builtin.cfg` SHA-256
  `62f5bb4f81cf28455bab48d158227c3f4f280dcaab0838e0472c4249e7696611`.
  The newly bound `xtensa_esp32s3.so` profile was 705,483 bytes with SHA-256
  `8bea9f0f2225db46a5ab682b257cd3590969ae4173ab2ceddde24d6e830dbee4`;
  ambient `XTENSA_GNU_CONFIG` was not inherited.
- COM3 was re-enumerated immediately before execution as exact USB device
  `303A:1001 / E0:72:A1:D4:1F:DC`. A five-second read-only monitor at 115200
  baud, DTR/RTS false, and zero transmit received consecutive heartbeats
  `10102..10106` (210 bytes).
- The single confirmed run started OpenOCD on dynamic loopback Tcl/GDB ports
  14773/14774 and proved readiness in 209 ms. It verified
  `esp32s3.cpu0=running`, observed the MI startup prompt in 22 ms, completed
  `1-gdb-version -> done`, connected with
  `2-target-select -> connected` in 591 ms, detached with
  `3-target-detach -> done`, and exited with `4-gdb-exit -> exit`.
- The exact target was `halted` after normal GDB detach, so the implementation
  requested its one fixed resume fallback. The final observation proved
  `esp32s3.cpu0=running` in 3 ms. GDB exited 0 gracefully in 3 ms; OpenOCD
  accepted framed `shutdown` and exited 0 gracefully in 11 ms. Neither process
  tree was force-killed, all output drains completed without truncation,
  oversized lines, dropped events, or read errors, and no listener remained on
  14773/14774. OpenOCD continued to report CPU1 examination failure with
  `OCD_ID=00000000`, so CPU1 remains unqualified.
- A subsequent exact probe-rs test on
  `303a:1001:E0:72:A1:D4:1F:DC` completed attach/disconnect, proving probe
  release. A final five-second zero-transmit UART monitor received heartbeats
  `10192..10195` after one partial pre-heartbeat log fragment (188 bytes),
  proving observable application recovery. No related OpenOCD, GDB, or
  embedded-debugger process and no dynamic-port listener remained. Evidence is
  retained under
  `target/hardware-acceptance/2026-08-24-openocd-gdb-session`.

This accepts successful interoperability for the exact profile-bound,
running-origin, fixed MI version/connect/detach/exit lifecycle on ESP32-S3 CPU0,
including verified fallback restoration and complete host/probe cleanup. It
does not accept CPU1, symbols or ELF loading, explicit register/memory/stack
inspection, breakpoints, watchpoints, general execution control, OpenOCD flash,
arbitrary MI/Tcl/monitor commands, or digest binding of the runtime USB adapter
identity and dynamically selected port numbers.

## Direct OpenOCD target-state roundtrip acceptance (2026-08-24)

- The user independently confirmed exact digest
  `06d650bc97d6f055572591a411a6a3be4c60979194aded349d32e869aafa593d`.
  It bound expected target `esp32s3.cpu0`, OpenOCD SHA-256
  `58ceca283262cd313fdb6b4ba94195b01502a15dc61b6ae0b986077449010179`,
  `esp32s3-builtin.cfg` SHA-256
  `62f5bb4f81cf28455bab48d158227c3f4f280dcaab0838e0472c4249e7696611`,
  a 3000 ms transition deadline, and the fixed
  `target current / curstate / halt / resume / shutdown` protocol.
- COM3 was re-enumerated immediately before execution as exact USB device
  `303A:1001 / E0:72:A1:D4:1F:DC`. A five-second monitor at 115200 baud with
  DTR/RTS false and zero transmitted bytes received consecutive heartbeats
  `12580..12584` (209 bytes).
- The single confirmed test started OpenOCD on dynamic loopback Tcl/GDB ports
  12171/12172 and proved readiness in 110 ms. It validated the exact current
  target and initial `running` state, observed `halted` after the fixed halt in
  29 ms, and observed final `running` after the fixed resume in 2 ms. The test
  requested no reset, GDB/monitor operation, register/memory/stack read,
  breakpoint, flash, or arbitrary Tcl command.
- OpenOCD accepted framed `shutdown`, exited 0 gracefully in 11 ms, and was not
  force-killed. Process-tree cleanup completed; stdout and stderr fully drained
  without truncation, oversized lines, dropped events, or read errors. No
  related process or listener on 12171/12172 remained.
- OpenOCD examined CPU0 successfully but again reported CPU1 examination
  failure with `Unexpected OCD_ID = 00000000`; this acceptance does not qualify
  CPU1. The digest also does not bind runtime adapter identity, dynamic port
  numbers, search-tree contents, transitive Tcl sources, or configuration
  semantics.
- A subsequent exact probe-rs attach/disconnect on
  `303a:1001:E0:72:A1:D4:1F:DC` succeeded, proving probe release. A final
  five-second DTR/RTS-false, zero-transmit UART monitor received consecutive
  heartbeats `12665..12668` after one partial log record (185 bytes), proving
  observable application recovery. Final process, port, and COM identity
  checks were clean. Evidence is retained under
  `target/hardware-acceptance/2026-08-24-openocd-target-roundtrip`.

This accepts only the exact, running-origin, direct-Tcl
`esp32s3.cpu0 running -> halted -> running` roundtrip and its restoration and
cleanup guarantees. It does not accept CPU1, reset, durable halt, general target
discovery/control, debugger data access, breakpoints/watchpoints, flash,
arbitrary commands, or broader configuration trust.

## Global OpenOCD reset and selected-target recovery acceptance (2026-08-24)

- The user independently confirmed exact digest
  `534095d32cdd29a88720230ffaaee6dd07edfd4b97fde287e81f436d76d782d6`.
  It bound expected selected target `esp32s3.cpu0`, OpenOCD SHA-256
  `58ceca283262cd313fdb6b4ba94195b01502a15dc61b6ae0b986077449010179`,
  `esp32s3-builtin.cfg` SHA-256
  `62f5bb4f81cf28455bab48d158227c3f4f280dcaab0838e0472c4249e7696611`,
  the fixed global `reset halt` and selected-target recovery catch envelopes,
  independent 3000 ms transition deadlines, and final selected-target running.
- COM3, Windows PnP, and probe-rs independently identified the same ESP32-S3
  native USB-JTAG device as `303A:1001 / E0:72:A1:D4:1F:DC`. A five-second
  115200-baud monitor held DTR/RTS false, transmitted zero bytes, and received
  consecutive baseline heartbeats `18865..18869`.
- The single confirmed test, with no automatic retry, started OpenOCD on dynamic
  loopback Tcl/GDB ports 2905/2906 and proved readiness in 150 ms. It strictly
  matched `esp32s3.cpu0` and initial `running`. The global reset catch code was
  0 and CPU0 reached `halted` in 292 ms. The one fixed recovery catch code was
  0 and CPU0 reached final `running` in 5 ms.
- OpenOCD accepted framed `shutdown`, exited 0 gracefully in 22 ms, and was not
  force-killed. Process-tree and port cleanup completed, and both bounded log
  streams drained without truncation, oversized lines, dropped records, or read
  errors. OpenOCD reported that CPU1 was also reset, but CPU1 examination still
  failed; its final state and restoration remain unqualified.
- The first post-reset UART sample showed the expected firmware counter restart
  and complete heartbeats `46..49`. An exact probe-rs attach/disconnect then
  succeeded, proving probe release. A final zero-transmit monitor received
  complete heartbeats `107..111`. Two partial records at reset/monitor
  boundaries are retained as disclosed non-atomic external-I/O effects.
- Structured evidence and all three UART captures are retained under
  `target/hardware-acceptance/2026-08-24-openocd-reset-recovery`. The acceptance
  summary SHA-256 is
  `2472bc6b3fe917dff9f62c8cd3f610f3e6132d48018948fcf9a42dfd2b91882d`.

This accepts only one exact global reset-halt plus observation, one fixed resume,
and final-running proof for selected CPU0, together with complete cleanup and
observable firmware recovery. It does not accept `reset init`, configurable or
repeated reset, CPU1 restoration, target-data access, GDB, breakpoints, flash,
monitor input, arbitrary Tcl, or broader configuration trust.

## Confirmed OpenOCD selected-register snapshot acceptance (2026-08-24)

- The user independently confirmed exact digest
  `7507f3e8fcc5a0ce5051348564358b6f8e0e8981f3321e6ecc4256444989dddd`.
  It bound `esp32s3.cpu0`, the ordered `pc/a0/a1/ps` selection, the six-command
  GDB/MI protocol, all lifecycle deadlines, and the exact OpenOCD, GDB, Xtensa
  profile, and top-level board-configuration identities.
- Before execution, `baud list --json` distinguished COM3 as Espressif
  `303A:1001 / E0:72:A1:D4:1F:DC` from the two SEGGER J-Link CDC ports. There
  was no related OpenOCD, GDB, or embedded-debugger process, and the evidence
  paths did not exist. All four bound host-file hashes still matched the plan.
- The confirmed physical command ran exactly once, with no automatic retry. It
  started OpenOCD on dynamic loopback Tcl/GDB ports 9804/9805 and proved
  readiness in 171 ms. The runtime OpenOCD identity matched the same native
  USB-JTAG serial, both ESP32-S3 taps were found, and selected CPU0 initially
  reported `running`.
- GDB completed the fixed six-command MI sequence with the required result
  classes: `version`, `connect`, `register names`, `selected values`, `detach`,
  and `exit`. The runtime inventory contained 270 uniquely named registers.
  Ordered output was
  `pc[0]=0x42012a0d`, `a0[212]=0x40378695`,
  `a1[213]=0x3fcdb550`, and `ps[73]=0x60025`.
- Normal GDB detach returned `done`, but CPU0 was subsequently observed
  `halted`. The confirmed policy therefore requested its one fixed resume
  fallback and proved final `esp32s3.cpu0=running` in 6 ms. GDB and OpenOCD
  both exited 0 gracefully, neither process tree was force-killed, all output
  drains completed, and the final residual debug-process count was zero.
- OpenOCD's attach handlers halted both cores and inspected flash mappings even
  though the tool issued no explicit flash command or write. Only selected
  CPU0 received a final state observation; CPU1's final state is therefore not
  qualified by this acceptance.
- Post-run COM enumeration was unchanged. One five-second 115200-baud monitor
  held DTR and RTS false, transmitted zero bytes, and received 180 bytes with
  consecutive firmware heartbeats `4675..4678`, providing application-level
  recovery evidence.
- The structured result, protocol log, UART log/JSONL, and acceptance summary
  are retained under
  `target/hardware-acceptance/2026-08-24-openocd-register-snapshot`. The result
  and stderr SHA-256 values are respectively
  `e5ccc72bcad6ea8025b5f5028add5e3bb82569a4434b77e16c1a04b00637b5a8` and
  `b2d758f16a0320ee6fe6ff57a5836426708a621376c0a47e0ddaba99841f9334`;
  the acceptance-summary SHA-256 is
  `feda510347a093d2e5e22aaa5897fafae2cfd8cd11c81df47f48baf0a668962b`.

This accepts one exact running-origin selected-register snapshot on ESP32-S3
CPU0, including runtime name resolution, ordered hexadecimal values, bounded
fallback restoration, process cleanup, and observable firmware recovery. It
does not accept CPU1 restoration, a halted-origin path, symbols or ELF loading,
memory/stack access, breakpoints/watchpoints, general execution control, flash,
arbitrary MI/Tcl/monitor commands, or digest binding of runtime adapter identity
and dynamically selected port numbers.

## Confirmed OpenOCD bounded-memory snapshot acceptance (2026-08-25)

- The user independently confirmed exact digest
  `40f185c3cdb99927a323a2955a7a6026e12cf07a46514c8e8b55aac667fc0c31`.
  It bound `esp32s3.cpu0`, exact request `0x42000000 + 32`, the declared NVM
  region `0x42000000 + 0x02000000`, complete-coverage parsing, the fixed
  five-command GDB/MI protocol, all deadlines, and exact OpenOCD, GDB, Xtensa
  profile, and top-level board-configuration identities. Region semantics were
  explicitly user-confirmed and not independently verified from OpenOCD's
  runtime memory map.
- Immediately before execution, `baud list`, Windows PnP, and probe-rs all
  identified the same accessible native USB-JTAG device as
  `303A:1001 / E0:72:A1:D4:1F:DC`, with its serial interface on COM3. A
  five-second 115200-baud monitor held DTR/RTS false, transmitted zero bytes,
  and received 199 bytes with consecutive baseline heartbeats `294..298`.
  A final host-only plan recomputation still produced the confirmed digest.
- The confirmed physical command ran exactly once, with no automatic retry. It
  started OpenOCD on dynamic loopback Tcl/GDB ports 4813/4814 and proved
  readiness in 354 ms. OpenOCD reported the exact runtime adapter serial,
  examined CPU0, and verified selected CPU0 initially `running`; CPU1
  examination again failed with `OCD_ID=00000000`.
- GDB completed the required result sequence
  `done / connected / done / done / exit`. The concrete read completed in 26 ms
  and returned one structured block covering exactly `[0x42000000,
  0x42000020)`: `e905024038863740ee0000000900000000630000000000012000003c2c2f0000`.
  Complete coverage was true, and SHA-256 was
  `6e5c379f5b716afd7e4915e5881f62d44034c8b6ece90d8490df9f25cc6ce5af`,
  exactly matching the previously accepted probe-rs snapshot at the same
  address and length.
- Normal detach completed but left CPU0 observed `halted`. The one fixed resume
  fallback then proved final `esp32s3.cpu0=running` in 4 ms. GDB exited 0
  gracefully in 17 ms and OpenOCD exited 0 gracefully in 59 ms; neither process
  tree was force-killed. No related process or connection on ports 4813/4814
  remained, and post-run serial/probe enumeration preserved the exact identity
  with `accessible=true`.
- OpenOCD attach handlers emitted CPU0 debug-controller/core reset messages,
  halted the target, and probed flash mappings before the explicit read. The
  wrapper issued no explicit reset, flash, memory-write, symbol, breakpoint,
  monitor, or arbitrary command. CPU1's final state was not observed, so it
  remains outside the accepted scope.
- The immediate zero-transmit UART monitor received 167 bytes and clean
  heartbeats `389..391` after two partial boundary records. A delayed monitor
  then received 201 bytes with clean consecutive heartbeats `530..534`, proving
  observable application recovery while preserving the disclosed non-atomic
  external-I/O boundary.
- Plans, the structured result, protocol log, serial/probe inventories, three
  UART captures, and `memory-acceptance-summary.json` are retained under
  `target/hardware-acceptance/2026-08-24-openocd-memory-snapshot`. The result
  and stderr SHA-256 values are respectively
  `1354d32fb5586055364f8015a34497a69acbb201364ac01954791609942f13b1` and
  `552b4ec1e188a9151b9c23e19050825b78b73806764859462788ba3d89e9cbe0`;
  the acceptance-summary SHA-256 is
  `cdc28b2eb4d445addfa64fc7da656e60fb11164ece00ea281664c5d2d905dfc5`.

This accepts one exact running-origin, bounded OpenOCD memory snapshot on
ESP32-S3 CPU0, including complete byte coverage, fixed-protocol cleanup,
fallback restoration, resource release, and observable firmware recovery. It
does not independently prove the declared NVM mapping, qualify CPU1 or another
address/range, accept a halted-origin path, or authorize memory writes,
symbols/ELF, register/stack commands, breakpoints/watchpoints, general execution
control, flash, arbitrary MI/Tcl/monitor commands, runtime-adapter digest
binding, or dynamic-port binding.

## Confirmed OpenOCD bounded-stack snapshot acceptance (2026-08-27)

- The user independently confirmed exact digest
  `f03172e03098e8da27210b5b4d97a53fa6178884c84d09d8f7557ebc13cbf5ae`.
  It bound `esp32s3.cpu0`, `--max-frames 8`, inclusive range `0..7`, fixed
  `-stack-list-frames --no-frame-filters 0 7`, the five-command GDB/MI
  protocol, all deadlines, strict result policy, and exact OpenOCD, GDB,
  Xtensa-profile, and top-level board-configuration identities. It did not bind
  runtime adapter identity, dynamic ports, or implicit unwinder read addresses.
- Immediately before execution, `baud list`, Windows PnP, and probe-rs all
  identified the same accessible native USB-JTAG device as
  `303A:1001 / E0:72:A1:D4:1F:DC`, with its serial interface on COM3. A
  five-second 115200-baud monitor held DTR/RTS false, transmitted zero bytes,
  and received 200 bytes with consecutive baseline heartbeats `442..446`. A
  final host-only plan recomputation still produced the confirmed digest.
- The confirmed physical command ran exactly once, with no automatic retry. It
  started OpenOCD on dynamic loopback Tcl/GDB ports 6794/6795 and proved
  readiness in 307 ms. OpenOCD reported the exact runtime adapter serial,
  examined CPU0, and verified selected CPU0 initially `running`; CPU1
  examination again failed with `OCD_ID=00000000`.
- GDB completed the required result sequence
  `done / connected / done / done / exit`. The concrete stack request completed
  in 5 ms and returned two contiguous frames: level 0 at `0x420129FF` and level
  1 at `0x40378695`, both `arch=xtensa` and `func=??`. The 8-frame limit was not
  reached and GDB reported no additional frame within this request, but physical
  call-stack completeness remains explicitly unproven. No ELF/symbol identity,
  frame filter, argument, local, or value request was used.
- Normal detach completed but left CPU0 observed `halted`. The one fixed resume
  fallback then proved final `esp32s3.cpu0=running` in 5 ms. GDB exited 0
  gracefully in 7 ms and OpenOCD exited 0 gracefully in 32 ms; neither process
  tree was force-killed. The initially observed Windows `TIME_WAIT` sockets
  expired, leaving zero related processes and zero connections on ports
  6794/6795. Post-run serial/PnP/probe enumeration preserved the exact identity
  with `accessible=true`.
- OpenOCD attach handlers emitted CPU0 debug-controller/core reset messages,
  halted the target, probed flash mappings, and exchanged a memory map before
  the explicit stack command. GDB unwinding may have implicitly read registers
  and target memory at addresses derived from live state; those addresses were
  not bound or independently audited. The wrapper issued no explicit reset,
  flash, memory/register, symbol, breakpoint, monitor, or arbitrary command.
  CPU1's final state was not observed and remains outside the accepted scope.
- The immediate zero-transmit UART monitor received 199 bytes with clean
  consecutive heartbeats `520..524`. A delayed monitor received 201 bytes with
  clean consecutive heartbeats `677..681`, proving observable application
  recovery. All captures used 115200 baud, DTR/RTS false, and zero transmitted
  bytes.
- The final plan, structured result, complete protocol log, serial/PnP/probe
  inventories, three UART captures, cleanup evidence, and
  `stack-acceptance-summary.json` are retained under
  `target/hardware-acceptance/2026-08-27-openocd-stack-snapshot`. The result and
  stderr SHA-256 values are respectively
  `4384db32f68102c315f43982f6f6de9e079d98e7314579c1a65262c0019f96bc`
  and `62cb1525196a1aed06c00b677c2e5a063152c65d72d3688615279b1cbd0a0cd8`;
  the acceptance-summary SHA-256 is
  `451cdb3a2ca3afa217b9d8a08d9251739179e8c82b33d219f3cadf5339dd7f42`.

This accepts one exact running-origin, bounded OpenOCD stack snapshot on
ESP32-S3 CPU0, including two GDB-reported frames, fixed-protocol cleanup,
fallback restoration, resource release, and observable firmware recovery. It
does not prove a complete physical call stack, bound or validate implicit
unwinder memory addresses, verify symbols or firmware identity, qualify CPU1 or
another target/frame limit/tool plan, accept a halted-origin path, or authorize
argument/local/value inspection, explicit register/memory commands,
breakpoints/watchpoints, general execution control, flash, or arbitrary
MI/Tcl/monitor commands.

## Confirmed OpenOCD offline ELF stack-annotation acceptance (2026-08-29)

- The user independently confirmed the exact outer digest
  `661893f5aec8dd7f9f5a5196b54ae15807218c6fe9e1eb4c120a5ae88ee23b6c`.
  Its inner bounded-stack digest remained
  `f03172e03098e8da27210b5b4d97a53fa6178884c84d09d8f7557ebc13cbf5ae`.
  The plan bound `esp32s3.cpu0`, `--max-frames 8`, the fixed five-command
  protocol, exact tools/profile/configuration, and the 2,221,600-byte Xtensa
  heartbeat ELF with SHA-256
  `676a89d78556f07500fcbe50a17c046c27d9d6e1e425ed9732c6f257a09f7b20`.
  It explicitly did not bind current target firmware identity, runtime adapter
  identity, dynamic ports, or implicit unwind-read addresses.
- Immediately before execution, all five bound file hashes still matched and
  no related process was running. `baud list`, Windows PnP, and probe-rs found
  only the same accessible `303A:1001 / E0:72:A1:D4:1F:DC` ESP USB-JTAG/serial
  device on COM3. A five-second 115200-baud monitor held DTR/RTS false,
  transmitted zero bytes, and received 199 bytes with consecutive heartbeats
  `256..260`.
- The confirmed command ran exactly once, with no automatic retry. OpenOCD used
  dynamic loopback Tcl/GDB ports 11988/11989 and proved readiness in 227 ms.
  It logged the exact adapter serial, examined CPU0, and observed selected CPU0
  initially running. CPU1 examination again failed with
  `OCD_ID=00000000` and remains unqualified.
- GDB completed `done / connected / done / done / exit`. The exact bounded
  stack request completed in 4 ms and returned level 0 `0x420129FF` plus level
  1 `0x40378695`; neither GDB frame carried a usable function name. Offline
  lookup kept level 0 exact and resolved it to eight innermost-to-outermost
  DWARF annotations, beginning with `core::ptr::read_volatile::<u32>` and ending
  with `<esp_hal::time::Instant>::elapsed`. It set
  `inline_annotations_truncated=true`, proving the configured resource limit
  was enforced. Level 1 was adjusted to `0x40378694`, was inside a loadable
  segment, and remained structured `unresolved` with no external-debug request
  or parser error. The report therefore recorded one resolved and one
  unresolved frame, as permitted by the confirmed policy.
- GDB never received the ELF path or loaded symbols. Annotation used only the
  already hashed in-memory ELF after target restoration and managed-process
  cleanup; it loaded no source content, GNU debug link, alternate/split debug
  data, or network resource. `runtime_firmware_identity_verified=false` and
  `physical_call_stack_completeness_proven=false` remained explicit. Historical
  flash evidence for the same ELF hash does not prove the target was unchanged
  at this run.
- Detach left CPU0 observed halted. The single fixed resume fallback proved
  final `esp32s3.cpu0=running` in 3 ms. GDB exited 0 gracefully in 5 ms and
  OpenOCD exited 0 gracefully in 12 ms; neither process tree was force-killed.
  No related process or listener remained. Seven unowned kernel `TIME_WAIT`
  entries were visible, and independent bind-and-close checks proved both exact
  dynamic ports immediately reusable.
- OpenOCD attach handlers again emitted CPU0 debug-controller/core reset
  messages, halted the target, initialized flash-mapping helpers, and exchanged
  a memory map. The wrapper issued no explicit reset, flash, memory/register,
  breakpoint, monitor, symbol-loading, or arbitrary command. CPU1 final state
  was not observed.
- The post-run zero-transmit UART monitor held DTR/RTS false and received 174
  bytes. One boundary fragment preceded complete consecutive heartbeats
  `374..377`, proving observable application recovery. Serial/PnP identity was
  unchanged and probe-rs still reported the exact EspJtag probe accessible.
- Plans, comparison, structured test output, complete stderr protocol log,
  serial/PnP/probe inventories, raw UART JSONL, cleanup evidence, and
  `annotated-stack-acceptance-summary.json` are retained under
  `target/hardware-acceptance/2026-08-28-openocd-annotated-stack`. The test and
  stderr SHA-256 values are respectively
  `ac9f53478fae4a618a34b7011e3174e39ac15167ea20cf39f64c58b18fa81e05`
  and `55267f73cee8dab3dd980b688b5d8b00f87941e0500c9b20a1178d2c449f1757`;
  the acceptance-summary SHA-256 is
  `a4b18cd711ba0a08ed49b1e10c600f9b52edd680dae526b9aa2dd04f93f59ab2`.

This accepts one exact running-origin ESP32-S3 CPU0 bounded snapshot followed
by partial in-process offline annotation, fixed restoration/cleanup, immediate
port reuse, and observable UART recovery. It does not accept runtime ELF
identity, resolution of every frame, a complete physical call stack, bounded
implicit unwind reads, source/external debug loading, CPU1, another ELF/target/
limit/tool plan, or any broader debugging capability.

### Host-only resolver refinement before the second physical acceptance

After this acceptance, read-only ELF inspection proved that `Reset` is a
zero-sized `STT_FUNC` at `0x40378638` in executable section `.rwtext`; the next
distinct same-section text symbol, `save_context`, starts at `0x40378698`.
Project-internal host-only resolution now labels adjusted caller `0x40378694`
as `inferred_symbol_table`, returns `Reset`, and reports the inferred half-open
range `[0x40378638, 0x40378698)` with declared size zero and inferred size 96.
The inline limit was also raised so the same top address returns all 12 DWARF
annotations without truncation.

The new policy permits only nonempty same-executable-section ranges ending at
the next distinct text symbol or section end, caps inferred spans at 64 KiB,
prefers explicit-sized symbols, and binds that policy into a new outer digest.
At this checkpoint these were host-only parser results. Digest
`661893f5...23b6c` remained the exact historical acceptance above but was stale
for the revised policy; no physical acceptance was inherited from it.

## Confirmed bounded zero-sized-symbol annotation acceptance (2026-08-29)

- The user independently confirmed exact outer digest
  `b85c65e2d3777f3730edf28c8d0fbf9cf2be782ac7121f1b429c638c2aeb4ed2`.
  The base stack digest remained
  `f03172e03098e8da27210b5b4d97a53fa6178884c84d09d8f7557ebc13cbf5ae`.
  The plan bound `esp32s3.cpu0`, `--max-frames 8`, the unchanged fixed
  five-command GDB protocol, exact tools/profile/configuration, and the same
  2,221,600-byte ELF with SHA-256
  `676a89d78556f07500fcbe50a17c046c27d9d6e1e425ed9732c6f257a09f7b20`.
- Immediately before execution, commit
  `28ba1a8fcfdb3e11ca0e43471219cfdcd2ae92da` had a clean worktree and all six
  checked binary/configuration/ELF hashes matched. `baud 0.1.0`, Windows PnP,
  and probe-rs found only COM3 and accessible EspJtag identity
  `303A:1001 / E0:72:A1:D4:1F:DC`. No related process was running. The
  zero-transmit 115200-baud baseline kept DTR/RTS false, received 205 bytes,
  and contained consecutive heartbeats `3192..3196`.
- The confirmed physical command ran exactly once and exited 0; no automatic
  retry occurred. OpenOCD became ready in 108 ms on dynamic loopback Tcl/GDB
  ports 14947/14949, logged the exact adapter serial, examined CPU0, and proved
  selected CPU0 initially running. CPU1 examination again failed with
  `OCD_ID=00000000` and remains unqualified.
- GDB completed the fixed result classes
  `done / connected / done / done / exit`. It returned exactly two frames:
  level zero `0x420129E4` and level one `0x40378695`; neither GDB frame supplied
  a usable function name and the frame limit was not reached.
- Offline lookup retained exact top address `0x420129E4` and returned 12 DWARF
  annotations, beginning with `core::ptr::read_volatile::<u32>` and ending with
  `main`. `inline_annotations_truncated=false`. It adjusted the caller to
  `0x40378694` and returned `resolution=inferred_symbol_table`, function
  `Reset`, section index 1, range `[0x40378638, 0x40378698)`, declared size 0,
  inferred size 96, and `size_inferred=true`. Both frames were inside loadable
  segments; neither requested external debug data, reported a lookup error, or
  rejected metadata. The report recorded 2 resolved / 0 unresolved frames.
- Detach left CPU0 observed halted. The one fixed resume fallback proved final
  `esp32s3.cpu0=running` in 4 ms. GDB exited 0 gracefully in 16 ms and OpenOCD
  exited 0 gracefully in 39 ms; neither process tree was force-killed and both
  cleanup reports were complete. OpenOCD attach handlers still emitted reset,
  flash-mapping, and memory-map behavior, while the wrapper issued no explicit
  reset, flash, register/memory, breakpoint, monitor, symbol-loading, or
  arbitrary command.
- The post-run zero-transmit UART monitor kept DTR/RTS false, received 190
  bytes, observed one boundary fragment, then complete consecutive heartbeats
  `3305..3308`. Serial/PnP identity was unchanged and probe-rs still found the
  exact EspJtag. No related process remained. Seven unowned `TIME_WAIT` rows
  were visible, and independent bind-and-close checks proved both exact dynamic
  ports reusable.
- Evidence is retained under
  `target/hardware-acceptance/2026-08-29-openocd-annotated-stack-v2`. The test
  JSON SHA-256 is
  `22cc005ab560741c734cc157db5f3f7641639fe4d84543a5be0679acbf2c1f51`,
  complete stderr SHA-256 is
  `5b6eaf42808874e96274468e40969615e5f2e1c13ef17f5a91a6f407e7708d4e`,
  and acceptance-summary SHA-256 is
  `f0c98c4b9dd802a25b94c6345d54376f9a3b9e5f14cf56fa315d18b9115d92a7`.

This accepts the current bounded zero-sized-symbol annotation policy only for
the exact digest, ELF, CPU0, frame limit, tools, profile, and configuration
above. `runtime_firmware_identity_verified=false`,
`runtime_firmware_identity_bound=false`, physical call-stack completeness
false, and implicit unwind-address binding false remain mandatory. CPU1,
another target/ELF/limit/tool plan, external/source debug loading, and every
broader debugging capability remain unaccepted. This evidence is not standing
authorization for a later physical execution.

## Host-only OpenOCD temporary hardware-breakpoint checkpoint (2026-08-29)

- `openocd breakpoint plan/test` is implemented for one exact nonzero numeric
  address and a fixed hardware-only insert/delete/empty-table roundtrip.
- Controlled tests cover official GDB/MI insertion and breakpoint-table shapes,
  unsafe result rejection, deterministic address-bound planning, stale digest
  rejection before Tcl execution, successful two-process cleanup, and malformed
  insertion cleanup without an additional OpenOCD Tcl resume.
- The empty GDB table is explicitly not treated as independent physical
  comparator readback. Runtime adapter identity, comparator capacity, and
  physical comparator cleanup remain unbound or unverified. Failure cleanup
  detach/exit may resume the target even though no extra Tcl resume is sent.
- No OpenOCD server was launched against physical hardware for this checkpoint,
  no breakpoint was installed on the attached ESP32-S3, and no physical target
  acceptance is claimed. Board attachment and all historical confirmations are
  not standing authorization. Any physical qualification requires a fresh
  host-only plan, independent exact-digest confirmation, one non-retried run,
  cleanup review, and external liveness checks.

## OpenOCD temporary hardware-breakpoint physical acceptance (2026-08-29)

- The user independently returned exact digest
  `f388b4e39504cd18387d6d1367ea12019d17e05796785b703e7c4fc6731a8802`.
  The confirmed physical command then ran exactly once against
  `esp32s3.cpu0` at `0x420129E4`, exited 0, and was not retried.
- Before execution, baud, Windows PnP, and probe-rs agreed on COM3 and the
  accessible EspJtag identity `303A:1001 / E0:72:A1:D4:1F:DC`. The
  zero-transmit 115200-baud baseline kept DTR/RTS false and returned complete
  consecutive heartbeats `49440..49444`.
- OpenOCD became ready in 217 ms on dynamic loopback Tcl/GDB ports 13769/13770.
  It logged the same adapter serial, examined CPU0, and proved the selected
  target initially running. CPU1 examination again failed with
  `OCD_ID=00000000` and remains unqualified. Confirmed attach handlers also
  probed flash mappings and halted CPU0; those effects remain part of R2.
- GDB returned the fixed result classes
  `done / connected / done / done / done / done / exit`. It installed exactly
  breakpoint 1 as enabled `hw breakpoint`, `disp=keep`, address `0x420129E4`,
  and hit count 0 in 13 ms. Delete returned `done` in 12 ms. The subsequent
  table contained exactly the canonical six columns, zero rows, and an empty
  body. No continue or breakpoint-hit execution was requested.
- Detach left CPU0 observed halted. Because the successful delete and empty
  GDB table were proven, the one fixed resume fallback was allowed and proved
  final `esp32s3.cpu0=running` in 4 ms. GDB and OpenOCD exited 0 gracefully in
  7/12 ms; neither process tree was force-killed and both cleanup reports were
  complete.
- The first post-run monitor retained 96 bytes of fragmented boundary output,
  including counter fragment `49508`; the next monitor returned complete
  heartbeats `49539..49540` with residual fragments. A final eight-second
  zero-transmit stability monitor returned eight complete consecutive
  heartbeats `49574..49581`. Every monitor kept DTR/RTS false. Serial, PnP, and
  probe enumeration identities were unchanged and the probe remained
  accessible.
- No related OpenOCD or GDB process remained, neither dynamic port had a TCP
  row, and independent bind-and-close checks proved ports 13769 and 13770
  reusable. Evidence is retained under
  `target/hardware-acceptance/2026-08-29-openocd-hardware-breakpoint`. The test
  JSON SHA-256 is
  `55c7f0a714c5c0028acc0efb29417577499c1cb6c3b85266737c13b82acf8c42`,
  complete stderr SHA-256 is
  `fc6a924a51ae5aede86ad1174afa44ce44ebadd8a4fc4d5df014bdb4c16b9996`,
  and acceptance-summary SHA-256 is
  `0d098b848a80bebe0d66ea20a9eaf41c6b8e59bafbca7331b186d42da4407cff`.

This accepts only the exact temporary hardware-breakpoint insert/delete/table
roundtrip above. The empty GDB table is still not an independent physical
comparator readback; runtime adapter identity, comparator capacity, and
physical comparator cleanup remain unbound or independently unverified. CPU1,
persistent/software/symbolic/conditional breakpoints, breakpoint-hit
execution, watchpoints, and broader GDB control remain unqualified. This
evidence is not standing authorization for another physical execution.

## Host-only OpenOCD temporary hardware-watchpoint checkpoint (2026-08-29)

- `openocd watchpoint plan/test` is implemented for one exact naturally
  aligned numeric RAM range. It accepts only 1/2/4/8-byte `read` and `access`
  modes, mapped to hardware-only GDB `rwatch` and `awatch`; write-only
  watchpoints are excluded because GDB may silently use software stepping.
- The fixed successful MI protocol has nine commands: GDB version, remote
  connection, C language selection, watchpoint insertion, strict one-row
  breakpoint-table classification, deletion, strict empty-table proof,
  detach, and exit. It never continues the target or waits for a hit while the
  watchpoint is installed. Expression evaluation may read the declared RAM.
  The empty table is protocol evidence only and does not independently prove
  physical comparator allocation or cleanup.
- Strict parsing accepts only exact `hw-rwpt`/`read watchpoint` or
  `hw-awpt`/`acc watchpoint` shapes for number 1, enabled, keep, hit count 0,
  and the exact expression. Software/write/pending/conditional/multi-location
  or otherwise expanded records are rejected. Failure cleanup is bounded and
  never adds a Tcl resume after a GDB failure, although GDB detach/exit and
  OpenOCD handlers may still resume the target.
- The implementation commit is
  `06a96d03d0bc5133e03d8d1991a02287b78b429a`; its rebuilt Windows binary is
  32,252,416 bytes with SHA-256
  `237c7a118576f8055ac11846c2e5c7b13276d654ef1be6c07e63ac8ca4ae33e3`.
  Gates passed with 214 library tests, 78 CLI tests, rustfmt, strict Clippy,
  `rustdoc -D warnings`, a 68-file Cargo package, the official Skill validator,
  and `git diff --check`.
- Two host-only plans bind `esp32s3.cpu0`, access mode, address `0x3FCDB550`,
  length 4, and declared RAM `[0x3FC88000, 0x3FCF0000)`. The exact expression
  is `*((char*)0x3fcdb550)@4`; the address lies in the previously accepted
  non-alias `SRAM1 Data bus` range. Both plans produced confirmation digest
  `3a502b8a88fa5778f9bbbb11cd92c7d4ebc5cf160858bb2035a634e038e20db8`.
  After removing random operation IDs and tool-version elapsed times, their
  JSON is identical; both stderr files are empty.
- The same committed binary regenerated the already accepted temporary
  hardware-breakpoint plan with unchanged digest
  `f388b4e39504cd18387d6d1367ea12019d17e05796785b703e7c4fc6731a8802`
  and unchanged insertion command `3-break-insert -h *0x420129e4`.
- Evidence is retained under
  `target/host-validation/2026-08-29-openocd-hardware-watchpoint`. Plan SHA-256
  values are respectively
  `613f330d8d4a59d65cc6ac4b4ba77aaa92258625fe0668a40c71a1202711d61c`
  and `cbaadbdd2106cad6df9f0d41e9fedde289c9b517b09fb5268ec9472ef1b86784`;
  `host-validation-summary.json` is 3,461 bytes with SHA-256
  `f214adf7b7dc4c125ffaabb4076abc1c1bf3dda44806ae12172a3cf990c5530c`.
- No OpenOCD server was started, no GDB remote connection was requested, no
  USB/JTAG access occurred, no physical watchpoint was inserted, no retry ran,
  and no related process remained. Hardware width/capacity, target RAM
  semantics, runtime adapter identity, hit behavior, physical comparator
  allocation, and physical cleanup are therefore still unqualified.

The next physical step is permitted only after the user independently returns
the exact new digest above. It is limited to one non-retried ESP32-S3 CPU0
`openocd watchpoint test`, followed by process/port cleanup review and external
UART/probe liveness checks. Historical confirmations and the connected board
are not standing authorization.

## OpenOCD temporary hardware-watchpoint physical acceptance (2026-08-29)

- The user independently returned exact digest
  `3a502b8a88fa5778f9bbbb11cd92c7d4ebc5cf160858bb2035a634e038e20db8`.
  Exactly one ESP32-S3 CPU0 `openocd watchpoint test` then ran for access mode
  over `0x3FCDB550 + 4`, exited 0, and was not retried. Immediately before the
  run, commit `af62d0edadf7e22365089f46eabea42399a4705c` had a clean worktree,
  the committed binary and four bound tool/config/profile hashes matched, and
  a fresh host-only plan reproduced the confirmed digest and fixed nine-command
  protocol.
- `baud 0.1.0`, Windows PnP, and probe-rs agreed before execution on COM3 and
  the accessible EspJtag identity `303A:1001 / E0:72:A1:D4:1F:DC`. The
  five-second 115200-baud baseline held DTR/RTS false, transmitted zero bytes,
  received 209 monitored bytes, and contained consecutive heartbeats
  `54867..54871`.
- OpenOCD became ready in 101 ms on dynamic loopback Tcl/GDB ports 4377/4378,
  logged the same adapter serial, examined CPU0, and proved the selected target
  initially running. CPU1 examination again failed with
  `OCD_ID=00000000` and remains unqualified. Attach handlers also halted CPU0,
  queried reset cause, initialized flash-mapping helpers, and exchanged a
  memory map; the wrapper issued no explicit reset, flash, general memory,
  register, symbol, monitor, continue, or arbitrary command.
- GDB returned the exact result classes
  `done / connected / done / done / done / done / done / done / exit`. In 5 ms
  insertion returned only `hw-awpt={number="1",exp="*((char*)0x3fcdb550)@4"}`.
  The following list contained exactly one canonical six-column row: number 1,
  `acc watchpoint`, `keep`, enabled, exact expression/original location, thread
  group `i1`, and hit count 0. Deletion returned `done` in 14 ms; the next list
  returned exactly zero rows, six canonical columns, and an empty body. The
  target was never intentionally continued while the watchpoint existed and no
  hit was requested.
- Detach left CPU0 observed halted. Because exact hardware classification,
  deletion, and the empty GDB table were all proven, the one fixed resume
  fallback was allowed and proved final `esp32s3.cpu0=running` in 3 ms. GDB and
  OpenOCD exited 0 gracefully in 20/12 ms; neither process tree was force-killed
  and both cleanup reports were complete.
- The first post-run zero-transmit monitor retained a boundary fragment, then
  returned complete consecutive heartbeats `54967..54970`. The final eight-
  second stability monitor returned eight complete consecutive heartbeats
  `54991..54998`. Both kept DTR/RTS false. Serial, PnP, and probe identities
  were unchanged and the probe remained accessible.
- No related process remained. Seven unowned `TIME_WAIT` rows were visible,
  and independent bind-and-close checks proved both exact dynamic ports
  reusable. The 21-check machine audit had zero failures. Evidence is retained
  under `target/hardware-acceptance/2026-08-29-openocd-hardware-watchpoint`;
  all 46 listed artifacts were rehashed with no missing, extra, size-mismatched,
  or hash-mismatched file. The test JSON SHA-256 is
  `831ab41a445e074b5be951262b7085d0b981093eeb719e3a44fec630ebc0d4ec`,
  complete stderr SHA-256 is
  `ead86f033552bbf6d1c33aa309bba142e39143e401b6fdb23b794a111e354be3`,
  audit SHA-256 is
  `4879d706b103605afcd8cc2815af0de93ec90ca6052c6dd594f4b5e2debb7b31`,
  and acceptance-summary SHA-256 is
  `d3c78dd7bcd8f1765b60f4776a21234671b5a6d951029897709095ca99a1e9be`.
- After evidence and documentation synchronization, gates passed again with
  214 library tests, 78 CLI tests, rustfmt, strict Clippy,
  `rustdoc -D warnings`, a 68-file Cargo package (1.8 MiB / 355.2 KiB
  compressed), the official Skill validator, artifact-manifest revalidation,
  and `git diff --check`. None of these gates started OpenOCD, opened COM3, or
  accessed USB/JTAG; the physical watchpoint test count remained exactly one.

This accepts only the exact access-mode GDB hardware-classification,
delete/empty-table, restoration, and cleanup roundtrip above. GDB may defer
physical comparator allocation until execution resumes, which this test did
not request; neither allocation nor physical cleanup was independently read
back. Runtime adapter identity, declared RAM semantics, target width/capacity,
`read` mode, hit execution, CPU1, persistent/write-only/symbolic/conditional
watchpoints, another range/target/tool plan, and broader GDB control remain
unqualified. This evidence is not standing authorization for another physical
execution.
