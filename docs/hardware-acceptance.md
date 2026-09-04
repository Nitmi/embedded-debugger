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

## nRF52840 DK sparse Intel HEX physical execution (2026-09-04)

- The fixture moved from an external custom board to the official DK's onboard
  nRF52840. The exact J-Link selector is `1366:1061:001050275757`. Initial
  software enumeration proved only USB probe visibility; the final run used the
  DK after external SWD wiring was removed, the normal onboard-target jumper
  configuration was restored, and the board was power-cycled.
- A 120-byte acceptance HEX with SHA-256
  `3653e6dc49764e0897f9e59111dba0f0435caf6ef4892701451de7663e04be2f`
  normalizes to two 16-byte code-Flash segments at `0x00000000` and
  `0x00001000`. It contains no UICR, SoftDevice, bootloader, or business-data
  segment and affects exactly the first two 4096-byte erase pages.
- The prior release produced plan `plan_7417167073e68c15` and digest
  `7417167073e68c15778a1062c33001b852455306d042b9644ff5a0ce67a1dc1c`,
  but exact-confirmation execution was rejected before attach by the original
  combined Intel HEX and segmented-image gates. No evidence file was created.
- The candidate implementation now separates Intel HEX execution, segmented
  programming, and non-boot NVM mutation. `nRF52840_xxAA` may proceed to a
  separately confirmed code-Flash-only acceptance plan, while every UICR plan
  remains blocked by `NON_BOOT_NVM_EXECUTION_ACCEPTANCE_REQUIRED` before attach.
- Controlled Replay coverage proves the two-segment code-Flash path can plan,
  program, independently verify both segments, reset, capture, restore, and
  publish evidence while `non_boot_nvm_flash=false`. A separate UICR regression
  proves that the non-boot gate remains closed.
- The release candidate is 17,693,696 bytes with SHA-256
  `a9cef79a5ca7e8bac86be7a681e837df26444a6b2d228401828df78d99d4741e`.
  A read-only native plan selected the exact J-Link and canonical target,
  returned `execution.supported=true`, and produced plan
  `plan_1db582c27aa6875c` with confirmation digest
  `1db582c27aa6875ca1ca2b5f19028e80240283bf2c0085778bef6f2090946089`.
  Its exact write ranges are `0x00000000 + 16` and `0x00001000 + 16`; the
  merged affected erase range is `0x00000000 + 8192`. This planning step only
  enumerated the probe and did not attach, erase, program, reset, or create
  execution evidence.
- The separately authorized, non-retried execution used that exact release,
  firmware, selector, target, and digest. It failed during `session.attach` with
  exit code 6, operation ID `op_e060effafa4d404bb128c72708b192e7`, and
  `PROTOCOL_ERROR: probe-rs failed to attach target` whose underlying message
  was `An ARM specific error occurred.` The service had not called its program
  operation, so no planned sector erase, firmware write, verification, or
  post-flash reset was performed and no evidence bundle was published.
- A post-failure read-only enumeration still found J-Link
  `1366:1061:001050275757` accessible. This proves USB probe visibility only;
  target routing, target power/reference voltage, SWD continuity, protection
  state, and onboard-device identity remained unresolved at that point. The
  failure was not retried.
- SEGGER-backed `nrfjprog 10.24.2` with J-Link DLL 9.24a enumerated serial
  `1050275757`. A separately authorized one-shot `deviceversion` request then
  reported `Access protection is enabled, can't read device version.` This
  independently explained the probe-rs attach rejection without attributing it
  to the sparse image or treating a process exit code as device acceptance.
- The user explicitly authorized one destructive `nrfjprog --recover` for that
  exact probe and accepted loss of user code and UICR. The command erased both
  areas, wrote the access-protection-disable image, returned exit code 0, and was
  not followed by an automatic flash. A fresh one-shot `deviceversion` then
  identified `NRF52840_xxAA_REV3` at 1000 kHz, proving the onboard target was
  accessible after recovery.
- A post-recovery native `probes test` passed attach and disconnect on exact
  selector `1366:1061:001050275757` and target `nRF52840_xxAA`. Operation
  `op_15a78a7040fb44c3ad302d221b69d4f6` completed without a requested flash,
  reset, execution continue, or memory read. Its effects still disclose that
  probe-rs attach can modify volatile target control and breakpoint state.
- A fresh read-only plan, operation `op_60bd913730b748f19ca19884b8bc6b0a`,
  reproduced `plan_1db582c27aa6875c` and confirmation digest
  `1db582c27aa6875ca1ca2b5f19028e80240283bf2c0085778bef6f2090946089`
  because every digest-bound input remained identical. The earlier authorization
  was not reused; the user supplied a new exact confirmation for one execution.
- The separately confirmed physical execution passed under operation
  `op_e04dbc9824524e50b3b836ab15ba777f` and session
  `ses_3f1a7c5bf48543568ddd1e80f8841ac1`. It erased the affected 8192-byte range,
  programmed 32 bytes across both sparse segments, independently verified both
  segment hashes, performed the planned reset/halt/snapshot/resume sequence, and
  disconnected cleanly. Evidence is 3,704 bytes with SHA-256
  `f115ebda93363c59da06e007d28c3735ec7d05bb8039cd851f7828b1ad15a84a`
  under
  `target/hardware-acceptance/2026-09-04-nrf52840-dk-sparse-hex/flash-evidence-after-recover.jsonl`.
- The snapshot reported `captured_state="halted"`, `state="running"`,
  `halt_reason="exception"`, `pc=0x00000008`, `sp=0x20040000`, and
  `lr=0xFFFFFFFF`. This qualifies the exact nRF52840 code-Flash-only sparse HEX
  execution and evidence path, but it does not claim a normally booted
  application. Because recovery erased the target before this run and there was
  no independent pre/post full-page comparison, preservation of pre-existing
  unwritten bytes also remains outside this exact acceptance. UICR execution
  remains blocked by `NON_BOOT_NVM_EXECUTION_ACCEPTANCE_REQUIRED`.

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

## Host-only OpenOCD bounded hardware-watchpoint-hit checkpoint (2026-08-30)

- Independent `openocd watchpoint hit plan/test` support is implemented in
  commit `909dd0ece8f084eb8e93d112c6e4081081d98e7e`. It keeps the existing
  classification-only command and digest unchanged, but adds asynchronous MI,
  all-stop mode, exactly one continue, strict watchpoint-stop attribution, a
  post-hit count of one, deletion/empty-table proof, and bounded failure
  interruption. No automatic retry is permitted.
- The fixed success protocol has 13 commands. Token 8 is exactly
  `-exec-continue --all`; success requires its `^running` result plus one
  token-correlated `access-watchpoint-trigger`/`hw-awpt` stop, the exact
  expression and value shape, a top-frame PC in the confirmed half-open
  interval, and a canonical post-hit row with `times=1`. The fixed failure
  cleanup is token 19 interrupt, token 20 delete, token 21 empty-table proof,
  token 22 detach, then bounded token 13 exit. A GDB failure never adds an
  OpenOCD Tcl resume.
- Gates passed with 223 library tests, 80 CLI tests, rustfmt, strict Clippy,
  `rustdoc -D warnings`, a 70-file Cargo package, the official Skill validator,
  and `git diff --check`. The committed Windows debug binary is 32,585,216
  bytes with SHA-256
  `e2d5e7dda271e45d80d1d881f750e16a332e5d4b116e782ab452cc8e4a50b025`.
- Two host-only plans bind `esp32s3.cpu0`, access mode, exact range
  `0x3FCDB550 + 4`, declared RAM `[0x3FC88000, 0x3FCF0000)`, expected PC
  `[0x420128C5, 0x420128D0)`, and a 10000 ms hit timeout. Both produced exact
  confirmation digest
  `8c6e2c0384da4aed8f495601ce61dc3d1bace8eaf537df3eca94b4803ea828fb`.
  Removing only random operation IDs and elapsed-time fields makes the two
  complete JSON plans identical; both stderr files are empty.
- The same committed binary regenerated the prior classification-only plan
  with unchanged digest
  `3a502b8a88fa5778f9bbbb11cd92c7d4ebc5cf160858bb2035a634e038e20db8`,
  nine commands, and no target execution request. This proves the old command
  surface did not inherit the hit behavior.
- The expected PC interval comes from local firmware ELF SHA-256
  `676a89d78556f07500fcbe50a17c046c27d9d6e1e425ed9732c6f257a09f7b20`.
  Fresh disassembly records `l32i/addi/s32i/s32i` at `0x420128C5`,
  `0x420128C8`, `0x420128CA`, and `0x420128CD`. This is provenance only:
  `runtime_firmware_identity_bound=false` and
  `runtime_firmware_identity_verified=false`. The tool does not prove that
  this ELF is currently running on the target.
- Evidence is retained under
  `target/host-validation/2026-08-30-openocd-hardware-watchpoint-hit`.
  Plan SHA-256 values are
  `d501856b727c31dc5f83063e2f86687df7cbe77fa52386df816fd123b32215e8`
  and
  `32164dea851844a54d831381e9da648af4184dddac82c66d7728256c0ca16b04`.
  The 4,926-byte machine summary has SHA-256
  `2be7381b81edad6166f7a6c4c2fba3983471aa793c12c5709d14d7d645eba89a`;
  all eight artifacts it lists were rehashed with zero size or digest
  mismatches.
- These plans ran only bounded executable-version probes and file hashing. No
  OpenOCD server started, no remote GDB connection was requested, no USB/JTAG
  or serial access occurred, no physical watchpoint was installed, no target
  continue was sent, no retry ran, and no exact related process remained.
  Runtime adapter identity, RAM semantics, physical comparator state, and the
  runtime firmware identity therefore remain unbound or unverified.

## Non-accepted OpenOCD hardware-watchpoint-hit attempt (2026-08-30)

- The user independently returned exact digest
  `8c6e2c0384da4aed8f495601ce61dc3d1bace8eaf537df3eca94b4803ea828fb`.
  A fresh plan matched it, all 19 machine preflight checks passed, and exactly
  one ESP32-S3 CPU0 physical command ran. It exited 5 with non-retryable
  `TIMEOUT`; no automatic or manual retry ran. This is failure evidence, not a
  physical acceptance.
- GDB inserted and classified the exact access watchpoint as number 1 with
  `times=0`, accepted exactly one `8-exec-continue --all`, and reported no hit
  during the 10000 ms bound. The timeout cleanup sent exactly one interrupt.
  Espressif GDB 17.1 returned `19^done` followed by a tokenless asynchronous
  SIGINT stop at `0x420129E4`, while the implementation expected stop token 8
  and therefore conservatively marked cleanup incomplete.
- The remainder of cleanup still completed: token 20 deleted watchpoint 1,
  token 21 proved a zero-row GDB table, token 22 detached, token 13 exited GDB,
  and both GDB and OpenOCD shut down gracefully with exit code 0. No related
  process remained and dynamic ports 1170 and 1171 were immediately
  rebindable. Physical comparator cleanup was not independently read back.
- The failure path deliberately sent no Tcl resume. OpenOCD's final
  point-in-time observation was `esp32s3.cpu0` halted at `0x420129E4`.
  A zero-transmit UART check with DTR and RTS disabled received 0 bytes after a
  pre-run baseline of 215 bytes and five consecutive heartbeats. Serial, PnP,
  and probe identities remained unchanged and the probe remained accessible.
  These observations are consistent with CPU0 still being halted; recovery was
  not attempted because it requires separate authority.
- Host-only provenance review found the primary planning error. The earlier
  register snapshot established `a1=0x3FCDB550`; it did not establish that
  `0x3FCDB550` held `heartbeat`. A preliminary disassembly-only review treated
  `a1 + 128` as the loop-local value, but a later concrete DWARF audit corrected
  that interpretation: `heartbeat` is `DW_OP_fbreg: 160` with frame base `a1`,
  while `a1 + 128` is a compiler temporary. Even the resulting historical
  arithmetic value `0x3FCDB5F0` is not runtime-bound or verified because the
  `a1` snapshot came from another PC and date. The timed-out run therefore does
  not demonstrate a comparator or target defect.
- The run also invalidated the synthetic fixture assumption that a GDB/MI
  asynchronous stop will carry the continue token. Before another physical
  attempt, hit and cleanup correlation must accept a tokenless stop only in the
  state with the single continue outstanding, while still allowing the matching
  token if one is present. It must retain strict reason/tuple/PC or
  post-interrupt SIGINT checks, reject competing stops and nonmatching tokens,
  and receive host-only regression coverage. That change will produce a new
  confirmation digest.
- Evidence is retained under
  `target/hardware-acceptance/2026-08-30-openocd-hardware-watchpoint-hit`.
  The 26-check post-run audit is 2,832 bytes with SHA-256
  `05c2952c2fa445d29dee31c3b789b1fbb7fe06e278e36af66e8d7f021b671eb4`.
  The non-acceptance summary is 5,945 bytes with SHA-256
  `d25f1c026967fcb9fe1d8628707e52a792cf6630823978c4ba64bc32f3d39445`;
  all 11 artifacts it lists were rehashed with no size or digest drift.

The confirmed one-run authority is spent. Any target recovery or power-state
change requires separate authorization. Any later watchpoint-hit execution also
requires the host fixes above, two identical new plans, and fresh exact
confirmation of their new digest; the connected board and this historical
digest are not standing authorization.

## Rejected CPU0 recovery command and resume-only host checkpoint (2026-08-30)

- The user separately authorized restoring CPU0 to running only, with no
  watchpoint installation and no retry. Preflight identified the same exact
  `303A:1001:E0:72:A1:D4:1F:DC` EspJtag and COM3, found no related process, and
  captured a five-second zero-transmit UART baseline with DTR and RTS disabled.
  The baseline contained 0 bytes, consistent with but not continuously proving
  that CPU0 remained halted.
- Exactly one command invocation requested native probe-rs `core run` for
  target `esp32s3`, core 0. It returned non-retryable
  `CAPABILITY_UNAVAILABLE` for missing `post_disconnect_core_state`. The
  service evaluates that capability before probe listing, selector resolution,
  attach, or core control, so probe selection, target attach, and `core.run`
  were not attempted and no target mutation occurred. Automatic retry count
  remained 0. A second five-second zero-transmit UART check also contained 0
  bytes, and no related process remained. The requested running outcome was not
  reached; CPU0 therefore remains likely halted.
- Recovery evidence remains alongside the failed watchpoint-hit evidence under
  `target/hardware-acceptance/2026-08-30-openocd-hardware-watchpoint-hit`.
  `recovery-authorization.json` is 853 bytes with SHA-256
  `4143c6907d55395231ad662f1fe374bfce8384ceb995450ff04917068f317fd7`.
  The structured 363-byte rejection has SHA-256
  `ff7c0f732508ca6da4f8a173e409475cfe4b5652a3ba21dbc9853cbcce87de36`.
  The 2,919-byte recovery-attempt summary has SHA-256
  `c7656c0cf71274ec3dc9fdf699d2a70d0ac6c04408a6485e900588a237c92b09`;
  all seven artifacts registered by that summary rehashed without drift.
- Commit `f5f88b6775a21143a348f6f91d9ef9c794369cc3` adds the independent
  `openocd resume plan/test` contract. It accepts only the exact selected target
  in `halted` or `running`; a halted origin can receive one fixed catch-wrapped
  resume, while a running origin receives no control command. Final running is
  mandatory. Halt, reset, flash, target-data, GDB/monitor,
  breakpoint/watchpoint, arbitrary Tcl, second resume, and automatic retry are
  excluded. OpenOCD configuration remains executable Tcl, runtime adapter
  identity and transitive sources remain unbound, and resumed firmware may
  perform arbitrary I/O.
- The feature checkpoint passed 231 library tests, 83 CLI tests, rustfmt,
  strict Clippy, `rustdoc -D warnings`, a 72-file Cargo package, the official
  Skill validator, and `git diff --check`. Its committed Windows debug binary
  is 32,706,048 bytes with SHA-256
  `30f56d641968f9fc58b243dd66174912e01dd79bf0a3fc7b682f2d24969cb3cd`.
- Two post-commit host-only plans bind `esp32s3.cpu0`, the same OpenOCD and
  top-level board configuration identities, 2000/10000/3000 ms managed-server
  deadlines, a 5000 ms target-state deadline, `halted|running -> running`, one
  maximum resume, and zero retries. Both produced exact digest
  `b7759dc2aa7b60a6e9e71b7c075d6c70ef84b7b9e4536c97ad0d305419b8224f`.
  Removing only random operation IDs and OpenOCD version-probe elapsed time
  makes the complete plans byte-identical, with normalized SHA-256
  `037a08a8ac184b078c9ae736cbcaa4e8822949c852ddc0dd073089ce36c373c2`.
  Both stderr files are empty.
- Host evidence is retained under
  `target/host-validation/2026-08-30-openocd-resume-only-recovery`. Plan SHA-256
  values are
  `24ed74e3e7e7b5cc3c6d342d8573db8a5f2a0372fca54c4ce083d4ef2e558928`
  and
  `9263b8beaae90f1e6f4ab11329dee414486f6e47e13133051ab1164575cdbb48`.
  The 4,710-byte host-validation summary has SHA-256
  `01c685033d79a2a1e3c9abcfc230115eb8b98966821e00db7e0c8d4a79e8543f`;
  all seven local artifacts and six referenced recovery artifacts rehashed with
  zero missing, size, or digest mismatches.
- The two plans ran only bounded executable-version probes and file hashing.
  They did not start an OpenOCD server, select a probe, attach to a target, send
  resume, open serial, install a watchpoint, reset, or perform a physical test;
  the final related-process count was 0. The prior natural-language authority
  was consumed by the one rejected command invocation and is not reused. One
  non-retried physical `openocd resume test` now requires the user to return the
  new exact digest independently.

## OpenOCD resume-only running-origin acceptance (2026-08-30)

- The user independently returned exact digest
  `b7759dc2aa7b60a6e9e71b7c075d6c70ef84b7b9e4536c97ad0d305419b8224f`.
  A fresh post-confirmation plan matched it and all 35 machine preflight checks
  passed. Exactly one physical `openocd resume test` then ran against
  `esp32s3.cpu0`; it exited 0 with `ok=true` and `complete=true`. Automatic and
  manual retry counts remained 0, and no watchpoint, halt, reset, flash,
  target-data, GDB/monitor, or arbitrary Tcl command was requested.
- After OpenOCD readiness, the first selected-target observation was already
  `running`. The confirmed idempotent policy therefore skipped its conditional
  resume: `resume=null`, `resume_command_count=0`, and the same observation was
  retained as the final `running` proof. This accepts the physical
  running-origin idempotent path and requested CPU0 running-state outcome. It
  does not physically qualify the `halted -> running` resume command path, and
  the evidence cannot determine whether CPU0 was already running before
  OpenOCD configuration executed or configuration-side effects changed it.
- OpenOCD recorded the exact adapter serial
  `E0:72:A1:D4:1F:DC`, found both JTAG taps, and successfully examined CPU0.
  CPU1 again returned `OCD_ID=00000000` and failed examination, so it remains
  unqualified. Dynamic Tcl/GDB ports were 13011/13012. Shutdown completed in 11
  ms with exit code 0, no forced process-tree kill, complete stdout/stderr
  drains, and complete process-tree cleanup.
- Independent cleanup checks found zero related OpenOCD, GDB,
  embedded-debugger, or baud processes. Three connection rows were unowned
  cleanup records; both 13011 and 13012 passed an immediate independent bind
  test. COM3, all three PnP nodes, and the exact accessible EspJtag identity
  were unchanged after the run.
- Firmware-level liveness was not recovered or proven. The five-second
  pre-run and eight-second post-run UART monitors both used 115200 baud,
  DTR/RTS false, and zero transmission; each received 0 bytes. Therefore this
  checkpoint does not accept heartbeat recovery, firmware operational
  liveness, watchpoint comparator cleanup, or any external-system behavior,
  despite the point-in-time CPU0 `running` state proof.
- Evidence is retained under
  `target/hardware-acceptance/2026-08-30-openocd-resume-only-recovery`.
  The test JSON is 9,960 bytes with SHA-256
  `5c4383a49a4e1de247013a77cc3e64bd3f1a9195d7f7cf2df21180750964133c`;
  complete stderr is 1,890 bytes with SHA-256
  `b208ec413015c04b574efa0022a93014ee887b6c1bb177a4d74c59bbb6b8f814`.
  The 35-check preflight SHA-256 is
  `f72aea4f1cc0c31b670977448eda305378d9367dcbd444b441558992bd8ecf8d`;
  the 37-check post-run audit SHA-256 is
  `ff3aa2be847cb3cb268de9855b17c07a887e8e4463d7cea59ca3ef1cd80522f7`.
  The 8,474-byte acceptance summary has SHA-256
  `82e88ba991cbb36cd0eae7d5263166c229bdb8626d595649e2ac9ae60d7e0bcc`;
  all 34 registered artifacts rehashed with no missing, extra, size, or digest
  mismatch.

This one-run authority is spent. Any further target control requires a new
plan and fresh authorization. Host-only work may continue on the watchpoint-hit
protocol and address derivation, but this checkpoint is not authority for
another recovery or hit attempt.

## Host-only watchpoint-hit protocol and address amendment (2026-08-31)

- Commit `59171b1ef814737608cb6e6343177fc890376663` contains the
  protocol, fixture, public evidence, Skill, and address-boundary changes. Full
  gates passed with 233 library tests, 83 CLI tests, rustfmt, strict Clippy,
  `rustdoc -D warnings`, a 72-file package, the official Skill validator, and
  `git diff --check`. Its Windows debug binary is 32,726,016 bytes with SHA-256
  `b944962aaa07d3405397b62bed49b2a904fb330038404b79daba766d4b70879b`.
- The GDB/MI hit lifecycle now accepts the asynchronous stop as tokenless, or
  with exact continue token 8 when a token is present, only inside the one fixed
  continue operation. Reports preserve both `observed_stop_token` and
  `stop_correlation`. Nonmatching tokens and competing stops fail closed.
- Timeout cleanup still sends at most one token-19 interrupt and never retries.
  It now accepts a tokenless-or-token-8 stop only when the event is exactly
  `reason="signal-received"` and `signal-name="SIGINT"`, then continues the
  existing delete, empty-table verification, detach, and bounded exit steps.
  This matches the non-accepted physical run without weakening stop identity.
- Controlled success and timeout fixtures now emit tokenless asynchronous
  records like Espressif GDB 17.1. Direct regressions retain matching-token
  compatibility and reject nonmatching tokens, competing stops, wrong signals,
  and non-all-stop scope. No target-facing command was run for this amendment.
- A fresh static audit used the unchanged 2,221,600-byte demo ELF SHA-256
  `676a89d78556f07500fcbe50a17c046c27d9d6e1e425ed9732c6f257a09f7b20`.
  Its concrete `heartbeat` variable DIE points to `DW_OP_fbreg: 160`; the
  concrete `main` frame base is `DW_OP_reg1 (a1)`. Source/line/disassembly
  evidence maps the assignment to `0x420128CD`, which stores the incremented
  value at `a1 + 160`. The `a1 + 128` load/store is a compiler temporary.
- The only recorded `a1=0x3FCDB550` value is from the separately confirmed
  2026-08-24 snapshot at PC `0x42012A0D`. It is historical point-in-time
  evidence, not the frame base for a later run. Adding 160 yields only the
  historical arithmetic candidate `0x3FCDB5F0`; it must not be used as a
  current watch address. The local ELF is also not attested as the image now
  running on the target.
- Two post-commit host-only `openocd registers plan` runs request only ordered
  `pc,a1` from `esp32s3.cpu0`. Both returned exact confirmation digest
  `a817ed1453fb2ff0e4f23d83ba07bf02c7d0fdeccba37c13913cbc939d188ba0`;
  after removing only `operation_id` and `elapsed_ms`, the complete plans are
  identical with normalized SHA-256
  `20c1179bc7823cefafa029177639d9ffa9db1a9203cc8baa75874628e96e1818`.
  The six-command R2 plan does not bind adapter, ELF, symbols, or firmware
  identity. It is a next current-frame evidence step, not watchpoint authority.
- Plan evidence is retained under
  `target/host-validation/2026-08-31-openocd-current-frame-registers`.
  Plan SHA-256 values are
  `8c3497364a6c67789204e6546317868a449bfac4309b4834e47eb719d1b43162`
  and
  `bd4f0738459ba3382dffc60882df056f013ead53a1b92cb7d2401d480930c39f`;
  both stderr files are empty. The 2,297-byte address provenance SHA-256 is
  `4749730c5bdfa40bccd42bf3d02188d8de402de34f2085f106d9bd73e56a6007`.
  The 4,041-byte machine summary SHA-256 is
  `f61e571c6a442daabe95f47659809fe1b9d94ab72c233b18967818e81f2709f4`;
  all five registered artifacts rehashed without size or digest drift.
- The paired plans ran only bounded executable-version probes and file hashing.
  They started no OpenOCD server or remote GDB connection, opened no USB/JTAG
  or serial device, changed no target state, installed no watchpoint, and left
  zero related processes. One physical register snapshot requires the user to
  return the new exact digest independently; it will not be run automatically.
- Consequently, this checkpoint deliberately produces no physical
  watchpoint-hit authorization. A later run needs separately reviewed current
  runtime frame evidence, adequate firmware-identity provenance, two identical
  post-commit plans, and a fresh exact digest. The connected board and every
  historical digest remain insufficient authority.

## Confirmed OpenOCD current-frame register snapshot acceptance (2026-08-31)

- The user independently returned exact digest
  `a817ed1453fb2ff0e4f23d83ba07bf02c7d0fdeccba37c13913cbc939d188ba0`.
  A fresh post-confirmation plan matched it exactly. Preflight found a clean
  worktree at `8818f3093d910d39c81be9c7ef6eef0fd9f6f43a`, the unchanged
  32,726,016-byte binary SHA-256
  `b944962aaa07d3405397b62bed49b2a904fb330038404b79daba766d4b70879b`,
  and no related process. Serial, PnP, and probe-rs independently resolved the
  one accessible EspJtag as `303a:1001:E0:72:A1:D4:1F:DC` on `COM3`.
- One and only one `openocd registers test` invocation requested ordered
  `pc,a1` from `esp32s3.cpu0`; no automatic or manual retry ran. The fixed
  six-command exchange enumerated 270 registers and returned
  `pc=0x420129e4` as register 0 and `a1=0x3fcdb550` as register 213. No ELF,
  symbols, explicit memory read, breakpoint/watchpoint, flash, reset, monitor
  command, arbitrary MI/Tcl, or CPU1 operation was requested.
- CPU0 was `running` before GDB attached. After successful detach it was still
  observed `halted`, so the confirmed fixed Tcl fallback sent one resume and
  proved `esp32s3.cpu0=running` 3 ms later. GDB and OpenOCD both exited
  gracefully with code 0, their managed process trees were completely cleaned,
  and dynamic Tcl/GDB ports 1950/1951 were immediately rebindable.
- OpenOCD selected and successfully examined CPU0, but CPU1 examination again
  failed with `OCD_ID=00000000`; CPU1 remains unaccepted. Attach handlers also
  queried flash mappings, as disclosed by the R2 plan, despite no explicit
  flash command. Transitive configuration semantics and runtime adapter
  identity remain outside the digest boundary.
- Against the unchanged local 2,221,600-byte ELF SHA-256
  `676a89d78556f07500fcbe50a17c046c27d9d6e1e425ed9732c6f257a09f7b20`,
  the point-in-time PC lies inside `main`'s half-open
  `[0x42010aa4,0x42012dbb)` range and resolves through inlined delay code to
  `src/bin/main.rs:87`. Combining the current `a1` with the audited
  `DW_OP_fbreg: 160` relation yields arithmetic candidate `0x3fcdb5f0`.
  This is current-frame evidence conditional on that local ELF; the operation
  did not attest the runtime image or read the candidate address. It therefore
  does not verify a watchpoint address or authorize a watchpoint-hit run.
- A five-second pre-monitor and eight-second post-monitor used baud 0.1.0 at
  115200 with DTR/RTS false and zero transmitted bytes. The pre-monitor was
  silent. The post-monitor received eight complete consecutive heartbeats
  `152480..152487` with the expected green/blue/red cycle, plus one 13-byte
  partial prefix, proving observable firmware liveness after restoration.
  Serial and probe identities remained unchanged and accessible, and no
  related process remained.
- Evidence is retained under
  `target/hardware-acceptance/2026-08-31-openocd-current-frame-registers`.
  The 21,505-byte structured result SHA-256 is
  `960620cc35062c31f27eafef6d8415ed9e53676d8bc01204cc6121e22b47bfa8`.
  The 6,649-byte acceptance summary SHA-256 is
  `2c40a5bd1ddbd58ecd3263a47114d6a8e7ea1ee2ca77bffb9d3da1d2c410d242`.
  The 3,080-byte environment audit SHA-256 is
  `daee08da11664cc59e6c719f81081a1baf7de61761395eee7ea9319369a41ebc`.
  Its 4,404-byte manifest SHA-256 is
  `35d9444cae3ab0c8696a31e21d632b6c5b91ef779ccab3a1170b59d529d71afa`;
  all 26 registered artifacts rehashed without size or digest drift.

This accepts only the exact point-in-time `pc,a1` selection and cleanup for the
confirmed CPU0/tool/profile/configuration plan. The one-run authority is spent.
Any memory read, firmware attestation, watchpoint installation or hit, retry,
or other target control requires its own reviewed plan and fresh authority.

## Confirmed OpenOCD ESP app runtime identity acceptance (2026-09-02)

- The user independently returned exact outer digest
  `2491f5efdc10dbf5b2a6b607d040880e1aa4be014766b9d4c81a3f31d1bcda98`
  after two identical host-only plans from commit
  `515f7f5cab32bf5416661bbac21ace8ae4951ca5`. Both plans bound
  `esp32s3.cpu0`, the exact OpenOCD/GDB/profile/configuration identities, the
  2,221,600-byte ELF SHA-256
  `676a89d78556f07500fcbe50a17c046c27d9d6e1e425ed9732c6f257a09f7b20`,
  `.flash.appdesc` at `0x3c000020 + 256`, its complete expected bytes, and the
  declared `0x3c000000 + 0x10000` NVM region. The nested memory digest was
  `5ef9add3edcea6bc9fbf839122d9dd3f9eff94c9740d31808bd022983f4de287`.
- Preflight found exactly one accessible EspJtag probe,
  `303a:1001:E0:72:A1:D4:1F:DC`, and exactly one matching serial port, COM3.
  No related OpenOCD or GDB process was running. A five-second 115200-baud
  baseline monitor used DTR/RTS false and transmitted no bytes; it received 236
  bytes containing complete heartbeats 97 through 102.
- One and only one `openocd esp-app-identity test` invocation ran; no automatic
  or manual retry occurred. Operation
  `op_5b97179e2ddd4d29afbbf5b9b785acaa` sent the fixed memory command
  `3-data-read-memory-bytes 0x3c000020 256` and received one block with complete
  coverage. It sent no memory write, symbol load, breakpoint/watchpoint, flash,
  reset, monitor, arbitrary MI/Tcl, or CPU1 command.
- The complete target descriptor exactly matched expected SHA-256
  `65d77b4a7a7507112ab899dc7d08167dba8ea19d3afb6cfa1c555fb5cc5d5621`.
  The descriptor parsed as magic `0xABCD5432`, project
  `yd-esp32-s3-rust-demo`, version `0.1.0`, build date `2026-08-12`, build time
  `05:38:59`, IDF version `0.0.0`, and embedded ELF SHA-256
  `676a89d78556f07500fcbe50a17c046c27d9d6e1e425ed9732c6f257a09f7b20`.
  Exact expected bytes, source bytes outside the hash slot, and the embedded ELF
  hash all matched, so `runtime_firmware_identity_verified=true`.
- CPU0 was initially running. GDB attachment left it halted, so the fixed
  fallback requested one resume and proved final `esp32s3.cpu0=running`. GDB
  detached and exited gracefully, OpenOCD shut down gracefully, both managed
  process trees were completely cleaned, and dynamic Tcl/GDB ports 8461/8462
  passed independent bind checks. No related process remained and the exact
  probe/COM3 identities were unchanged and accessible.
- OpenOCD observed the exact adapter serial `E0:72:A1:D4:1F:DC`, successfully
  examined CPU0, and failed CPU1 examination with `OCD_ID=00000000`; CPU1 is
  excluded. Runtime adapter identity was observed but was not part of the
  confirmation digest. Attach handlers also performed the disclosed flash-map
  discovery despite no explicit flash command.
- The runtime map identified FLASH at `0x3c000000 + 0x3000`, followed by R/W
  memory at `0x3c003000`. The exact read interval
  `[0x3c000020,0x3c000120)` is contained in the observed FLASH mapping, but the
  confirmed 64 KiB NVM declaration is wider. This acceptance does not verify
  the declaration beyond the exact read or elevate
  `target_memory_map_semantics_verified`, `cryptographic_authenticity_verified`,
  or `secure_boot_verified`; all remain false.
- A seven-second post-run UART monitor again used 115200 baud, DTR/RTS false,
  and zero transmission. It received 280 bytes containing complete consecutive
  heartbeats 249 through 255, proving observable firmware liveness after target
  restoration.
- Evidence is retained under
  `target/hardware-acceptance/2026-09-02-openocd-esp-app-identity`. The
  27,724-byte structured result SHA-256 is
  `90318b81e411bef4789bc2eaf3d4ac9a1ee12389346585a01854005d3f5da92b`;
  complete 8,017-byte stderr SHA-256 is
  `2a0d4023e133fb008fb9694b1a549c5bcaa0940d7fba2f1b04a22f054097f838`.
  Baseline UART JSONL/log SHA-256 values are
  `19de48dd26ce14d2593c9880a49a42c835d320c8b8955ced32b0ab4e4be21f6a`
  and `0589ed5b15fe931ff7b4278f29065657b46e80e159332b8df602cfbf2ded1be0`;
  post-run values are
  `576fc9fb649ed571f7c4b95185f5f8c6ae6292af92d1147452dff4700e4e987d`
  and `fb8080038b1b93d5de37da8927249561cf4c0976570ea92e39c57cc81f674cb6`.
  The 5,888-byte acceptance summary SHA-256 is
  `a4536a29e26a3785d9f74b6710671ba4a74efc797006cf289e34295a5fbdada1`.
  The 1,343-byte artifact manifest SHA-256 is
  `414ce2fde3dfcf7e2d0bdd59c4d113139842d034b42266d635464ef15a8ca056`;
  all seven registered artifacts rehashed without size or digest drift.

This accepts only the exact point-in-time descriptor read and cleanup for the
confirmed CPU0/tool/profile/configuration/ELF plan. The one-run authority is
spent. Any register or memory read, firmware re-attestation, watchpoint
installation or hit, retry, or other target control requires its own reviewed
plan and fresh authority.

## Confirmed fresh current-frame register snapshot acceptance (2026-09-02)

- Two fresh host-only plans from commit
  `bf6c2dfaf43320eaee43044a3164975d485d1b21` requested ordered `pc,a1` from
  `esp32s3.cpu0`. Both were complete, normalized identically, and returned
  digest `a817ed1453fb2ff0e4f23d83ba07bf02c7d0fdeccba37c13913cbc939d188ba0`.
  This value matched a spent 2026-08-31 digest because every confirmation input
  was unchanged. The user explicitly returned it again after reviewing this
  new pair; historical authorization was not reused.
- Preflight rehashed both plan artifacts and the 17,647,104-byte planner binary
  SHA-256
  `b90d3c4a1945254323e002bef2cf8dea35419b2bb321419e6665e6f64eff9c55`,
  found a clean worktree and no related process, and resolved exactly one
  accessible EspJtag plus COM3 to serial `E0:72:A1:D4:1F:DC`. The OpenOCD
  executable and top-level configuration identities remained unchanged. A
  five-second, zero-transmit UART baseline with DTR/RTS false received complete
  heartbeats 1655 through 1659.
- One and only one `openocd registers test` invocation ran; no automatic or
  manual retry occurred. Operation `op_2909e26f76bb4261b7c115bf2bf7da5c`
  enumerated 270 structured register names and issued
  `4-data-list-register-values --skip-unavailable x 0 213`. It returned
  `pc[0]=0x42012a6c` and `a1[213]=0x3fcdb550`. No explicit memory command, ELF
  or symbol load, breakpoint/watchpoint, flash, reset, monitor, arbitrary MI/Tcl,
  or CPU1 operation was requested.
- CPU0 was running before GDB attached. Detach returned `done`, but the target
  was then observed halted, so the fixed fallback requested one resume and
  proved final `esp32s3.cpu0=running` four milliseconds later. GDB and OpenOCD
  both shut down gracefully with exit code 0 and complete process-tree cleanup.
  Dynamic Tcl/GDB ports 4391/4392 passed immediate independent bind tests, and
  no related process remained.
- OpenOCD observed adapter serial `E0:72:A1:D4:1F:DC`, successfully examined
  CPU0, and again failed CPU1 examination with `OCD_ID=00000000`; CPU1 remains
  excluded. Attach handlers performed the disclosed flash-map discovery. The
  adapter identity and transitive configuration semantics remain outside the
  confirmation digest.
- The unchanged 2,221,600-byte local ELF SHA-256
  `676a89d78556f07500fcbe50a17c046c27d9d6e1e425ed9732c6f257a09f7b20`
  places the point-in-time PC inside audited `main` range
  `[0x42010aa4,0x42012dbb)`. Combining current `a1` with the audited
  `heartbeat` relation `DW_OP_fbreg: 160` yields arithmetic candidate
  `0x3fcdb5f0`. The earlier descriptor identity and this register snapshot are
  separate operations, so they do not prove atomic firmware continuity. This
  operation also did not read the candidate memory and therefore does not
  verify a watchpoint address or authorize a watchpoint hit.
- A seven-second post-run monitor again used 115200 baud, DTR/RTS false, and
  zero transmission. It received one leading partial boundary line followed by
  six complete consecutive heartbeats 1771 through 1776. Probe and serial
  identities remained unchanged and accessible after the run.
- Evidence is retained under
  `target/hardware-acceptance/2026-09-02-openocd-current-frame-registers`.
  The 21,506-byte structured result SHA-256 is
  `948a3cde676d1cf94f45bb36d72441fdbb82908a100b100755d4096832a9eaab`;
  complete 9,010-byte stderr SHA-256 is
  `aade5d8a4f34bb19ce906b5f3badbc7d93a19ec962e12f46216fe14ed67daadb`.
  The 5,672-byte acceptance summary SHA-256 is
  `dbf5654ff1173c61670cf4cdb30b35b54e3cb2b00e54de01b5716f8d1f103f31`.
  The 1,341-byte manifest SHA-256 is
  `8f1c065db34153bb23de74c7076ab8bcdf4410ca9cf83c86d3c4025459d60d0b`;
  all seven registered artifacts rehashed without size or digest drift.

This accepts only the exact point-in-time ordered register values and cleanup
for the confirmed CPU0/tool/profile/configuration plan. The new one-run
authority is spent. Candidate-memory access, firmware re-attestation,
watchpoint installation or hit, retry, or other target control requires its own
reviewed plan and fresh authority.

## Confirmed heartbeat candidate memory snapshot acceptance (2026-09-02)

- Two host-only plans from commit
  `34a2636d62f8a0ee0cb4cd15a1928a0eb2fbd6be` bound `esp32s3.cpu0`, exact
  address `0x3FCDB5F0 + 4`, declared RAM
  `[0x3FC88000,0x3FCF0000)`, the fixed command
  `3-data-read-memory-bytes 0x3fcdb5f0 4`, and the complete-coverage and cleanup
  policies. They normalized identically and returned digest
  `38c60e31837633806c9ff44e654e776f55d4e6b0be5aed7679201b3c61e9a8a2`,
  which the user returned exactly. The declaration was confirmation input;
  `target_memory_map_semantics_verified=false`.
- Preflight rehashed both plans and the 17,647,104-byte release binary SHA-256
  `b90d3c4a1945254323e002bef2cf8dea35419b2bb321419e6665e6f64eff9c55`,
  found a clean worktree and no related process, and resolved exactly one
  accessible EspJtag plus COM3 to serial `E0:72:A1:D4:1F:DC`. A five-second
  115200-baud baseline used DTR/RTS false and transmitted no bytes; it received
  complete consecutive heartbeats `2744..2748`.
- One and only one `openocd memory test` invocation ran; no automatic or manual
  retry occurred. Operation `op_5ceb1f49cbe14c9896b0bc7b81e8c5f6` returned
  one exact block `[0x3FCDB5F0,0x3FCDB5F4)` with complete coverage and bytes
  `ed0a0000`, SHA-256
  `b21ab1f16140ece032cd994c6ee66b6461f32b697a46c1a1a0879815b0e4b06b`.
  Interpreted as a little-endian `u32`, the value is `2797`. No memory write,
  register command, ELF or symbol load, breakpoint/watchpoint, explicit flash,
  reset, monitor, arbitrary MI/Tcl, or CPU1 command was requested.
- The audited demo source initializes `heartbeat` at `src/bin/main.rs:63`,
  increments it at line 85, logs it at line 86, and delays one second at line
  87. The memory value `2797` is strictly between the complete pre-run
  heartbeat maximum `2748` and post-run minimum `2867`. This strongly supports
  `0x3FCDB5F0` as the point-in-time runtime `heartbeat` location for this run.
  It does not make the separate ELF identity, register snapshot, memory read,
  and UART observations atomic or prove firmware continuity between them.
- CPU0 was initially running. GDB detached successfully but left it halted, so
  the fixed fallback requested one resume and proved final
  `esp32s3.cpu0=running`. GDB and OpenOCD exited gracefully with complete
  process-tree cleanup. Dynamic Tcl/GDB ports 2320/2321 passed independent bind
  checks, no related process remained, and the exact probe/COM3 identities were
  unchanged and accessible.
- OpenOCD observed adapter serial `E0:72:A1:D4:1F:DC`, successfully examined
  CPU0, and again failed CPU1 examination with `OCD_ID=00000000`; CPU1 remains
  excluded. Attach handlers performed the disclosed flash-map discovery. The
  runtime map contained the address in a read/write entry beginning at
  `0x3c003000`, but runtime adapter identity, transitive configuration semantics,
  and target RAM semantics remain outside the confirmation boundary.
- A seven-second post-run UART monitor again used 115200 baud, DTR/RTS false,
  and zero transmission. After one leading partial boundary line it received
  complete consecutive heartbeats `2867..2871`, proving observable firmware
  liveness after target restoration.
- Evidence is retained under
  `target/hardware-acceptance/2026-09-02-openocd-heartbeat-candidate-memory`.
  The 19,813-byte structured result SHA-256 is
  `ddd73ca49fc7f337234e006cd317922a8135a993c37c0c635edb6516bc22484f`;
  complete 7,391-byte stderr SHA-256 is
  `218c34d6327cbbc198f973c7ecaa14346d023c2c799879820072b11ea90eb183`.
  Baseline UART JSONL/log SHA-256 values are
  `291ef3562b76315ba4899dc777b22db9eb6f6707a21877c799112877a0decbde`
  and `d356431bff9aa41d58b2c4a92f24e71cfe8c67a068eb7a8ba3d6452ae34317bc`;
  post-run values are
  `ac52ae65beb09f7994d79b951465eeb01dd15938343e6718db5ee1c444ac8271`
  and `7cf6ffcf32103e229070ca398bdae867bfa87d9772fbb6d9919743d9b4a926bc`.
  The 4,197-byte acceptance summary SHA-256 is
  `b3e4516e4704a499c20c891f03d55e18e2692b35a9703e23360fdac5e3d013c1`.
  The 1,341-byte artifact manifest SHA-256 is
  `87864d04e998bafce8e0a163e0c06ada71251e870c56bea7fdab4b70346afef5`;
  all seven registered artifacts rehashed without size or digest drift.

This accepts only the exact point-in-time candidate bytes and cleanup for the
confirmed CPU0/tool/profile/configuration plan. The address has sufficient
operational evidence to become input to a newly reviewed watchpoint-hit plan,
but the one-run memory authority is spent. No watchpoint was installed or hit,
and any hit test, retry, or other target control requires two fresh matching
plans and a new exact authorization digest.

## Confirmed heartbeat hardware-watchpoint hit acceptance (2026-09-02)

- Two host-only plans from commit
  `acece4621ccabdae52c4d5a12be9a80e1564c16c` bound `esp32s3.cpu0`, exact
  access watchpoint `0x3FCDB5F0 + 4`, declared RAM
  `[0x3FC88000,0x3FCF0000)`, expression
  `*((char*)0x3fcdb5f0)@4`, expected PC
  `[0x420128CD,0x420128D3)`, one `8-exec-continue --all`, and a 10000 ms
  deadline. Both plans were complete and normalized identically after removing
  only operation IDs and elapsed times. They returned digest
  `29421b87617f0067d037773f4596e967989a86bb313676608a77132cda6556d0`,
  which the user returned exactly.
- Offline ELF audit used the unchanged 2,221,600-byte heartbeat ELF SHA-256
  `676a89d78556f07500fcbe50a17c046c27d9d6e1e425ed9732c6f257a09f7b20`.
  It placed the exact `s32i a8, a1, 160` store at `0x420128CD`, with the
  immediate successor at `0x420128D0` and first excluded instruction at
  `0x420128D3`. The interval semantics were confirmed input, not runtime
  attestation. Earlier exact memory evidence had read `0x3FCDB5F0` as
  little-endian heartbeat `2797`, bracketed by UART sequences.
- Final preflight rehashed every plan artifact and the 17,647,104-byte release
  binary SHA-256
  `b90d3c4a1945254323e002bef2cf8dea35419b2bb321419e6665e6f64eff9c55`,
  confirmed the exact Git head and clean worktree, and found no related process.
  Exactly one accessible EspJtag and COM3 both resolved to serial
  `E0:72:A1:D4:1F:DC`. OpenOCD and top-level board configuration identities
  matched the plan. A five-second 115200-baud baseline with DTR/RTS false and
  zero transmission received complete consecutive heartbeats `8465..8469`.
- One and only one `openocd watchpoint hit test` invocation ran; no automatic
  or manual retry occurred. Operation `op_70e9896feb994e33986113f74e67569b`
  inserted exact `hw-awpt` number 1, classified one canonical
  `acc watchpoint` row with `times=0`, and accepted exactly one token-8
  continue. Within 107 ms, OpenOCD reported target halt PC `0x420128CD`; GDB
  emitted one tokenless correlated `access-watchpoint-trigger` at frame PC
  `0x420128D0`, inside the confirmed interval, with exact expression and an
  old/new value tuple. The post-hit table reported `times=1`.
- Token 10 deleted watchpoint 1 and token 11 proved the exact canonical
  six-column table empty. Token 12 detached and token 13 exited GDB. No failure
  interrupt or retry path ran. GDB and OpenOCD both shut down gracefully with
  complete process-tree cleanup. Detach left CPU0 halted, so the fixed successful
  fallback requested one selected-target resume and proved final
  `esp32s3.cpu0=running`. Dynamic Tcl/GDB ports 6919/6920 were independently
  free afterward, no related process remained, and probe/COM3 identities stayed
  unchanged and accessible.
- OpenOCD observed adapter serial `E0:72:A1:D4:1F:DC`, successfully examined
  CPU0, and again failed CPU1 examination with `OCD_ID=00000000`; CPU1 remains
  excluded. Attach handlers performed the disclosed flash-map discovery. The
  runtime map contained the watched address in a read/write entry, but runtime
  adapter identity, transitive configuration semantics, target RAM semantics,
  and runtime firmware identity remain outside the confirmation boundary.
- A seven-second post-run UART monitor used 115200 baud, DTR/RTS false, and zero
  transmission. It retained malformed boundary fragments caused by the short
  debug interruption, then received complete consecutive heartbeats
  `8543..8545`, proving observable firmware liveness after restoration.
- Evidence is retained under
  `target/hardware-acceptance/2026-09-02-openocd-heartbeat-watchpoint-hit`.
  The 29,329-byte structured result SHA-256 is
  `060977f1678345945b68c7dc64c8c923da7312d13f80859baad49f8a7b311f3b`;
  complete 10,436-byte stderr SHA-256 is
  `6105ea416cbde09b17c64f25803a390d3d67aa25392fe92b48167520fdaf7f36`.
  Baseline UART JSONL/log SHA-256 values are
  `68759169f74b9c0bf21a200d4889d2066a800d3f9d3e7321d3ba73326e8be5d9`
  and `9e3bec89296306373f355255e74b4a003278f43d5258dd675dc4f0279e6dc929`;
  post-run values are
  `389f7165bac8a940e466299888e77f6d674385f8e65b778f8723fcc91877009d`
  and `d87ec3072fffa351b9a68e1148a79d748164602fcb8405331fd614c1cdef67a9`.
  The 4,338-byte acceptance summary SHA-256 is
  `b17dba07a5e4e614be1492cc4486807fd084250b5ad64ac1cd15d4b66ef63c1c`.
  The 1,347-byte artifact manifest SHA-256 is
  `0004c4314fe71a21b73d116ba3be4335816b535a4dbc16ea4603989db4057db5`;
  all seven registered artifacts rehashed without size or digest drift.

This accepts one exact GDB-attributed physical access-watchpoint hit, bounded
execution, deletion/empty-table proof, restoration, and cleanup for the
confirmed CPU0/tool/profile/configuration/range/PC plan. It does not independently
read physical comparator registers, prove runtime firmware identity or
continuity, verify the declared RAM semantics, qualify CPU1, or authorize
another hit, retry, address, mode, interval, or target operation. The one-run
authority is spent.

## Native nRF52840 DK joint runtime acceptance (2026-09-04)

- The official nRF52840 DK onboard target was selected through J-Link
  `1366:1061:001050275757` with target `nRF52840_xxAA`. `baud 0.1.0` selected
  exact `COM11` with USB VID/PID `1366:1061` and serial `001050275757`.
  Earlier Windows PnP evidence identified this port as `MI_00`; the native
  command itself bound the exact COM name and USB triple exposed by `baud`.
- The pre-existing confirmed flash contained the DK smoke firmware whose HEX
  SHA-256 was
  `5cf20f3632670abaa04f087cc9353a204cfff35c1798af5edd09ea2629911ad9`.
  Its runtime source-build identity was
  `b7d4f3608a63dadac5a0bae5a29276ce15771487`. The build line is source-revision
  evidence, not a self-hash or authenticity proof for the final HEX bytes.
- Release executable SHA-256
  `99326c9c10c9ee4cde263d2d730cbf4713b5ac921e425069adc818abd8bd6fc7`
  ran one `runtime accept` command. It opened COM11 at 115200 baud with
  DTR=true, RTS=false and zero transmitted bytes, then performed exactly one
  `snapshot reset-capture`. No automatic or manual retry occurred.
- Runtime assertions accepted one exact `EAT_NRF52840_DK_READY v1`, one exact
  build-identity line containing source revision
  `b7d4f3608a63dadac5a0bae5a29276ce15771487`, and 31 complete exact
  `EAT_NRF52840_DK_HEARTBEAT` lines. There was no partial tail. Both the baud
  process and structured result exited successfully.
- The reset snapshot captured the single Armv7E-M core halted at
  `PC=0x00000100`, `SP=0x20040000`, and `LR=0xFFFFFFFF`, restored its expected
  final state to `running`, and disconnected the probe. Structured effects
  reported reset=true and flash, erase, recover, non-boot NVM access, serial
  transmit, and automatic retries all false.
- Complete 8,046-byte evidence is retained under
  `target/hardware-acceptance/2026-09-04-nrf52840-dk-smoke/native-runtime-accept-2`.
  Its SHA-256 is
  `b5456b4c33a362cca2670154f56d714d44edb96fdf00983b1a2c22fd1ccaa080`.
  The baud result, empty stderr, JSONL, and text log are independently hashed in
  the report. This accepts the native command's exact probe/serial/reset/assert/
  cleanup path on this DK. It does not authorize another flash, prove the
  physical RESET button routing, or turn source revision telemetry into signed
  firmware attestation.
