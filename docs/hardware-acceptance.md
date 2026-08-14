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

Partially run on 2026-08-13 and 2026-08-14 with probe-rs 0.32.0 on Windows:

- nRF52840: J-Link `1366:1061:001050282192`, detected target
  `nRF52840_xxAA`, silicon `NRF52840_xxAA_REV2`. Product-level `probes test`
  completed attach and disconnect. The single-core guarded workflow reports all
  required flash, verify, reset, halt/run, register-read, and memory-read
  capabilities.
- ESP32-S3: native USB-JTAG `303a:1001:E0:72:A1:D4:1F:DC`, detected target
  `esp32s3`. Product-level `probes test` completed attach and disconnect.
  Before reset acceptance, state-preserving `snapshot capture` completed
  repeatedly with `cpu0` as `running -> halted -> running` and `cpu1` explicitly
  unavailable. A standalone probe-rs system reset then completed successfully.
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
- A subsequent independent live snapshot proved the states survived disconnect:
  `cpu0` entered as running and returned to running at `PC=0x420969FE`,
  `SP=0x3FCDB5D0`, `LR=0x4203DAF8`; `cpu1` entered halted and returned halted at
  `PC=0x400003C0`. This accepts native ESP32-S3 `reset` and
  `multi_core_post_flash`. It does not claim all volatile target state is
  unchanged: probe-rs clears hardware breakpoints on attach, and its ESP32-S3
  sequence disables the super, timer-group 0/1, and RTC watchdogs. Structured
  `effects` reports these R1 side effects.
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
- Product-level `registers read` passed on ESP32-S3 `cpu0`. An explicit
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
  R1 effect explicitly. This accepts native ESP32-S3 register reads on `cpu0`.
- Product-level `memory read` passed on ESP32-S3 `cpu0`. With a deliberately
  invalid probe selector, `0x3FF00000 + 16` (Generic/MMIO) and
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
  accepts bounded native ESP32-S3 RAM/NVM reads on `cpu0`; it does not accept
  Generic/MMIO reads, writes, unbounded output, or atomic capture against the
  still-running secondary core and DMA.
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
USB-JTAG fixture. Bounded state-preserving register and RAM/NVM reads on CPU0
also passed with pre-attach safety rejection and post-read heartbeat recovery.
