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

Partially run on 2026-08-13 with probe-rs 0.32.0 on Windows:

- nRF52840: J-Link `1366:1061:001050282192`, detected target
  `nRF52840_xxAA`, silicon `NRF52840_xxAA_REV2`. Product-level `probes test`
  completed attach and disconnect. The single-core guarded workflow reports all
  required flash, verify, reset, halt/run, register-read, and memory-read
  capabilities.
- ESP32-S3: native USB-JTAG `303a:1001:E0:72:A1:D4:1F:DC`, detected target
  `esp32s3`. Product-level `probes test` completed attach and disconnect. Flash
  and verify are discoverable, while reset/halt/run/register/memory operations
  remain conservatively unavailable because the current workflow does not yet
  define a safe multi-core post-flash snapshot.
- Serial baseline at 115200 baud with DTR and RTS held false: nRF `COM16`
  emitted seven `Z` bytes in three seconds; nRF `COM15` and ESP32-S3 `COM3`
  were silent. No bytes were transmitted.
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

The nRF single-page guarded write, read-back verification, post-reset snapshot,
page preservation, evidence inspection, backup comparison, and observable
runtime checks passed. The first 4096-byte Flash page was physically erased and
reprogrammed, but its final byte content is identical to the write-before
baseline. The cross-sector and unplugged-probe cases remain pending.
