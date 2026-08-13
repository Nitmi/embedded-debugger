# Public contract v1

## Result envelope

Successful commands return one JSON object on stdout when `--json` is set:

```json
{
  "schema_version": "1.0",
  "ok": true,
  "operation": "flash.plan",
  "operation_id": "op_<uuid>",
  "data": {},
  "warnings": [],
  "artifacts": []
}
```

Runtime failures use the same outer identity and a stable error code:

```json
{
  "schema_version": "1.0",
  "ok": false,
  "operation": "flash.execute",
  "operation_id": "op_<uuid>",
  "error": {
    "code": "CONFIRMATION_MISMATCH",
    "message": "flash confirmation digest does not match the current plan",
    "retryable": false,
    "details": {},
    "suggested_actions": []
  }
}
```

Diagnostic logs belong on stderr. A command never mixes a human preamble into
JSON stdout.

`doctor` reports capabilities compiled into this binary separately from
optional external executables. Native probe-rs discovery and guarded flashing
do not require the standalone `probe-rs` CLI to be installed.

`probes test --probe <exact-selector> --target <exact-target>` is an
`R1_REVERSIBLE_CONTROL` operation. It opens the selected probe, attaches to the
target, and disconnects without requesting erase, program, reset, halt,
snapshot, or arbitrary user memory access. Backend attach sequences may still
access volatile target control state as disclosed by `effects`. A successful
result contains the session identity, conservative capability matrix, ordered
`session.attach` and `session.disconnect` records, and `complete=true`.

`snapshot capture --probe <exact-selector> --target <exact-target>` is an
`R1_REVERSIBLE_CONTROL` one-shot observation. It attaches to the exact target,
records the original state of every enabled core, halts cores that were
running, reads PC/SP/LR, restores only those cores that were originally
running, and disconnects. Disabled cores remain in the ordered core inventory
with `available=false` and an `unavailable_reason`; at least one core must be
available. The response distinguishes `original_state`, `captured_state`, and
the final restored `state`. It does not request reset, erase, program, arbitrary
memory write, or a persistent debug session.

R1 debug control is not equivalent to side-effect-free target inspection. Both
`probes test` and `snapshot capture` return an `effects` object. It records
whether the command requested reset, Flash, or arbitrary memory writes; whether
core execution-state restoration was verified; and any known backend-managed
volatile target changes. probe-rs clears hardware breakpoints during attach and
may invoke target-specific attach/halt sequences. The ESP32-S3 sequence disables
several watchdogs. Agents must surface these notes instead of treating R1 as
R0 read-only behavior.

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | Success |
| 2 | Safety guard denied the operation |
| 3 | Verification or assertion failed |
| 4 | Probe or target unavailable |
| 5 | Timeout |
| 6 | Backend protocol failure |
| 7 | Configuration, fixture, or input error |
| 8 | OS or transport permission denied |
| 10 | Internal invariant or I/O failure |

## Addresses and bytes

Addresses are JSON strings such as `"0x08000000"`, avoiding precision loss in
JavaScript clients. Firmware and artifact content is identified with lowercase
SHA-256 hex strings. Large binary content will be returned as bounded artifact
references rather than unbounded inline data.

The current contract accepts raw `.bin` firmware. A probe-rs plan requires an
explicit `--base-address`; Replay takes its address and erase impact from the
fixture. A plan exposes:

- `firmware.base_address`: the first byte to program.
- `ranges`: exact bytes supplied by the image.
- `erase_ranges`: complete sectors affected by programming.
- `policy`: erase mode, preservation, verification, and post-flash behavior.
- `confirm_digest`: SHA-256 over backend, probe, target, firmware, both range
  sets, and policy.

The probe-rs workflow limits raw BIN data to readable boot NVM. It does not
grant the probe-rs full-chip erase permission. `preserve_unwritten_bytes=true`
means bytes in an affected sector but outside `ranges` are read and restored.
Mutation plans also require a non-empty probe hardware serial number; a VID/PID
selector alone is not accepted as stable device identity.

## Snapshot and evidence semantics

`core.captured_state` is the state while PC/SP/registers were read. `core.state`
is the state after capture is complete. The guarded flash workflow normally
reports `captured_state="halted"` and `state="running"`.

For live multi-core observations, each `cores[]` entry also has a stable target
core `index`, target-defined `name`, `architecture`, and `original_state`.
Disabled cores omit `original_state` and `snapshot`; they are not silently
dropped. A complete live capture means state restoration and session disconnect
both succeeded. Live captures are returned in the result envelope but are not
yet published as standalone evidence artifacts.

Evidence is reserved before opening hardware and published without overwriting
an existing path. `complete=true` means program, verify, reset, snapshot,
resume, and session disconnect all completed. New evidence includes the plan
identity, confirmation digest, write/erase ranges, policy, flash report, and
ordered operations.

ELF and HEX segment parsing are not yet part of this contract.

## Compatibility

Readers must reject unsupported major schema versions. New optional fields may
be added within the `1.x` line. Existing field meaning, error code meaning, and
risk classification cannot change within the major version.
