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

`registers read [name...] --probe <exact-selector> --target <exact-target>
--core <index>` is an `R1_REVERSIBLE_CONTROL` one-shot observation. It validates
the zero-based core index and a maximum of 64 requested names before attach,
records the selected core's original state, halts it only when necessary, reads
the selected registers while halted, verifies restoration to the original
state, and disconnects. Names and target-defined aliases are matched
case-insensitively; two names resolving to one register are rejected. Omitting
names requests the complete backend inventory only when that inventory contains
at most 64 registers. Every reading contains a canonical name, aliases, backend
register ID, width in bits, kind, and fixed-width hexadecimal raw value. The
result distinguishes `original_state`, halted `captured_state`, and final
restored `state`. Unknown or ambiguous names use `CONFIG_INVALID` with the
available canonical names. A successful response always has at least one
reading and `effects.core_execution_state_restoration_verified=true`. Replay
requires explicit `register_cores` evidence for the selected core; it never
synthesizes register IDs or widths from a legacy PC/SP snapshot.

`snapshot reset-capture --probe <exact-selector> --target <exact-target>` is an
`R1_REVERSIBLE_CONTROL` reset-policy acceptance command. It requires reset,
halt, run, and register-read capabilities; multi-core targets additionally
require `multi_core_post_flash`. The command performs system reset-and-halt,
captures every available core while halted, restores each core to its explicit
`expected_final_state`, verifies those states, and disconnects. It reports
`effects.reset_requested=true` and never requests erase, program, or arbitrary
memory write. CPU0 is expected to run after the workflow. Secondary cores retain
the running or halted state observed immediately after the target reset sequence.

R1 debug control is not equivalent to side-effect-free target inspection.
`probes test`, `registers read`, `snapshot capture`, and
`snapshot reset-capture` return an
`effects` object. It records
whether the command requested reset, Flash, or arbitrary memory writes; whether
core execution-state restoration was verified; and any known backend-managed
volatile target changes. probe-rs clears hardware breakpoints during attach and
may invoke target-specific attach/halt sequences. The ESP32-S3 sequence disables
several watchdogs. Halting a running core can also interrupt in-flight peripheral
activity or produce partial external I/O; restoration cannot undo bytes or
physical actions already emitted. Agents must surface these notes instead of
treating R1 as R0 read-only behavior.

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

The native accepted contract currently executes raw `.bin` firmware. A
probe-rs BIN plan requires an explicit `--base-address`; Replay takes its
address and erase impact from the fixture. The target-gated ESP-IDF path
requires an explicit
`--format idf --flash-size <SIZE>` and rejects `--base-address`. An `.elf`
extension is intentionally ambiguous and is never interpreted as ESP-IDF
without that format selection.

A plan exposes:

- `firmware.base_address`: the first byte to program.
- `firmware.size`: source-file bytes, before image generation.
- `firmware.program_size`: the total number of generated bytes to program.
- `firmware.segments`: ordered physical segments with kind, address, length,
  and SHA-256.
- `firmware.image_options`: the pinned generator, target chip, declared flash
  capacity, and chip revision for a generated image.
- `ranges`: exact bytes supplied by the image.
- `erase_ranges`: complete sectors affected by programming.
- `policy`: erase mode, preservation, verification, and post-flash behavior.
- `execution`: whether the current backend can execute the complete plan, plus
  stable blockers when it cannot.
- `confirm_digest`: SHA-256 over backend, probe, target, source identity,
  generated segment manifests and hashes, image options, both range sets,
  policy, and execution readiness.

The probe-rs workflow limits raw BIN data to readable boot NVM. It does not
grant the probe-rs full-chip erase permission. `preserve_unwritten_bytes=true`
means bytes in an affected sector but outside `ranges` are read and restored.
Mutation plans also require a non-empty probe hardware serial number; a VID/PID
selector alone is not accepted as stable device identity.

ESP-IDF normalization uses the pinned espflash 4.5.0 library and emits physical
bootloader, partition-table, and application ranges. The backend validates that
all generated ranges are non-overlapping readable boot NVM and that the
declared capacity fits the target package's boot-flash window. Normalization
does not attach, reset, or write the target. Planning still enumerates probes to
bind an exact stable identity into the digest.

The shared execution layer validates every segment payload against its planned
length and SHA-256, stages all non-overlapping segments in one backend commit,
and independently verifies every segment. `flash.segments[]` reports each kind,
physical address, length, SHA-256, and verification result. The service rejects
backend reports whose aggregate bytes, source digest, segment manifest, or
aggregate verification state differ from the confirmed firmware manifest.

`capabilities.segmented_flash` and `capabilities.multi_core_post_flash` are
false by default and may be advertised only after target-specific acceptance.
The native probe-rs ESP32-S3 target has passed both acceptance gates.
A normalized plan reports
`SEGMENTED_FLASH_ACCEPTANCE_REQUIRED` when that capability is absent. Multi-core
targets report `MULTI_CORE_POST_FLASH_POLICY_UNVERIFIED` until their backend can
perform and prove reset, snapshot, state restoration, and cleanup across all
described cores.
For such a blocked plan, even the exact digest returns
`CAPABILITY_UNAVAILABLE` before target attach, evidence reservation, flash
operations, or reset. Probe enumeration has already occurred at that point and
is reported separately in the error details.

## Snapshot and evidence semantics

`core.captured_state` is the state while PC/SP/registers were read. `core.state`
is the state after capture is complete. The guarded flash workflow normally
reports `captured_state="halted"` and `state="running"`.

New flash results and evidence include `post_flash_cores[]`, with exactly one
entry for every target core index. Available cores contain a snapshot captured
while halted and must finish in their declared `expected_final_state`. A missing
expected state in older schema `1.x` data means `running`. At least one available
core must be expected to run. Disabled or inaccessible cores omit both expected
state and snapshot and retain a non-empty reason; they are never silently
dropped. The legacy `snapshot` result field and
`core` evidence field remain as compatibility views of the lowest-index
available core. Evidence inspection rejects an invalid inventory or a
compatibility view that does not match it. Older evidence without
`post_flash_cores` remains readable within schema `1.x`.

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

General ELF and Intel HEX loading are not yet part of this contract. ESP-IDF
application ELF normalization is the only format-aware path; execution is
available only to backends and targets whose capability matrix satisfies the
entire guarded workflow.

## Compatibility

Readers must reject unsupported major schema versions. New optional fields may
be added within the `1.x` line. Existing field meaning, error code meaning, and
risk classification cannot change within the major version.
