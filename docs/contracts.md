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
optional external executables. In particular, native probe-rs discovery does
not require the standalone `probe-rs` CLI to be installed.

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

The initial Replay milestone accepts raw `.bin` firmware. Its fixture must
declare the base address so a flash plan never presents a fabricated or unknown
write range. ELF and HEX segment parsing belongs to the native probe-rs
milestone.

## Compatibility

Readers must reject unsupported major schema versions. New optional fields may
be added within the `1.x` line. Existing field meaning, error code meaning, and
risk classification cannot change within the major version.
