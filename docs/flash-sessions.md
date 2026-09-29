# Bounded development flash sessions

The bounded executor in 0.2.2 passed one physical nRF52840 DK A/B session.
The optional native transcript recording is new in the 0.2.3 candidate and
has host-side tests only. Check `embedded-debugger flash session serve --help`
on the exact installed executable before relying on `--transcript-dir`.

The one-time plan is host-only. It records the exact executable SHA-256,
probe selector, target, canonical build directory, image format/options,
allowed write and *whole-sector erase* windows, maximum flash count, duration,
and a random nonce. Review all of these fields, then approve the returned
`confirm_digest` once. This is distinct from each firmware plan digest.

```powershell
embedded-debugger --backend probe-rs flash session plan `
  --probe <exact-vid:pid:serial> --target nRF52840_xxAA `
  --firmware-directory C:\project\build --format hex `
  --write-start 0x00000000 --write-length 0x00100000 `
  --erase-start 0x00000000 --erase-length 0x00100000 `
  --max-flashes 10 --duration-seconds 1800 `
  --output C:\session\nrf-development.json --json
```

After the user approves that exact scope digest, start the same executable
with stdin/stdout pipes:

```powershell
embedded-debugger --backend probe-rs flash session serve `
  C:\session\nrf-development.json --confirm <approved-scope-digest> `
  --transcript-dir C:\session\transcript
```

Create a new, empty transcript directory before starting `serve`. The optional
`--transcript-dir` stores the bounded request bytes consumed in `requests.jsonl` and
stdout response lines in `responses.jsonl`, without a host-side pipe adapter.
Files are created exclusively, so a prior transcript cannot be overwritten.
Keep stderr separately when capturing process diagnostics. Transcript I/O
failure ends the executor without retry; a failed response after target
mutation is indeterminate and requires evidence review.
The native executor closes on count exhaustion or failure even if its caller
still holds stdin open.

The process emits one `flash.session.ready` JSON line. Send one JSON line
per build, with a new evidence path each time:

```json
{"operation":"flash","firmware":"C:\\project\\build\\app.hex","evidence":"C:\\session\\flash-001.evidence.json"}
```

Each successful response is `flash.session.flash` with `remaining`,
the newly computed native Flash Plan, verified flash result, and evidence
reference. Send `{"operation":"close"}` to end early. The process ends
automatically after the approved count. An error response ends the process;
do not send another request or retry a failed/uncertain flash.

Only ordinary code-Flash images are accepted. Intel HEX sessions are currently
limited to `nRF52840_xxAA` Code Flash `0x00000000..0x00100000`; ESP-IDF
sessions are limited to `esp32s3`. UICR, APPROTECT/security changes,
non-boot NVM, recover, and whole-chip erase are not authorized by this mode.
The native target capability gates, exact probe identity, plan digest
recomputation, read-back verification and cleanup evidence remain in force.

The approved plan is bound to its original path and executable hash. Starting
the process creates a permanent `.active` sidecar beside the plan, so the
same approval cannot restart after close, expiry, failure, or a process crash.
The counter and deadline live only in that process. To continue, generate and
approve a new plan with a new nonce. Do not delete the sidecar to reactivate an
old grant. The marker protects against accidental replay in a trusted
development workspace; it is not a defense against a local user deliberately
editing or removing files. The Agent should still review runtime readiness
and stop on unexpected board behavior between builds.
