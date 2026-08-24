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
`openocd_host_inspection_available=true` means this binary can perform the
bounded host inspection described below; it does not mean an OpenOCD executable
or target backend is available.

## OpenOCD host inspection

`openocd inspect [--executable <PATH>] [--config <FILE>...] [--search <DIR>...]
[--timeout-ms <MS>]` is a host-only `R0_READ_ONLY` operation. The executable
defaults to `openocd` and is resolved to one exact regular file from `PATH`, or
from the explicit path. No alternate backend is selected when resolution or
identity checking fails.

The command validates scalar bounds before filesystem access. The version
deadline defaults to 2000 ms and must be 100..=30000 ms. It launches only the
resolved executable with `--version`, closes stdin, drains stdout and stderr
independently, retains at most 64 KiB from each stream, and kills the child on
deadline expiry. Success requires exit code zero, completely drained and
untruncated output, and a line beginning with `Open On-Chip Debugger` or
`OpenOCD `. Timeout is a retryable `TIMEOUT`; a missing or unsuccessful tool is
`CAPABILITY_UNAVAILABLE`; a selected executable with the wrong identity is
`CONFIG_INVALID`; output truncation or an incomplete stream is
`PROTOCOL_ERROR`.

At most 64 top-level configuration files and 64 search directories may be
provided. Each is canonicalized, must have the requested filesystem type, must
not duplicate an earlier canonical path, and must not contain `#`. Argument
order is preserved. Every top-level file is limited to 4 MiB and returned with
its canonical path, exact byte length, and lowercase SHA-256. These checks do
not parse or execute the configuration because OpenOCD configuration is Tcl;
therefore `semantic_validation=false` and `sourced_files_resolved=false` are
mandatory. Hashes cover only the explicitly listed top-level files.

A successful result has `scope="host_only"`, `complete=true`, the executable
and configuration manifests, and the requirements for later server enablement.
The capability fields `config_semantic_validation`, `server_launch`, `tcl_rpc`,
`gdb_mi`, `target_operations`, and `flash` remain false. The requirements name
loopback binding, dynamic GDB/Tcl ports, a disabled telnet server, Tcl RPC
readiness, the Tcl `0x1a` message terminator, the `shutdown` command, and
process-tree cleanup. `server_enablement_requirements.implemented=true` means
the separate guarded server lifecycle below implements those requirements. The
inspection operation's own server and target capability fields remain false.

## Guarded OpenOCD server lifecycle

`openocd server plan` accepts the same executable, repeatable `--config`, and
repeatable `--search` inputs plus independently bounded version, startup, and
shutdown deadlines. At least one explicit top-level config is required. Version
timeout is 100..=30000 ms (default 2000), startup is 100..=60000 ms (default
10000), and shutdown is 100..=30000 ms (default 3000). Scalar and count bounds
are rejected before filesystem access.

Planning is host-side, but its returned execution risk is conservatively
`R2_DEVICE_WRITE`: OpenOCD configuration is executable Tcl and may reset or
write a target, execute a host command, or perform other behavior not requested
by this tool. The plan hashes the exact selected executable (maximum 512 MiB),
binds its recognized version, and reuses the canonical top-level config
manifests. Its `confirm_digest` also binds ordered search directory paths and
all lifecycle policy fields. It explicitly reports that search directory
contents, transitive sources, and Tcl semantics are neither bound nor verified.

`openocd server test --confirm <DIGEST>` recomputes the complete plan and fails
with `CONFIRMATION_MISMATCH` before configuration execution unless the digest is
exact. It does not accept arbitrary `-c` or Tcl input. The launcher binds to
`127.0.0.1`, asks the operating system for GDB and Tcl ports with port zero,
disables telnet, and passes only canonical search directories and top-level
configs. OpenOCD stdout and stderr are drained concurrently, forwarded to
stderr, hashed completely, and retained up to 256 KiB per stream. Log lines are
limited to 16 KiB and a bounded event queue; truncation, oversized lines,
dropped events, or incomplete drains are `PROTOCOL_ERROR`.

Readiness requires observing both dynamic endpoint announcements and receiving
a recognizable OpenOCD `version` response over Tcl RPC. Tcl requests and
responses use byte `0x1a` framing and responses are limited to 64 KiB. The test
then sends `shutdown` and requires a successful graceful process exit within
the shutdown deadline. A Windows Job Object or Unix process group covers the
complete descendant tree; timeout and drop paths force termination. The result
contains endpoint identities, readiness and shutdown timings, complete bounded
log summaries, effects, confirmation limits, and `complete=true`.

This checkpoint advertises `server_launch=true`, `tcl_rpc=true`, and
`dynamic_gdb_endpoint=true` only in the server-test result. `gdb_mi`,
`target_operations`, and `flash` remain false. A listening GDB socket and a Tcl
version response do not prove target examination, CPU state preservation, or
debugger semantics.

## Bounded GDB/MI host lifecycle

`openocd gdb inspect` is an independent `R0_READ_ONLY` host operation. It
resolves one exact executable, runs only `--version` with a 100..=30000 ms
deadline (default 10000), requires a line beginning with `GNU gdb`, and hashes
the executable with a 512 MiB maximum. Stdout and stderr are drained
concurrently with the same 64 KiB per-stream version-probe limit used by
OpenOCD inspection. A successful inspection keeps
`gdb_mi_host_process=false` and all remote or target capabilities false.

`openocd gdb test` repeats that exact inspection and then starts the selected
binary with the fixed arguments `--nx --nh --quiet --interpreter=mi2`. It
does not accept extra GDB arguments, CLI commands, MI commands, initialization
files, symbol files, or target endpoints. Input is direct ASCII terminated by
LF; no shell or locale-dependent text pipeline is involved. Startup and
shutdown deadlines are independently bounded to 100..=60000 ms (default
10000) and 100..=30000 ms (default 3000).

The only input sequence is `1-gdb-version` followed by `2-gdb-exit`. Readiness
requires a valid MI startup prompt. The first request must produce the
token-correlated result `1^done`; the exit request must produce `2^exit`,
followed by a successful process exit. The framing parser recognizes prompts,
result, async, and quoted stream record categories plus result tokens and
classes. It deliberately does not claim to parse arbitrary nested MI values or
provide a general debugger command channel.

MI stdout and diagnostic stderr are drained concurrently, forwarded to the
parent stderr, completely hashed, and retained up to 256 KiB per stream. Lines
are limited to 16 KiB and the event queue to 256 records. Truncation, oversized
lines, dropped events, malformed records, unmatched tokens, incomplete drains,
or unsuccessful exit are `PROTOCOL_ERROR`. A Windows Job Object or Unix process
group owns the complete descendant tree on success, timeout, protocol failure,
and drop.

A successful test has `scope="managed_gdb_mi_lifecycle"`,
`risk="R0_READ_ONLY"`, and `gdb_mi_host_process=true`. This proves only the
selected local process and fixed MI2 handshake. `remote_target_connection`,
symbol loading, register/memory/stack access, breakpoints, execution control,
and flash remain false. The OpenOCD server result also continues to advertise
`gdb_mi=false`: two independently successful host results do not prove a target
session. Only the separately planned and confirmed operation below crosses that
boundary.

## Confirmed OpenOCD and GDB session

`openocd session plan` accepts exact OpenOCD and GDB executable selections,
one optional `--gdb-xtensa-config <FILE>`, one required exact
`--expected-target <NAME>`, repeatable OpenOCD config and search inputs, and
bounded OpenOCD version,
startup, and shutdown, GDB version, startup, command, and shutdown, and target
state deadlines. The target-state deadline defaults to 3000 ms and must be
100..=30000 ms. The GDB remote command deadline defaults to 10000 ms and must
be 100..=60000 ms. Session-specific scalar bounds are validated before either
executable or configuration path is inspected.

The returned `R2_DEVICE_WRITE` plan binds both exact executable hashes and
recognized versions, whether an Xtensa target configuration was selected and,
when present, its canonical path, byte length, SHA-256, and fixed
`XTENSA_GNU_CONFIG` delivery mechanism. It also binds the ordered top-level
config manifests and search paths, the exact expected current-target name, the
loopback/dynamic endpoint policy, all deadlines, the fixed MI2 contract, and
target-state policy. Search
directory contents, transitive Tcl sources, configuration semantics, and the
runtime adapter/USB serial identity remain explicitly unbound. The
runtime-selected port number is necessarily not known at planning time. No
firmware or symbol identity is required because this operation accepts neither.

`openocd session test --confirm <DIGEST>` recomputes the plan and rejects a
nonmatching digest before configuration Tcl executes. After the guarded server
becomes ready, bounded Tcl RPC reads `target current`, validates that name
against a 128-byte ASCII allow list, and queries `<name> curstate`. GDB is not
started unless the name exactly matches the confirmed `--expected-target` and
the state is exactly `running`.

The GDB process uses only `--nx --nh --quiet --interpreter=mi2`. Ambient
`XTENSA_GNU_CONFIG` is always removed. When a target configuration was selected
and confirmed, the process receives only its canonical path through that fixed
environment variable. The profile is a native module and may execute host code
when GDB starts; the plan hashes but does not load it. Its complete MI input is
fixed to these token-correlated commands and result classes:

```text
1-gdb-version                                      -> 1^done
2-target-select remote 127.0.0.1:<dynamic-port>   -> 2^connected
3-target-detach                                    -> 3^done
4-gdb-exit                                         -> 4^exit
```

No extra GDB argument, arbitrary environment variable, initialization file,
symbol, ELF, explicit target-data command, monitor command, or arbitrary MI
command is accepted. Async and stream
records may occur around the four results but retain the existing bounded
framing and output requirements. The effects do not equate this narrow MI
command set with a packet-free connection: ordinary remote negotiation may
exchange stop state, target descriptions, memory-map metadata, or register
state. Confirmed OpenOCD configuration may also install a GDB-attach handler
that probes flash or resets and halts a protected target.

OpenOCD's default GDB attach event may halt the current target. After GDB
cleanup, the tool queries the original target state. If `running` is not
proven, it issues exactly `targets <validated-initial-name>; resume`, polls the
same target within the target-state deadline, and requires a final exact
`running` state. A restoration failure is `VERIFICATION_FAILED`; errors include
the available GDB cleanup/output, target restoration, OpenOCD readiness,
shutdown, and log evidence. OpenOCD is always shut down and both process trees
remain isolated and bounded on success and failure.

A complete result enables only server launch, Tcl RPC, GDB/MI, remote target
connection, state observation, attach/detach, and restoration resume.
Symbol loading, register/memory/stack reads, breakpoints, watchpoints, general
execution control, flash, and arbitrary commands remain false. Halted-origin
sessions are not supported by this checkpoint.

`probes test --probe <exact-selector> --target <exact-target>` is an
`R1_REVERSIBLE_CONTROL` operation. It opens the selected probe, attaches to the
target, and disconnects without requesting erase, program, reset, halt,
snapshot, or arbitrary user memory access. Backend attach sequences may still
access volatile target control state as disclosed by `effects`. A successful
result contains the session identity, conservative capability matrix, ordered
`session.attach` and `session.disconnect` records, and `complete=true`.
It does not guarantee preservation of a pre-existing halted state; probe-rs
teardown may resume that core and discloses this in `effects`.

`snapshot capture --probe <exact-selector> --target <exact-target>` is an
`R1_REVERSIBLE_CONTROL` one-shot observation. It attaches to the exact target,
records the original state of every enabled core, halts cores that were
running, reads PC/SP/LR, restores only those cores that were originally
running, and disconnects. Disabled cores remain in the ordered core inventory
with `available=false` and an `unavailable_reason`; at least one core must be
available. The response distinguishes `original_state`, `captured_state`, and
the final restored `state`. It does not request reset, erase, program, arbitrary
memory write, or a persistent debug session. A successful response requires
`post_disconnect_core_state=true`; otherwise the command fails before probe
selection.

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
synthesizes register IDs or widths from a legacy PC/SP snapshot. A successful
response also requires `post_disconnect_core_state=true` before probe selection.

`memory read <address> <length> --probe <exact-selector> --target <exact-target>
--core <index>` is an `R1_REVERSIBLE_CONTROL` one-shot observation. Address and
length accept decimal or `0x`-prefixed values. Before probe discovery or attach,
the backend requires a non-zero range of at most 4096 bytes fully contained in
exactly one readable target-described RAM or NVM region assigned to the selected
core. Overflowing, cross-region, ambiguous, Generic/MMIO, and larger ranges use
`CONFIG_INVALID`. The probe-rs backend performs an exact byte read and does not
use an aligned convenience API that could access bytes outside the request.
The response contains the requested `range`, complete target `region` metadata,
`encoding="hex"`, lowercase `data`, and SHA-256 over the returned bytes. It also
distinguishes original, halted capture, and restored core states. A complete
response requires exact range/core/byte-count agreement, verified state
restoration, and disconnect. The read is not an atomic system snapshot: other
cores, peripherals, and DMA are not halted. Replay requires matching
`memory_cores` and hexadecimal `memory_blocks`; missing evidence is never
synthesized. A successful response also requires
`post_disconnect_core_state=true` before probe selection; malformed ranges are
still rejected before this capability check.

`core status|halt|run|continue|step --probe <exact-selector> --target
<exact-target> --core <index>` uses one versioned core-state contract.
`original_state` is the state observed after attach, `state` is the state
guaranteed after disconnect, and `state_changed` must exactly match their
difference. Status cannot change the state. Halt must finish halted and strict
run must finish running; repeating either action is valid and reports
`state_changed=false`. Continue requires `original_state=halted`, requests
execution, and may report running or an immediate halted result with a non-empty
halt reason. It sets `effects.execution_continue_requested=true` but does not
claim an intentional durable final-state change. Step also requires
`original_state=halted`, executes one instruction, finishes halted, and reports
the normalized `halt_reason="step"`, explicit `pc_before`/`pc_after` evidence
plus `effects.instruction_step_requested=true`; it does not set
`intentional_final_core_state_change_requested` because the final execution
state remains halted. Halted observations may include a normalized
`halt_reason`, while running observations must not. Halt/run set
`effects.intentional_final_core_state_change_requested=true`.

`core continue-until-halt --probe <exact-selector> --target <exact-target>
--core <index> [--timeout-ms <ms>] [--poll-interval-ms <ms>]` extends Continue
with a bounded wait. Timeout is 10..=60000 ms (default 5000); polling is
10..=1000 ms (default 25) and cannot exceed the timeout. These options and the
core index are validated before probe selection. `data.wait.continuation`
contains the immediate Continue observation. The final `outcome` is `halted`
or `timed_out`; `state`, `halt_reason`, `elapsed_ms`, and `poll_count` describe
the bounded observation. A halted outcome requires a non-empty reason. A
timed-out outcome is a successful complete report, requires `state="running"`
and no halt reason, requires `elapsed_ms >= timeout_ms`, and does not synthesize
an error or halt event.

A backend must advertise both `core_status` and
`post_disconnect_core_state` before any core-state command may select or attach
a probe. Halt, run, continue, and step additionally require their matching
capabilities. Continue-until-halt additionally requires `continue_execution`
and `continue_until_halt`.
`core_status` alone means the backend can observe state while a session is
alive; it is deliberately insufficient for a process that immediately tears
that session down. Replay provides explicit `control_cores` evidence and
preserves transitions across later operations within one service/backend
instance. The same post-disconnect capability is required by live snapshot,
register-read, and memory-read commands because they also report a final
restored state. Native probe-rs currently sets it false: probe-rs 0.32 session
teardown resumes a halted Xtensa core and disables Cortex-M halting debug.
Native observation and control are available through the long-running
`session serve` lease and report `state_scope="active_session"`. One-shot native
commands remain gated until a backend/target pair proves the post-disconnect
guarantee. Missing guarantees return `CAPABILITY_UNAVAILABLE` before probe
discovery.

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
`probes test`, `core status|halt|run|continue|continue-until-halt|step`,
`breakpoints.*`,
`registers read`, `memory read`, `snapshot capture`, and
`snapshot reset-capture` return an `effects` object. It records whether the
command requested reset, Flash, continue, a single instruction step, hardware
breakpoint configuration, bounded memory read, or arbitrary memory writes;
whether core execution-state restoration or breakpoint state was verified; and
any known backend-managed volatile target changes. probe-rs clears hardware
breakpoints during attach and may invoke target-specific attach/halt sequences.
The ESP32-S3 sequence disables several watchdogs, and session teardown can
resume a core that was halted before attach. Halting a running core can also
interrupt in-flight peripheral activity or produce partial external I/O;
restoration cannot undo bytes or physical actions already emitted. Agents must
surface these notes instead of treating R1 as R0 read-only behavior.

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | Success |
| 2 | Safety guard denied the operation |
| 3 | Verification or assertion failed |
| 4 | Probe or target unavailable |
| 5 | Timeout |
| 6 | Backend capability unavailable or protocol failure |
| 7 | Configuration, fixture, or input error |
| 8 | OS or transport permission denied |
| 10 | Internal invariant or I/O failure |

## Addresses and bytes

Addresses are JSON strings such as `"0x08000000"`, avoiding precision loss in
JavaScript clients. Firmware and artifact content is identified with lowercase
SHA-256 hex strings. Large binary content will be returned as bounded artifact
references rather than unbounded inline data. The bounded `memory read` exception
inlines at most 4096 bytes as lowercase hexadecimal and includes its SHA-256.

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

## Persistent session JSONL

`session serve --target <exact-target> [--idle-timeout-ms <ms>]` is a
foreground stdio service. It emits JSONL regardless of the global `--json`
flag: each non-empty stdin line is one request and each request receives
exactly one stdout line. Diagnostics stay on stderr. A request line is limited
to 64 KiB and `request_id` to 128 bytes. Malformed lines return
`PROTOCOL_ERROR` without terminating the server.

Open one exact probe/target lease:

```json
{"schema_version":"1.0","request_id":"req-open","operation":"session.open","probe":"303a:1001:E0:72:A1:D4:1F:DC","target":"esp32s3"}
```

The response adds `request_id` to the normal versioned result envelope and
returns `data.session.session_id`, `state="open"`,
`transport="stdio_jsonl"`, and
`close_policy="halt_clear_hardware_breakpoints_run_observed_cores_before_disconnect"`.
Both `session.open` and `session.status` include `lease_policy`, whose
`idle_timeout_ms` and `idle_timeout_action` report the effective server policy.
Only one session may be open. Target matching is exact; later operations must
echo the opaque session ID so stale or foreign clients cannot control the
current lease. The response capability matrix contains the hardware-breakpoint
capacity negotiated from the live core rather than a target-name guess.

```json
{"schema_version":"1.0","request_id":"req-halt","operation":"core.halt","session_id":"ses_<opaque>","core":0}
{"schema_version":"1.0","request_id":"req-status","operation":"core.status","session_id":"ses_<opaque>","core":0}
{"schema_version":"1.0","request_id":"req-run","operation":"core.run","session_id":"ses_<opaque>","core":0}
{"schema_version":"1.0","request_id":"req-continue","operation":"core.continue","session_id":"ses_<opaque>","core":0}
{"schema_version":"1.0","request_id":"req-wait","operation":"core.continue_until_halt","session_id":"ses_<opaque>","core":0,"timeout_ms":5000,"poll_interval_ms":25}
{"schema_version":"1.0","request_id":"req-step","operation":"core.step","session_id":"ses_<opaque>","core":0}
{"schema_version":"1.0","request_id":"req-breakpoint-list","operation":"breakpoints.list","session_id":"ses_<opaque>","core":0}
{"schema_version":"1.0","request_id":"req-breakpoint-set","operation":"breakpoints.set","session_id":"ses_<opaque>","core":0,"address":"0x420129D4","slot":0}
{"schema_version":"1.0","request_id":"req-breakpoint-clear","operation":"breakpoints.clear","session_id":"ses_<opaque>","core":0,"slot":0}
{"schema_version":"1.0","request_id":"req-breakpoint-clear-all","operation":"breakpoints.clear_all","session_id":"ses_<opaque>","core":0}
{"schema_version":"1.0","request_id":"req-registers","operation":"registers.read","session_id":"ses_<opaque>","core":0,"names":["pc","sp","lr"]}
{"schema_version":"1.0","request_id":"req-memory","operation":"memory.read","session_id":"ses_<opaque>","core":0,"address":"0x42000000","length":32}
```

In-session core responses report `state_scope="active_session"`. They require
`core_status` plus the action capability, but deliberately do not require
`post_disconnect_core_state`: their state guarantee ends when the lease closes
or the process terminates. This is distinct from one-shot `core` commands,
which retain the detach-safe capability gate.

`core.step` additionally requires the selected core to already be halted. A
running-origin step is rejected with `CONFIG_INVALID` before the backend issues
the instruction, so the lease remains running and the request cannot silently
turn step into halt-plus-step.

`core.run` is a strict desired-state operation: success requires its immediate
post-command observation to be running. `core.continue` is an event-oriented
operation that requires a halted origin, requests execution, and then reports
the immediate observed result. Running is valid; halted is also valid when a
non-empty `halt_reason` explains the immediate stop. This lets a client
distinguish a real breakpoint hit from a failed resume. The result sets
`effects.execution_continue_requested=true` without claiming an intentional
durable final state.

`core.continue_until_halt` has the same halted-origin rule, then performs
bounded polling. The option bounds and response fields match the one-shot
contract, but the final state is scoped to the active lease and therefore does
not require `post_disconnect_core_state`. A `timed_out` result is `ok=true`,
leaves the core running, and keeps the same session ID usable for a later
status, halt, breakpoint operation, or close. The service is synchronous and
single-request: while this operation is polling, it cannot read a second JSONL
request, so cross-request cancellation is not part of this transport version.
The timeout is the current bounded stop mechanism; true asynchronous
cancellation requires a concurrent owner or broker.

`breakpoints.list` requires a non-zero `hardware_breakpoints` capability and
returns every indexed comparator slot. It may be called while the core is
running, although a backend may transiently halt the core to read the debug
registers; the returned `original_state` and `state` must match.
`breakpoints.set`, `breakpoints.clear`, and `breakpoints.clear_all` additionally
require halt/run support and a halted selected core. Set requires `address` and
accepts an optional `slot`; without a slot it chooses the lowest free one. A
repeat of the same address is idempotent, including the same explicit slot.
The same address in a different requested slot and an overwrite of an occupied
slot are `CONFIG_INVALID`. Clear requires a slot and is idempotent when it is
already empty; clear-all is also idempotent. Every successful response contains
the exact `capacity`, complete contiguous `before` and `after` inventories,
`requested_address`, `requested_slot`, `affected_slot`, and an exact `changed`
flag. Duplicate active addresses and capacity/index mismatches are protocol
errors. Native physical acceptance currently covers ESP32-S3 CPU0 only.

`registers.read` accepts at most 64 unique register names. An empty `names`
array requests the backend's complete supported register set. `memory.read`
uses the canonical hexadecimal `address` string and a numeric `length`; the
request must be 1..4096 bytes and wholly contained in one readable RAM or NVM
region for the selected core. Range, overflow, overlap, MMIO, and size errors
are rejected before any target-core read or state change. Both operations
capture the original core state, halt only when needed, perform the bounded
read, and restore that state before replying. Their reports include
`risk="R1_REVERSIBLE_CONTROL"`,
structured `effects`, ordered `operations`, `complete=true`, and
`state_scope="active_session"`; they do not claim atomicity for peripherals,
DMA, other cores, or external UART writes.

`session.status` reports the active identity, open timestamp, close policy,
lease policy, observed core indexes, and cores tracked for hardware-breakpoint
cleanup. A mutation attempt is tracked before the backend write, so even a
partial or failed write is included in close cleanup. `session.close` first
issues and verifies an idempotent halt for each tracked breakpoint core, clears
and reads back every slot, then issues and verifies an idempotent run for every
observed or read core before disconnecting. Its report includes
`hardware_breakpoint_cleanup`, final core observations, structured effects, and
ordered operations. If explicit breakpoint cleanup cannot be verified, the
service skips the explicit resume step rather than deliberately running with a
possibly stale breakpoint, then still attempts backend disconnect.
`server.shutdown` succeeds only after the active session has been closed. EOF
and transport failures invoke the same best-effort close path and record
cleanup on stderr.

The CLI default idle timeout is 300000 ms. A finite value must be
100..=86400000 ms; 0 disables expiry. This option is validated before fixture
loading, probe discovery, or target attach. No deadline runs before
`session.open`. While a lease is active, each structurally valid request renews
the deadline only after processing and response output complete, including a
valid request that receives an operation-level error. Blank, malformed, and
oversized lines do not renew it. Because the backend remains exclusively owned
by the main loop, expiry is checked only between requests and never interrupts
an in-flight operation. Long requests therefore receive a fresh full idle
interval after they finish; asynchronous cancellation remains a separate
future capability.

On idle expiry, the service applies the same guarded close policy as explicit
close and EOF, writes one compact versioned `session.idle_expired` JSON object
to stderr, and exits with code 0. The event contains `idle_timeout_ms`,
`action="close_and_exit"`, and the complete close report under `close`. If
cleanup fails, stderr instead receives
`session.idle_expiry_cleanup_failed` with the structured error and the process
returns the mapped failure code. An OS-level hard kill or power loss cannot run
this path and still relies on backend teardown behavior. The separate MCP
supervisor below can replace a failed process, but it cannot retroactively prove
that target cleanup completed.

General ELF and Intel HEX loading are not yet part of this contract. ESP-IDF
application ELF normalization is the only format-aware path; execution is
available only to backends and targets whose capability matrix satisfies the
entire guarded workflow.

## MCP stdio adapter

`mcp serve` is a JSON-RPC transport over the same single-owner session service.
It does not duplicate backend behavior, relax capability gates, or create a
second cleanup policy. The server supports MCP `initialize`, `ping`,
`notifications/initialized`, `tools/list`, `tools/call`, and `shutdown`.
Each input line is limited to 64 KiB; oversized or malformed lines return a
JSON-RPC `-32600` error without renewing an active idle lease.

`tools/list` returns one tool named `embedded_debugger_request`. Its required
`operation` and optional fields map directly to the persistent JSONL request
contract; the adapter adds `schema_version` and a generated `request_id` before
dispatching to the existing session service:

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "method": "tools/call",
  "params": {
    "name": "embedded_debugger_request",
    "arguments": {
      "operation": "session.open",
      "probe": "replay:stlink-v3:0039002A3432510433343034",
      "target": "STM32G431CBTx"
    }
  }
}
```

The tool result contains the normal versioned embedded-debugger envelope in
both `structuredContent` and a text content item. An operation-level failure is
therefore an MCP tool result with `isError=true` and the original stable error
code. Invalid JSON-RPC method or tool argument shapes are transport errors
(`-32600`, `-32601`, or `-32602`) and do not terminate the server. The adapter
exposes `session.open`, `session.status`, `core.*`, `breakpoints.*`,
`registers.read`, `memory.read`, and `session.close`; flash and one-shot
commands remain CLI-only until their lifecycle guarantees are suitable for a
long-lived Agent tool call. Idle lease expiry, request ordering, session IDs,
and close evidence have exactly the JSONL semantics above.

## MCP subprocess supervisor

`supervisor mcp` is the preferred Agent/plugin entry point. It validates the
selected backend, fixture or target, child idle timeout, and bounded restart
policy before spawning the existing `mcp serve` command. Defaults are three
restarts and a 250 ms delay; `max_restarts` must be 0..=32 and
`restart_delay_ms` 0..=60000. A value of zero disables the corresponding
restart count or delay. OpenOCD remains an explicit unsupported backend.

The supervisor is a transparent JSONL stdio proxy during normal operation.
Client request IDs remain in flight until a matching child response is drained.
A duplicate in-flight ID is rejected as `-32003`. Expected MCP shutdown and
parent stdin EOF close the child transport and never trigger a restart.

If the child exits unexpectedly, every request that still lacks a response is
completed exactly once with JSON-RPC `-32001`. Its data contains the child
generation, exit details, and `restart_required=true`; its message states that
target state is indeterminate. The supervisor never replays those requests,
including reads, because an R1 target operation may already have executed even
when its response was lost.

After the first successful connection initialization, the supervisor caches
only the original MCP `initialize` request and an observed
`notifications/initialized` notification. Each replacement child is a new
private MCP connection, so that side-effect-free handshake is its first
interaction and uses a supervisor-private request ID. The internal response is
not forwarded to the external client. This preserves the standard external MCP
lifecycle: the client does not send a second `initialize` on its existing
connection. An external request that arrives during the private handshake is
rejected without forwarding as retryable `-32002`.

The replacement child starts without a debug lease. An old `session_id`
therefore receives the ordinary session `PROTOCOL_ERROR`; the caller must open
a new exact probe/target lease and explicitly inspect or recover the target.
Structured `supervisor.child_exited`, `supervisor.child_restarted`, and
`supervisor.child_ready` events are written to stderr. Reaching the restart
limit terminates the supervisor with an `INTERNAL` error and exit code 10.
None of these process guarantees claim that a hard-killed child cleared
breakpoints, restored core state, completed a write, or disconnected cleanly.

## Compatibility

Readers must reject unsupported major schema versions. New optional fields may
be added within the `1.x` line. Existing field meaning, error code meaning, and
risk classification cannot change within the major version.
