---
name: embedded-debugger
description: Use embedded-debugger for structured embedded flashing and debugging through probe-rs or Replay, plus confirmed OpenOCD/GDB lifecycles and temporary hardware-breakpoint/watchpoint qualification. Trigger when work needs exact probe selection, bounded target control, cleanup evidence, or verified debug-tool integration.
---

# Embedded Debugger

Use `embedded-debugger` as the structured debug control layer. Prefer the
`embedded_debugger_request` MCP tool when available; otherwise use the CLI and
the same versioned JSON contract. Do not replace it with ad hoc probe-rs or
OpenOCD shell parsing.

## Before hardware

1. Run `embedded-debugger doctor` and `embedded-debugger --backend probe-rs probes list --json`.
2. Select the probe by its complete selector, including serial identity. Select the exact target name; never infer either from a friendly board name.
3. For native operations, surface the returned capability matrix and `effects` before taking an R1 action. Replay is the safe path for contract tests and offline analysis.
4. When a serial console is relevant, use the `baud` skill for port identity and read-only monitoring. Keep DTR/RTS false unless the board protocol explicitly requires otherwise.

## OpenOCD and GDB host checks

Use `openocd inspect` before any OpenOCD configuration execution. Configuration
files are Tcl; crossing into `openocd server test` requires a reviewed
`openocd server plan` and its exact confirmation digest.

For direct OpenOCD halt/run qualification, run `openocd target plan` with the
exact executable, top-level config/search inputs, and exact
`--expected-target`. Surface the R2 effects, including target interruption,
partial external I/O, and unbound runtime adapter identity. Require the user to
return the exact digest before `openocd target test`. The fixed test accepts
only a running origin, proves halted, always attempts the fixed resume after
the halt result, and requires final running plus complete server cleanup. Do
not retry failure automatically. A success proves only fixed selected-target
halt/run; it does not authorize reset, GDB, register/memory/stack access,
breakpoints, flash, monitor commands, or arbitrary Tcl.

For a halted-target recovery, use the independent `openocd resume plan/test`
workflow, never `openocd target test` or `openocd reset test`. Surface that the
plan accepts only the exact current target in `halted` or `running`, sends one
fixed catch-wrapped resume only from `halted`, sends no control command from
`running`, requires final `running`, and fixes both maximum resume count to one
and automatic retries to zero. Also surface that loading OpenOCD configuration
executes Tcl, runtime adapter identity and non-selected target states remain
unbound, and resumed firmware may perform arbitrary I/O. Generate two identical
host-only plans and require a fresh exact digest immediately before every
physical recovery. Do not reuse prior authorization, retry a failure, or claim
halt, reset, watchpoint cleanup, target-data access, or non-selected-target
restoration.

For reset, use the independent `openocd reset plan/test` workflow. Before
requesting confirmation, surface that OpenOCD resets all defined targets and
runs configuration-defined reset events, while the tool observes and recovers
only the exact selected target. The fixed test requires a running origin, exact
Tcl catch code 0 for reset and recovery, a halted selected-target observation,
one fixed catch-wrapped selected-target resume, final running, and complete
cleanup. Require the exact reset digest immediately before execution. Do not
claim non-selected target restoration, and never retry a failed reset test
automatically. Success does not authorize `reset init`, another reset mode,
GDB, target-data access, breakpoints, flash, monitor commands, or user Tcl.
ESP32-S3 CPU0 has passed this exact narrow workflow; do not generalize that
acceptance to CPU1, another target, or any excluded capability.

Use `openocd gdb inspect --executable <PATH> --json` to prove an exact GNU GDB
file, then `openocd gdb test --executable <PATH> --json` to prove only the
fixed local MI2 version/exit lifecycle. A successful
`gdb_mi_host_process=true` does not authorize or prove a remote target session.
Do not infer symbol, register, memory, stack, breakpoint, execution-control, or
flash support while those capability fields remain false.

For the combined interoperability check, run `openocd session plan` with exact
`--openocd-executable`, `--gdb-executable`, top-level `--config`, and `--search`
inputs plus the exact OpenOCD `--expected-target` name. Surface its
`R2_DEVICE_WRITE` effects and confirmation boundary, including the unbound
runtime adapter identity, then require the user to return the exact digest
before `openocd session test`. The test requires the current target name to
match and its state to start and finish `running`; attach may halt it, detach
normally resumes it, and the tool may issue one fixed OpenOCD resume fallback
before final verification. Do not retry a lost or failed test automatically
because target outcome may be indeterminate.

For Espressif Xtensa targets, resolve the target-specific profile before
planning. Prefer the actual `xtensa-esp-elf-gdb` binary with
`--gdb-xtensa-config <exact-profile.so>` so both files are hash-bound; do not
substitute a small board launcher whose dynamically selected GDB child is not
represented by that launcher hash. Surface that the profile is native host
code loaded only during confirmed execution. Use the identical option for
plan and test. Ambient `XTENSA_GNU_CONFIG` is deliberately ignored. A missing
or changed profile requires a new plan and confirmation.

For explicit OpenOCD register inspection, use the independent
`openocd registers plan/test` workflow with the same exact tool, profile,
configuration, search, and expected-target inputs. Add each desired register as
`--register <NAME>`; do not request more than 64. Surface the normalized ordered
selection, fixed inventory/value MI commands, R2 configuration and attach
effects, restoration policy, and unbound runtime adapter identity. Require the
user to return the exact new digest before `test`.

The register test requires a running origin, resolves names only from GDB's
structured runtime inventory, reads only the resolved selected numbers, and
fails if any requested value is unknown, ambiguous, unavailable, missing,
duplicate, extra, malformed, or non-hexadecimal. A connected failure still
attempts fixed detach, GDB exit, selected-target running restoration, and
OpenOCD cleanup. Never retry automatically. Success proves only the returned
selected register values and cleanup for that exact target/tool/profile plan;
it does not authorize ELF/symbol loading, memory/stack access, breakpoints,
execution control, flash, monitor commands, arbitrary MI/Tcl, CPU1, or another
target. ESP32-S3 CPU0 has passed one exact `pc/a0/a1/ps` acceptance run with
fallback restoration and UART recovery; do not generalize it beyond that
target and selection.

For explicit OpenOCD memory inspection, use the independent
`openocd memory plan/test` workflow. Require an exact `--address` and 1..=4096
`--length` plus `--region-start`, `--region-length`, and explicit
`--region-kind ram|nvm`. Do not infer the region from an address or accept MMIO,
unknown, cross-region, overflowing, or unbounded requests. Surface that the
region is a user-confirmed input: containment is checked and digest-bound, but
the target memory-map semantics are not independently verified. A wrong region
declaration may still make a read side effectful.

The memory plan binds the concrete read command and complete-coverage policy in
its own R2 digest. Require the user to return that exact digest before `test`.
The fixed test permits only version, remote connect, one
`-data-read-memory-bytes`, detach, and exit. It accepts split result blocks only
when their structured `begin/offset/end/contents` metadata and decoded bytes
cover the whole request in order without gaps or overlaps. Partial,
inaccessible, malformed, reordered, duplicate, or extra output is failure.

A connected memory failure still attempts fixed detach, GDB exit,
selected-target running restoration, and OpenOCD cleanup. Never retry
automatically. Success proves only the exact returned bytes and SHA-256 for the
confirmed declared range. It does not authorize region inference, memory
writes, symbols/ELF, register/stack commands, breakpoints, execution control,
flash, monitor commands, arbitrary MI/Tcl, CPU1, or another target. ESP32-S3
CPU0 has passed one exact `0x42000000 + 32` acceptance run with complete
coverage, a SHA-256 matching the prior probe-rs snapshot, fallback restoration,
process cleanup, and UART recovery. Treat that qualification as exact to the
confirmed target, range, tools, and configuration; the NVM declaration remains
user-confirmed rather than independently verified from OpenOCD's memory map.

For OpenOCD stack inspection, use only the independent
`openocd stack plan/test` workflow with an explicit `--max-frames` in 1..=32.
Surface the fixed zero-based inclusive range, disabled frame filters, no
ELF/symbol identity, and the R2 distinction between bounded returned frames and
unbound implicit unwind reads. GDB may read target registers and memory at
addresses derived from live unwind state; invalid state can reach an unexpected
or side-effectful address even though no explicit memory command is sent.

Require the exact new digest before `test` and never retry automatically. The
fixed exchange permits only version, remote connect, one
`-stack-list-frames --no-frame-filters 0 <limit-1>`, detach, and exit. Treat
function/source fields as optional bounded GDB metadata, not verified symbols;
do not claim a complete physical call stack. A connected failure still follows
fixed detach, exit, selected-target running restoration, and OpenOCD cleanup.
Success does not authorize ELF/symbol loading, frame filters,
argument/local/value reads, explicit memory/register commands, breakpoints,
execution control, flash, monitor commands, arbitrary MI/Tcl, CPU1, or another
target. ESP32-S3 CPU0 has passed one exact `--max-frames 8` acceptance run that
returned two unsymbolized frames, used fallback restoration, released both
process trees and dynamic ports, and recovered UART heartbeats. Treat that
qualification as exact to the confirmed target, limit, tools, profile, and
configuration; it still does not bind implicit unwind-read addresses or prove
physical call-stack completeness or symbol correctness.

When the user supplies an exact executable ELF for offline annotation, add the
same `--elf <FILE>` to both stack `plan` and `test`. This selects the separate
`openocd.stack.annotated.*` contract and a new outer digest; never reuse the
base stack digest as its confirmation. Surface the canonical ELF path, SHA-256,
parser policy, and unchanged inner stack digest for review.

The annotated workflow never loads the ELF in GDB. It parses only the bound
in-memory bytes after target restoration and process cleanup, rejects compressed
debug sections, limits sections/symbols/build IDs and all text, examines at most
17 DWARF records and returns at most 16 annotations per stack frame, and resumes
at most eight declined split-DWARF continuations before ending that lookup. It
never loads external debug data, reads source contents, or uses the network.
After DWARF and explicit-size symbol fallback fail, a zero-sized text symbol may
be inferred only to the next distinct text symbol or section end in the same
executable section, with a 64 KiB maximum span. Surface
`resolution=inferred_symbol_table` and `symbol_evidence`; do not present an
inferred range as a declared symbol size. Treat all function/source output as
identity-bound offline annotation only. Always preserve
`runtime_firmware_identity_verified=false`: choosing an ELF does not prove the
target runs it. Never claim physical call-stack completeness, and retain the
same R2 effects, unbound unwind-read warning, disabled capabilities, and
no-automatic-retry rule.

The earlier eight-annotation, nonzero-sized-only policy passed one ESP32-S3 CPU0
run but produced partial annotation; its digest is stale. The current policy has
passed a separate exact, independently confirmed, non-retried acceptance with
`--max-frames 8` and the same bound heartbeat ELF. It returned 12 untruncated
top-frame annotations through `main` and inferred `Reset` for adjusted caller
`0x40378694` over `[0x40378638, 0x40378698)`. The fixed fallback restored CPU0
running, both managed processes cleaned up, both ports were reusable, and UART
recovered. Treat this as acceptance only for digest `b85c65e2...b4ed2`, that
ELF, CPU0, limit, tools, profile, and configuration. Do not infer current
target/ELF equality, physical call-stack completeness, bounded unwind reads,
CPU1 support, or broader symbol correctness. Acceptance evidence is not
standing authorization: require a fresh plan review and exact confirmation for
every later physical execution, and never retry automatically.

For a temporary OpenOCD hardware-breakpoint qualification, use only
`openocd breakpoint plan/test` with an exact nonzero numeric `--address` and
the same exact session inputs. Surface the R2 effects and the fixed
`-break-insert -h *0x...`, delete, and empty-table protocol. The command does
not accept symbols, expressions, software or conditional breakpoints, continue
the target while installed, or wait for a hit. Require a fresh exact digest
immediately before every physical `test`; prior breakpoint, stack, or session
acceptance is not authorization.

Success requires GDB to identify breakpoint 1 as hardware-assisted at the
exact address with zero hits, delete it, and return the exact empty six-column
table before running restoration. Do not claim that this independently reads
the physical comparator: runtime adapter identity, comparator capacity, and
physical comparator cleanup remain unbound or unverified. If the breakpoint
exchange fails after connection but before normal detach, the tool attempts
fixed delete/list/detach. Every GDB failure records a point-in-time target state
but sends no additional Tcl resume. GDB detach, GDB exit, or configured detach
handlers may still resume the target. Treat the outcome as potentially
indeterminate, perform explicit recovery only with fresh authority, and never
retry automatically. ESP32-S3 CPU0 has passed one exact, independently
confirmed, non-retried run at `0x420129E4`: insertion metadata matched, deletion
returned an exact empty GDB table, final running was proven, both processes and
ports cleaned up, and UART recovered after retained boundary fragments. Treat
that acceptance as exact to digest `f388b4e3...a8802`, address, CPU0, tools,
profile, and configuration. It does not independently verify physical
comparator cleanup or capacity, qualify CPU1, or authorize a persistent
breakpoint, breakpoint-hit execution, watchpoint, symbol loading, or general
GDB control. It is not standing authorization for another physical run.

For a temporary OpenOCD hardware-watchpoint qualification, use only
`openocd watchpoint plan/test`. Require an exact nonzero `--address`, exact
`--length 1|2|4|8`, containing `--region-start`/`--region-length`, explicit
`--region-kind ram`, and `--mode read|access`, plus identical exact session
inputs. The address must be naturally aligned and the whole range contained in
the declared RAM region. Never infer RAM from an address; NVM, MMIO, unknown
regions, symbols, user expressions, and write-only mode are not authorized.

Surface before confirmation that the tool fixes GDB to C and evaluates
`*((char*)0x<address>)@<length>` during creation. That evaluation may read the
declared range, and a wrong RAM declaration may make it side effectful. Only
GDB `rwatch` and `awatch` are used because they are hardware-only; normal
write-only watchpoints may fall back to software stepping. Require a fresh exact
watchpoint digest immediately before every physical `test`; no breakpoint,
memory, session, or historical acceptance authorizes it.

Success requires the exact `hw-rwpt`/`hw-awpt` insertion tuple, one matching
`read watchpoint`/`acc watchpoint` table row with number 1 and zero hits,
deletion, the exact empty six-column table, final running, and full process
cleanup. The target is not intentionally continued while installed, so do not
claim a hit, physical comparator allocation, target width/capacity support, or
physical cleanup. GDB can defer resource failure until resume. After insertion
failure the tool attempts fixed delete/list/detach, records point-in-time target
state, and sends no additional Tcl resume; detach/exit or configured handlers
may still resume the target. Never retry automatically, and perform manual
recovery only with fresh authority. Controlled tests are not physical target
acceptance. One separately confirmed, non-retried ESP32-S3 CPU0 `access` run
over `0x3FCDB550 + 4` has passed exact insertion classification, deletion,
empty-table proof, final-running restoration, process/port cleanup, and UART
recovery. Treat it as exact to digest `3a502b8a...0db8`, access mode, range,
CPU0, tools, profile, and configuration. It does not qualify `read`, comparator
allocation/cleanup, width/capacity, hit execution, CPU1, or any later physical
plan, and is not standing authorization.

For a real OpenOCD hardware-watchpoint hit, switch to the independent
`openocd watchpoint hit plan/test` workflow. Keep every base watchpoint input
identical and additionally require an explicit `--expected-pc-start`, nonzero
`--expected-pc-length` at most 1 MiB, and bounded `--hit-timeout-ms`. Derive the
half-open PC interval from inspected firmware code, then state that its meaning
is user-confirmed: the tool does not load that ELF or attest the firmware
currently running on the target. Never widen the interval merely to make a
failed stop pass.

Before any physical `hit test`, generate the complete plan twice, compare the
two `confirm_digest` values and stable contract fields, stop, and ask the user
to return the fresh exact digest. Old watchpoint classification, breakpoint,
hit, or other operation digests never authorize this execution. Surface that
the target will run once while the watchpoint is installed and may perform
arbitrary firmware-defined I/O. There is no automatic retry under any failure
condition; a second attempt requires a new plan review and a new confirmation.

Accept success only when token 8 yields `^running` plus one correlated
mode-specific `*stopped`, the exact watchpoint number/expression/value shape,
a top-frame PC inside the confirmed interval, a canonical post-hit row with
`times=1`, deletion, exact empty-table proof, final running, and complete
process cleanup. Result/stop ordering may vary and repeated running notices are
allowed. On timeout or malformed/unrelated stop, the tool may attempt exactly
one interrupt followed by fixed delete/list/detach/exit; it sends no additional
Tcl resume after GDB failure. Treat incomplete cleanup as indeterminate,
perform recovery only with fresh authority, and never present controlled host
fixtures as physical target acceptance.

A complete combined test proves only the selected tools' fixed MI2
version/connect/detach/exit lifecycle, loopback endpoint, target-state
observation, and restoration. It does not authorize ELF or symbol loading,
explicit register/memory/stack reads, breakpoints, watchpoints, general
execution control, flash, monitor commands, or arbitrary MI/Tcl input. Still
surface the plan's implicit effects: remote negotiation may exchange target
descriptions, memory-map metadata, stop/register state, and confirmed OpenOCD
attach handlers may probe flash or reset/halt a protected target.

## Persistent session

The MCP server exposes one tool, `embedded_debugger_request`. Call it with
`operation="session.open"`, exact `probe` and `target`, then reuse the opaque
`session_id` returned in every later request. The supported operations are
`session.status`, `core.status`, `core.halt`, `core.run`, `core.continue`,
`core.continue_until_halt`, `core.step`, `breakpoints.list|set|clear|clear_all`,
`registers.read`, `memory.read`, and `session.close`.

Always close the session explicitly. The server also applies its idle lease
policy and will halt tracked breakpoint cores, clear and verify comparator
slots, run observed cores, disconnect, and emit structured expiry evidence on
stderr. A session response is scoped to the active lease; do not claim that a
halt or breakpoint survives process teardown unless a separate acceptance
result proves it.

The plugin launches the bounded MCP supervisor. If its child exits before a
tool response, treat JSON-RPC `-32001` as an indeterminate target outcome and
never repeat the operation automatically. The supervisor restores only the MCP
handshake. Any old `session_id` is stale after a restart, so inspect the error,
open a new exact probe/target lease, and recover explicitly. A retryable
`-32002` means the replacement child is still completing that private
handshake; the rejected request was not forwarded.

## Safety boundaries

- Treat halt, run, step, continue, register reads, memory reads, and breakpoint changes as R1 reversible control, not side-effect-free inspection. Report the response `effects` and warnings.
- Keep memory reads within the validated single-region limit of 4096 bytes. Do not turn an MMIO or cross-region request into a guessed read.
- Breakpoint mutation requires a halted selected core. Preserve the complete before/after slot inventory and cleanup evidence.
- Flashing is not exposed through the MCP session tool. Use the CLI `flash plan` first, require the exact confirmation digest for `flash execute`, and preserve the evidence path.
- Treat `ok=true` as a completed operation, not proof that every target-side expectation was satisfied. Inspect `complete`, state fields, verification flags, and ordered operations.

Read [mcp.md](references/mcp.md) for the MCP launch shape and request schema.
