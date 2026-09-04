---
name: embedded-debugger
description: Use embedded-debugger for structured embedded flashing and debugging through probe-rs or Replay, plus confirmed OpenOCD/GDB lifecycles, ESP runtime firmware identity, and temporary hardware-breakpoint/watchpoint qualification. Trigger when work needs exact probe selection, bounded target control, cleanup evidence, or verified debug-tool integration.
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

## Runtime acceptance

After a separately planned, confirmed, and completed flash, prefer
`runtime accept` when firmware readiness must be correlated with one exact
reset-capture. Prefer `--contract <test-contract.json>` plus a new evidence path
for a repeatable board test. The strict contract must bind the complete probe,
target, serial port, VID, PID, USB serial number, optional interface identity,
ready line, optional build-identity line, heartbeat line, and any forbidden
complete lines. Contract mode rejects direct acceptance fields and captures the
exact contract bytes and SHA-256 in the evidence package. For a one-off direct
run, supply those identities explicitly and repeat `--forbid-line` for every
exact complete line that must not occur. Use the board-documented DTR/RTS values;
the command transmits no serial bytes.

Accept the run only when `data.report.accepted=true` and the complete-line counts
satisfy every configured assertion, including zero observations for every
forbidden complete line. A `VERIFICATION_FAILED` result still points to complete
evidence; inspect it and do not retry automatically. The command
performs one R1 reset-capture but never flashes, erases, recovers, accesses UICR,
or creates a second monitor. Treat source-revision telemetry as source identity,
not as cryptographic attestation of the final firmware artifact.

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

ESP32-S3 CPU0 has physically passed only the running-origin idempotent branch:
OpenOCD observed it running before the conditional phase, sent zero resume
commands, proved final running, and cleaned the managed process and ports. The
post-run zero-transmit UART monitor remained silent. Do not treat this as
halted-origin resume qualification, firmware liveness, heartbeat recovery,
CPU1 support, or standing authorization for another target-control run.

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
target and selection. A second exact, non-retried `pc,a1` run under digest
`a817ed1453fb2ff0e4f23d83ba07bf02c7d0fdeccba37c13913cbc939d188ba0`
returned `0x420129e4/0x3fcdb550`, used fallback restoration, and recovered eight
heartbeats. A later fresh authorization of the same deterministic digest
returned `0x42012a6c/0x3fcdb550`, again used fallback restoration, completed
process/port cleanup, and recovered six complete heartbeats after one partial
serial boundary line. Treat both authorizations as spent. Neither run
authorizes derived-memory access or a watchpoint.

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
user-confirmed rather than independently verified from OpenOCD's memory map. A
separate 2026-09-02 CPU0 acceptance read exact RAM candidate
`0x3FCDB5F0 + 4` as `ed0a0000` (little-endian `2797`), bracketed by complete
zero-transmit UART heartbeat sequences `2744..2748` and `2867..2871`. Fallback
restoration returned CPU0 to running and both process trees and dynamic ports
cleaned up. Treat this only as point-in-time operational watch-address evidence:
the ELF, register, and memory operations were not atomic, firmware continuity
and target RAM semantics remain unverified, and the read authorizes no
watchpoint installation or hit.

For an ESP-IDF executable, use the independent
`openocd esp-app-identity plan/test` workflow before treating ELF-derived
addresses as belonging to the running image. Require the same exact session
inputs, `--elf <FILE>`, a containing `--region-start`/`--region-length`, and
explicit `--region-kind nvm`. Do not accept RAM, infer the region from the
section address, or reuse a memory/stack digest.

Planning must finish before hardware access. Surface the canonical ELF path and
complete SHA-256, the exact `.flash.appdesc` address and 256-byte length, source
and expected descriptor hashes, expected descriptor bytes, the nested memory
digest, and the outer digest. The ELF must be a little-endian executable Xtensa
or RISC-V image with exactly one allocated read-only descriptor section. Its
source ELF hash slot must be zero; the expected target bytes are derived by
copying the complete ELF SHA-256 into descriptor bytes `0x90..0xB0` and changing
nothing else. Require the exact fresh outer digest before `test`.

The test performs one exact 256-byte target read through the fixed memory
protocol and requires all bytes to match. It does not load the ELF or symbols
into GDB. On mismatch, inspect the returned detach, final-running restoration,
GDB exit, and OpenOCD cleanup evidence and never retry automatically. Success
permits `runtime_firmware_identity_verified=true` only as point-in-time,
non-adversarial build identity. Always preserve
`cryptographic_authenticity_verified=false`, `secure_boot_verified=false`, and
`target_memory_map_semantics_verified=false`; target-controlled descriptor
bytes are not signed attestation. The result does not itself authorize a later
watchpoint or prove that firmware cannot change between operations. Generate
and confirm every later physical plan separately.

The 2026-09-02 ESP32-S3 CPU0 acceptance used outer digest
`2491f5efdc10dbf5b2a6b607d040880e1aa4be014766b9d4c81a3f31d1bcda98`
for one non-retried read of `.flash.appdesc` at `0x3c000020 + 256`. The target
descriptor exactly matched expected SHA-256
`65d77b4a7a7507112ab899dc7d08167dba8ea19d3afb6cfa1c555fb5cc5d5621`
for ELF SHA-256
`676a89d78556f07500fcbe50a17c046c27d9d6e1e425ed9732c6f257a09f7b20`;
CPU0 returned to running, cleanup completed, and UART heartbeats continued.
Treat this qualification as exact and point-in-time. The confirmed 64 KiB NVM
declaration was wider than OpenOCD's observed `0x3000`-byte FLASH mapping,
although the exact descriptor read was contained in that mapping. Do not infer
the rest of the declaration, bind the observed adapter retroactively, include
CPU1, or reuse this spent authorization.

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
mode-specific `*stopped` while that single continue is outstanding. The stop
may be tokenless, or may carry exactly token 8; reject every nonmatching token
and competing stop. Continue to require the exact watchpoint
number/expression/value shape, a top-frame PC inside the confirmed interval, a
canonical post-hit row with `times=1`, deletion, exact empty-table proof, final
running, and complete process cleanup. Result/stop ordering may vary and
repeated running notices are allowed. On timeout or malformed/unrelated stop,
the tool may attempt exactly one interrupt; accept its stop only when it is
tokenless or token 8 and exactly `signal-received`/`SIGINT`, then perform fixed
delete/list/detach/exit. It sends no additional Tcl resume after GDB failure.
Treat incomplete cleanup as indeterminate, perform recovery only with fresh
authority, and never present controlled host fixtures as physical target
acceptance.

When the watch address is stack-local, keep static and runtime evidence
separate. DWARF or disassembly may establish a frame-relative offset, but it
does not establish the current frame base or runtime firmware identity. Never
add a static offset to a historical stack-pointer snapshot and present the sum
as a current address. The audited ESP32-S3 demo ELF places `heartbeat` at
`DW_OP_fbreg: 160` with frame base register `a1`; `a1 + 128` is only a compiler
temporary in that build. A separately confirmed 2026-08-31 `pc,a1` snapshot
placed PC `0x420129e4` inside that local ELF's `main` range and yielded arithmetic
candidate `0x3fcdb5f0` from `a1=0x3fcdb550`. A later 2026-09-02 descriptor read
verified that same ELF only at its own point in time; it does not retroactively
bind the historical frame or prove continuity between operations. A subsequent
fresh `pc,a1` snapshot returned `0x42012a6c/0x3fcdb550`; that PC is also inside
the audited `main` range and yields the same arithmetic candidate. Candidate
memory was then read once under separate digest
`38c60e31837633806c9ff44e654e776f55d4e6b0be5aed7679201b3c61e9a8a2` and
returned `ed0a0000` (little-endian `2797`), strictly between complete UART
heartbeat sequences `2744..2748` and `2867..2871`. This completed the
operational address-evidence prerequisite. Two fresh matching hit plans then
bound `0x3fcdb5f0 + 4`, access mode, PC interval
`[0x420128cd,0x420128d3)`, and a 10-second deadline. The separately confirmed,
non-retried physical run under digest `29421b87...56d0` stopped once at
`0x420128d0` with exact `access-watchpoint-trigger`/`hw-awpt` evidence,
proved `times=1`, deleted the watchpoint, proved the table empty, restored CPU0
running, completed process/port cleanup, and recovered UART heartbeats. Treat
this as exact point-in-time GDB-attributed hit acceptance only. It does not
independently read comparator state, prove firmware continuity or identity,
verify target RAM semantics, qualify CPU1 or another address/mode/interval, or
provide standing authority. Every later physical hit still requires two fresh
matching plans and their exact newly returned digest.

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
- Flashing is not exposed through the MCP session tool. Use the CLI `flash plan` first, require the exact confirmation digest for `flash execute`, and preserve the evidence path. Treat Intel HEX, segmented programming, and non-boot NVM as independent gates; code-Flash acceptance never authorizes UICR, and any `NON_BOOT_NVM_EXECUTION_ACCEPTANCE_REQUIRED` blocker must stop before attach.
- Treat `ok=true` as a completed operation, not proof that every target-side expectation was satisfied. Inspect `complete`, state fields, verification flags, and ordered operations.

Read [mcp.md](references/mcp.md) for the MCP launch shape and request schema.
