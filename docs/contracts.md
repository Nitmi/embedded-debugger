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
classes. Result records are structurally parsed, including nested lists and
tuples, but this host-only lifecycle does not interpret target data or provide a
general debugger command channel.

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

## Confirmed OpenOCD selected-register snapshot

`openocd registers plan` reuses the exact OpenOCD/GDB/session inputs and adds
repeatable `--register <NAME>`. Selection validation runs before executable or
configuration lookup. It requires 1..=64 names, permits only ASCII alphanumeric
plus `_`, `-`, `.`, or `:`, limits each name to 64 bytes, normalizes to
lowercase, and rejects ASCII case-insensitive duplicates. The digest is
independent from `openocd session`: it binds the ordered normalized selection,
the six-command MI contract, tool/config/profile identities, deadlines, exact
expected target, restoration policy, effects, and confirmation limits.

The operation remains `R2_DEVICE_WRITE`. Explicit register reads are data
inspection, but OpenOCD configuration is executable Tcl, the confirmed native
Xtensa profile may execute host code, and attach handlers may probe flash,
reset, or halt a protected target. Search-tree contents, transitive Tcl sources,
configuration semantics, runtime adapter identity, and dynamic port values stay
unbound. No firmware or symbol identity is accepted or required.

`openocd registers test --confirm <DIGEST>` rejects a stale digest before Tcl
execution, requires the exact selected target to start `running`, and runs only:

```text
1-gdb-version                                                    -> 1^done
2-target-select remote 127.0.0.1:<dynamic-port>                 -> 2^connected
3-data-list-register-names                                      -> 3^done
4-data-list-register-values --skip-unavailable x <numbers...>   -> 4^done
5-target-detach                                                  -> 5^done
6-gdb-exit                                                       -> 6^exit
```

The complete `register-names` list is parsed as structured MI. Every selected
name must resolve case-insensitively to exactly one non-empty canonical entry;
the resolved indices alone form command 4. The `register-values` result must
contain exactly `number` and hexadecimal `value` for every requested index, no
unknown or duplicate index, and no missing value. Values are returned in the
confirmed request order and normalized to lowercase `0x` form. An unknown,
ambiguous, unavailable, malformed, duplicate, missing, or extra result is
`PROTOCOL_ERROR`.

After a connected-path snapshot error, the tool still attempts fixed token-5
detach before bounded token-6 exit. All paths then query the original target,
use the one fixed OpenOCD resume fallback when `running` is not proven, require
final running, shut down OpenOCD, and retain GDB/OpenOCD cleanup evidence.
Failure is never automatically retried. Success enables only selected register
inventory/read in addition to the accepted connection and restoration
capabilities. ELF/symbol loading, memory/stack reads, breakpoints/watchpoints,
general execution control, flash, monitor input, and arbitrary MI/Tcl remain
false.

## Confirmed OpenOCD bounded memory snapshot

`openocd memory plan` reuses the exact OpenOCD/GDB/session inputs and requires
`--address`, `--length`, `--region-start`, `--region-length`, and
`--region-kind ram|nvm`. Address arithmetic, the 1..=4096-byte request limit,
region non-emptiness, overflow, and complete containment are validated before
any executable or configuration lookup. MMIO and unknown region kinds are not
accepted.

The declared region is a user-confirmed safety input, not a discovered target
memory map. Its kind and bounds, the exact request, the concrete memory command,
complete-coverage response policy, tool/config/profile identities, deadlines,
target restoration policy, effects, and confirmation limits are bound in an
independent digest. `declared_region_semantics_verified` and
`target_memory_map_semantics_bound` remain false. A wrong region declaration can
still select MMIO or another side-effectful target address.

The operation remains `R2_DEVICE_WRITE` because OpenOCD configuration is Tcl,
the optional Xtensa profile is native host code, attach handlers may probe
flash/reset/halt, and attachment interrupts the target. A confirmed test
requires the exact selected target to start `running` and permits only:

```text
1-gdb-version                                             -> 1^done
2-target-select remote 127.0.0.1:<dynamic-port>          -> 2^connected
3-data-read-memory-bytes <confirmed-address> <length>    -> 3^done
4-target-detach                                           -> 4^done
5-gdb-exit                                                -> 5^exit
```

The `memory` result must be a structured list of tuples containing exactly
`begin`, `offset`, `end`, and hexadecimal `contents`. Multiple blocks are
accepted only in strict ascending offset order from zero, with no gap, overlap,
duplicate, extra range, or missing byte. Each `begin` must equal the confirmed
address plus `offset`; `end` is treated as exclusive and its span must equal the
decoded content length. The blocks must cover the entire confirmed request.
Malformed hexadecimal, mismatched metadata, inaccessible gaps, partial reads,
and unexpected fields are `PROTOCOL_ERROR`.

A complete report returns lowercase hex data, SHA-256, and block evidence. A
connected-path failure still attempts fixed token-4 detach before token-5 exit;
all paths then prove the initial selected target `running`, using only the one
fixed resume fallback when needed, and clean up OpenOCD. Failure is not retried
automatically. Success enables only this bounded memory read. Symbols/ELF,
register/stack commands, memory writes, breakpoints/watchpoints, general
execution control, flash, monitor input, arbitrary MI/Tcl, and unverified
region inference remain unavailable.

## Confirmed ESP app runtime firmware identity

`openocd esp-app-identity plan` reuses the exact OpenOCD/GDB/session inputs and
requires `--elf`, `--region-start`, `--region-length`, and
`--region-kind nvm`. Region kind, non-emptiness, overflow, and later descriptor
containment are validated before target access. RAM, MMIO, and unknown
declarations are rejected.

The host preflight canonicalizes and reads one regular, nonempty ELF of at most
64 MiB. It requires executable kind, little endianness, Xtensa or RISC-V 32-bit
architecture, and exactly one allocated, read-only, nonzero, four-byte-aligned
`.flash.appdesc` section of exactly 256 bytes. The descriptor magic must be
`0xABCD5432`; fixed metadata fields must be printable ASCII with zero padding;
and source bytes `0x90..0xB0` must be zero.

The expected runtime descriptor copies the exact source section and replaces
only `0x90..0xB0` with SHA-256 of the complete ELF, matching the pinned
`espflash 4.5.0` IDF image rule. The outer confirmation digest binds the nested
memory digest, canonical ELF path and complete bytes/hash, section address and
layout, source and expected descriptor hashes, complete expected descriptor
bytes, explicit NVM declaration, fixed parser/derivation policy, effects, and
trust boundary.

`openocd esp-app-identity test` recomputes the outer plan and rejects a stale
digest before Tcl execution. Its nested target protocol is the bounded memory
protocol above, fixed to one `-data-read-memory-bytes <section-address> 256`.
No symbol or executable file is passed to GDB. Success requires complete
coverage, strict target descriptor parsing, and exact equality of all 256
bytes. The report returns both descriptors, hashes, parsed metadata, and
`runtime_firmware_identity_verified=true`.

A mismatch is `VERIFICATION_FAILED` after the nested operation has detached,
restored the selected target to `running`, exited GDB, and shut down OpenOCD;
the error retains that evidence and records that no retry occurred. The result
is non-adversarial build identity, not a chain of trust. It always keeps
`cryptographic_authenticity_verified=false`, `secure_boot_verified=false`, and
`target_memory_map_semantics_verified=false`.

## Confirmed OpenOCD bounded stack snapshot

`openocd stack plan` reuses the exact OpenOCD/GDB/session inputs and requires
`--max-frames` in 1..=32. The limit is validated before executable or
configuration lookup. Its independent digest binds the tool/config/profile
identities, exact selected target, deadlines, running-restoration policy,
frame limit, inclusive range `0..limit-1`, disabled-frame-filter policy,
result validation, effects, and confirmation boundary.

The operation remains `R2_DEVICE_WRITE`. OpenOCD configuration is executable
Tcl, the optional Xtensa profile is native host code, attach handlers may probe
flash/reset/halt, and attachment may interrupt the target. In addition, stack
unwinding may read target registers and memory at addresses derived from live
registers, stack contents, and architecture unwind rules. The returned frame
count is bounded, but those implicit target-read addresses cannot be known or
bound by the confirmation digest. Invalid unwind state can therefore reach an
unexpected or side-effectful target address. The plan reports
`unwinder_target_memory_addresses_bound=false` and
`implicit_unwinder_target_access_addresses_bound=false`.

A confirmed test requires the exact selected target to start `running` and
permits only:

```text
1-gdb-version                                                   -> 1^done
2-target-select remote 127.0.0.1:<dynamic-port>                -> 2^connected
3-stack-list-frames --no-frame-filters 0 <confirmed-high>      -> 3^done
4-target-detach                                                 -> 4^done
5-gdb-exit                                                      -> 5^exit
```

The `stack` response must use the GDB/MI result-list shape
`stack=[frame={...}, ...]`. Each tuple must contain decimal `level` and a
0x-prefixed hexadecimal `addr`; levels must be unique and contiguous from zero.
Only documented optional `func`, `file`, `fullname`, `line`, `from`, `arch`,
and `addr_flags` scalar fields are accepted. Optional text is bounded to 4096
bytes per field and rejects control characters. Empty results, duplicate or
unknown fields, nested values, malformed numbers, noncontiguous levels, extra
top-level variables, and more frames than confirmed are `PROTOCOL_ERROR`.

Python frame filters are explicitly disabled. No ELF or symbol file is loaded,
and no argument, local, or value is requested. Optional function/source fields
are returned as GDB-reported metadata only; the plan requires no firmware
identity and makes no symbol accuracy claim. If `returned_frames` equals the
confirmed limit, `additional_gdb_frames_possible=true`. The report always keeps
`physical_call_stack_completeness_proven=false`, including when fewer frames are
returned, because unwindability is not proof of the physical call stack.

A connected-path failure still attempts fixed token-4 detach before bounded
token-5 exit. Every path then observes the original selected target, uses only
the fixed resume fallback when `running` is not proven, requires final running,
and shuts down OpenOCD with complete output/process evidence. Failures are not
retried automatically. Success enables only the bounded stack snapshot in
addition to the accepted connection and restoration capabilities. Symbol/ELF
loading, argument/local/value inspection, explicit memory/register commands,
breakpoints/watchpoints, general execution control, flash, monitor input, and
arbitrary MI/Tcl remain false.

## Confirmed OpenOCD stack snapshot with offline ELF annotation

Adding `--elf <FILE>` to `openocd stack plan/test` selects the independent
`openocd.stack.annotated.plan/test` contract. Omitting it follows the unchanged
bounded-stack contract above and produces the same base confirmation digest as
before this feature.

The frame limit is still validated first. The ELF preflight then canonicalizes
and reads one regular, nonempty file of at most 64 MiB into memory. It requires
ELF format and executable kind, caps sections at 65,536, symbols at 262,144,
and the optional build ID at 64 bytes, rejects compressed
`.debug_*`/`.zdebug_*` data, and validates the in-file DWARF context before any
target access. The outer digest binds:

- the complete base stack confirmation digest;
- canonical ELF path, byte length, SHA-256, format, kind, architecture,
  address width, endianness, entry, and optional build ID;
- `object 0.39.1` and `addr2line 0.25.1` plus the exact lookup, fallback,
  metadata, inline-frame, compression, and external-data policies; and
- the added host effects and confirmation boundary.

The target-facing exchange remains exactly the five commands documented in the
base contract. GDB is never given the ELF path and never executes
`-file-exec-and-symbols`, `-file-symbol-file`, or another symbol-loading
command. Once the base test has restored the selected target, exited GDB, and
shut down OpenOCD, annotation reconstructs a resolver from the already hashed
in-memory bytes. It does not invoke an external process, execute embedded
scripts, read source-file contents, access the network, or load files named by
GNU debug links, alternate links, or split DWARF requests.

Level-zero lookup uses the exact GDB address. A nonzero later-frame address is
treated as a return address and decremented by one. Addresses outside a
loadable segment remain unresolved. For each stack frame, the resolver examines
at most 17 innermost-to-outermost in-file DWARF records and returns at most 16
annotations. The seventeenth record is observed only to prove truncation. It
resumes at most eight split-DWARF continuations with no supplied data; a ninth
request ends the DWARF lookup and permits only the in-file symbol fallback.

When DWARF provides no usable function or source metadata, fallback first
selects the smallest containing, defined, nonzero-sized in-file text symbol.
Its address and declared end must both remain inside its referenced executable
section. Only when that fails may the resolver consider a defined zero-sized
text symbol. Its half-open range is inferred from the symbol address to the next
distinct text symbol in the same executable section, or to that section's end
when no later symbol exists. Empty, cross-section, overflowing,
non-executable-section, and greater-than-64-KiB inferred ranges are unusable.
Explicit-sized candidates retain priority. Every symbol fallback includes
`symbol_evidence`; an inferred result is serialized as
`resolution=inferred_symbol_table`; `symbol_evidence` reports its ELF section
index, start, exclusive end, zero declared size, inferred size, and
`size_inferred=true`, while an explicitly sized result reports inferred size
zero. Function, path, and parser-error text is capped at 4096
bytes and rejects control characters. Missing external debug data or malformed
address-specific DWARF yields structured unresolved/fallback evidence rather
than triggering a filesystem search or repeating the target operation.

`elf.sha256` proves the bytes used for annotation. It does not identify the
firmware running on the target. The plan does not read or compare target flash,
and a matching build ID is not obtained from the target, so
`runtime_firmware_identity_verified=false` and
`runtime_firmware_identity_bound=false` are mandatory. Physical call-stack
completeness and implicit unwind-read addresses also remain unproven. This
feature adds no target command or capability and retains the base R2/no-retry
policy.

The earlier eight-annotation, nonzero-sized-only policy passed one exact
`esp32s3.cpu0`, `--max-frames 8` qualification but returned a truncated top
frame and unresolved caller. That result remains historical evidence only; its
outer digest is stale for the current policy.

The current policy then passed a separate exact, independently confirmed,
non-retried physical qualification. GDB returned level zero `0x420129E4` and
level one `0x40378695`. The in-memory resolver returned 12 top-frame DWARF
annotations through `main` with no truncation and adjusted the caller to
`0x40378694`, where it selected `Reset` from inferred range
`[0x40378638, 0x40378698)` with declared size zero and inferred size 96. The
fixed fallback proved final CPU0 running, both managed processes exited
gracefully, dynamic ports 14947/14949 were reusable, and UART heartbeats
recovered. This acceptance is exact to outer digest `b85c65e2...b4ed2`, ELF
SHA-256, target, tools, profile, configuration, and frame limit. It does not
change the mandatory runtime-identity, unwind-address, physical-completeness,
CPU1, external-data, source-read, or disabled-capability statements above, and
does not authorize a later physical execution without a fresh plan review and
confirmation.

## Confirmed OpenOCD temporary hardware-breakpoint roundtrip

`openocd breakpoint plan` reuses the exact combined OpenOCD/GDB session inputs
and requires one `--address`. The address must be a nonzero numeric value; zero
is rejected before executable or configuration lookup. Symbols, source
locations, expressions, conditions, command lists, requested slots, software
breakpoints, persistent breakpoints, and hit/continue behavior have no input
surface.

The independent `R2_DEVICE_WRITE` digest binds the exact numeric address,
hardware-only insertion policy, strict insertion response, deletion and empty
table proof, fixed success and failure protocols, tool/config/profile
identities, expected current target, deadlines, restoration policy, effects,
and confirmation boundary. It does not bind the runtime adapter identity,
dynamic port, hardware-breakpoint capacity, or physical comparator state.

A confirmed test requires the selected target to start `running` and permits
this success sequence only:

```text
1-gdb-version                                      -> 1^done
2-target-select remote 127.0.0.1:<dynamic-port>   -> 2^connected
3-break-insert -h *0x<confirmed-address>           -> 3^done
4-break-delete 1                                   -> 4^done
5-break-list                                       -> 5^done
6-target-detach                                    -> 6^done
7-gdb-exit                                         -> 7^exit
```

The target is not intentionally continued while the breakpoint exists and no
breakpoint hit is requested. The insertion result must contain exactly one
`bkpt` tuple. Breakpoint number 1 must be an enabled `hw breakpoint` with
`disp=keep`, the exact requested hexadecimal address, and `times=0`. Only
bounded documented scalar metadata and bounded `thread-groups` are accepted.
Pending, multi-location, software, condition, command, script, duplicate,
unknown, malformed, or extra result data is `PROTOCOL_ERROR`.

Deletion is not considered complete from `4^done` alone. `-break-list` must
return exactly `nr_rows="0"`, `nr_cols="6"`, canonical columns `number`,
`type`, `disp`, `enabled`, `addr`, and `what`, plus an empty body. The parser
supports the official named `body=[bkpt={...}]` shape so a residual entry is
reported as a nonempty table rather than accepted or ignored. Success then
requires final selected-target `running`, using the existing single fixed Tcl
resume fallback only after the empty GDB table has been proven.

After a breakpoint-exchange failure following remote connection and before
normal detach, the MI owner attempts token-8 fixed delete, token-9 list
verification, and token-10 detach before bounded GDB exit. Delete may report
`done` or `error`; cleanup is complete only when the follow-up list proves the
exact empty table and detach succeeds. Every GDB failure path records a
point-in-time target observation and does not send an additional OpenOCD Tcl
resume because physical comparator cleanup has not been independently proven.
GDB detach, GDB exit, or configuration-defined detach handlers may still
resume the target. Reports therefore expose both
`target_resume_possible_during_failure_cleanup=true` and
`explicit_openocd_resume_after_gdb_failure=false`; manual recovery may be
required and no failed physical test is automatically retried.

An empty GDB table proves GDB bookkeeping cleanup, not an independent physical
comparator readback. Complete success enables only one temporary hardware
breakpoint roundtrip. Persistent, software, symbolic, conditional, and
multi-location breakpoints, watchpoints, breakpoint-hit execution, general
execution control, symbol loading, explicit register/memory/stack commands,
flash, monitor input, and arbitrary MI/Tcl remain unavailable. Controlled
protocol, parser, digest, cleanup, target-state, and two-process regressions
pass. No physical target acceptance is inherited from those tests.

A separately confirmed, non-retried ESP32-S3 CPU0 physical run has now passed
for digest `f388b4e3...a8802` and exact address `0x420129E4`. GDB reported one
enabled hardware breakpoint with zero hits, accepted its deletion, and returned
the exact zero-row six-column table before detach. The fixed fallback then
proved final running, both managed processes exited gracefully, both dynamic
ports were reusable, and zero-transmit UART monitoring recovered from boundary
fragments to eight consecutive heartbeats. This acceptance remains exact to
that digest, address, CPU0, tools, profile, and configuration. It does not turn
the empty GDB table into physical comparator readback, qualify CPU1 or
comparator capacity, authorize hit execution or persistent breakpoints, or
provide standing authority for a later physical run.

## Confirmed OpenOCD temporary hardware-watchpoint roundtrip

`openocd watchpoint plan` reuses the exact combined OpenOCD/GDB session inputs
and requires `--address`, `--length`, `--region-start`, `--region-length`,
`--region-kind ram`, and `--mode read|access`. The address must be nonzero, the
length must be exactly 1, 2, 4, or 8 bytes, the address must be naturally
aligned to that length, and the whole non-overflowing request must fit inside
the nonempty declared RAM region. NVM is rejected. These checks complete before
executable, profile, configuration, or search-path inspection.

The CLI does not accept an expression. It generates exactly
`*((char*)0x<lowercase-address>)@<decimal-length>` after fixing GDB's language
to C. Expression evaluation while the watchpoint is created may read the
declared range. Region containment is verified and digest-bound, but RAM
semantics are user-confirmed rather than independently checked. A wrong region
declaration can therefore turn that evaluation into a side-effectful access.

Only GDB `rwatch` and `awatch` are exposed as `read` and `access`. GDB defines
those operations as hardware-only. Ordinary write watchpoints are omitted
because GDB may fall back to software single-stepping for `watch`. Symbols,
user expressions, conditions, commands, requested slots, persistent
watchpoints, hit/continue behavior, and arbitrary GDB input have no surface.

The independent `R2_DEVICE_WRITE` digest binds the exact numeric range,
declared RAM region, mode, generated expression, C-language selection, strict
insertion and classification policies, delete/empty-table proof, fixed success
and failure protocols, tool/config/profile identities, expected current target,
deadlines, effects, restoration, and confirmation boundary. It does not bind
runtime adapter identity, dynamic port, actual RAM semantics, target-supported
watchpoint widths, comparator capacity, physical allocation, or physical
cleanup.

A confirmed test requires the selected target to start `running` and permits
this success sequence only:

```text
1-gdb-version                                      -> 1^done
2-target-select remote 127.0.0.1:<dynamic-port>   -> 2^connected
3-gdb-set language c                               -> 3^done
4-break-watch -r|-a <generated-expression>         -> 4^done
5-break-list                                       -> 5^done
6-break-delete 1                                   -> 6^done
7-break-list                                       -> 7^done
8-target-detach                                    -> 8^done
9-gdb-exit                                         -> 9^exit
```

Insertion must return exactly one `hw-rwpt` tuple for `read` or `hw-awpt` tuple
for `access`, containing only `number="1"` and the exact generated `exp`.
The first list must then return one row in the canonical six-column
`BreakpointTable`. That row must have number 1, `disp="keep"`,
`enabled="y"`, `times="0"`, exact `what` and `original-location`, and type
`read watchpoint` or `acc watchpoint` matching the mode. A bounded
`thread-groups` list is optional. Address, pending, condition, command, script,
locations, unknown, malformed, duplicate, extra, write/software, or mismatched
data is `PROTOCOL_ERROR`.

Deletion is not complete from `6^done` alone. Token 7 must return exactly zero
rows, six canonical columns, and an empty body. Success then requires final
selected-target `running`, using the existing one fixed Tcl resume fallback
only after hardware classification and the empty GDB table are proven. The
target is never intentionally continued while the watchpoint exists, and no hit
is requested.

After an insertion attempt fails before normal detach, the MI owner attempts
token-10 delete, token-11 exact empty-table verification, and token-12 detach,
then bounded GDB exit and OpenOCD cleanup. A connection or language-selection
failure attempts detach without issuing an unnecessary delete. Every GDB
failure records a point-in-time target observation and sends no additional Tcl
resume because physical cleanup is unproven. GDB detach, GDB exit, or configured
detach handlers may still resume the target. Manual recovery may be required,
and failed physical tests are never retried automatically.

The insertion tuple and listed type prove GDB hardware classification, not that
a physical comparator was allocated. GDB can defer resource-limit failure until
the inferior resumes, which this qualification deliberately does not do. An
empty table proves GDB bookkeeping cleanup, not physical comparator readback.
Complete success therefore enables only a temporary read/access classification
and cleanup roundtrip. Write-only or persistent watchpoints, hit execution,
breakpoints, general execution control, symbol loading, explicit register or
general memory commands, memory writes, stack reads, flash, monitor input, and
arbitrary MI/Tcl remain unavailable. Controlled parser, digest, cleanup,
target-state, two-process, and CLI regressions pass.

One independently confirmed physical ESP32-S3 CPU0 run has passed for exact
digest `3a502b8a...0db8`, `access` mode, and range `0x3FCDB550 + 4`. It returned
the exact `hw-awpt` tuple and `acc watchpoint` row, deleted number 1, proved the
canonical table empty, restored final running, gracefully cleaned both managed
processes, proved both dynamic ports reusable, and recovered stable UART
heartbeats. This qualifies only that exact physical classification/cleanup
roundtrip. It does not independently prove physical comparator allocation or
cleanup, target width/capacity, RAM semantics, hit behavior, `read` mode, CPU1,
another plan, or standing authority for a later run.

## Confirmed OpenOCD bounded hardware-watchpoint hit

`openocd watchpoint hit plan/test` is independent from the classification-only
workflow above. It reuses the same exact address, 1/2/4/8-byte alignment and
RAM-containment checks, generated C expression, and hardware-only
`read|access` modes. It additionally requires `--expected-pc-start`, a nonzero
`--expected-pc-length` no greater than 1 MiB, and `--hit-timeout-ms` in
100..=60000 ms. PC overflow and all scalar errors fail before host-file or tool
inspection.

The expected PC range is half-open and user-confirmed. It binds the runtime
location allowed to attribute the hit, but the tool does not verify executable
memory semantics, load an ELF, or attest that the target is running the local
firmware used to derive that interval. Target RAM semantics, runtime adapter
identity, dynamic ports, transitive OpenOCD sources, and physical comparator
register state also remain unbound.

The independent `R2_DEVICE_WRITE` digest binds the complete base watchpoint
plan plus the exact PC interval, timeout, asynchronous/all-stop policy, strict
stop parser, success and failure protocols, one-continue/no-retry policy,
effects, restoration policy, tool/config/profile identities, target name, and
lifecycle deadlines. Every physical execution requires two identical current
host-only plans and a fresh exact digest; a classification digest or any prior
acceptance is stale for this command.

A confirmed success permits only this fixed MI sequence:

```text
1-gdb-version                                      -> 1^done
2-gdb-set mi-async on                              -> 2^done
3-gdb-set non-stop off                             -> 3^done
4-target-select remote 127.0.0.1:<dynamic-port>   -> 4^connected
5-gdb-set language c                               -> 5^done
6-break-watch -r|-a <generated-expression>         -> 6^done
7-break-list                                       -> 7^done, times=0
8-exec-continue --all                              -> 8^running + [8]*stopped
9-break-list                                       -> 9^done, times=1
10-break-delete 1                                  -> 10^done
11-break-list                                      -> 11^done, empty table
12-target-detach                                   -> 12^done
13-gdb-exit                                        -> 13^exit
```

The result and asynchronous stop may arrive in either order, and bounded
repeated `*running,thread-id="all"` notifications are accepted. While this
single continue operation is outstanding, exactly one stop is accepted when it
is tokenless or carries matching continue token 8. It must also contain the
mode-specific `read-watchpoint-trigger`/`hw-rwpt` or
`access-watchpoint-trigger`/`hw-awpt`, number 1, the exact expression, and an
allowed value tuple. Read mode requires only `value`; access mode permits only
`new` or `old` plus `new`. Its top-frame address must lie inside the confirmed
PC interval. If `stopped-threads` is reported it must be `all`. Unrelated
signals/exits/scope loss, missing or extra fields, nonmatching tokens,
competing stops, unsupported frame shapes, or out-of-range PCs are
`PROTOCOL_ERROR`.

After the accepted stop, the canonical one-row table must match the original
watchpoint with `times=1`. Deletion is complete only after token 11 proves the
exact empty six-column table. The normal path then detaches, verifies the
selected target running, permits the one existing fixed Tcl resume fallback
only after the hit and cleanup are proven, and closes both process trees.
Success proves one GDB-attributed physical watchpoint event for the exact run;
it still does not independently read comparator registers or prove firmware
identity.

If execution is running or indeterminate after a protocol error or timeout,
the GDB owner attempts this separate bounded cleanup exactly once:

```text
19-exec-interrupt --all   -> 19^done and tokenless-or-token-8 SIGINT *stopped
20-break-delete 1        -> done or error, followed by verification
21-break-list            -> exact empty table
22-target-detach         -> done
13-gdb-exit              -> exit
```

The interrupt stop must be the single correlated `signal-received`/`SIGINT`
event; a competing stop, other signal, or nonmatching token leaves interrupt
cleanup incomplete. An already observed stop skips the interrupt. No failure
path repeats the continue, hit, interrupt, cleanup, or physical test, and no
GDB failure path sends an additional OpenOCD Tcl resume. Detach, exit, or
configuration handlers may nevertheless resume the target. A failed
interrupt/delete/detach leaves the target potentially indeterminate and
requires separately authorized manual recovery. Controlled fixtures cover
tokenless and matching-token correlation, nonmatching and competing stops,
immediate stop-before-result ordering, repeated running notifications, strict
hit parsing, timeout interruption, fixed cleanup, deterministic plans, stale
digests, and preflight rejection. Physical target acceptance is separate and
remains pending.

## Confirmed OpenOCD target state roundtrip

`openocd target plan` accepts one exact OpenOCD executable, at least one
top-level configuration, ordered search paths, one required exact
`--expected-target`, the managed-server deadlines, and a target transition
deadline. The target deadline defaults to 3000 ms and is bounded to
100..=30000 ms. Target syntax and the deadline are rejected before executable
or configuration lookup.

The returned plan is `R2_DEVICE_WRITE`. Its digest binds the exact OpenOCD
executable identity/version, top-level configuration manifests, ordered search
paths, loopback/dynamic endpoint lifecycle, fixed Tcl protocol, exact expected
current-target name, all deadlines, and the `running -> halted -> running`
policy. Search-directory contents, transitive Tcl sources, configuration
semantics, runtime USB adapter identity, and dynamically selected ports remain
explicitly unbound.

`openocd target test --confirm <DIGEST>` recomputes the plan and rejects a
mismatch before configuration Tcl executes. After managed-server readiness it
uses bounded `0x1a`-framed Tcl RPC to execute only this protocol:

```text
target current                                  -> exact confirmed name
<validated-current-target> curstate             -> running
targets <validated-current-target>; halt        -> poll until halted
targets <validated-current-target>; resume      -> poll until running
shutdown                                        -> graceful OpenOCD exit
```

The runtime name must pass the same 128-byte ASCII allow list used by the
combined GDB session and must exactly equal the confirmed name before target
control starts. A non-running origin is rejected without a halt or resume.
After any halt result, including an error or a failure to observe `halted`, the
tool attempts the one fixed resume transition with a fresh bounded deadline.
The result is successful only when the halt command cleanly reaches `halted`,
the resume command cleanly reaches `running`, OpenOCD shuts down gracefully,
and all logs and process-tree cleanup are complete. Failure evidence preserves
the initial observation, available halt/resume transitions, final state,
readiness, shutdown, and bounded logs. A final state other than proven
`running` is `VERIFICATION_FAILED` and must not be retried automatically.

The explicit halt is a real target-control effect and may interrupt peripheral
activity or external I/O at a partial record boundary. Reviewed configuration
or target grouping may also affect target state beyond the selected core, so
the conservative R2 classification remains. A complete result enables only
server launch, Tcl RPC, selected-target state observation, fixed halt/run, and
verified final restoration. Reset, GDB/MI, register/memory/stack reads,
breakpoints, watchpoints, flash, monitor commands, and arbitrary Tcl remain
false.

## Confirmed OpenOCD selected-target resume-only recovery

`openocd resume plan` accepts the managed OpenOCD inputs, one exact
`--expected-target`, and a final-state deadline bounded to 100..=30000 ms. It
validates target syntax and the deadline before resolving the executable or
reading configuration files. The resulting `R2_DEVICE_WRITE` digest is
independent from server, session, halt/run roundtrip, reset, breakpoint, and
watchpoint digests.

The digest binds the exact executable identity/version, top-level configuration
manifests, ordered search paths, loopback dynamic-endpoint lifecycle, all
deadlines, exact selected current-target name, fixed Tcl protocol, accepted
`halted|running` origin policy, maximum resume count of one, and zero-retry
policy. Search-directory contents, transitive sources, Tcl semantics, runtime
adapter identity, dynamic port numbers, and non-selected target inventory and
states remain explicitly unbound.

`openocd resume test --confirm <DIGEST>` recomputes the plan and rejects a
mismatch before configuration Tcl executes. Its complete fixed protocol is:

```text
target current
  -> exact confirmed selected target name
<validated-current-target> curstate
  -> halted or running; every other state fails before control
if halted only:
  format {__EMBEDDED_DEBUGGER_RESUME_ONLY_V1__%d} [catch {targets <validated-current-target>; resume}]
    -> exact catch code 0, issued at most once
<validated-current-target> curstate
  -> running proven within the bounded deadline
shutdown
  -> graceful OpenOCD exit
```

A target-name mismatch fails before resume. A running origin is idempotent: the
tool sends no resume command and treats the initial observation as the final
running proof. A halted origin receives exactly one fixed catch-wrapped resume,
then bounded state polling. A nonzero or malformed catch envelope, transport
error, missing observation, lifecycle error, or non-running final state fails
closed. Once the managed server has started, every execution error includes the
available initial, transition, final-state, readiness, shutdown, bounded-log,
`resume_command_count`, and `automatic_retry_count=0` evidence. No failure path
sends a second resume or automatically retries the physical operation.

The command sends no halt, reset, flash, register/memory/stack, GDB/monitor,
breakpoint/watchpoint, or arbitrary Tcl request. This narrow command surface
does not mean configuration execution is side-effect-free: OpenOCD configuration
is executable Tcl and can access or reset targets, and resumed firmware can
perform arbitrary firmware-defined I/O. The result observes and proves only the
exact selected target; non-selected target states are not inventoried or
restored. Physical execution always requires two identical host-only plans and
a fresh exact digest confirmation.

## Confirmed OpenOCD reset and selected-target recovery

`openocd reset plan` accepts the managed OpenOCD inputs, one exact
`--expected-target`, and a target-state deadline bounded to 100..=30000 ms. It
validates the target syntax and deadline before resolving the executable or
reading configuration files. The resulting `R2_DEVICE_WRITE` plan is separate
from every server, session, and target-roundtrip digest.

The digest binds the exact executable identity/version, top-level configuration
manifests, ordered search paths, loopback dynamic-endpoint lifecycle, all
deadlines, exact selected current-target name, fixed reset/recovery Tcl catch
envelopes, global reset scope, and selected-target recovery policy.
Search-directory contents, transitive sources, Tcl and reset-event semantics,
runtime adapter identity, dynamic port numbers, and non-selected target
inventory and states remain explicitly unbound.

`openocd reset test --confirm <DIGEST>` recomputes the plan and rejects a
mismatch before configuration Tcl executes. Its complete fixed protocol is:

```text
target current
  -> exact confirmed selected target name
<validated-current-target> curstate
  -> running
format {__EMBEDDED_DEBUGGER_RESET_V1__%d} [catch {reset halt}]
  -> exact catch code 0, then selected target polled until halted
format {__EMBEDDED_DEBUGGER_RECOVERY_V1__%d} [catch {targets <validated-current-target>; resume}]
  -> exact catch code 0, then selected target polled until running
shutdown
  -> graceful OpenOCD exit
```

OpenOCD defines reset as affecting all configured targets and firing reset
events. The result therefore reports global reset effects while proving state
only for the exact selected target. It does not inventory, restore, or verify
non-selected targets. Configuration and reset-event Tcl may have effects beyond
the fixed commands even though only top-level configuration files are hashed.

The selected target must start `running`. A name mismatch or another initial
state stops before reset. After every reset result, including a nonzero catch
code, malformed envelope, transport error, or missing halted observation, the
tool makes one fixed catch-wrapped selected-target resume attempt with a fresh
deadline. It never issues a second reset automatically. Success requires catch
code 0 for reset and recovery, selected-target `halted`, final `running`,
graceful shutdown, complete output drains, and process-tree cleanup. Failure
evidence retains every available transition and lifecycle field; failures must
not be retried automatically.

A complete physically accepted result enables only fixed reset-halt,
selected-target resume, selected-target state observation, and final running
verification. It does not enable `reset init`, configurable reset modes,
non-selected target restoration, GDB/MI, register/memory/stack reads,
breakpoints/watchpoints, flash, monitor commands, or arbitrary Tcl.

ESP32-S3 CPU0 physical acceptance under digest
`534095d32cdd29a88720230ffaaee6dd07edfd4b97fde287e81f436d76d782d6`
proved reset and recovery catch code 0, selected-target
`running -> halted -> running`, graceful process-tree cleanup, exact probe
reattach, and restarted UART heartbeats. OpenOCD also reported resetting CPU1,
but CPU1 examination failed; its final state and restoration remain unverified.
This acceptance does not widen any capability excluded above.

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

## Offline runtime contract setup

`runtime init` creates a new project contract from `--name`, `--board`, and
the existing direct runtime identity and assertion fields. It requires exact
probe, target, port, USB VID/PID, USB serial, ready line, and heartbeat line
inputs; it never discovers values or copies a reference fixture. Defaults match
direct `runtime accept`: 115200 baud, DTR/RTS=false, 15 seconds, 400 ms startup
delay, and three complete heartbeats. Interface, build line, and forbidden lines
are optional. Missing build identity means build correlation is not asserted.

The initializer serializes the existing strict contract schema, validates it
through the acceptance loader before filesystem writes, creates missing parent
directories, and uses exclusive file creation. Existing files are never replaced;
`OUTPUT_EXISTS` returns exit code 2. The contract bytes include a final newline
and are deterministic for identical inputs, independently of output location.
It sets zero transmit/retries, complete cleanup, and separate flash confirmation;
`firmware` is an empty object and `visual` is null. No firmware artifact, memory
layout, security policy, or physical capability is inferred.

`runtime inspect <FILE>` validates an existing contract without writing files.
It reads one bounded regular-file snapshot (at most 1 MiB), uses the same strict
JSON parser and semantic checks as `runtime accept`, and hashes those exact
bytes. Both commands return `scope=host_only_no_hardware_access`, `valid=true`,
an artifact path/size/SHA-256, and the full contract document. The fields
`hardware_identity_verified`, `runtime_firmware_identity_verified`, and
`flash_authorized` are always false. `valid` means configuration validation only,
not an observed device, supported target/backend, executable prerequisite, or
successful hardware acceptance. Global backend and fixture arguments do not
cause backend initialization; no component process is started.

Unknown typed fields, invalid USB IDs, retry or transmit requests, weakened
cleanup, invalid bounds, duplicate forbidden lines, and lines that are both
required and forbidden fail validation. Metadata objects `firmware` and `visual`
remain descriptive: their contents are not interpreted as scripts, artifact
hash checks, or enforced Flash boundaries. Flash still uses its separate plan.
The source contract hash is not a flash confirmation digest. Offline inspection
does not reserve or authorize a later runtime operation; `accept` reloads and
captures the contract actually used, then performs its normal hardware checks.

## Joint runtime acceptance

`runtime accept` composes the existing `snapshot reset-capture` contract with
the external `baud` structured serial contract. It is an
`R1_REVERSIBLE_CONTROL` operation and requires an exact probe selector, target,
serial port, four-digit hexadecimal USB VID/PID, USB serial number, ready line,
heartbeat line, and new evidence path. An exact build-identity line is optional;
when supplied it becomes mandatory. Duration is 1..=120 seconds, monitor startup
delay is 0..=5000 ms, and at least one heartbeat is always required.

Before target control, the command verifies one accessible exact probe and asks
`baud list --json` for one port matching all four serial identity fields. It
requires the selected executable's version output to begin with `baud `. It then
starts exactly one `baud monitor --json` with the selected baud rate, DTR/RTS
values, identity guards, duration, zero transmitted bytes, and a private artifact
directory. A Windows Job Object or Unix process group owns the monitor process
tree; failure and timeout paths request termination and never start a replacement.

After the bounded startup delay, an already exited monitor prevents target
control. Otherwise the command performs exactly one reset-capture through the
selected backend. It waits for the original monitor, validates its process and
JSON exit codes, requires its reported port and baud rate to match, and reads only
JSONL artifacts canonically contained by the reserved artifact directory. JSONL
input is limited to 8 MiB. Receive-event text is concatenated in event order so a
line split across events can be reconstructed; only newline-terminated, exact,
case-sensitive lines satisfy assertions. A partial tail is reported and never
counts.

Success requires monitor completion, reset-capture completion, at least one
exact ready line, the exact build line when configured, and the requested number
of exact heartbeats. The result contains the complete reset report, selected
probe and serial records, assertion counts, fixed effects, ordered operations,
the retained artifact directory, and SHA-256 references for baud stdout, stderr,
JSONL, log, and the final evidence file. `serial_transmit_requested`, `flash_operation_requested`,
`erase_requested`, `recover_requested`, and `non_boot_nvm_access_requested` are
always false. Automatic retries are fixed at zero.

An assertion failure publishes the complete report first, then returns
`VERIFICATION_FAILED` with exit code 3 and the evidence reference. Existing
evidence or artifact paths are rejected before hardware access. A failure before
the serial monitor starts performs no reset; once target control begins, the
reset-capture result or structured error and all available serial artifacts are
preserved. This command does not perform or authorize the separately guarded
flash that must precede a runtime test.

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
address and erase impact from the fixture. Intel `.hex` and `.ihex` files are
auto-detected and may also be selected with `--format hex`. Intel HEX control
records, checksums, EOF placement, 32-bit address bounds, and overlap are
validated before probe enumeration. Parsed data is normalized into contiguous,
non-overlapping physical segments; sparse ranges remain separate. nRF52840
segments wholly inside `0x10001000..0x10002000` are identified as `uicr`.
Planning accepts readable nonvolatile target regions, including non-boot NVM
such as UICR, and reports all affected erase sectors. Intel HEX execution
is independently gated by `capabilities.intel_hex_flash`; segmented execution
also requires `capabilities.segmented_flash`. A segment identified as `uicr`
additionally requires `capabilities.non_boot_nvm_flash`, otherwise the complete
plan is blocked with `NON_BOOT_NVM_EXECUTION_ACCEPTANCE_REQUIRED` before attach.
The sole narrower exception is an explicit
`--allow-nrf52840-development-debug` policy. It is valid only for target
`nRF52840_xxAA`, at least one ordinary data segment wholly within its
`0x00000000..0x00100000` Code Flash, and exactly one four-byte UICR segment at
`0x10001208` containing `5a000000`. Its fixed allowed Code Flash range,
register, value, UICR-page erase range, unwritten-byte preservation,
persistence, and security effect are serialized into `policy` and therefore
bound by `confirm_digest`. Service and backend independently validate the same
contract. Any mismatch fails closed; the option does not set the generic
non-boot-NVM capability.
The target-gated ESP-IDF path requires an explicit
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
- `policy`: erase mode, preservation, verification, post-flash behavior, and
  any exact target-specific persistent configuration exception.
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

`capabilities.intel_hex_flash`, `capabilities.segmented_flash`,
`capabilities.non_boot_nvm_flash`, and `capabilities.multi_core_post_flash` are
false by default and independently target-gated. Ordinary Intel HEX or
segmented code-Flash acceptance never implies permission to mutate UICR or
another non-boot NVM region.
The native probe-rs ESP32-S3 target has passed both acceptance gates.
On 2026-09-04, the nRF52840 target passed one separately confirmed physical
Intel HEX and segmented execution on ordinary code Flash using the official DK.
Both sparse segments verified and complete reset/halt/snapshot/resume evidence
was published. That exact run followed a separately authorized access-protection
recovery and did not independently prove preservation of pre-existing unwritten
bytes or normal application readiness. `non_boot_nvm_flash` remains false, so
this acceptance does not authorize arbitrary UICR. A later exact
development-debug plan may bypass only this one blocker when its target,
payload, erase isolation, policy, and confirmation all match. Replay and CLI
tests cover that narrow path. On 2026-09-05, one separately confirmed probe-rs
execution on J-Link `1366:1061:001050275757` verified the 661-byte smoke code
segment and exact four-byte APPROTECT word, completed reset/halt/snapshot/resume,
and disconnected. This qualifies that exact image and policy; independent
before/after preservation comparison and subsequent serial readiness were not
part of that run. The generic `non_boot_nvm_flash` capability remains false.
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
