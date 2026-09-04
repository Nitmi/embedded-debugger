# embedded-debugger

`embedded-debugger` is an agent-safe control plane for embedded flashing and
debugging. It is CLI-first: humans, scripts, CI, Skills, and MCP clients will all
use the same versioned domain contract.

The current milestone implements the contract, a deterministic Replay backend,
and a native probe-rs guarded flash workflow:

```text
discover -> select exact probe/target -> flash plan -> confirm digest
         -> sector erase/program -> read-back verify
         -> reset-and-halt -> snapshot -> resume -> evidence
```

Replay is a product backend, not a throwaway mock: it powers CI, regression
fixtures, issue reports, and offline Agent analysis. The OpenOCD target backend
is being enabled in guarded checkpoints. Host inspection and a managed server
lifecycle are available:

```console
cargo run -- openocd inspect \
  --executable openocd \
  --config path/to/board.cfg \
  --search path/to/openocd/scripts \
  --json
```

`openocd inspect` resolves one exact executable, runs only `--version` with a
bounded deadline and output limit, and canonicalizes and hashes the explicitly
listed top-level configuration files. It does not execute OpenOCD configuration
Tcl, connect to a probe, allocate ports, or touch a target. The response is
therefore `scope="host_only"`, `risk="R0_READ_ONLY"`, and explicitly keeps
server launch, Tcl RPC, GDB/MI, target operations, and flash disabled. Repeating
`--config` or `--search` preserves argument order; duplicate paths and paths
containing `#` are rejected. Use `--timeout-ms` to override the 2000 ms version
deadline within 100..=30000 ms.

Executing an OpenOCD configuration is a different risk boundary because `.cfg`
files are executable Tcl. First generate a launch plan, review its disclosed
limits, and then return the exact digest:

```console
cargo run -- openocd server plan \
  --executable openocd \
  --config path/to/board.cfg \
  --search path/to/openocd/scripts \
  --json

cargo run -- openocd server test \
  --executable openocd \
  --config path/to/board.cfg \
  --search path/to/openocd/scripts \
  --confirm <confirm_digest> \
  --json
```

`server test` is conservatively `R2_DEVICE_WRITE`: configuration Tcl can access
the host and target even though the tool itself adds only loopback binding,
dynamic GDB/Tcl ports, a Tcl `version` readiness query, and `shutdown`. The
digest binds the selected executable file and version, top-level config hashes,
search directory paths, and lifecycle deadlines. It does not bind search tree
contents, transitively sourced files, or Tcl semantics. Runtime logs stay on
stderr and in bounded summaries; telnet is disabled, and the complete process
tree is isolated and cleaned up. This checkpoint exposes the dynamic GDB
endpoint but does not yet claim GDB/MI, target operations, or flash.

The GDB host process is enabled as a separate read-only checkpoint:

```console
cargo run -- openocd gdb inspect \
  --executable path/to/gdb \
  --json

cargo run -- openocd gdb test \
  --executable path/to/gdb \
  --json
```

`gdb inspect` resolves and hashes one exact executable (maximum 512 MiB), runs
only bounded `--version`, and requires a `GNU gdb` identity. `gdb test` repeats
that inspection, disables initialization files, fixes
`--interpreter=mi2`, and permits only tokenized `1-gdb-version` and
`2-gdb-exit` commands. It requires the startup prompt, `1^done`, `2^exit`, a
successful process exit, complete bounded output, and descendant cleanup. The
default GDB version and MI startup deadlines are 10000 ms; shutdown is 3000 ms.
Both commands are `scope="host_only"` or
`scope="managed_gdb_mi_lifecycle"` and `risk="R0_READ_ONLY"`: they do not start
OpenOCD, load symbols, open a remote endpoint, connect to a probe, or touch a
target. Only `gdb_mi_host_process` becomes true in the test result. Remote
connection, register/memory/stack access, breakpoints, execution control, and
flash remain false.

The first combined OpenOCD + GDB checkpoint is a separately confirmed target
lifecycle:

```console
cargo run -- openocd session plan \
  --openocd-executable path/to/openocd \
  --gdb-executable path/to/gdb \
  --gdb-xtensa-config path/to/xtensa_target.so \
  --expected-target <exact-openocd-target-name> \
  --config path/to/board.cfg \
  --search path/to/openocd/scripts \
  --json

cargo run -- openocd session test \
  --openocd-executable path/to/openocd \
  --gdb-executable path/to/gdb \
  --gdb-xtensa-config path/to/xtensa_target.so \
  --expected-target <exact-openocd-target-name> \
  --config path/to/board.cfg \
  --search path/to/openocd/scripts \
  --confirm <confirm_digest> \
  --json
```

The optional `--gdb-xtensa-config` selects the exact native target profile
loaded through Espressif GDB's `XTENSA_GNU_CONFIG` environment variable. Its
canonical path, size, and SHA-256 are bound by the combined digest. Ambient
values are removed even when the option is omitted. The selected file is
native host code and is loaded only by the confirmed test, not by the plan.
Use the actual `xtensa-esp-elf-gdb` binary plus the target-specific profile
instead of relying on a launcher that dynamically selects unbound children.

The combined digest binds both executable identities, the optional Xtensa
profile selection and identity, the OpenOCD config manifest and search paths,
the exact expected OpenOCD current-target name, fixed MI2 protocol, deadlines,
and restoration policy. The test refuses to
start GDB unless the runtime current target exactly matches that name and is
`running`. It then permits only version, remote connect, detach, and GDB exit.
Because default OpenOCD attach may halt the CPU, the tool verifies `running`
after GDB cleanup and sends one fixed OpenOCD `resume` fallback when needed.
The operation remains `R2_DEVICE_WRITE` because confirmed config Tcl can do
more than the wrapper requests. It loads no ELF or symbols and sends no
explicit target-data, breakpoint, flash, monitor, or arbitrary command. Normal
remote negotiation may still exchange stop state, target descriptions,
memory-map metadata, or register state; a confirmed OpenOCD attach handler may
also probe flash or reset/halt a protected target. These effects are present in
the plan even though exposed register, memory, stack, breakpoint, watchpoint,
general execution control, flash, and arbitrary-command capabilities stay
false.
OpenOCD does not currently expose a digest-bound USB adapter serial through
this workflow, so the confirmation boundary reports runtime adapter identity as
unbound; use an adapter-specific serial setting in reviewed configuration when
the driver supports one.

Selected OpenOCD register inspection is a separate confirmed checkpoint:

```console
cargo run -- openocd registers plan \
  --openocd-executable path/to/openocd \
  --gdb-executable path/to/gdb \
  --gdb-xtensa-config path/to/xtensa_target.so \
  --expected-target <exact-openocd-target-name> \
  --config path/to/board.cfg \
  --search path/to/openocd/scripts \
  --register pc --register sp \
  --json

cargo run -- openocd registers test \
  --openocd-executable path/to/openocd \
  --gdb-executable path/to/gdb \
  --gdb-xtensa-config path/to/xtensa_target.so \
  --expected-target <exact-openocd-target-name> \
  --config path/to/board.cfg \
  --search path/to/openocd/scripts \
  --register pc --register sp \
  --confirm <confirm_digest> \
  --json
```

The plan accepts 1..=64 restricted ASCII register names, normalizes them to
lowercase, rejects case-insensitive duplicates, and binds both names and order.
The test adds only `3-data-list-register-names` and
`4-data-list-register-values --skip-unavailable x <resolved-numbers>` between
the accepted version/connect and detach/exit commands. Structured MI parsing
resolves each selected name to exactly one runtime register number and requires
one hexadecimal value for every selection; unknown, ambiguous, unavailable,
duplicate, malformed, or extra results fail closed. Failure after connection
still attempts fixed detach, GDB exit, selected-target running restoration, and
OpenOCD cleanup.

This remains `R2_DEVICE_WRITE`: OpenOCD configuration and attach handlers keep
their broader disclosed effects even though the explicit data operation is a
register read. It accepts no ELF, symbols, memory or stack read, breakpoint,
execution-control command, flash, monitor input, or arbitrary MI/Tcl. Do not
retry a failed confirmed test automatically. Controlled process and parser
regressions pass. ESP32-S3 CPU0 has also passed one separately confirmed
`pc/a0/a1/ps` physical snapshot with verified fallback restoration and UART
recovery. Two later, separately authorized, non-retried `pc,a1` snapshots used
the same deterministic plan digest. They returned
`0x420129e4/0x3fcdb550` and then `0x42012a6c/0x3fcdb550`; both restored final
running and recovered consecutive UART heartbeats. These acceptances do not
extend to CPU1, another target, memory at a derived address, or any watchpoint
operation.

Bounded OpenOCD memory inspection is another independent checkpoint:

```console
cargo run -- openocd memory plan \
  --openocd-executable path/to/openocd \
  --gdb-executable path/to/gdb \
  --gdb-xtensa-config path/to/xtensa_target.so \
  --expected-target <exact-openocd-target-name> \
  --config path/to/board.cfg \
  --search path/to/openocd/scripts \
  --address 0x20000000 --length 32 \
  --region-start 0x20000000 --region-length 0x10000 \
  --region-kind ram \
  --json

cargo run -- openocd memory test \
  --openocd-executable path/to/openocd \
  --gdb-executable path/to/gdb \
  --gdb-xtensa-config path/to/xtensa_target.so \
  --expected-target <exact-openocd-target-name> \
  --config path/to/board.cfg \
  --search path/to/openocd/scripts \
  --address 0x20000000 --length 32 \
  --region-start 0x20000000 --region-length 0x10000 \
  --region-kind ram \
  --confirm <confirm_digest> \
  --json
```

The request must be 1..=4096 bytes and fully contained in an explicitly
declared `ram` or `nvm` region. The declaration and arithmetic are digest-bound,
but the tool does not claim that OpenOCD independently verified the target
memory map; a wrong declaration can still cause a side-effectful read. The
fixed MI command may return multiple readable blocks, and the wrapper accepts
them only when their metadata and decoded bytes provide complete ordered
gap-free coverage of the exact request. Partial or malformed results fail
closed and still take the fixed detach, target-restoration, and cleanup paths.
Memory writes, MMIO/unknown declarations, expressions, symbols, stack reads,
breakpoints, execution control, flash, monitor input, and arbitrary commands
remain unavailable in the memory-snapshot workflow. ESP32-S3 CPU0 has passed
one separately confirmed, non-retried `0x42000000 + 32` physical snapshot: GDB
returned complete coverage
with the same SHA-256 as the prior probe-rs snapshot, the fixed fallback
restored CPU0 to running, both process trees and ports were released, and UART
heartbeats recovered. This acceptance does not independently verify the
declared NVM semantics and does not extend to CPU1, another range, or another
target/tool plan. A later separately confirmed, non-retried CPU0 RAM snapshot
read exact candidate `0x3FCDB5F0 + 4` as `ed0a0000` (little-endian `2797`).
That value was strictly between complete zero-transmit UART heartbeat sequences
`2744..2748` before and `2867..2871` after the operation, consistent with the
audited firmware's once-per-second `heartbeat` update. The fixed fallback
restored CPU0 to running, both process trees and dynamic ports were released,
and UART liveness recovered. This is point-in-time operational watch-address
evidence only: separate ELF/register/read operations are not atomic, firmware
continuity and target RAM semantics remain unproven, and no watchpoint
installation or hit is authorized.

ESP runtime firmware identity is a separate, descriptor-specific checkpoint:

```console
cargo run -- openocd esp-app-identity plan \
  --openocd-executable path/to/openocd \
  --gdb-executable path/to/gdb \
  --gdb-xtensa-config path/to/xtensa_target.so \
  --expected-target <exact-openocd-target-name> \
  --config path/to/board.cfg \
  --search path/to/openocd/scripts \
  --elf path/to/firmware.elf \
  --region-start 0x3c000000 --region-length 0x10000 \
  --region-kind nvm \
  --json

cargo run -- openocd esp-app-identity test \
  --openocd-executable path/to/openocd \
  --gdb-executable path/to/gdb \
  --gdb-xtensa-config path/to/xtensa_target.so \
  --expected-target <exact-openocd-target-name> \
  --config path/to/board.cfg \
  --search path/to/openocd/scripts \
  --elf path/to/firmware.elf \
  --region-start 0x3c000000 --region-length 0x10000 \
  --region-kind nvm \
  --confirm <confirm_digest> \
  --json
```

Planning accepts only a little-endian executable Xtensa or RISC-V ELF of at
most 64 MiB with exactly one allocated, read-only, 256-byte
`.flash.appdesc`. It strictly parses the ESP app descriptor, requires the
source `app_elf_sha256` slot at bytes `0x90..0xB0` to be zero, hashes the
complete ELF, and derives the expected image descriptor by replacing only that
slot according to the pinned `espflash 4.5.0` rule. The outer digest binds the
complete nested memory plan, exact ELF and expected descriptor bytes, section
address/layout, explicit containing NVM region, parser policy, and effects.

The test sends the same fixed five-command memory protocol and reads only the
ELF-declared 256-byte descriptor. Success requires exact byte-for-byte equality
and returns `runtime_firmware_identity_verified=true`. A mismatch is reported
only after detach, final-running restoration, and process cleanup, with no
automatic retry. This is strong non-adversarial build identity evidence, not
signed attestation: `cryptographic_authenticity_verified`,
`secure_boot_verified`, and `target_memory_map_semantics_verified` remain
false. ESP32-S3 CPU0 has passed one separately confirmed, non-retried physical
identity run for ELF SHA-256
`676a89d78556f07500fcbe50a17c046c27d9d6e1e425ed9732c6f257a09f7b20`:
the complete target descriptor exactly matched expected SHA-256
`65d77b4a7a7507112ab899dc7d08167dba8ea19d3afb6cfa1c555fb5cc5d5621`,
CPU0 was restored to running, both process trees and ports were released, and
UART heartbeats continued. The confirmed declaration covered 64 KiB from
`0x3c000000`, while OpenOCD's runtime map identified only the first `0x3000`
bytes as FLASH; the exact descriptor read at `0x3c000020 + 256` is inside that
observed range, but the wider declaration and target memory-map semantics
remain unverified. Runtime adapter identity was observed but not digest-bound,
and CPU1 remains outside this acceptance.

Bounded OpenOCD stack inspection is an independent confirmed checkpoint:

```console
cargo run -- openocd stack plan \
  --openocd-executable path/to/openocd \
  --gdb-executable path/to/gdb \
  --gdb-xtensa-config path/to/xtensa_target.so \
  --expected-target <exact-openocd-target-name> \
  --config path/to/board.cfg \
  --search path/to/openocd/scripts \
  --max-frames 16 \
  --json

cargo run -- openocd stack test \
  --openocd-executable path/to/openocd \
  --gdb-executable path/to/gdb \
  --gdb-xtensa-config path/to/xtensa_target.so \
  --expected-target <exact-openocd-target-name> \
  --config path/to/board.cfg \
  --search path/to/openocd/scripts \
  --max-frames 16 \
  --confirm <confirm_digest> \
  --json
```

Add an exact executable ELF when offline function/source annotation is needed:

```console
cargo run -- openocd stack plan \
  --openocd-executable path/to/openocd \
  --gdb-executable path/to/gdb \
  --gdb-xtensa-config path/to/xtensa_target.so \
  --expected-target <exact-openocd-target-name> \
  --config path/to/board.cfg \
  --search path/to/openocd/scripts \
  --max-frames 16 \
  --elf path/to/firmware.elf \
  --json

cargo run -- openocd stack test \
  --openocd-executable path/to/openocd \
  --gdb-executable path/to/gdb \
  --gdb-xtensa-config path/to/xtensa_target.so \
  --expected-target <exact-openocd-target-name> \
  --config path/to/board.cfg \
  --search path/to/openocd/scripts \
  --max-frames 16 \
  --elf path/to/firmware.elf \
  --confirm <annotated_confirm_digest> \
  --json
```

The plan accepts an exact 1..=32 frame limit and binds the fixed command
`3-stack-list-frames --no-frame-filters 0 <limit-1>`. It loads no ELF or symbol
file, runs no Python frame filters, and requests no arguments, locals, or
values. Structured parsing requires levels to be contiguous from zero and each
frame to contain a 64-bit hexadecimal address. Optional function/source text is
bounded metadata only; without a firmware identity it is not a symbolization
claim. Reaching the requested limit reports that additional GDB frames may
exist, and the result never claims that the physical call stack is complete.

The returned frame count is bounded, but the underlying unwind is not an
address-bounded memory operation: GDB may read live registers and target memory
at addresses derived from unwind state. A corrupted stack or unwind state can
therefore reach an unexpected or side-effectful address. That unbound effect is
explicit in the R2 plan and confirmation boundary. Connected failures still
attempt fixed detach, GDB exit, selected-target running restoration, and
OpenOCD cleanup. Do not retry automatically. This workflow does not authorize
symbol/ELF loading, argument/local/value inspection, explicit memory/register
commands, breakpoints, execution control, flash, monitor input, or arbitrary
MI/Tcl. Controlled parser and two-process lifecycle regressions pass; no
physical acceptance is inferred from those tests alone. ESP32-S3 CPU0 has now
passed one separately confirmed, non-retried `--max-frames 8` snapshot: GDB
returned two unsymbolized frames, the fixed fallback restored CPU0 to running,
both process trees and dynamic ports were released, and UART heartbeats
recovered. This exact acceptance does not bind implicit unwind-read addresses,
prove physical call-stack completeness or symbols, qualify CPU1, or extend to
another frame limit, target, tool, profile, or configuration.

With `--elf`, the CLI returns the separate
`openocd.stack.annotated.plan/test` contract. Planning accepts only a regular,
nonempty executable ELF of at most 64 MiB. It binds the canonical path, exact
bytes and SHA-256, format, kind, architecture, address size, endianness, entry,
optional build ID, parser versions, annotation policy, and the unchanged base
stack digest. Inspection permits at most 65,536 sections, 262,144 symbols, and
a 64-byte build ID. The existing no-ELF path remains the exact prior contract.

Annotation happens in process, after the confirmed target restoration and both
managed processes have completed. GDB never receives the ELF path. The tool
does not run ELF auto-load scripts or an external `addr2line`, read source-file
contents, use the network, or locate `.gnu_debuglink`, alternate, or split
DWARF files. Compressed debug sections are rejected before target access.
Level zero uses its exact address; later frames use return address minus one
when nonzero. Per stack frame, the resolver examines at most 17 in-file DWARF
records and returns at most 16 annotations; the extra record is used only to
prove truncation. It resumes at most eight declined split-DWARF continuations;
a ninth request ends that DWARF lookup without loading external data. Fallback
first selects the smallest containing defined nonzero-sized in-file text symbol
whose declared range remains inside its executable section. If none exists, it
may infer a half-open range for a defined zero-sized
text symbol, but only inside the same executable section, only until the next
distinct text-symbol address or section end, and only for a nonempty span no
larger than 64 KiB. Such results use `resolution=inferred_symbol_table` and
include `symbol_evidence` with the section index, exact range, declared size,
inferred size, and inference flag; explicitly sized fallback results return the
same evidence with inferred size zero. Text metadata remains capped at 4096
bytes.

This is identity-bound offline annotation, not trusted runtime symbolization.
The digest proves which ELF bytes were used but does not prove that the
connected target is running those bytes; reports therefore keep
`runtime_firmware_identity_verified=false` and
`physical_call_stack_completeness_proven=false`. The base OpenOCD/GDB protocol,
unbound unwind-read risk, R2 classification, no-retry rule, and all disabled
debug capabilities remain unchanged.

The earlier eight-annotation, nonzero-sized-only policy passed one separately
confirmed ESP32-S3 CPU0 run but produced partial annotation: eight truncated
top-frame entries and one unresolved caller. Its outer digest is historical and
stale for the current policy.

The current policy has now passed its own separately confirmed, non-retried
ESP32-S3 CPU0 run with `--max-frames 8` and the exact 2,221,600-byte Xtensa ELF.
GDB returned level zero `0x420129E4` and level one `0x40378695`. Offline lookup
returned all 12 top-frame DWARF annotations through `main` without truncation,
then adjusted the caller to `0x40378694` and resolved it as
`inferred_symbol_table / Reset` with evidence range
`[0x40378638, 0x40378698)`, declared size zero, and inferred size 96. The single
fixed fallback restored CPU0 running; GDB and OpenOCD exited gracefully; both
dynamic ports were reusable; and zero-transmit UART heartbeats recovered. This
acceptance remains exact to digest `b85c65e2...b4ed2`, ELF, CPU0, frame limit,
tools, profile, and configuration. It does not prove runtime target/ELF
identity, physical stack completeness, bounded implicit unwind addresses, CPU1,
or any broader debugging capability, and it is not standing authorization for
a future physical execution.

Temporary OpenOCD hardware-breakpoint qualification is a separate confirmed
checkpoint:

```console
cargo run -- openocd breakpoint plan \
  --openocd-executable path/to/openocd \
  --gdb-executable path/to/gdb \
  --gdb-xtensa-config path/to/xtensa_target.so \
  --expected-target <exact-openocd-target-name> \
  --config path/to/board.cfg \
  --search path/to/openocd/scripts \
  --address 0x420129E4 \
  --json

cargo run -- openocd breakpoint test \
  --openocd-executable path/to/openocd \
  --gdb-executable path/to/gdb \
  --gdb-xtensa-config path/to/xtensa_target.so \
  --expected-target <exact-openocd-target-name> \
  --config path/to/board.cfg \
  --search path/to/openocd/scripts \
  --address 0x420129E4 \
  --confirm <confirm_digest> \
  --json
```

The plan accepts only one exact nonzero numeric address and fixes
`-break-insert -h *0x...`; it has no symbol, expression, software-breakpoint,
condition, command-list, continue, or hit-wait input. The target is not
intentionally run while the breakpoint is installed. Success requires GDB to
report breakpoint 1 as an enabled `hw breakpoint` at the exact address with
zero hits, then accept its deletion and return an exact empty six-column
breakpoint table before detach and running-state restoration.

This is still `R2_DEVICE_WRITE`. Runtime adapter identity, hardware-breakpoint
capacity, and physical comparator state are not independently bound or read
back. If the breakpoint exchange fails after connection but before normal
detach, the tool attempts fixed delete, list, and detach cleanup before exit.
Every GDB failure records a point-in-time target observation and sends no
additional OpenOCD Tcl resume. GDB detach, GDB exit, or configuration-defined
detach handlers may nevertheless resume the target, so failure can require
manual recovery and must never be retried automatically. Controlled parser and
two-process lifecycle tests pass. One separately confirmed ESP32-S3 CPU0 run at
`0x420129E4` has also passed; that exact acceptance does not generalize to a
later plan or a different target/address.

Temporary OpenOCD hardware-watchpoint qualification is another independent
confirmed checkpoint:

```console
cargo run -- openocd watchpoint plan \
  --openocd-executable path/to/openocd \
  --gdb-executable path/to/gdb \
  --gdb-xtensa-config path/to/xtensa_target.so \
  --expected-target <exact-openocd-target-name> \
  --config path/to/board.cfg \
  --search path/to/openocd/scripts \
  --address <current-runtime-address> \
  --length 4 \
  --region-start 0x3FC88000 \
  --region-length 425984 \
  --region-kind ram \
  --mode access \
  --json

cargo run -- openocd watchpoint test \
  <the-identical-options> \
  --confirm <confirm_digest> \
  --json
```

Only `read` and `access` modes are exposed. They map to GDB `rwatch` and
`awatch`, which GDB defines as hardware-only; ordinary write watchpoints are
not exposed because GDB may implement them by software single-stepping. The
request must be one exact nonzero, naturally aligned 1/2/4/8-byte range wholly
inside a user-declared RAM region. NVM, MMIO, unknown regions, symbols, and
user expressions are rejected before tool lookup.

The fixed MI sequence selects C, creates
`*((char*)0x<address>)@<length>`, lists and strictly classifies the single row,
deletes number 1, proves the canonical table empty, then detaches and exits.
Expression evaluation during creation may read the declared RAM range. A wrong
RAM declaration can therefore make this access side effectful. The target is
never intentionally continued while the watchpoint exists, and no hit is
requested.

Success proves GDB's `hw-rwpt`/`hw-awpt` insertion response, exact
`read watchpoint`/`acc watchpoint` table classification, GDB bookkeeping
cleanup, final running restoration, and process cleanup. It does not prove
physical comparator allocation, target width/capacity support, or physical
comparator cleanup; some resource failures are reported by GDB only when the
inferior resumes. Runtime adapter identity and target RAM semantics also remain
unbound. Failures after insertion attempt fixed delete/list/detach cleanup,
record a point-in-time target state, issue no additional Tcl resume, and must
not be retried automatically. Controlled and CLI coverage passes. One
independently confirmed, non-retried ESP32-S3 CPU0 `access` run over
`0x3FCDB550 + 4` also returned exact `hw-awpt`/`acc watchpoint` evidence,
deleted it, proved the canonical table empty, restored final running, cleaned
both processes and ports, and recovered stable UART heartbeats. That exact
acceptance does not qualify `read`, hit execution, physical comparator
allocation/cleanup, another range/target/tool plan, or a later physical run.

A real temporary hardware-watchpoint hit is a stronger, independent confirmed
checkpoint:

```console
cargo run -- openocd watchpoint hit plan \
  --openocd-executable path/to/openocd \
  --gdb-executable path/to/gdb \
  --gdb-xtensa-config path/to/xtensa_target.so \
  --expected-target <exact-openocd-target-name> \
  --config path/to/board.cfg \
  --search path/to/openocd/scripts \
  --address <current-runtime-address> \
  --length 4 \
  --region-start 0x3FC88000 \
  --region-length 425984 \
  --region-kind ram \
  --mode access \
  --expected-pc-start <derived-pc-start> \
  --expected-pc-length <derived-pc-length> \
  --hit-timeout-ms 10000 \
  --json

cargo run -- openocd watchpoint hit test \
  <the-identical-options> \
  --confirm <fresh-confirm_digest> \
  --json
```

The hit plan reuses all classification checks, then binds asynchronous MI,
all-stop mode, one `-exec-continue --all`, a 100..=60000 ms hit deadline, and
one user-confirmed nonempty expected-PC half-open interval of at most 1 MiB.
The interval is runtime provenance only: neither its executable semantics nor
the identity of the firmware running on the target is verified. While the
watchpoint is active, target firmware executes and may perform arbitrary I/O.

Success requires token-8 `^running` and exactly one mode-specific `*stopped`
record while that single continue operation is outstanding. The asynchronous
stop is normally tokenless; a present token is accepted only when it is exactly
8. The stop must also carry number 1, the exact expression and value-tuple
shape, a top-frame PC inside the confirmed interval, followed by `times=1`,
deletion, an exact empty table, final running restoration, and complete process
cleanup. Result and stop ordering may vary, and repeated running notifications
are accepted. A competing or unrelated stop, nonmatching token, wrong
reason/tuple/PC, unsupported field, timeout, or malformed record fails closed.

If execution may still be running after failure, cleanup attempts exactly one
`-exec-interrupt --all` and requires one tokenless-or-token-8
`signal-received`/`SIGINT` stop before fixed delete/list/detach and bounded
exit. It sends no additional OpenOCD Tcl resume after a GDB failure. Cleanup
handlers may nevertheless resume the target, and incomplete cleanup can leave
state indeterminate. The tool never retries the continue, interrupt, or
physical operation automatically. Generate two identical host-only plans and
obtain a fresh exact digest before every physical `test`; classification
acceptance and all historical digests are insufficient authority.

For stack-local watch values, an ELF frame-relative offset is not a current
runtime address. Bind the exact ELF evidence, derive the variable's frame
offset, and obtain a current frame base through a separately reviewed runtime
operation. Never combine a historical stack-pointer snapshot with a static
offset. In the ESP32-S3 demo evidence, DWARF identifies `heartbeat` as frame
base `a1 + 160`; the previously considered `a1 + 128` slot is a compiler
temporary. A separately confirmed current snapshot returned
`pc=0x420129e4` and `a1=0x3fcdb550`. A later, separately confirmed 2026-09-02
descriptor read verified the same local ELF only at that operation's point in
time. A new separately authorized register snapshot then returned
`pc=0x42012a6c`, again inside that ELF's audited `main` range, with unchanged
`a1=0x3fcdb550`, yielding current arithmetic candidate `0x3fcdb5f0`. The
candidate was then read once under a separate exact confirmed memory plan. It
returned `ed0a0000`, little-endian `2797`, strictly between complete UART
heartbeat sequences `2744..2748` before and `2867..2871` after the operation.
That closed the operational address-evidence prerequisite. Two fresh matching
hit plans then bound exact address `0x3fcdb5f0 + 4`, access mode, expected PC
`[0x420128cd,0x420128d3)`, and one 10-second continue. Under separately
returned digest `29421b87...56d0`, one non-retried physical run produced an
`access-watchpoint-trigger` at `0x420128d0`, changed the canonical hit count
from zero to one, deleted the watchpoint, proved the GDB table empty, restored
CPU0 running, cleaned both process trees and ports, and recovered UART
heartbeats. This exact acceptance proves one GDB-attributed comparator event,
not independent comparator-register state, firmware continuity or identity,
target RAM semantics, CPU1, another address/mode/PC interval, or authorization
for a later physical run.

Selected-target resume-only recovery is an independent confirmed checkpoint:

```console
cargo run -- openocd resume plan \
  --executable path/to/openocd \
  --expected-target <exact-openocd-target-name> \
  --config path/to/board.cfg \
  --search path/to/openocd/scripts \
  --json

cargo run -- openocd resume test \
  --executable path/to/openocd \
  --expected-target <exact-openocd-target-name> \
  --config path/to/board.cfg \
  --search path/to/openocd/scripts \
  --confirm <confirm_digest> \
  --json
```

The digest binds the exact OpenOCD/config identities, fixed catch-wrapped Tcl
protocol, exact selected target, `halted|running -> running` policy, deadlines,
maximum resume count of one, and zero-retry policy. The test validates the
runtime current-target name before control. A halted target receives one fixed
`targets <validated-name>; resume`; a running target receives no control
command and is verified idempotently. A name mismatch or any other initial
state fails before resume. No failure path retries or sends a second resume.

The workflow sends no halt, reset, flash, GDB/monitor, target-data,
breakpoint/watchpoint, or arbitrary Tcl command. It remains
`R2_DEVICE_WRITE`: launching reviewed OpenOCD configuration executes Tcl that
may itself access or reset a target, and resumed firmware may perform arbitrary
peripheral or external I/O. Runtime adapter identity, transitive configuration
sources, and non-selected target states remain unbound. Generate two identical
host-only plans and obtain a fresh exact digest before each physical recovery;
an earlier recovery request or digest is not standing authorization.

ESP32-S3 CPU0 has physically passed only the running-origin idempotent branch
of this workflow under digest
`b7759dc2aa7b60a6e9e71b7c075d6c70ef84b7b9e4536c97ad0d305419b8224f`.
OpenOCD observed CPU0 already running after readiness, so the tool sent zero
resume commands and proved final running plus complete cleanup. The
halted-origin resume command remains physically unqualified. A zero-transmit
post-run UART monitor remained silent, so this acceptance does not claim
firmware liveness or heartbeat recovery.

Direct OpenOCD halt/run qualification is a separate confirmed checkpoint:

```console
cargo run -- openocd target plan \
  --executable path/to/openocd \
  --expected-target <exact-openocd-target-name> \
  --config path/to/board.cfg \
  --search path/to/openocd/scripts \
  --json

cargo run -- openocd target test \
  --executable path/to/openocd \
  --expected-target <exact-openocd-target-name> \
  --config path/to/board.cfg \
  --search path/to/openocd/scripts \
  --confirm <confirm_digest> \
  --json
```

The digest binds the exact OpenOCD/config identities, fixed Tcl protocol,
expected current-target name, deadlines, and `running -> halted -> running`
policy. The test refuses a mismatched target or non-running origin before any
control command. It sends only fixed `targets <validated-name>; halt` and
`targets <validated-name>; resume`, polls the selected target after each, and
attempts resume after every halt result. Final `running` is mandatory even on a
failed halt path. This remains `R2_DEVICE_WRITE` because configuration Tcl is
not semantically bound; the explicit halt can also interrupt peripheral I/O at
a partial record boundary. It does not request reset, GDB, registers, memory,
stack, breakpoints, flash, monitor input, or arbitrary Tcl. Do not retry a
failed test automatically because target outcome may be indeterminate.

The fixed roundtrip has passed physical acceptance on ESP32-S3 CPU0 using the
exact confirmed digest
`06d650bc97d6f055572591a411a6a3be4c60979194aded349d32e869aafa593d`.
The run proved `esp32s3.cpu0` as `running -> halted -> running`, gracefully
released OpenOCD and both dynamic ports, permitted an exact probe-rs reattach,
and recovered zero-transmit UART heartbeats. CPU1 examination still fails on
this fixture and remains unqualified.

Reset qualification is a separate global-effect checkpoint:

```console
cargo run -- openocd reset plan \
  --executable path/to/openocd \
  --expected-target <exact-openocd-target-name> \
  --config path/to/board.cfg \
  --search path/to/openocd/scripts \
  --json

cargo run -- openocd reset test \
  --executable path/to/openocd \
  --expected-target <exact-openocd-target-name> \
  --config path/to/board.cfg \
  --search path/to/openocd/scripts \
  --confirm <confirm_digest> \
  --json
```

The digest binds a fixed `reset halt` Tcl catch envelope, OpenOCD's global
reset scope, exact selected current-target name, catch-wrapped selected-target
recovery, deadlines, and the same executable/configuration identities. The test
accepts only a running selected target, requires exact Tcl catch code 0 for both
reset and recovery, proves that target halted, always attempts the one fixed
recovery, and requires final running plus complete server cleanup. OpenOCD
reset affects all defined targets and fires configuration-defined reset events;
the operation does not inventory, restore, or verify non-selected target states.
It does not use
`reset init`, a second reset fallback, GDB, target-data access, breakpoints,
flash, monitor input, or user Tcl. Do not automatically retry a failure.
Controlled fixtures pass. ESP32-S3 CPU0 physical acceptance used digest
`534095d32cdd29a88720230ffaaee6dd07edfd4b97fde287e81f436d76d782d6`:
the reset and recovery catch codes were 0, CPU0 proved
`running -> halted -> running`, OpenOCD cleaned up without a forced kill, the
exact probe reattached, and zero-transmit UART heartbeats restarted. CPU1 was
reset but still failed examination, so its final state remains unqualified.
Every other physical target requires its own separately confirmed plan.

Native probe discovery is available through the embedded probe-rs library:

```console
cargo run -- --backend probe-rs probes list --json
```

This command is read-only and does not require the standalone `probe-rs` CLI.
The official probe-rs Espressif plugin is registered in-process, so native ESP
USB-JTAG probes and Espressif targets are visible to the embedded library too.

Test an exact probe/target connection without requesting erase, program, reset,
halt, snapshot, or arbitrary user memory access:

```console
cargo run -- --backend probe-rs probes test \
  --probe <vid:pid:serial> --target <exact-target> --json
```

The command performs one attach/disconnect lifecycle and reports the target's
conservative capability matrix as `R1_REVERSIBLE_CONTROL`. probe-rs teardown
can resume a core that was halted before attach, so callers must not treat this
diagnostic as state preserving.

Capture PC, SP, and LR from every enabled core while preserving each core's
original running or halted state:

```console
cargo run -- --fixture examples/replay/stm32g4.json snapshot capture \
  --probe replay:stlink-v3:0039002A3432510433343034 \
  --target STM32G431CBTx --json
```

This `R1_REVERSIBLE_CONTROL` command names every described core, explicitly
reports disabled cores, and returns `original_state`, the halted
`captured_state`, and the final restored `state`. It preserves the observed
core execution state and does not request a reset,
Flash operation, or arbitrary memory write. The structured `effects` field
still reports backend-managed volatile target changes: probe-rs clears hardware
breakpoints on attach, and some target debug sequences change control
registers. On ESP32-S3, the current probe-rs sequence disables multiple
watchdogs during attach/halt. This is why the command is R1 rather than R0.

The versioned core-state contract is available through `core status`,
`core halt`, `core run`, `core continue`, `core continue-until-halt`, and
`core step`. A successful one-shot response guarantees that its final observed
state still describes the target after the debug session has disconnected.
Ordinary actions use `data.core`; the bounded wait uses `data.wait`. This
guarantee is advertised separately as
`capabilities.post_disconnect_core_state`.

`core run` is strict: success means the immediate verification still observed
the core running. `core continue` instead requires a halted origin, resumes
execution, and reports either an immediate running state or a new halted state
with a non-empty halt reason. This distinction matters when a breakpoint is
hit before a strict run verification can observe the transient running state.
`core continue-until-halt` extends the event-oriented form with bounded status
polling. It reports `outcome="halted"` with a reason or a successful
`outcome="timed_out"` with the core still running. Timeout and poll interval are
validated before probe selection, and timeout never pretends that a halt
occurred. In the persistent JSONL path it also leaves the lease usable.
`core step` also requires a halted origin, executes one target instruction, and
must finish halted with `halt_reason="step"`, `pc_before`, `pc_after`, and
`effects.instruction_step_requested=true`. Replay implements and tests all five
core-control actions plus the bounded wait, including repeatable idempotent
halt/run, immediate and delayed breakpoint results, timeout, the halted step
boundary, and state continuity within one backend instance.
Native probe-rs exposes the session-scoped actions, register reads, and bounded
memory reads through the foreground `session serve` owner while its exclusive
lease remains active. ESP32-S3 continue, continue-until-halt, and step are
accepted on CPU0.

Read a bounded set of registers from one core while preserving that core's
original running or halted state:

```console
cargo run -- --fixture examples/replay/stm32g4.json registers read pc sp lr \
  --probe replay:stlink-v3:0039002A3432510433343034 \
  --target STM32G431CBTx --core 0 --json
```

Names and architecture-defined aliases are matched case-insensitively. Omitting
the positional names reads the target's register inventory only when it contains
at most 64 entries; larger inventories require an explicit selection. Each
reading reports its canonical name, aliases, backend register ID, bit width,
kind, and fixed-width hexadecimal value. Floating-point values are returned as
raw register bit patterns. The command halts only the selected core when needed,
verifies restoration to its original state, and disconnects. As with live
snapshots, probe-rs attach sequences can modify volatile debug-control state, so
the result is classified as `R1_REVERSIBLE_CONTROL` and includes `effects`.
Halting can also interrupt an in-flight peripheral or log write; restoring the
core state cannot retract bytes already emitted externally.

Read a bounded byte range from target-described RAM or NVM while preserving the
selected core's original state:

```console
cargo run -- --fixture examples/replay/stm32g4.json memory read 0x20007F00 32 \
  --probe replay:stlink-v3:0039002A3432510433343034 \
  --target STM32G431CBTx --core 0 --json
```

The exact inline limit is 4096 bytes. Planning completes before probe discovery
or attach and accepts only one readable RAM or NVM region assigned to the
selected core. Zero-length, overflowing, cross-region, ambiguous, Generic/MMIO,
and larger requests return `CONFIG_INVALID`. The probe-rs backend uses exact
byte reads rather than an alignment helper that may access bytes outside the
requested range. Results include the target-described region, lowercase hex
data, SHA-256, and `running`/`halted` capture and restoration states. This is an
R1 one-shot observation: other cores and DMA remain live, and attach/halt can
still alter the volatile state disclosed in `effects`. Replay requires explicit
core-state and byte-block evidence; it never invents missing memory content.

All successful one-shot core-state, live snapshot, register-read, and
memory-read reports require `post_disconnect_core_state=true`. Native probe-rs
currently advertises the underlying in-session read and execution-control
capabilities but sets this guarantee to false, so these commands return
`CAPABILITY_UNAVAILABLE` before probe selection. probe-rs 0.32 deconfigures
cores when a `Session` is dropped; this resumes a halted Xtensa core and
disables halting debug on Cortex-M. Persistent native observation and control
therefore use the foreground JSONL session service rather than a short-lived
CLI process:

```console
cargo run -- --backend probe-rs session serve --target esp32s3 \
  --idle-timeout-ms 300000
```

An active lease expires after five idle minutes by default. Set
`--idle-timeout-ms 0` to disable expiry; finite values must be
100..=86400000 ms. `session.open` and `session.status` expose the effective
`lease_policy`. The deadline starts only after a lease opens and restarts after
each structurally valid request has finished and its response has been written.
Blank, malformed, and oversized lines do not renew it. A request already in
flight is never interrupted by the lease timer.

Write one compact JSON request per stdin line. Start with `session.open` and an
exact probe/target, then use the returned `session_id` for `session.status`,
`core.status`, `core.halt`, `core.run`, `core.continue`,
`core.continue_until_halt`, `core.step`,
`breakpoints.list`, `breakpoints.set`, `breakpoints.clear`,
`breakpoints.clear_all`, `registers.read`, `memory.read`, and `session.close`.
For example:

```json
{"schema_version":"1.0","request_id":"req-registers","operation":"registers.read","session_id":"ses_<opaque>","core":0,"names":["pc","sp","lr"]}
{"schema_version":"1.0","request_id":"req-memory","operation":"memory.read","session_id":"ses_<opaque>","core":0,"address":"0x42000000","length":32}
{"schema_version":"1.0","request_id":"req-step","operation":"core.step","session_id":"ses_<opaque>","core":0}
{"schema_version":"1.0","request_id":"req-breakpoint","operation":"breakpoints.set","session_id":"ses_<opaque>","core":0,"address":"0x420129D4","slot":0}
{"schema_version":"1.0","request_id":"req-continue","operation":"core.continue","session_id":"ses_<opaque>","core":0}
{"schema_version":"1.0","request_id":"req-wait","operation":"core.continue_until_halt","session_id":"ses_<opaque>","core":0,"timeout_ms":5000,"poll_interval_ms":25}
{"schema_version":"1.0","request_id":"req-clear","operation":"breakpoints.clear","session_id":"ses_<opaque>","core":0,"slot":0}
```

`core.step` is only accepted while the selected core is halted; it preserves
that halted execution state within the active lease while advancing one
instruction and reports the R1 instruction effect. `core.continue` is also
halted-only, but unlike strict `core.run` it treats an immediate breakpoint hit
as a successful observed result instead of a protocol failure.
`core.continue_until_halt` additionally polls until a halt or its bounded
deadline. A `timed_out` response is successful, leaves the core running, and
keeps the lease usable. The current JSONL server processes one request at a
time, so this request occupies the server until it returns; a second JSONL
request cannot asynchronously cancel it.

Hardware-breakpoint capacity is negotiated from the live core during
`session.open`; ESP32-S3 CPU0 currently reports two accepted slots. Listing
returns every slot and is allowed while running. Mutations require a halted
core. Set accepts an optional slot, otherwise chooses the lowest free slot;
repeating the same address is idempotent, occupied-slot overwrites are rejected,
and clear/clear-all are also idempotent. Every result carries the complete
`before` and `after` slot inventory plus explicit verification effects.

Register and memory reads preserve the core's running or halted state within
the active lease and return structured R1 `effects` plus ordered operations.
Memory reads keep the same target-region and 4096-byte bounds as the one-shot
command. Finish with `server.shutdown`. Responses are one versioned JSON object
per stdout line; diagnostics stay on stderr. Core responses are explicitly
scoped to the active session. Close, stdin EOF, and idle expiry first halt cores
with managed breakpoints, clear and verify all of their slots, then run every
observed core and disconnect. Successful expiry emits a versioned
`session.idle_expired` lifecycle object with the complete close report on
stderr, then exits with code 0. See [`docs/contracts.md`](docs/contracts.md) for
the wire contract.

### MCP stdio adapter and supervisor

The preferred Agent entry point is a bounded supervisor around the thin MCP
adapter. The child still uses the same persistent session owner; neither layer
introduces a second hardware API or cleanup policy:

```console
embedded-debugger --backend probe-rs supervisor mcp --target esp32s3 \
  --idle-timeout-ms 300000 --max-restarts 3 --restart-delay-ms 250
```

After `initialize`, call `tools/list` and use the single
`embedded_debugger_request` tool. Its arguments are the persistent JSONL
fields with a required `operation`, so `session.open` returns the opaque
`session_id` used by later `core.*`, `breakpoints.*`, `registers.read`,
`memory.read`, and `session.close` calls. The tool returns the normal
versioned envelope in both `structuredContent` and text content; operation
failures retain the same stable error codes. Flash planning/execution and
one-shot commands remain CLI operations. Plugin manifests are provided in
`mcp.json` (Agent Plugins) and `.mcp.json` (Codex plugin validation).

On an unexpected child exit, every unanswered request receives JSON-RPC
`-32001` with an explicit indeterminate-target warning and is never replayed.
The supervisor starts a fresh child within its bounded restart budget and
privately restores only the side-effect-free MCP initialize handshake. The
external client remains on one standards-compliant lifecycle; an old
`session_id` is rejected by the fresh owner and must be replaced through a new
exact `session.open`. Requests arriving during the short private handshake get
retryable `-32002` without being forwarded. Structured restart events stay on
stderr. A hard child kill can still leave target state unknown, so restart is
availability recovery, not proof of core or breakpoint cleanup. Run `mcp serve`
directly only when a process manager already owns this lifecycle.

Exercise the target's accepted reset policy without flashing it:

```console
cargo run -- --backend probe-rs snapshot reset-capture \
  --probe <vid:pid:serial> --target <exact-target> --json
```

This command performs a system reset-and-halt, captures PC/SP/LR from every
available core, restores each core to its explicit `expected_final_state`, and
disconnects. On the accepted ESP32-S3 policy, CPU0 resumes while secondary
cores preserve the state in which the reset sequence left them. The result sets
`effects.reset_requested=true`; it never requests erase or program.

## Build

```console
cargo build
cargo test
```

## Quick start

Inspect the environment and validate the bundled fixture:

```console
cargo run -- doctor
cargo run -- --fixture examples/replay/stm32g4.json replay validate
cargo run -- --fixture examples/replay/stm32g4.json probes list
```

Create a flash plan for the bundled dummy firmware:

```console
cargo run -- --fixture examples/replay/stm32g4.json flash plan examples/firmware/demo.bin --json
```

Copy the returned `confirm_digest` into the execute command:

```console
cargo run -- --fixture examples/replay/stm32g4.json flash execute examples/firmware/demo.bin \
  --confirm <digest> --evidence run.evidence.json --json
```

Changing the firmware, target, or probe changes the digest. Execution rejects a
stale or incorrect confirmation before a backend write is attempted.

## Native probe-rs flash

List probes and create a plan for a raw BIN image:

```console
cargo run -- --backend probe-rs probes list --json
cargo run -- --backend probe-rs flash plan firmware.bin \
  --probe <vid:pid:serial> --target STM32G431CBTx \
  --base-address 0x08000000 --json
```

Review the returned `ranges`, `erase_ranges`, `policy`, and exact identities,
then execute with the same selection and returned digest:

```console
cargo run -- --backend probe-rs flash execute firmware.bin \
  --probe <vid:pid:serial> --target STM32G431CBTx \
  --base-address 0x08000000 --confirm <digest> \
  --evidence run.evidence.json --json
```

The executable native workflow accepts raw BIN data in readable boot flash. It
erases only affected sectors, restores bytes outside the image within those
sectors, does not grant full-chip erase permission, verifies by read-back,
captures PC/SP/LR while halted after reset, resumes the core, disconnects, and
then atomically publishes complete evidence. Device-write plans require a probe
that reports a non-empty hardware serial number, so reconnecting another
same-model probe cannot silently satisfy an old confirmation digest.

## Intel HEX sparse image planning

Intel HEX files are normalized into ordered physical-address segments without
attaching to the target. The format is auto-detected from `.hex` and `.ihex`
filename extensions, or can be selected explicitly with `--format hex`:

```console
cargo run -- --backend probe-rs flash plan whole.hex \
  --probe <vid:pid:serial> --target nRF52840_xxAA --json
```

Parsing fails closed on malformed record lengths, invalid checksums, missing or
misplaced EOF records, unsupported record types, 32-bit address overflow, and
overlapping data records. Contiguous records are merged; sparse ranges remain
separate and each normalized segment receives its own SHA-256. For
`nRF52840_xxAA`, segments wholly inside `0x10001000..0x10002000` are
labeled `uicr` in the plan.

probe-rs planning accepts segments in readable nonvolatile regions, including
nRF52 UICR, and reports the complete affected erase-sector set. The confirmation
digest binds the original HEX hash and size, normalized segment addresses,
lengths and hashes, erase impact, exact probe/target identity, policy, and
execution blockers. Intel HEX execution is deliberately unavailable and reports
`INTEL_HEX_EXECUTION_ACCEPTANCE_REQUIRED` until target-specific sparse-flash and
non-boot-NVM acceptance is completed.

## ESP-IDF physical image planning

An ESP-IDF application ELF can be normalized into its physical bootloader,
partition-table, and application segments without attaching to the target:

```console
cargo run -- --backend probe-rs flash plan app.elf \
  --probe <vid:pid:serial> --target esp32s3 \
  --format idf --flash-size 8MB --json
```

The format and flash capacity are explicit safety inputs; `.elf` is not guessed
to mean ESP-IDF. `--chip-revision <number>` is available when image generation
depends on a silicon revision. The plan records the source hash and size,
generated byte count, each physical segment and hash, image-generation options,
write and erase ranges, exact probe/target identity, and execution readiness.
The confirmation digest binds all of those fields.

Image normalization uses the pinned espflash 4.5.0 library. The declared flash
capacity must fit the target package's boot-flash address window. The shared
execution layer can stage all physical segments in one transaction, verify each
segment independently, and publish per-segment results in evidence. Replay
exercises that full path with a single-core ESP32-C3 fixture and the complete
multi-core evidence path with an ESP32-S3 fixture.

Native execution remains target-gated. A probe-rs target must explicitly
advertise `segmented_flash` only after physical acceptance, and multi-core
targets also require a complete post-flash reset/snapshot/resume policy.
ESP32-S3 has passed both gates on native USB-JTAG: its normalized ESP-IDF plan is
executable after exact digest confirmation. Other targets continue to report
explicit blockers until their own physical acceptance is complete.

## Design constraints

- Successes and failures have a stable `schema_version` and `operation_id`.
- Hardware mutation requires a plan and exact confirmation digest.
- Backends advertise capabilities; callers do not infer them from backend names.
- Evidence is written atomically and referenced by SHA-256.
- Replay fixtures are validated and cannot silently opt into unsupported behavior.
- A complete evidence bundle means the debug session was also disconnected.

See [docs/contracts.md](docs/contracts.md),
[ADR-0001](docs/decisions/0001-cli-first-control-plane.md),
[ADR-0002](docs/decisions/0002-core-state-follows-session-lifetime.md),
[ADR-0003](docs/decisions/0003-persistent-session-jsonl-lease.md), and
[ADR-0004](docs/decisions/0004-fail-closed-mcp-supervision.md), and
[ADR-0005](docs/decisions/0005-openocd-host-inspection-boundary.md),
[ADR-0006](docs/decisions/0006-guarded-openocd-server-lifecycle.md), and
[ADR-0007](docs/decisions/0007-bounded-gdb-mi-host-lifecycle.md), and
[ADR-0008](docs/decisions/0008-confirmed-openocd-gdb-session.md),
[ADR-0009](docs/decisions/0009-confirmed-openocd-target-state-roundtrip.md),
[ADR-0010](docs/decisions/0010-confirmed-openocd-reset-recovery.md),
[ADR-0011](docs/decisions/0011-confirmed-openocd-register-snapshot.md),
[ADR-0012](docs/decisions/0012-confirmed-openocd-memory-snapshot.md),
[ADR-0013](docs/decisions/0013-confirmed-openocd-stack-snapshot.md),
[ADR-0014](docs/decisions/0014-offline-elf-stack-annotations.md),
[ADR-0015](docs/decisions/0015-bounded-zero-size-symbol-inference.md),
[ADR-0016](docs/decisions/0016-confirmed-openocd-hardware-breakpoint-roundtrip.md),
[ADR-0017](docs/decisions/0017-confirmed-openocd-hardware-watchpoint-roundtrip.md),
[ADR-0018](docs/decisions/0018-confirmed-openocd-hardware-watchpoint-hit.md),
[ADR-0019](docs/decisions/0019-confirmed-openocd-selected-target-resume.md), and
[ADR-0020](docs/decisions/0020-confirmed-esp-app-runtime-identity.md).

## Current status

Replay and native probe-rs guarded application flashing are implemented.
Native discovery and attach/disconnect have been exercised on an nRF52840 over
J-Link and an ESP32-S3 over native ESP USB-JTAG. An nRF52840 single-page guarded
write has passed exact-digest confirmation, read-back verification, unwritten
byte preservation, reset/halt/snapshot/resume, complete evidence inspection,
backup comparison, and serial runtime checks. The same preservation guarantees
also passed for a 32-byte image crossing two adjacent 4 KiB pages. Physical
probe removal returns stable unavailable errors without selecting another
connected probe or creating evidence. ESP-IDF ELF normalization, segmented
staging, per-segment verification, and single- and multi-core post-flash
evidence reporting now pass end-to-end Replay coverage. Native ESP execution
has now passed on ESP32-S3: exact-confirmation segmented programming, independent
per-segment verification, preservation of every byte outside the image ranges,
multi-core post-reset evidence, a full 16 MiB external readback, and serial
heartbeat checks all succeeded. System-reset snapshots also passed. Live
snapshots and bounded register and RAM/NVM reads passed running-origin ESP32-S3
exercises, including pre-attach MMIO and size rejection plus serial heartbeat
recovery, but are now native capability-gated because halted-origin teardown is
not state preserving. OpenOCD host inspection and guarded managed-server
planning are implemented. The server launcher fixes loopback-only dynamic
endpoints, disables telnet, proves Tcl readiness, performs graceful shutdown,
bounds logs, and enforces process-tree cleanup. Its exact-confirmation Windows
lifecycle passed on ESP32-S3 native USB-JTAG, including dynamic endpoints, Tcl
version/shutdown, exit and port cleanup, probe-rs reattach, and UART heartbeat
recovery. OpenOCD reported CPU0 examination success but CPU1 examination
failure. A separate Espressif GDB 17.1 host-only checkpoint now proves fixed
MI2 startup, token-correlated version/exit commands, graceful exit, bounded
output, and Windows Job Object cleanup without opening a remote connection. A
confirmed combined-session implementation now adds a running-origin
precondition, fixed MI version/connect/detach/exit exchange, fixed resume
fallback, final running-state verification, and complete two-process cleanup.
Its controlled regression path passes. The first physical ESP32-S3 attempt
failed closed during remote register negotiation because a generic Espressif
GDB was launched without its ESP32-S3 Xtensa profile. Both process trees were
cleaned, the fixed fallback restored CPU0 to `running`, probe-rs reattached,
and UART heartbeats resumed. The exact profile is now hash-bound, and a second,
separately confirmed physical run completed the fixed MI version/connect/
detach/exit exchange. The fixed fallback restored CPU0 to `running`, both
process trees and dynamic ports were released, probe-rs reattached, and UART
heartbeats continued. This accepts only the narrow combined lifecycle. A
separate selected-register snapshot has passed its own exact-digest ESP32-S3
CPU0 physical acceptance, including ordered values, fallback restoration,
process cleanup, and UART recovery. A bounded declared-region memory snapshot
has also passed its own exact-digest ESP32-S3 CPU0 physical acceptance for
`0x42000000 + 32`, including complete byte coverage, fallback restoration,
process cleanup, and UART recovery. Its NVM declaration remains user-confirmed,
not OpenOCD-memory-map verified. A separate bounded stack-snapshot workflow has
also passed one exact-digest ESP32-S3 CPU0 physical acceptance with
`--max-frames 8`: GDB returned two unsymbolized frames, fallback restoration
proved final running, resources were released, and UART recovered. Only the
returned frame range is bound; implicit unwind-read addresses, symbol identity,
and physical call-stack completeness remain unproven. The separate offline
ELF-annotation contract has also passed one exact-plan ESP32-S3 CPU0 run: one
top frame resolved to eight bounded DWARF annotations, one caller remained
unresolved, and cleanup plus UART recovery completed. A separate temporary
OpenOCD hardware-breakpoint roundtrip now passes strict parser, digest,
two-process success, and failure-cleanup regressions. One independently
confirmed, non-retried ESP32-S3 CPU0 run at `0x420129E4` also proved the exact
hardware insertion, deletion, empty GDB table, final running state, graceful
cleanup, reusable ports, and UART recovery. Physical comparator state and
capacity remain independently unverified. A separate temporary OpenOCD
hardware-watchpoint workflow now has strict `read`/`access` planning,
classification, cleanup, digest, controlled-process, and CLI coverage. One
independently confirmed, non-retried ESP32-S3 CPU0 `access` run over
`0x3FCDB550 + 4` proved the exact GDB hardware classification, deletion, empty
table, final running state, graceful cleanup, reusable ports, and UART
recovery. `read` mode, comparator allocation, width/capacity support, hit
behavior, and physical cleanup remain unqualified. A separate bounded
ESP app-descriptor identity workflow now has strict ELF/descriptor parsing,
nested memory and outer confirmation digests, exact-byte comparison, and fixed
detach/restoration/cleanup coverage. One independently confirmed, non-retried
ESP32-S3 CPU0 run verified the exact local ELF SHA-256 against the 256-byte
runtime descriptor, restored CPU0 to running, released both process trees and
dynamic ports, and preserved UART heartbeats. This is point-in-time,
non-adversarial build identity only: authenticity, secure boot, target
memory-map semantics, and digest-bound adapter identity remain false. A
separate bounded hardware-watchpoint-hit workflow now adds asynchronous
all-stop execution,
strict token/reason/value/PC attribution, one-hit table verification, bounded
interrupt cleanup, deterministic confirmation, and controlled host coverage.
Its physical ESP32-S3 acceptance remains pending. GDB-loaded symbols,
trusted runtime symbolization, argument/local/value
inspection, general ELF/HEX loading, RTT, memory writes, Generic/MMIO or
undeclared-region reads, register writes, software/symbolic/conditional
breakpoints, persistent OpenOCD breakpoints, breakpoint-hit execution,
write-only or persistent watchpoints,
asynchronous request cancellation, durable crash recovery,
multi-client arbitration, other physically accepted native segmented targets,
and non-boot NVM writes are not yet exposed. A separate fixed direct-OpenOCD
`running -> halted -> running` command now passes controlled process/Tcl
regressions and exact-digest physical acceptance on ESP32-S3 CPU0; it does not
expose general execution control. A separate fixed global-reset and
selected-target-recovery command now passes controlled Tcl/status/cleanup
regressions and exact-digest physical acceptance on ESP32-S3 CPU0; it does not
claim non-selected target restoration. The core
status/halt/run/continue/continue-until-halt/step contract is complete in
Replay. Its session-scoped native path, idle lease expiry, and slot-addressable
hardware breakpoints are accepted on ESP32-S3 CPU0; live attach negotiates two
comparator slots. Native one-shot
commands that promise a final core state remain capability-gated because
probe-rs cannot guarantee every reported execution state across session
teardown. The MCP stdio adapter and the `skills/embedded-debugger` Skill now
expose the same persistent session contract to Agent clients. Replay covers
the complete handshake and open/close lifecycle offline, and the same
handshake, CPU0 status, close, and shutdown path has passed a native ESP32-S3
USB-JTAG smoke run. A second native lease also passed MCP register and mapped
NVM reads, CPU0 halt/status/step/run, immediate hardware-breakpoint hit and
exact PC verification, comparator clear, complete close/disconnect, bounded
continue-until-halt event/timeout results, and supervised idle expiry cleanup.
The bounded MCP subprocess supervisor now passes Replay coverage for transparent
proxying, standards-compatible private handshake restoration, stale-session
rejection, startup validation, and restart exhaustion. The same outer-connection
recovery, stale-session rejection, new lease, complete close/disconnect, and
probe release path passed native ESP32-S3 idle-child replacement acceptance.
See `CHANGELOG.md` and
[docs/hardware-acceptance.md](docs/hardware-acceptance.md).

## Acknowledgments

The architecture review included
[Adancurusul/embedded-debugger-mcp](https://github.com/Adancurusul/embedded-debugger-mcp),
probe-rs, OpenOCD, GDB/MI, and the existing Nitmi `baud-cli` and `blea`
projects. See `NOTICE` for the current source-reuse status.

## License

MIT
