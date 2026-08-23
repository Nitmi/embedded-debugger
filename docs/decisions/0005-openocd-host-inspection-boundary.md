# ADR-0005: OpenOCD starts with bounded host inspection

- Status: accepted
- Date: 2026-08-23

## Context

An Agent can invoke OpenOCD directly, but then every caller must independently
resolve distributions, execute configuration, parse logs, choose ports, detect
readiness, terminate processes, and decide which target capabilities are safe
to advertise. OpenOCD configuration files are Tcl programs, so an ad hoc static
parser cannot prove their semantics, while starting OpenOCD merely to inspect a
file may execute adapter and target initialization.

The official [OpenOCD running documentation](https://openocd.org/doc/html/Running.html)
defines `--version`, repeatable `--file` and `--search` options, and warns
against `#` in configuration file names. The
[server configuration](https://openocd.org/doc/html/Server-Configuration.html)
supports loopback binding, disabled services, and OS-selected ports. The
[Tcl RPC interface](https://www.openocd.org/doc/html/Tcl-Scripting-API.html)
uses byte `0x1a` as the command and response terminator, while the general
[`shutdown` command](https://www.openocd.org/doc/html/General-Commands.html)
defines the server exit operation. GDB documents a
specific [`--interpreter=mi2`](https://www.sourceware.org/gdb/current/onlinedocs/gdb.html/Mode-Options.html)
mode for machine clients.

## Decision

1. The first OpenOCD checkpoint is `openocd inspect`, a versioned host-only
   operation. It never attaches to a probe or target.
2. A bare executable name is resolved through `PATH`; an explicit path is
   canonicalized. The exact resolved file alone is launched with `--version`.
3. Version probing has a 100..=30000 ms deadline, captures at most 64 KiB per
   stream, requires a recognizable OpenOCD identity and zero exit status, and
   returns stable errors for missing, timed-out, malformed, or noisy tools.
4. Explicit top-level configuration files and search directories are
   canonicalized, bounded, deduplicated, and kept in argument order. Top-level
   files receive byte counts and SHA-256 identities. Paths containing `#` are
   rejected.
5. Inspection does not parse or execute configuration Tcl and does not resolve
   transitively sourced files. The response states both limitations.
6. Server, Tcl RPC, GDB/MI, target control, and flash capabilities remain false
   until their own lifecycle and hardware acceptance gates pass.
7. A later server checkpoint must bind to `127.0.0.1`, disable telnet, allocate
   GDB and Tcl ports dynamically, prove readiness through framed Tcl RPC, use
   Tcl `shutdown` for graceful exit, and guarantee process-tree cleanup after
   timeout or crash. The version child timeout implemented here does not by
   itself qualify that server process-tree guarantee.
8. Advanced debugger semantics will use GDB with the fixed `mi2` interpreter;
   this project will not maintain a partial GDB Remote Serial Protocol client.

## Consequences

- Agents can deterministically establish whether a selected host tool and
  explicit top-level inputs are usable without touching hardware.
- A successful inspection cannot be mistaken for an OpenOCD target backend;
  every target-facing capability is explicitly false.
- Tcl syntax, transitive `source` resolution, adapter initialization, port
  readiness, and target behavior remain unknown until the managed server layer
  exists.
- Real OpenOCD and GDB toolchains are still required for the next physical
  checkpoint. Replay and temporary process fixtures cover this host contract in
  CI without inventing target evidence.
