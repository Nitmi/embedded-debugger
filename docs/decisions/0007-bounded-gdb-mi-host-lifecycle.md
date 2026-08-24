# ADR-0007: Prove GDB/MI as a bounded host lifecycle before target attachment

- Status: accepted
- Date: 2026-08-24

## Context

The guarded OpenOCD server lifecycle proves a loopback GDB endpoint, but a
listening socket does not prove that a selected GDB executable starts, speaks a
stable machine protocol, correlates requests correctly, or exits cleanly.
Combining both processes immediately would also cross a target-control boundary:
a remote GDB attachment can examine, halt, reset, or otherwise affect a target.

GNU GDB documents GDB/MI as its line-oriented machine interface and recommends
that front ends request a specific version rather than the moving `mi` alias.
The fixed `mi2` interface is widely available and already selected by the
project architecture. GDB also executes system and user initialization files by
default unless explicitly disabled.

## Decision

1. Add `openocd gdb inspect` as a host-only executable identity operation. It
   resolves one exact file, runs bounded `--version`, requires a `GNU gdb`
   identity, and returns the exact file size and SHA-256.
2. Add `openocd gdb test` as a separate host-only managed process. It launches
   only `--nx --nh --quiet --interpreter=mi2` and accepts no user arguments,
   initialization files, symbols, target endpoint, CLI command, or arbitrary MI
   command.
3. The complete input sequence is fixed to tokenized `1-gdb-version` and
   `2-gdb-exit`. Success requires the startup prompt, `1^done`, `2^exit`, and a
   successful process exit. Missing or mismatched tokens fail closed.
4. The parser validates MI framing, record category, token, and result class for
   this fixed exchange. It does not claim a complete AST for arbitrary nested
   MI values and is not exposed as a general command channel.
5. Stdout and stderr are drained concurrently, completely hashed, bounded for
   retention and line length, and forwarded to the parent stderr. Any loss,
   truncation, malformed record, or incomplete drain makes the result
   incomplete.
6. Windows uses a Job Object and Unix a process group. Cleanup covers
   descendants on success, timeout, protocol failure, and drop.
7. The operation is `R0_READ_ONLY` because it starts no OpenOCD server, opens no
   network endpoint, loads no symbols, and connects to no probe or target. It
   requires no mutation confirmation digest.
8. Only the specifically named `gdb_mi_host_process` capability becomes true.
   Remote connection and every target-facing capability remain false. The
   independently proven OpenOCD endpoint and GDB process must not be inferred to
   form a working target session.

## Consequences

- Host tool failures, startup encoding problems, MI framing drift, and leaked
  process trees are detected before any target is involved.
- Direct ASCII writes avoid shell encodings such as a UTF-8 BOM being prepended
  to the first MI token.
- The 10000 ms default version and startup deadlines accommodate the measured
  cold-start cost of the official Espressif Windows distribution while
  retaining hard upper bounds.
- A later combined-session plan must bind the exact OpenOCD plan, GDB
  executable identity, target endpoint, symbol/ELF identity, allowed MI command
  policy, deadlines, and target-state restoration policy. It must receive an
  appropriate risk classification and confirmation before remote attachment.

## References

- [GNU GDB/MI](https://sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI.html)
- [GDB/MI development and front ends](https://sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI-Development-and-Front-Ends.html)
- [GDB/MI miscellaneous commands](https://sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI-Miscellaneous-Commands.html)
- [Espressif ESP-IDF tool manifest](https://github.com/espressif/esp-idf/blob/master/tools/tools.json)
