# ADR-0014: Bind an ELF for offline stack annotation without GDB symbol loading

- Status: accepted
- Date: 2026-08-27

## Context

The bounded OpenOCD stack snapshot deliberately loads no symbols. Its first
ESP32-S3 acceptance returned useful addresses but only `func=??`. Loading an
ELF into GDB would change the target-facing protocol and expand the host trust
boundary: object files can trigger GDB auto-load scripts, separate debug-file
search, and optional debuginfod access. An ELF selected by the user also does
not by itself prove that the connected target is running those exact bytes.

Offline address resolution can avoid those effects when the caller owns all
input loading. `addr2line::Context` accepts caller-provided DWARF sections and
supports inline frames. Its lower-level lookup API explicitly exposes split
DWARF load requests, which can be declined without locating another file.

## Decision

1. Add optional `--elf <FILE>` to `openocd stack plan/test`. Select a separate
   `openocd.stack.annotated.plan/test` operation and outer digest only when it
   is present. Keep the no-ELF path and digest input unchanged.
2. Before hardware access, require a canonical regular, nonempty executable ELF
   of at most 64 MiB. Cap sections at 65,536, symbols at 262,144, and the
   optional build ID at 64 bytes. Reject compressed debug sections rather than
   decompressing attacker-controlled metadata.
3. Bind the complete base stack digest plus the ELF canonical path, exact
   bytes/hash, format/kind/architecture/address width/endianness/entry/build ID,
   fixed parser versions, resolution policy, effects, and boundary.
4. Never pass the ELF path to GDB. Do not run GDB symbol/file commands, an
   external `addr2line`, object auto-load scripts, or embedded host code.
5. Parse only in-memory sections with `object 0.39.1` and `addr2line 0.25.1`.
   Resume at most eight split DWARF continuations per frame with no supplied
   data; terminate that DWARF lookup on a ninth request. Do not read source
   files, GNU debug links, alternate links, DWO/DWP files, or the network.
6. Run annotation only after the base stack test has completed target
   restoration, GDB exit, and OpenOCD cleanup. Never rerun the target operation
   because a frame cannot be resolved.
7. Use the exact level-zero address. For later nonzero frames, subtract one from
   the return address. Resolve only addresses in loadable segments.
8. Examine and return at most eight in-file DWARF frames per stack frame. Fall
   back to the smallest containing defined, nonzero-sized in-file text symbol.
   Bound text to 4096 bytes and reject control characters.
9. Report unresolved frames and whether split DWARF was requested. Never turn
   missing external data or address-specific malformed metadata into an
   external search or a target retry.
10. State that ELF identity is bound while runtime firmware identity is not.
    Keep `runtime_firmware_identity_verified=false`, physical call-stack
    completeness false, implicit unwind addresses unbound, and the base R2 and
    no-automatic-retry policy.

## Consequences

- Agents receive useful function/source annotations without broadening the
  GDB/MI command channel or allowing executable auto-load behavior.
- Exact ELF bytes and policy are reviewable and confirmation-bound, while a
  stale or wrong-but-valid ELF can still produce plausible incorrect names.
- Split/external or compressed debug information is intentionally unavailable;
  some frames remain unresolved even when another tool could locate metadata.
- A future trusted runtime-symbolization claim needs a separate target firmware
  identity mechanism and confirmation contract.

## References

- [GDB/MI file commands](https://sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI-File-Commands.html)
- [GDB auto-loading security](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading.html)
- [GDB separate debug files](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Separate-Debug-Files.html)
- [GDB debuginfod settings](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Debuginfod-Settings.html)
- [`addr2line` caller-managed context](https://docs.rs/addr2line/0.25.1/addr2line/struct.Context.html)
- [ADR-0013: Confirmed bounded stack snapshot](0013-confirmed-openocd-stack-snapshot.md)
