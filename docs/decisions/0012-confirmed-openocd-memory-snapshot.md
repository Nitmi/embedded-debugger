# ADR-0012: Confirm bounded OpenOCD memory snapshots with declared regions

- Status: accepted
- Date: 2026-08-24

## Context

The accepted register snapshot proves a fixed GDB/MI target-data exchange, but
it does not authorize memory access. A raw address alone is not enough to call a
read safe: a mistaken address can select MMIO, an alias, an unreadable boundary,
or another target-specific region with side effects. OpenOCD configuration and
attach handlers also retain their broader R2 effects.

GDB/MI defines `-data-read-memory-bytes address count`. Its result is a `memory`
list containing one tuple per successfully read block, with `begin`, `offset`,
`end`, and hexadecimal `contents`. GDB may skip unreadable ranges and split a
request into multiple accessible blocks. A successful MI result therefore does
not by itself prove that every requested byte was returned.

## Decision

1. Add independent `openocd memory plan/test` commands without changing any
   accepted server, session, target, reset, or register confirmation input.
2. Require one exact address and a length of 1..=4096 bytes. Reject zero,
   overflow, and oversize before executable or configuration lookup.
3. Require an explicit containing region start, length, and kind (`ram` or
   `nvm`). Reject MMIO/unknown kinds at the CLI and reject a request that is not
   fully contained in the declared region.
4. Treat the region as user-confirmed input, not a discovered target memory
   map. Bind its bounds and kind in the digest while reporting that its target
   semantics remain unverified. A wrong declaration can still cause a
   side-effectful read.
5. Bind the exact OpenOCD/GDB/profile/config identities, ordered search paths,
   all deadlines, exact target, concrete memory command, complete-coverage
   policy, restoration policy, effects, and confirmation boundary in a new
   digest. Retain `R2_DEVICE_WRITE`.
6. Permit only five MI tokens: version, remote connect, one concrete
   `-data-read-memory-bytes`, detach, and GDB exit. No user expression or
   arbitrary MI text enters the command.
7. Parse the `memory` result structurally. Permit multiple blocks only when they
   begin at relative offset zero, are in strict ascending order, have no gaps or
   overlaps, and cover the exact confirmed length.
8. Require every block to contain exactly the documented four fields. Require
   `begin == requested_address + offset`, treat `end` as exclusive, require the
   address span to equal the decoded hexadecimal byte count, and reject extra,
   empty, malformed, reordered, partial, or out-of-range blocks.
9. Return lowercase hexadecimal data, SHA-256, and per-block evidence. After a
   connected failure, attempt fixed detach before bounded GDB exit, then prove
   the selected running origin was restored and always clean up OpenOCD.
10. Never retry a failed physical test automatically. Keep symbols/ELF,
    register and stack commands, memory writes, breakpoints/watchpoints,
    execution control, flash, monitor input, and arbitrary MI/Tcl unavailable.

## Consequences

- Agents can request an exact bounded RAM/NVM snapshot without receiving a
  general expression evaluator or GDB command channel.
- A partial GDB read is useful failure evidence but never a successful snapshot.
- Planning proves arithmetic and declared-region containment only. It does not
  prove that the target actually maps that region as RAM/NVM.
- Physical qualification still requires a deterministic host-only plan,
  independent digest confirmation, one execution, target restoration, cleanup,
  and an external liveness check where available.

## References

- [GDB/MI data manipulation commands](https://sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI-Data-Manipulation.html)
- [GDB/MI result records](https://sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI-Result-Records.html)
- [ADR-0008: Confirmed OpenOCD and GDB session](0008-confirmed-openocd-gdb-session.md)
- [ADR-0011: Confirmed selected-register snapshot](0011-confirmed-openocd-register-snapshot.md)
