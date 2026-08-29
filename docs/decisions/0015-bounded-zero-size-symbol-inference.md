# ADR-0015: Bound zero-sized text-symbol inference

- Status: accepted
- Date: 2026-08-29

## Context

The first confirmed ESP32-S3 offline-annotation run returned caller address
`0x40378695`. After the non-top-frame return-address adjustment, in-process
DWARF lookup and the nonzero-sized symbol fallback left `0x40378694`
unresolved. GNU `addr2line` reported `Reset` for the same bound ELF and address.

Read-only `nm`, `readelf`, and disassembly evidence identified the difference:
`Reset` is a defined `STT_FUNC` in executable section `.rwtext`, starts at
`0x40378638`, and has declared size zero. The next distinct text symbol in that
section is `save_context` at `0x40378698`. The address is inside the intervening
instructions. The ELF contains 284 defined text symbols: 140 with nonzero size
and 144 with zero size, so dropping every zero-sized function loses substantial
useful metadata.

The same top-frame address has 12 in-file DWARF annotations. The original limit
of eight hid the application entry layers even though the data remained within
a small fixed bound.

## Decision

1. Keep DWARF as the first resolver and explicitly sized text symbols as the
   first symbol-table fallback. Require their declared range to remain within
   the referenced executable section.
2. Consider a zero-sized symbol only when it is a defined text symbol whose
   address lies inside its referenced executable section.
3. Infer its exclusive end from the next strictly greater defined text-symbol
   address in the same section. Use the executable-section end only when no
   later same-section text symbol exists. Symbols at the same address are
   aliases, not end boundaries.
4. Reject empty, overflowing, cross-section, non-executable-section, and spans
   larger than 64 KiB. Invalid or rejected names still act as boundaries, so
   name sanitation cannot extend another symbol's inferred range.
5. Resolve deterministic aliases by inferred range length, nearest start,
   section index, and sanitized name. Never let an inferred candidate displace
   a containing explicitly sized candidate.
6. Serialize inferred results separately as
   `resolution=inferred_symbol_table`. Return `symbol_evidence` containing the
   ELF section index, start, exclusive end, declared size, inferred size, and
   `size_inferred` flag.
7. Raise the returned inline-annotation limit to 16. Permit examination of one
   additional DWARF record solely to determine whether those 16 results were
   truncated, making the bound 17 examined records.
8. Bind symbol counts, both limits, inference span, policy text, capability,
   effects, and confirmation-boundary flag into the outer confirmation digest.
   Keep the base GDB/OpenOCD stack protocol and its digest unchanged.
9. Treat the prior physical acceptance as historical evidence only. The changed
   policy requires a new plan, independent exact-digest confirmation, and at
   most one separately authorized physical execution with no automatic retry.

## Consequences

- Common zero-sized linker and assembly functions become useful without
  invoking an external symbolizer or loading the ELF into GDB.
- An inferred name remains weaker evidence than DWARF or a declared symbol
  extent, and the structured result makes that distinction machine-readable.
- The 64 KiB and same-section constraints deliberately leave ambiguous large
  gaps unresolved rather than assigning a plausible but weak name.
- Host-only verification against the bound heartbeat ELF now returns all 12
  top-frame annotations and resolves `0x40378694` as `Reset` over
  `[0x40378638, 0x40378698)`. It does not prove runtime ELF identity or extend
  the earlier target acceptance.

## Validation

After the host-only checkpoint, the user independently confirmed outer digest
`b85c65e2d3777f3730edf28c8d0fbf9cf2be782ac7121f1b429c638c2aeb4ed2`.
One non-retried ESP32-S3 CPU0 execution returned 12 untruncated top-frame DWARF
annotations through `main` and inferred `Reset` for adjusted caller
`0x40378694` with exact range `[0x40378638, 0x40378698)`. Fixed restoration
proved CPU0 running, managed cleanup completed, dynamic ports were reusable,
and UART heartbeats recovered. Runtime ELF identity, CPU1, implicit unwind
addresses, and physical call-stack completeness remain unqualified.

## References

- [ADR-0014: Bind an ELF for offline stack annotation](0014-offline-elf-stack-annotations.md)
- [`object::ObjectSymbol::size`](https://docs.rs/object/0.39.1/object/read/trait.ObjectSymbol.html#tymethod.size)
- [`addr2line::Context`](https://docs.rs/addr2line/0.25.1/addr2line/struct.Context.html)
