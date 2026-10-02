# 0021: Bounded RTT up-channel capture

Status: implemented local candidate; physical acceptance pending.

## Decision

Keep RTT in the debugger backend, sharing its probe ownership and exact identity
checks. Introduce a host-only immutable plan and one bounded capture service,
with default unsupported backend methods. A standalone trace process must not
open the same probe concurrently with a debug session. Persistent RTT requests
can reuse these backend methods in a later checkpoint.

The initial native profile is nRF52840 ARM32, little-endian. Use probe-rs memory
access, but parse only the supplied header and selected descriptor. The upstream
RTT attachment helper discovers all channels and their name strings; that would
expand the memory-read scope beyond this selected-channel operation. This
implementation follows the standard RTT header/descriptor layout without
scanning, following names, changing mode or enabling a general memory-write API.

## Consequences

RTT output is not a pure target read: the consumer must advance one RAM read
cursor. Plans expose that exact write, and ring boundaries are verified against
the built-in RAM map. The read path remains hardware-free to test through a
memory interface; Replay contains explicit channel byte fixtures and optional
failure injection instead of fabricating target output.

Capture output is a versioned summary plus bounded JSONL artifact. Separate
payload/artifact hashes, wall and monotonic clocks, byte cursors and explicit
stop/cleanup results support offline review. Partial data and cleanup errors
survive failure. Normal capture issues no explicit target execution control and
never claims that attach/drop preserved running state. Firmware-side overflow
cannot be inferred; a byte/time/chunk boundary is a bounded capture, not an
assertion that the complete stream was received.

This checkpoint leaves SWO, defmt decoding, interactive input, ELF symbol
discovery, merged serial timelines, persistent RTT/MCP requests and physical
hardware acceptance for later work. It does not replace the authorized flash
session policy, firmware runtime identity assertions or Toolkit component lock.
