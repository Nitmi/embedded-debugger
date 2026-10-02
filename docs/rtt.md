# Bounded RTT capture

The `0.2.4` source candidate adds a CLI-first capture workflow. It is not a
published release or a physical hardware acceptance result. It supports Replay
and the probe-rs nRF52840 ARM32 profile; other native targets and OpenOCD RTT
return `CAPABILITY_UNAVAILABLE`. General trace, SWO, down-channel input and
persistent-session/MCP RTT requests are not enabled by this checkpoint.

## Plan and capture

This runnable example uses the repository's synthetic Replay channel and never
touches hardware. Its address is a fixture address, not a board configuration.

```powershell
$cli = 'D:\Code\ai\embedded-debugger\target\debug\embedded-debugger.exe'
$common = @('--json', '--backend', 'replay', '--fixture', 'examples/replay/stm32g4.json')
$selection = @('--probe', 'replay:stlink-v3:0039002A3432510433343034', '--target', 'STM32G431CBTx', '--control-block', '0x20000100', '--duration-ms', '100', '--poll-interval-ms', '5', '--max-bytes', '63')
$plan = & $cli @common rtt plan @selection | ConvertFrom-Json
& $cli @common rtt capture @selection --confirm $plan.data.confirm_digest --evidence 'D:\Code\tmp\new-rtt-evidence.jsonl'
```

Run from the repository root after `cargo build --locked`. Choose a new evidence
path for each capture. For native use, select `--backend probe-rs`, one exact
probe selector and `nRF52840_xxAA`, and obtain the actual initialized
`_SEGGER_RTT` address from the exact firmware/linker output. Do not guess an
address or use the fixture address on a real board. This checkpoint does not
automatically find the symbol or verify what firmware is running.

Planning constructs the built-in target profile and binds the expected probe
selector without enumerating devices, attaching or reading target memory. The
digest includes executor version, protocol/buffer policy, backend, target profile,
probe, core, control-block address, channel, RAM region, limits, chunk bounds and
requested effects. Changed inputs
require a new plan. Native execution resolves one exact accessible probe and
the existing attach path rechecks its identity. The plan digest is a machine
gate; user authorization can cover the bounded task without another manual
question for each sample. It grants no flash or erase permission.

The native reader validates the 16-byte RTT magic, channel counts, selected
32-bit descriptor and ring bounds before consumption. It reads only the header,
one up-channel descriptor and its data spans. It does not read name strings or
other channels. Header/table, read-cursor slot and the data ring must fit in the
same built-in RAM region; the data ring cannot overlap the descriptor table.
Changed static metadata or an unexpected read cursor from another consumer
fails the capture without retry. A running producer may update its write cursor.

RTT consumption advances only the selected descriptor's 32-bit RAM read offset.
Captured bytes are consumed even if evidence storage later fails; consumption
cannot be undone. Up-channel mode is preserved. An empty read does not write the
cursor. No explicit reset, halt, resume, register request, down-channel write,
mode change, arbitrary memory write, flash or recover operation is issued.
Normal debug attachment and session drop can affect target state, so the result
does not claim running state or state preservation after disconnect.

## Bounds and evidence

- Sampling duration: 10..60000 ms, default 5000.
- Captured payload: 1..1048576 bytes, default 65536.
- Poll interval: 1..1000 ms, default 50, no greater than duration.
- Per-read payload: at most 4096 bytes; at most 4096 nonempty chunks.
- Up/down counts in the header: each at most 16; selected up channel 0..15.
- Ring size: 2..1048576 bytes, wholly inside verified RAM.

The capture stops with `duration_limit`, `byte_limit` or `chunk_limit`. These
are successful bounded outcomes, not proof that all firmware output was
observed. Probe I/O latency can extend the wall time: the deadline bounds the
sampling loop, not an interruptible hard deadline for a native transport call
or the preceding attach. A silent channel succeeds with zero bytes; readiness
or heartbeat assertions belong to the caller. Overflow and firmware-side
dropped bytes are not measurable from this RTT header and are not claimed zero.

The JSONL file is exclusively created and receives `capture.started`,
`rtt.channel`, `rtt.chunk` and `capture.finished` records. It is flushed after
each record. Chunk data uses hex to preserve arbitrary bytes and split UTF-8
or binary messages. Each chunk has a sequence, capture-relative byte `cursor`
and `next_cursor`, UTC timestamp, and monotonic elapsed milliseconds. These byte
cursors identify positions within the saved capture, not a target RAM pointer
or a resume token for another capture. Correlation with baud requires a separate
association; clocks do not independently prove device or firmware identity.

The final stdout report contains the exact plan, channel, byte/chunk totals,
stop reason, raw-payload SHA-256, cleanup results and an evidence file reference
with its own byte size/SHA-256. It does not inline the log payload. Once attached,
both channel stop and disconnect are attempted after start, read, validation or
output failure. A failure preserves partial evidence and cleanup errors and
does not automatically restart or retry. A process crash/power loss is outside
the normal cleanup guarantee. An existing evidence path is rejected before
discovery or target attachment.

## Software validation

No attached hardware is required:

```console
cargo test --locked --offline --lib rtt
cargo test --locked --offline --test rtt_cli
```

The fake memory interface exercises the exact native ring-reader code, including
wraparound, foreign cursor movement, reset/corrupt metadata, non-RAM pointers,
read failure and a cursor-write failure without retry. Replay checks lossless
byte reconstruction, hashes, bounds, deadline, partial evidence and cleanup.
These tests do not constitute physical probe-rs/nRF52840 RTT acceptance.
