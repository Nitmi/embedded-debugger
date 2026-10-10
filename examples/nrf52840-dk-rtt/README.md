# nRF52840 DK RTT acceptance fixture

Development-only, dependency-free Rust firmware for the DK's **onboard** target.
Building this fixture alone does not prove physical RTT support. A separate
single-flash/single-capture DK run passed on 2026-10-10 after an explicitly
authorized access-protection recovery: 7,528 bytes and 40 ordered heartbeats,
with complete native stop/disconnect evidence. See the
[hardware acceptance record](../../docs/hardware-acceptance.md#nrf52840-dk-bounded-rtt-acceptance-2026-10-10)
for executor identities, evidence hashes and limits.

It creates one ARM32 SEGGER-compatible RTT up channel, no down channels, a
1024-byte nonblocking/skip ring, and an ELF `_SEGGER_RTT` symbol. It publishes
data before the write cursor with a memory barrier; the host owns the read cursor.
The producer algorithm is an independent small implementation of the documented
[RTT ring interface](https://kb.segger.com/RTT), not vendored SEGGER code.

The reset handler copies `.data` and clears `.bss` before initializing the control
block. The initial READY/build banner fits in the ring, and the producer waits
for its first consumption before emitting nominal 250 ms heartbeats. Each frame
repeats READY/build and includes an eight-digit hex heartbeat sequence plus a
skipped-frame counter. Partial final lines do not count as complete heartbeats.
This wait is fixture-specific; it is not a proposed policy for normal firmware.

The image contains only Code Flash bytes; it never programs UICR. Its startup
does write the development software `APPROTECT.DISABLE=0x5A`. Improved-APPROTECT
revisions require compatible **pre-existing** UICR provisioning, as described by
[Nordic](https://devzone.nordicsemi.com/nordic/nordic-blog/b/blog/posts/working-with-the-nrf52-series-improved-approtect).
If reattachment fails, stop and preserve evidence; do not automatically recover,
program UICR or add a reset. No UART, BLE, GPIO, motor or other external I/O is
configured by this image. SysTick is polled without interrupts. Panic/fault
handlers stop producing logs and loop; host assertions must then fail.

## Build offline

The existing `thumbv7em-none-eabihf` target and `llvm-tools-preview` are required.
From the debugger repository root:

```powershell
python examples/nrf52840-dk-rtt/build.py --output D:/Code/tmp/new-dk-rtt-build
```

The output directory must not exist. Cargo runs `--locked --offline`. The builder
records source hashes normalized to UTF-8/LF, compiler version, ELF/HEX hashes,
actual RTT symbol addresses and Code Flash ranges. It checks HEX checksums,
overlapping bytes, vector table, RAM symbol sizes/alignment and metadata/ring
non-overlap; UICR/non-Code-Flash bytes fail the build. BUILD_ID binds these source
inputs, not the final binary and not a cryptographic firmware attestation.
Different toolchains can produce different binary bytes with the same source ID;
retain the independent ELF/HEX SHA-256 values in `manifest.json`.

The producer reservation tests run on the host, including exhaustive small-ring
cursor combinations. They neither compile nor execute the MMIO startup:

```powershell
rustc --edition 2024 --test examples/nrf52840-dk-rtt/src/ring.rs -o D:/Code/tmp/new-ring-tests.exe
& D:/Code/tmp/new-ring-tests.exe
python -m unittest discover -s tests -p test_rtt_dk_preparation.py -v
```

## Physical acceptance scope

Only after agreeing that the current DK test firmware may be replaced:

1. Recheck the exact accessible J-Link `1366:1061:001050275757`. Physical routing
   to the onboard chip is a user-confirmed precondition; probe identity alone
   cannot prove it. Exclude competing debug/RTT consumers.
2. Rehash the chosen native executors and unchanged HEX. Use the workstation's
   locked official debugger for its original guarded `flash plan`/`flash execute`
   workflow, once, with verification, reset/halt/snapshot/resume and disconnect.
   Surface all erase/write ranges and blockers first. Do not use the UICR policy.
3. After a successful flash and complete native cleanup, use the separately
   hash-bound local 0.2.4 candidate for `rtt plan`/`rtt capture`, once. Obtain
   `--control-block` from this build's manifest, not an example address. Select
   core 0/up channel 0, `--duration-ms 10000 --poll-interval-ms 50 --max-bytes 65536`.
   The native digest remains a machine guard; it grants no flash authorization.
4. Preserve stdout, stderr, exit codes and a fresh exclusive JSONL evidence path.
   RTT reads metadata/data and updates only the selected RAM read cursor; it does
   not request an extra reset/halt/resume. Attach/drop can affect target state;
   post-disconnect running state is not verified by RTT capture.
5. Evaluate unchanged evidence offline:

```powershell
python scripts/check_rtt_dk_evidence.py --manifest D:/Code/tmp/new-dk-rtt-build/manifest.json --plan D:/Code/tmp/new-rtt-plan.json --report D:/Code/tmp/new-rtt-result.json --evidence D:/Code/tmp/new-rtt.jsonl
```

Require matching native plan, session identity, channel metadata, hashes, chunk
sequence/byte cursors, schema, monotonic elapsed times, successful stop/disconnect
and `duration_limit`. Require the exact initial/repeated READY/build, at least
three complete heartbeats starting at 1 and incrementing by 1, `SKIPPED=0`, and
more than 3072 payload bytes to exercise repeated use of the 1024-byte ring.
Reconstruct raw bytes before assertions; a known partial frame at the end is
allowed. The reported source build identity is telemetry, not binary attestation.

No retries, RAM scan, names/other-channel reads, down-channel input, mode changes,
recover, UICR writes, extra reset, serial or BLE stage belongs to this acceptance.
Stop after the first failed/indeterminate hardware result; preserve partial data
and native cleanup. A later capture needs a new agreed scope and evidence path;
this first-capture fixture assumes freshly reset producer state.
