# Saved runtime receive bytes

These are unchanged receive-byte reconstructions from the physical nRF52840 DK
A/B managed run on 2026-10-19, using the onboard chip, J-Link
`1366:1061:001050275757` and COM11. Each 15-second zero-transmit observation used
115200 baud, DTR=true and RTS=false. The binary files preserve the CRLF bytes;
`.gitattributes` marks `*.bin` binary.

| File | Bytes | SHA-256 |
| --- | --- | --- |
| nrf52840-dk-A.raw.bin | 956 | c041e8b6598e77becf2ba08451b850679913a9d9410816ab3dfa58a685a51e5c |
| nrf52840-dk-B.raw.bin | 956 | 2270bc8650d98f09999c7a75d88119c38208ae6cca069dc7e9b5065d812dcd64 |

Both captures contain two complete heartbeats, READY, the exact A/B BUILD line,
then 29 complete heartbeats. The full-capture heartbeat count is 31. Tests pin
the byte hashes and exercise native runtime acceptance using a fake serial
driver and Replay debug backend. Re-evaluating saved bytes is an offline
assertion check, not another hardware execution or a new physical qualification
of the revised executable.

Original report: `D:\Code\tools\hil-runner\acceptance\dk-ab-0.2.0-20261019.md`.
Original evidence ZIP SHA-256:
`25d742e1b6ee8905a95ed37806a0b0bd5fde47c68b695d7e537c6907da15129d`.
