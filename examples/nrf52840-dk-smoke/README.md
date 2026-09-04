# nRF52840 DK smoke firmware

This standalone, dependency-free Rust firmware provides device-level assertions
for the official nRF52840 DK without enabling UICR or access protection.

It performs two observable actions after reset:

- toggles LED1 on P0.13 (active low);
- sends `EAT_NRF52840_DK_READY v1` once,
  `EAT_NRF52840_DK_BUILD_ID v1 <git-commit>` once, then
  `EAT_NRF52840_DK_HEARTBEAT` repeatedly through UART0 TX on P0.06.

The build ID is bound to the smoke firmware source commit (and gains a
`-dirty` suffix when tracked source changes are present). It is useful for
runtime source-version correlation, but is not a cryptographic attestation of
the final ELF/HEX bytes.

The DK interface MCU routes the application UART to USB Serial Port 0. Observe
it at 115200 baud, 8 data bits, no parity, one stop bit, and no flow control.
The terminal must assert DTR so the interface MCU connects the UART pins; keep
RTS false and transmit no bytes. On a dual-port DK, bind Serial Port 0 by its
exact USB interface identity rather than guessing from the COM number.

## Build

Install the target and LLVM tools once:

```powershell
rustup target add thumbv7em-none-eabihf
rustup component add llvm-tools-preview
```

Then build the ELF and Intel HEX artifacts:

```powershell
.\build.ps1
```

Generated artifacts and their SHA-256 values are printed and written below the
repository's ignored `target/firmware/nrf52840-dk-smoke` directory. The build
also writes a machine-readable artifact `manifest.json`. Flashing is a separate
guarded operation: generate a fresh `embedded-debugger flash plan`, review every
range and effect, and provide the exact confirmation digest before execution.

`test-contract.json` records the bounded hardware-test contract. In particular,
the serial stage must bind an exact COM-port USB identity, assert DTR, keep RTS
false, transmit zero bytes, observe for eight seconds, find the READY line, and
find at least three complete HEARTBEAT lines. Any target mutation defaults to
zero automatic retries.

Pin assignments follow the official nRF52840 DK hardware guide. UART register
addresses and values follow the nRF52840 product specification.
