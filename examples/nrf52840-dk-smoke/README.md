# nRF52840 DK smoke firmware

This standalone, dependency-free Rust firmware provides device-level assertions
for the official nRF52840 DK. It is development-only firmware: its image writes
`UICR.APPROTECT=0x0000005A` and its reset path immediately writes
`APPROTECT.DISABLE=0x5A` so nRF52840 Fxx-and-later devices keep SWD debug access
available across resets. Do not copy that policy into a production image.

It performs two observable actions after reset:

- toggles LED1 on P0.13 (active low);
- sends `EAT_NRF52840_DK_READY v1` once,
  `EAT_NRF52840_DK_BUILD_ID v1 <source-manifest-sha256>` once, then
  `EAT_NRF52840_DK_HEARTBEAT` repeatedly through UART0 TX on P0.06.

The build ID is a SHA-256 over a deterministic manifest of the firmware's six
source and build-input files. It remains stable when unrelated repository files
change and is useful for runtime source correlation, but is not a cryptographic
attestation of the final ELF/HEX bytes. The generated `manifest.json` records
every input hash plus the independent ELF and HEX hashes.

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
This image deliberately contains one non-boot-NVM word at `0x10001208`; the
current native execution gate will report
`NON_BOOT_NVM_EXECUTION_ACCEPTANCE_REQUIRED` and refuse to attach until the
target-specific UICR workflow has passed acceptance.

`test-contract.json` records the bounded hardware-test contract qualified on the
repository owner's DK fixture. In particular, it binds the exact J-Link, target,
COM-port USB identity, runtime build line, and the only allowed UICR word;
asserts DTR; keeps RTS false;
transmits zero bytes; observes for 15 seconds; finds the READY line and at least
three complete HEARTBEAT lines; and rejects configured fault or panic lines.
Any target mutation defaults to zero automatic retries. Replace every physical
identity and the build line before reusing the contract for another board or
newly flashed firmware.

Run the combined post-flash acceptance with only the reviewed contract and a
fresh evidence path:

```powershell
embedded-debugger --backend probe-rs runtime accept `
  --contract .\test-contract.json `
  --evidence .\runtime.evidence.json --json
```

The command captures the exact contract bytes and hash alongside the serial and
reset evidence. Contract mode cannot be mixed with direct acceptance options.

Pin assignments follow the official nRF52840 DK hardware guide. UART register
addresses and values follow the nRF52840 product specification.
