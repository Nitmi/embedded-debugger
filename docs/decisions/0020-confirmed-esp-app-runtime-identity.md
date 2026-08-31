# ADR-0020: Confirm ESP runtime firmware identity from the mapped app descriptor

- Status: accepted
- Date: 2026-08-31

## Context

Offline ELF stack annotation binds the file used for symbol lookup but does not
prove that the connected target is running that build. This blocks strong use
of ELF-derived addresses for later breakpoint or watchpoint work.

ESP-IDF images expose a 256-byte `esp_app_desc_t` through the allocated,
read-only `.flash.appdesc` section. The source ELF contains descriptor metadata
and a zero `app_elf_sha256` slot. The pinned `espflash 4.5.0` image rule hashes
the complete input ELF and replaces only that 32-byte slot in the generated
image. Reading the mapped descriptor can therefore distinguish ordinary builds
without loading the ELF into GDB.

The descriptor is target-controlled self-description. It is neither signed
attestation nor proof of secure-boot state, and a malicious target can spoof it.

## Decision

1. Add independent `openocd esp-app-identity plan/test` commands. They wrap the
   accepted bounded-memory lifecycle rather than adding another GDB protocol.
2. Require a canonical regular executable ELF of at most 64 MiB, little-endian
   Xtensa or RISC-V 32-bit architecture, with exactly one allocated, read-only,
   four-byte-aligned `.flash.appdesc` section of exactly 256 bytes.
3. Strictly parse descriptor magic `0xABCD5432` and fixed ASCII metadata. Require
   the source ELF's bytes `0x90..0xB0` to be zero.
4. Derive the expected runtime descriptor deterministically: SHA-256 the
   complete exact ELF and copy the 32 digest bytes into `0x90..0xB0`, changing
   no other source-descriptor byte.
5. Require an explicit containing region start, length, and kind. Accept only
   `--region-kind nvm`, verify arithmetic and complete containment, and bind the
   declaration. Continue to report that target memory-map semantics are not
   independently verified.
6. Bind the complete nested memory digest, canonical ELF path, exact ELF bytes
   and hash, section address/layout, source and expected descriptor hashes,
   complete expected descriptor bytes, parser/derivation rule, effects, and
   trust boundary in a new outer digest.
7. The confirmed target exchange remains the fixed five-command memory
   protocol. Its sole explicit payload read is exactly 256 bytes at the
   ELF-declared section address. No ELF or symbols are passed to GDB.
8. Accept success only when all 256 returned bytes exactly equal the derived
   descriptor and the target descriptor parses strictly. Return metadata,
   hashes, and comparison booleans.
9. On mismatch, return `VERIFICATION_FAILED` only after the nested operation has
   detached, restored the selected target to `running`, and cleaned up GDB and
   OpenOCD. Include that cleanup evidence and never retry automatically.
10. Set `runtime_firmware_identity_verified=true` only for exact equality.
    Always keep `cryptographic_authenticity_verified=false`,
    `secure_boot_verified=false`, and
    `target_memory_map_semantics_verified=false`.

## Consequences

- Agents can obtain point-in-time, build-specific evidence before applying
  ELF-derived debug addresses, without enabling GDB auto-load or arbitrary
  memory reads.
- A different ordinary build fails even when project/version text is reused,
  because the complete ELF SHA-256 and every descriptor byte must match.
- The operation remains `R2_DEVICE_WRITE` because reviewed OpenOCD Tcl,
  attach handlers, native Xtensa profile loading, and target interruption retain
  their existing effects.
- This evidence is not a chain of trust. Secure-boot or signed-attestation work
  requires a separate mechanism and confirmation contract.

## References

- [ADR-0012: Confirmed bounded memory snapshot](0012-confirmed-openocd-memory-snapshot.md)
- [ADR-0014: Offline ELF stack annotations](0014-offline-elf-stack-annotations.md)
