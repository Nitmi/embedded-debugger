# Local CLI installation

For a precompiled Windows x64 candidate without Rust, use the
[binary package workflow](binary-release.md). Do not extract it over a
Cargo-managed installation; keep source and archive installation paths distinct.

From a trusted source checkout, the package tool can install a verified candidate
into a version-and-target-specific directory without executing it or changing
`PATH`:

```console
python scripts/package_binary.py install <archive.zip> --checksum <archive.zip.sha256> --install-root <directory> --json
```

The command validates the archive before writing, stages new files before an
atomic directory rename, and writes `installation.json` with the archive,
manifest, executable and source identities. Repeating the exact install is
idempotent. Any changed, missing or extra file in an existing destination is an
error; the command never repairs or overwrites it. Select the returned full
executable path explicitly for host checks and toolkit configuration. Retaining
older version directories provides rollback without changing Cargo ownership.

## Install from a trusted checkout

Use Rust 1.89 or newer and the native compiler/linker prerequisites needed to
build this repository. On Windows with the MSVC target, this includes the C++
build tools and Windows SDK. Review and select the intended source revision
before installing; a local path builds the current checkout, including edits.
Build dependencies can execute host build scripts, so only use trusted sources.

From the repository root:

```console
git status --short
git rev-parse HEAD
cargo install --path . --locked --bin embedded-debugger
```

This uses the release profile and preserves the checked-in dependency lockfile.
Add `--offline` when the locked dependencies are already cached; missing cached
dependencies cause an error, not an implicit network fallback. The first build
may otherwise need network access and can take several minutes.

Cargo manages the installed executable and its package record. With the default
Cargo home, the executable is `~/.cargo/bin/embedded-debugger` (with `.exe` on
Windows). Cargo root/home overrides can change the destination; check the actual
installation output and `cargo install --list`. Keep that installation's `bin`
directory on `PATH`, not the source checkout's `target/release` directory.
No custom launcher, plugin reinstall, or target configuration is required.

## Verify without hardware

From a directory outside the source checkout:

```console
embedded-debugger --version
embedded-debugger runtime --help
cargo install --list
```

For the `0.2.1` release, the version must be `embedded-debugger 0.2.1` and runtime
help must include `init` and `inspect`. On PowerShell, check command resolution
and record the actual installed binary hash:

```powershell
Get-Command embedded-debugger -All
Get-FileHash (Get-Command embedded-debugger -CommandType Application).Source -Algorithm SHA256
```

If multiple commands are found, resolve PATH precedence before using hardware.
Do not use `doctor`, `probes list`, or `probes test` as generic installation
checks: component diagnostics can enumerate hardware and target tests can attach.

When Embedded Agent Toolkit is installed, run its installed
`scripts/toolkit_doctor.py --json` and `--strict --json`. This aggregate doctor
only checks plugin layout and invokes component `--version`. With baud, BLEA,
and this CLI on PATH, both checks should return `ready` without
`EMBEDDED_AGENT_DEBUGGER`. Report any existing override separately; it can mask
a missing or shadowed PATH installation. A host-ready result does not establish
board connectivity, firmware identity, or permission to flash.

## Upgrade, roll back, or remove

Keep the source revision, installed version, and executable hash with acceptance
evidence. Install the intended reviewed checkout with the same Cargo command.
Do not add `--force` preemptively: first inspect any existing executable and its
Cargo ownership. Use it only when intentionally replacing that exact installation.

Cargo's normal installation is a single active binary, not a side-by-side version
store. For rollback, retain the prior trusted executable separately or reinstall
its source revision from a separate checkout; do not reset a working tree with
user changes. Rebuilding the same version need not reproduce the same binary
hash, so verify the resulting executable again. After any changed binary, review
component plans before hardware use and do not reuse an old confirmation digest
merely because the version string is unchanged.

To intentionally remove this Cargo-managed CLI, use
`cargo uninstall embedded-debugger` with the matching install root when overridden.
This removes the installed binary and its Cargo record, not the source repository,
the toolkit plugin, evidence, or other component tools.
