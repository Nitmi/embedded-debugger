# Windows x64 CLI candidate

This is an unsigned precompiled `embedded-debugger` candidate for Windows x64
(`x86_64-pc-windows-msvc`). Running the CLI does not require Rust or Python.
It does not bundle the toolkit plugin, baud, BLEA, OpenOCD, GDB, probe drivers,
firmware, or target configuration. Install the components your workflow needs
separately. Host runtime prerequisites and driver requirements still apply;
this archive is not a claim of clean-machine or new-board qualification.

## Verify before running

Obtain the archive and its SHA-256 from a trusted channel. In PowerShell, compare
the hash with the supplied `.zip.sha256` file before extracting or running:

```powershell
Get-FileHash .\embedded-debugger-0.2.0-x86_64-pc-windows-msvc.zip -Algorithm SHA256
Get-Content .\embedded-debugger-0.2.0-x86_64-pc-windows-msvc.zip.sha256
```

The source repository also provides a full, host-only verifier (Python 3.11+):

```console
python scripts/package_binary.py verify <archive.zip> --checksum <archive.zip.sha256> --json
```

That verifier checks the exact member layout, per-file sizes and hashes, version,
target, and source revision. It neither extracts files nor executes any program.
A checksum detects changed content relative to the expected value; it is not a
signature and does not establish who published the package.

## Use an isolated version

Extract into a new directory, not over a Cargo-managed installation or another
version. The archive contains one version-and-target-named root directory. From
that extracted root, run only these host checks first:

```powershell
.\embedded-debugger.exe --version
.\embedded-debugger.exe runtime --help
```

Use the full executable path for project integrations, or deliberately place
its directory on PATH after checking existing command precedence. The archive
does not modify PATH, install or activate plugins, or create services. To upgrade,
extract a new version beside the old one and switch the selected path. Keep the
old directory for rollback; do not overwrite hardware evidence or project files.

For a toolkit host check, its `EMBEDDED_AGENT_DEBUGGER` process override can
select the extracted executable. Only the aggregate `toolkit_doctor.py` checks
component versions without hardware access. Native component `doctor`, discovery,
and target commands are not equivalent to version/help checks. Offline readiness
does not authorize flashing or prove board or firmware identity.

## Build and provenance

From a clean committed source checkout on Windows x64, using Python 3.11+, Cargo,
Rust, and the native build prerequisites:

```console
python scripts/package_binary.py build --offline --output-dir target/binary-dist --json
```

Omit `--offline` only when dependency downloads are intended. The builder uses
`cargo build --locked --release --bin embedded-debugger --target
x86_64-pc-windows-msvc`, selects Cargo's reported executable, and checks its
version. It records the source commit, Rust/Cargo versions, binary hash, and
locked dependency inventory. Builds execute trusted source build scripts on
the host, but the builder never invokes hardware operations or installs tools.
Existing archive/checksum outputs are refused; choose a new output directory.
An interrupted write can leave partial output, which the verifier will reject.

ZIP ordering, timestamps, permissions, and storage method are fixed, so identical
payloads and build metadata produce identical archives. This is archive
reproducibility, not a promise of reproducible compiler output across machines.

`DEPENDENCIES.json` lists target-filtered Cargo metadata, including build and
development dependencies. Other platforms are not queried or downloaded merely
to generate this inventory. It is not a precise runtime SBOM or complete third-party
license notice bundle. `LICENSE` covers this project only. Signing, full license
review, runtime SBOM generation, and clean-machine testing remain public-release
work; neither this script nor the CI artifact step publishes a public release.
