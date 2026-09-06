# Windows x64 CLI candidate

This is an unsigned precompiled `embedded-debugger` candidate for Windows x64
(`x86_64-pc-windows-msvc`). Running the CLI does not require Rust or Python.
It does not bundle the toolkit plugin, baud, BLEA, OpenOCD, GDB, probe drivers,
firmware, or target configuration. Install the components your workflow needs
separately. Host runtime prerequisites and driver requirements still apply;
this archive is not a claim of clean-machine or new-board qualification. See the
bundled `WINDOWS_RUNTIME.md` and `Test-WindowsCandidate.ps1` for runtime prerequisites
and the bounded host smoke. The inspected build imports `VCRUNTIME140.dll`.

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
Rust, the native build prerequisites, and a trusted `cargo-about 0.9.2` executable:

```console
python scripts/package_binary.py build --offline --cargo-about <exact-cargo-about-path> --output-dir target/binary-dist --json
```

Obtain cargo-about from its [upstream release](https://github.com/EmbarkStudios/cargo-about/releases/tag/0.9.2)
or build the pinned version from trusted source. The builder requires an explicit
path and verifies its version; it never installs it or modifies PATH. CI verifies
the pinned Windows tool archive SHA-256 before running it. A tool version string
alone is not publisher authentication.

Run `cargo fetch --locked` as a separate network-enabled preparation step when
caches are incomplete. cargo-about 0.9.2 queries all-platform Cargo metadata before
filtering its graph, so its offline cache needs can exceed this Windows build.
The builder always invokes license gathering with `--frozen --fail`; it does not
fall back to online license lookups. Omit the builder's `--offline` only when Cargo
build/metadata dependency downloads are intended. The builder uses
`cargo build --locked --release --bin embedded-debugger --target
x86_64-pc-windows-msvc`, selects Cargo's reported executable, and checks its
version. It records the source commit, Rust/Cargo versions, binary hash,
cargo-about executable hash, and locked dependency inventory. Builds execute trusted source build scripts on
the host, but the builder never invokes hardware operations or installs tools.
Existing archive/checksum outputs are refused; choose a new output directory.
An interrupted write can leave partial output, which the verifier will reject.

ZIP ordering, timestamps, permissions, and storage method are fixed, so identical
payloads and build metadata produce identical archives. This is archive
reproducibility, not a promise of reproducible compiler output across machines.

`DEPENDENCIES.json` lists target-filtered Cargo metadata, including build and
development dependencies. It is not a precise runtime SBOM. `LICENSE` covers this
project only. New v2 archives additionally include:

- `THIRD_PARTY_LICENSES.json`: normalized cargo-about selections, original
  license/notice/copyright/author documents from Cargo.lock-checksummed crates.io
  archives, package source URLs and explicit review gaps. Local cache paths are
  not exported. The builder rejects a compiled Cargo artifact whose package is
  missing from the cargo-about report; metadata-only packages remain labeled.
- `THIRD_PARTY_NOTICES.txt`: readable license texts and original source documents,
  including nested vendor notices discovered by conventional filenames.
- `THIRD_PARTY_SOURCES.zip`: original registry `.crate` archives for selected
  MPL-2.0 components, including serialport. Their checksum is bound to Cargo.lock.
  Keep these materials together with the candidate. Source collection does not
  prove that local compiled source copies were unmodified.

The collector never extracts dependency archives or chooses SPDX alternatives
itself; cargo-about handles selection using committed `about.toml`. It preserves
upstream documents even when cargo-about uses fallback text. Missing documents,
fallback texts, MPL source delivery and modifications remain explicit review
items, not automatically approved exceptions. Binary integrity verification does
not establish legal sufficiency or fully validate the semantics of every notice.
See [Mozilla's MPL guidance](https://www.mozilla.org/en-US/MPL/2.0/FAQ/), especially
source delivery for compiled components, and
[cargo-about's configuration](https://embarkstudios.github.io/cargo-about/cli/generate/config.html).

Signing, full license review (including vendored code and toolchain/runtime
materials), precise runtime SBOM generation, and clean-machine testing remain
public-release work. Neither this script nor the CI artifact step publishes a
public release. The verifier continues to accept original v1 candidates, while
reporting that those archives do not contain these license materials.
