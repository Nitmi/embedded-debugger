# Windows runtime qualification

The Windows x64 candidate runs without Rust, Cargo or Python. It is not a
fully static executable: the 2026-09-06 candidate with executable SHA-256
`f1cd8c50b8a8e429d1e404c0e84c4c3ce87593815a63d92c7c352391c2f26275`
imports `VCRUNTIME140.dll` and Windows Universal CRT API sets. Import inspection
used Microsoft DUMPBIN 14.44.35226.0 with `/DEPENDENTS`; it did not run the binary.
Recheck imports after compiler, linker, dependency or build-flag changes.

## Runtime prerequisite

Use Microsoft's supported x64 Visual C++ v14 Redistributable when the required
runtime is absent. The runtime must be at least as recent as the build tools
used for the binary. Download it only from the
[official Microsoft page](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist).
Do not download individual DLLs from third-party sites or copy DLLs from a
development machine into the CLI package. This package does not install or bundle
the redistributable. Driver installation and USB access are separate checks.

The inspected build also imports Windows system libraries including `winusb.dll`,
`setupapi.dll`, `cfgmgr32.dll`, `ws2_32.dll`, COM and cryptographic libraries.
An import list is not a complete runtime behavior inventory: dynamically loaded
libraries and backend-specific tools may still be needed for hardware workflows.

## Reusable host smoke

After verifying the ZIP and extracting it into an isolated directory, run the
bundled `Test-WindowsCandidate.ps1` using Windows PowerShell 5.1 or newer. Obtain
the executable SHA-256 from the verified `release-manifest.json`, not from an
untrusted executable alone. Choose a new report filename in an existing folder:

```powershell
powershell -NoProfile -File .\Test-WindowsCandidate.ps1 `
  -Executable .\embedded-debugger.exe `
  -ExpectedSha256 <verified-executable-sha256> `
  -ReportPath .\host-smoke.json `
  -EnvironmentLabel 'development host'
```

It reserves a new report before execution, checks executable identity, and only
runs `--version` and `runtime --help` with ten-second deadlines and a system-only
child PATH. It does not run doctor, enumerate devices, install software or change
persistent environment variables. An existing report is refused. An execution
policy restriction is reported by PowerShell; this workflow does not change that
policy. Review and sign the script according to your organization's policy.

## Clean Windows Sandbox acceptance

The source repository can prepare a one-run Windows Sandbox bundle around an
already verified candidate. Preparation requires Python 3.11+ on the host; the
Sandbox guest itself requires neither Python nor Rust:

```console
python scripts/windows_sandbox_acceptance.py prepare <archive.zip> --checksum <archive.zip.sha256> --output-dir target/clean-windows-acceptance
```

Preparation refuses an existing output directory. It verifies the candidate,
copies only the archive, checksum and pinned guest script into an input folder,
then creates `Run-Clean-Windows-Acceptance.wsb`. Open that file once. It launches
Windows Sandbox with networking, clipboard, audio/video input, printer sharing
and vGPU disabled; Protected Client is enabled. The input mapping is read-only
and a separate folder is writable only for evidence. No source workspace, home
directory, USB device, development tool or credential is mapped.

The guest verifies all immutable inputs and release payload hashes, proves that
the input mapping rejects a write, requires zero operational non-loopback network
interfaces, records its Windows/VC runtime environment, and runs only `--version`
and `runtime --help`. It never invokes device discovery or a hardware backend.
It extracts with the Windows .NET ZIP API rather than `Expand-Archive`, because
Windows 11 24H2 Sandbox images can omit the Store-backed PowerShell Archive module.
Wait for the result, close Sandbox, then run on the host:

```console
python scripts/windows_sandbox_acceptance.py verify target/clean-windows-acceptance
```

The verifier rechecks the candidate, exact WSB restrictions, request nonce,
read-only/network observations, `WDAGUtilityAccount` identity and both evidence
hashes. Only this successful combination emits `clean_environment_verified=true`.
That means a fresh disposable Windows Sandbox instance for the exact recorded
host-derived Windows image and pre-existing VC runtime state. It does not mean a
pristine Windows installation, authenticated publisher, broad OS compatibility,
or hardware qualification. Evidence is not cryptographically attested and still
requires custody appropriate to the release process.

Windows Sandbox is an optional Windows feature. This project does not enable it,
change virtualization settings or reboot the host. If the launcher is unavailable,
enable Sandbox deliberately using Microsoft's documented process or use a fresh
disposable Windows x64 VM and preserve equivalent evidence. A CI runner or a
developer host with a reduced PATH is not equivalent to this acceptance.

## Manual disposable-VM fallback

1. Create the disposable environment with networking and device redirection
   disabled. Map only the candidate input folder read-only and a dedicated empty
   evidence output folder, not a home directory or source workspace.
2. Copy the verified candidate into the guest. Do not install Rust, Python,
   drivers or the toolkit. Run the host smoke once and preserve its JSON,
   including a failure if the VC runtime is missing.
3. If needed, install the authentic Microsoft x64 redistributable **inside the
   guest only**, then run the smoke with a new report filename. Record installer
   version/hash and exit code. Do not use a global PATH override to mask failure.
4. Preserve the guest's provenance and both results. Only mark that exact
   OS/runtime combination qualified after inspecting the evidence. Do not infer
   hardware functionality, signing or broad OS support from this smoke.

The bundled host-smoke script deliberately leaves
`clean_environment_verified=false`: it cannot prove that the supplied environment
label describes a fresh VM. The Sandbox host verifier supplies that separate,
bounded conclusion from its configuration and evidence. A manual VM requires
equivalent operator provenance and cannot use that automated Sandbox conclusion.

References: [DUMPBIN /DEPENDENTS](https://learn.microsoft.com/en-us/cpp/build/reference/dependents),
[Windows Sandbox](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/).
