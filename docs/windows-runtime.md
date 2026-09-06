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

## Clean Windows acceptance, still pending

Use a disposable Windows x64 VM or Windows Sandbox. Record Windows build,
architecture, environment origin and runtime installation state. A CI runner or
a developer host with a reduced PATH is not equivalent to a clean machine.

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

The script deliberately leaves `clean_environment_verified=false`: it cannot
prove that the supplied environment label describes a fresh VM. The operator's
environment evidence supplies that separate qualification. Windows Sandbox and
Hyper-V management commands were not available on the current host during this
checkpoint; no optional Windows feature was enabled or machine reboot requested.

References: [DUMPBIN /DEPENDENTS](https://learn.microsoft.com/en-us/cpp/build/reference/dependents),
[Windows Sandbox](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/).
