[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Executable,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedSha256,
    [Parameter(Mandatory = $true)][string]$ReportPath,
    [string]$EnvironmentLabel = 'unspecified host',
    [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+$')][string]$ExpectedVersion = '0.2.0'
)

$ErrorActionPreference = 'Stop'
# Reserve evidence before starting the executable; never overwrite another run.
$reportStream = [IO.File]::Open([IO.Path]::GetFullPath($ReportPath), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
$report = [ordered]@{
    schema_version = 'embedded-debugger.windows-host-smoke.v1'
    ok = $false
    environment_label = $EnvironmentLabel
    clean_environment_verified = $false
    hardware_access = $false
    executable_started = $false
    executable = $Executable
    expected_sha256 = $ExpectedSha256.ToLowerInvariant()
    expected_version = $ExpectedVersion
    timestamp_utc = [DateTime]::UtcNow.ToString('o')
    os_version = [Environment]::OSVersion.Version.ToString()
    is_64_bit_os = [Environment]::Is64BitOperatingSystem
    checks = @()
    error = $null
}

function Invoke-HostCheck([string]$ExecutablePath, [string]$Arguments) {
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $ExecutablePath
    $startInfo.Arguments = $Arguments
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.WorkingDirectory = $env:SystemRoot
    $startInfo.EnvironmentVariables['PATH'] = "$env:SystemRoot\System32;$env:SystemRoot"
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) { throw 'Cannot start candidate' }
        $report.executable_started = $true
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(10000)) {
            $process.Kill()
            $process.WaitForExit()
            throw "Host check timed out: $Arguments"
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        return [ordered]@{ arguments = $Arguments; exit_code = $process.ExitCode; stdout = $stdout; stderr = $stderr }
    } finally {
        $process.Dispose()
    }
}

function Get-CandidateHash([string]$FilePath) {
    $stream = [IO.File]::OpenRead($FilePath)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-', '').ToLowerInvariant()
    } finally {
        $algorithm.Dispose()
        $stream.Dispose()
    }
}

try {
    $candidate = Get-Item -LiteralPath $Executable
    if ($candidate.PSIsContainer -or ($candidate.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $candidate.Name -ne 'embedded-debugger.exe') {
        throw 'Expected a regular embedded-debugger.exe file'
    }
    $report.executable = $candidate.FullName
    $actualHash = Get-CandidateHash $candidate.FullName
    $report.actual_sha256 = $actualHash
    if ($actualHash -cne $ExpectedSha256.ToLowerInvariant()) { throw 'Executable checksum mismatch; not started' }
    $runtime = Get-Item -LiteralPath "$env:SystemRoot\System32\VCRUNTIME140.dll" -ErrorAction SilentlyContinue
    $report.system_vcruntime140 = if ($runtime) { $runtime.VersionInfo.FileVersion } else { $null }
    $version = Invoke-HostCheck $candidate.FullName '--version'
    $report.checks += $version
    if ($version.exit_code -ne 0 -or $version.stdout.Trim() -cne "embedded-debugger $ExpectedVersion" -or $version.stderr.Trim()) {
        throw 'Version smoke failed; inspect runtime availability and executable identity'
    }
    $help = Invoke-HostCheck $candidate.FullName 'runtime --help'
    $report.checks += $help
    if ($help.exit_code -ne 0 -or $help.stdout -notmatch 'inspect' -or $help.stderr.Trim()) { throw 'Runtime help smoke failed' }
    if ((Get-CandidateHash $candidate.FullName) -ne $ExpectedSha256) { throw 'Executable changed during smoke' }
    $report.ok = $true
} catch {
    $report.error = $_.Exception.Message
} finally {
    try {
        $json = $report | ConvertTo-Json -Depth 8
        $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($json + "`n")
        $reportStream.Write($bytes, 0, $bytes.Length)
    } finally {
        $reportStream.Dispose()
    }
}
$json
if (-not $report.ok) { exit 1 }
