[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InputDirectory,
    [Parameter(Mandatory = $true)][string]$EvidenceDirectory
)

$ErrorActionPreference = 'Stop'
$resultPath = Join-Path $EvidenceDirectory 'sandbox-result.json'
$smokePath = Join-Path $EvidenceDirectory 'windows-host-smoke.json'
$resultStream = [IO.File]::Open([IO.Path]::GetFullPath($resultPath), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
$result = [ordered]@{
    schema_version = 'embedded-debugger.windows-sandbox-result.v1'
    ok = $false
    nonce = $null
    request_sha256 = $null
    archive_sha256 = $null
    executable_sha256 = $null
    input_mapping_read_only_observed = $false
    network_interfaces_up_non_loopback = $null
    hardware_access = $false
    environment = $null
    smoke_report_sha256 = $null
    error = $null
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

try {
    $requestPath = Join-Path $InputDirectory 'request.json'
    $request = Get-Content -Raw -LiteralPath $requestPath | ConvertFrom-Json
    $result.nonce = $request.nonce
    $result.request_sha256 = Get-Sha256 $requestPath
    if ($request.schema_version -cne 'embedded-debugger.windows-sandbox-request.v1') { throw 'Unsupported request schema' }

    $probePath = Join-Path $InputDirectory ('.write-probe-' + $request.nonce)
    try {
        [IO.File]::WriteAllText($probePath, 'input must be read-only')
        Remove-Item -LiteralPath $probePath -Force -ErrorAction SilentlyContinue
        throw 'Input mapping accepted a write'
    } catch [UnauthorizedAccessException] {
        $result.input_mapping_read_only_observed = $true
    } catch [IO.IOException] {
        $result.input_mapping_read_only_observed = $true
    }

    $interfaces = @([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object {
        $_.OperationalStatus -eq [Net.NetworkInformation.OperationalStatus]::Up -and
        $_.NetworkInterfaceType -notin @([Net.NetworkInformation.NetworkInterfaceType]::Loopback, [Net.NetworkInformation.NetworkInterfaceType]::Tunnel)
    })
    $result.network_interfaces_up_non_loopback = $interfaces.Count
    if ($interfaces.Count -ne 0) { throw 'A non-loopback network interface is operational' }

    $computer = Get-CimInstance Win32_ComputerSystem
    $runtime = Get-Item -LiteralPath "$env:SystemRoot\System32\VCRUNTIME140.dll" -ErrorAction SilentlyContinue
    $result.environment = [ordered]@{
        os_version = [Environment]::OSVersion.Version.ToString()
        is_64_bit_os = [Environment]::Is64BitOperatingSystem
        user_name = [Environment]::UserName
        computer_name = [Environment]::MachineName
        manufacturer = $computer.Manufacturer
        model = $computer.Model
        system_vcruntime140_before_execution = if ($runtime) { $runtime.VersionInfo.FileVersion } else { $null }
    }
    if (-not $result.environment.is_64_bit_os -or $result.environment.user_name -cne 'WDAGUtilityAccount') {
        throw 'Environment does not identify as Windows Sandbox x64'
    }

    foreach ($entry in $request.immutable_inputs.psobject.Properties) {
        $path = Join-Path $InputDirectory $entry.Name
        if ((Get-Sha256 $path) -cne $entry.Value) { throw "Immutable input differs: $($entry.Name)" }
    }
    $archivePath = Join-Path $InputDirectory $request.archive_name
    if ((Get-Sha256 $archivePath) -cne $request.archive_sha256) { throw 'Candidate archive checksum mismatch' }
    $checksumText = [IO.File]::ReadAllText((Join-Path $InputDirectory $request.checksum_name)).Replace("`r`n", "`n")
    if ($checksumText -cne "$($request.archive_sha256)  $($request.archive_name)`n") { throw 'Candidate checksum file differs' }

    $work = Join-Path $env:TEMP ('eat-clean-acceptance-' + $request.nonce)
    if (Test-Path -LiteralPath $work) { throw 'Guest work directory already exists' }
    New-Item -ItemType Directory -Path $work | Out-Null
    Expand-Archive -LiteralPath $archivePath -DestinationPath $work
    $candidateRoot = Join-Path $work "embedded-debugger-$($request.version)-$($request.target)"
    $manifest = Get-Content -Raw -LiteralPath (Join-Path $candidateRoot 'release-manifest.json') | ConvertFrom-Json
    if ($manifest.source_revision -cne $request.source_revision -or $manifest.target -cne $request.target -or $manifest.version -cne $request.version) {
        throw 'Release manifest identity differs'
    }
    foreach ($file in $manifest.files) {
        $path = Join-Path $candidateRoot $file.path
        if ((Get-Item -LiteralPath $path).Length -ne $file.size -or (Get-Sha256 $path) -cne $file.sha256) {
            throw "Release payload differs: $($file.path)"
        }
    }
    $executable = Join-Path $candidateRoot 'embedded-debugger.exe'
    if ((Get-Sha256 $executable) -cne $request.executable_sha256) { throw 'Executable digest differs' }
    powershell.exe -NoProfile -File (Join-Path $candidateRoot 'Test-WindowsCandidate.ps1') `
        -Executable $executable -ExpectedSha256 $request.executable_sha256 `
        -ExpectedVersion $request.version -ReportPath $smokePath `
        -EnvironmentLabel 'Windows Sandbox; networking and redirection disabled by pinned WSB'
    if ($LASTEXITCODE -ne 0) { throw 'Candidate smoke failed' }
    $smoke = Get-Content -Raw -LiteralPath $smokePath | ConvertFrom-Json
    if (-not $smoke.ok -or $smoke.hardware_access -or $smoke.actual_sha256 -cne $request.executable_sha256) {
        throw 'Candidate smoke evidence differs'
    }
    $result.archive_sha256 = $request.archive_sha256
    $result.executable_sha256 = $request.executable_sha256
    $result.smoke_report_sha256 = Get-Sha256 $smokePath
    $result.ok = $true
} catch {
    $result.error = $_.Exception.Message
} finally {
    try {
        $json = $result | ConvertTo-Json -Depth 8
        $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($json + "`n")
        $resultStream.Write($bytes, 0, $bytes.Length)
    } finally {
        $resultStream.Dispose()
    }
}

$json
if (-not $result.ok) { exit 1 }
