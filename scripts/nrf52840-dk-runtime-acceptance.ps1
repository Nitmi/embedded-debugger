[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$ConfirmDigest,

    [string]$PlanDirectory = 'D:\Code\ai\embedded-debugger\target\hardware-acceptance\2026-09-04-nrf52840-dk-smoke\joint-runtime-acceptance'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-JsonFile {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $json = $Value | ConvertTo-Json -Depth 20
    $utf8NoBom = New-Object System.Text.UTF8Encoding -ArgumentList $false
    [System.IO.File]::WriteAllText($Path, $json, $utf8NoBom)
}

function Fail {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "RUNTIME_ACCEPTANCE_ABORTED: $Message"
}

$confirmationPath = Join-Path $PlanDirectory 'confirmation-input.json'
$planPath = Join-Path $PlanDirectory 'plan.json'
if (-not (Test-Path -LiteralPath $confirmationPath) -or -not (Test-Path -LiteralPath $planPath)) {
    Fail "plan files are missing under $PlanDirectory"
}

$confirmationHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $confirmationPath).Hash.ToUpperInvariant()
$expectedDigest = $ConfirmDigest.ToUpperInvariant()
if ($confirmationHash -ne $expectedDigest) {
    Fail "confirmation input SHA-256 mismatch (expected $expectedDigest, actual $confirmationHash)"
}

$plan = Get-Content -LiteralPath $planPath -Raw | ConvertFrom-Json
if ([string]$plan.confirm_digest -ne $expectedDigest) {
    Fail "plan confirm_digest does not match the supplied digest"
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$debuggerExe = Join-Path $repoRoot 'target\release\embedded-debugger.exe'
$confirmation = Get-Content -LiteralPath $confirmationPath -Raw | ConvertFrom-Json
$debuggerHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $debuggerExe).Hash.ToUpperInvariant()
if ($debuggerHash -ne [string]$confirmation.debug.executable_sha256) {
    Fail "embedded-debugger release SHA-256 mismatch (actual $debuggerHash)"
}

$baudCommand = Get-Command baud -ErrorAction SilentlyContinue
if ($null -eq $baudCommand) {
    Fail 'baud executable is not available on PATH'
}
$baudVersion = (& $baudCommand.Source --version | Out-String).Trim()
if ($baudVersion -notmatch '^baud 0\.1\.0$') {
    Fail "unexpected baud version: $baudVersion"
}

$evidenceDirectory = Join-Path $PlanDirectory 'execution'
New-Item -ItemType Directory -Path $evidenceDirectory -Force | Out-Null
$preflightPath = Join-Path $evidenceDirectory 'preflight.json'
$monitorStdoutPath = Join-Path $evidenceDirectory 'baud-monitor.stdout.json'
$monitorStderrPath = Join-Path $evidenceDirectory 'baud-monitor.stderr.log'
$debuggerStdoutPath = Join-Path $evidenceDirectory 'embedded-debugger.stdout.json'
$debuggerStderrPath = Join-Path $evidenceDirectory 'embedded-debugger.stderr.log'
$summaryPath = Join-Path $evidenceDirectory 'joint-runtime-summary.json'

$doctorRaw = & $debuggerExe --backend probe-rs doctor --json
$doctorExit = $LASTEXITCODE
$doctor = ($doctorRaw | Out-String | ConvertFrom-Json)
if ($doctorExit -ne 0 -or -not [bool]$doctor.ok) {
    Fail "embedded-debugger doctor failed"
}

$probesRaw = & $debuggerExe --backend probe-rs probes list --json
$probesExit = $LASTEXITCODE
$probes = ($probesRaw | Out-String | ConvertFrom-Json)
$probe = @($probes.data.probes | Where-Object {
        $_.id -eq [string]$confirmation.debug.probe -and $_.accessible -eq $true
    })
if ($probesExit -ne 0 -or $probe.Count -ne 1) {
    Fail "exact accessible probe was not uniquely present"
}

$baudListRaw = & $baudCommand.Source list --json
$baudListExit = $LASTEXITCODE
$baudList = ($baudListRaw | Out-String | ConvertFrom-Json)
$expectedVid = [Convert]::ToInt32([string]$confirmation.serial.vid, 16)
$expectedPid = [Convert]::ToInt32([string]$confirmation.serial.pid, 16)
$serial = @($baudList.ports | Where-Object {
        $_.device -eq [string]$confirmation.serial.port -and
        [int]$_.vid -eq $expectedVid -and
        [int]$_.pid -eq $expectedPid -and
        [string]$_.serial_number -eq [string]$confirmation.serial.serial_number
    })
if ($baudListExit -ne 0 -or $serial.Count -ne 1) {
    Fail "exact COM11 USB identity was not uniquely present"
}

$pnp = @(Get-CimInstance Win32_PnPEntity | Where-Object {
        $_.Name -match ('\(' + [regex]::Escape([string]$confirmation.serial.port) + '\)$')
    })
$expectedPnpInterfacePattern = '&' + [regex]::Escape([string]$confirmation.serial.pnp_interface) + '(?:&|\\)'
if ($pnp.Count -ne 1 -or [string]$pnp[0].PNPDeviceID -notmatch $expectedPnpInterfacePattern) {
    Fail "COM11 PnP interface is not the required $($confirmation.serial.pnp_interface)"
}

$preflight = [ordered]@{
    schema_version = '1.0'
    operation = 'nrf52840-dk-runtime-joint-acceptance.preflight'
    confirm_digest = $expectedDigest
    baud_version = $baudVersion
    debugger_sha256 = $debuggerHash
    doctor = $doctor
    probe = $probe[0]
    serial = $serial[0]
    pnp_device_id = [string]$pnp[0].PNPDeviceID
    target = [string]$confirmation.debug.target
    hardware_access = 'discovery_only'
}
Write-JsonFile -Value $preflight -Path $preflightPath

$monitorArguments = @(
    'monitor',
    '--port', [string]$confirmation.serial.port,
    '--baud', [string]$confirmation.serial.baud,
    '--duration', [string]$confirmation.serial.duration_seconds,
    '--dtr', ([string]$confirmation.serial.dtr).ToLowerInvariant(),
    '--rts', ([string]$confirmation.serial.rts).ToLowerInvariant(),
    '--expected-vid', [string]$confirmation.serial.vid,
    '--expected-pid', [string]$confirmation.serial.pid,
    '--expected-serial-number', [string]$confirmation.serial.serial_number,
    '--json',
    '--log-dir', $evidenceDirectory
)
$monitorProcess = Start-Process -FilePath $baudCommand.Source -ArgumentList $monitorArguments -WindowStyle Hidden -PassThru -RedirectStandardOutput $monitorStdoutPath -RedirectStandardError $monitorStderrPath
$debuggerExit = $null

try {
    Start-Sleep -Milliseconds 400
    if ($monitorProcess.HasExited) {
        Fail "baud monitor exited before the target-control stage"
    }
    $debuggerArguments = @(
        '--backend', 'probe-rs',
        '--json',
        'snapshot', 'reset-capture',
        '--probe', [string]$confirmation.debug.probe,
        '--target', [string]$confirmation.debug.target
    )
    & $debuggerExe @debuggerArguments 1> $debuggerStdoutPath 2> $debuggerStderrPath
    $debuggerExit = $LASTEXITCODE
}
finally {
    $monitorProcess.WaitForExit()
}

$monitorExit = $monitorProcess.ExitCode
$monitorResult = Get-Content -LiteralPath $monitorStdoutPath -Raw | ConvertFrom-Json
$debuggerResultRaw = Get-Content -LiteralPath $debuggerStdoutPath -Raw
try {
    $debuggerResult = $debuggerResultRaw | ConvertFrom-Json
} catch {
    $debuggerResult = [ordered]@{
        ok = $false
        parse_error = $_.Exception.Message
        raw_output = $debuggerResultRaw
    }
}
$text = [string]$monitorResult.steps[0].text
$lines = $text -split "`r?`n"
$readyCount = @($lines | Where-Object { $_ -ceq [string]$confirmation.assertions.ready_line }).Count
$heartbeatCount = @($lines | Where-Object { $_ -ceq [string]$confirmation.assertions.heartbeat_line }).Count
$strictAcceptance = ($monitorExit -eq 0 -and $debuggerExit -eq 0 -and [bool]$monitorResult.ok -and [bool]$debuggerResult.ok -and $readyCount -ge [int]$confirmation.assertions.ready_minimum -and $heartbeatCount -ge [int]$confirmation.assertions.heartbeat_minimum_complete)

$summary = [ordered]@{
    schema_version = '1.0'
    operation = 'nrf52840-dk-runtime-joint-acceptance'
    confirm_digest = $expectedDigest
    probe = [string]$confirmation.debug.probe
    target = [string]$confirmation.debug.target
    port = [string]$confirmation.serial.port
    pnp_interface = [string]$confirmation.serial.pnp_interface
    baud = [int]$confirmation.serial.baud
    dtr = [bool]$confirmation.serial.dtr
    rts = [bool]$confirmation.serial.rts
    transmit_bytes = [int]$confirmation.serial.transmit_bytes
    monitor_exit_code = $monitorExit
    debugger_exit_code = $debuggerExit
    bytes_received = [int]$monitorResult.steps[0].bytes_received
    ready_exact_count = $readyCount
    heartbeat_exact_count = $heartbeatCount
    strict_acceptance = $strictAcceptance
    debug_result = $debuggerResult
    artifacts = [ordered]@{
        preflight = $preflightPath
        baud_result = $monitorStdoutPath
        baud_stderr = $monitorStderrPath
        debugger_result = $debuggerStdoutPath
        debugger_stderr = $debuggerStderrPath
        baud_log_directory = $evidenceDirectory
    }
}
Write-JsonFile -Value $summary -Path $summaryPath
Write-JsonFile -Value $summary -Path (Join-Path $PlanDirectory 'joint-runtime-summary.json')

if (-not $strictAcceptance) {
    Write-Output ($summary | ConvertTo-Json -Depth 20)
    exit 1
}

Write-Output ($summary | ConvertTo-Json -Depth 20)
exit 0
