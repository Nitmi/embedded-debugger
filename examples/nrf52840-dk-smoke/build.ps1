$ErrorActionPreference = 'Stop'

$crateRoot = $PSScriptRoot
$repoRoot = Split-Path -Parent (Split-Path -Parent $crateRoot)
$targetTriple = 'thumbv7em-none-eabihf'
$outputDir = Join-Path $repoRoot 'target\firmware\nrf52840-dk-smoke'

Push-Location $crateRoot
try {
    $gitCommit = (& git -C $crateRoot rev-parse --verify HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $gitCommit -notmatch '^[0-9a-f]{40}$') {
        throw "unable to resolve the smoke firmware source commit"
    }
    $dirtyTracked = (& git -C $crateRoot status --porcelain --untracked-files=no).Trim()
    $buildId = if ([string]::IsNullOrWhiteSpace($dirtyTracked)) {
        $gitCommit
    } else {
        "$gitCommit-dirty"
    }

    $previousBuildId = $env:NRF_SMOKE_BUILD_ID
    $env:NRF_SMOKE_BUILD_ID = $buildId
    try {
        & cargo build --release
        if ($LASTEXITCODE -ne 0) {
            throw "cargo build failed with exit code $LASTEXITCODE"
        }
    } finally {
        if ($null -eq $previousBuildId) {
            Remove-Item Env:NRF_SMOKE_BUILD_ID -ErrorAction SilentlyContinue
        } else {
            $env:NRF_SMOKE_BUILD_ID = $previousBuildId
        }
    }

    $sysroot = (& rustc --print sysroot).Trim()
    $hostLine = & rustc -vV | Select-String '^host:' | Select-Object -First 1
    $hostTriple = $hostLine.ToString().Substring(5).Trim()
    $objcopy = Join-Path $sysroot "lib\rustlib\$hostTriple\bin\llvm-objcopy.exe"
    if (-not (Test-Path -LiteralPath $objcopy -PathType Leaf)) {
        throw "llvm-objcopy not found at $objcopy; install llvm-tools-preview"
    }

    $builtElf = Join-Path $crateRoot "target\$targetTriple\release\nrf52840-dk-smoke"
    if (-not (Test-Path -LiteralPath $builtElf -PathType Leaf)) {
        throw "built ELF not found at $builtElf"
    }

    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    $elf = Join-Path $outputDir 'nrf52840-dk-smoke.elf'
    $hex = Join-Path $outputDir 'nrf52840-dk-smoke.hex'
    Copy-Item -LiteralPath $builtElf -Destination $elf -Force
    & $objcopy -O ihex $elf $hex
    if ($LASTEXITCODE -ne 0) {
        throw "llvm-objcopy failed with exit code $LASTEXITCODE"
    }

    $artifacts = foreach ($artifact in @($elf, $hex)) {
        $item = Get-Item -LiteralPath $artifact
        $hash = Get-FileHash -LiteralPath $artifact -Algorithm SHA256
        [ordered]@{
            path = $artifact
            length = $item.Length
            sha256 = $hash.Hash
        }
    }

    $manifest = [ordered]@{
        schema_version = '1.0'
        board = 'Nordic nRF52840 DK'
        target = 'nRF52840_xxAA'
        build_id = $buildId
        target_triple = $targetTriple
        uart = [ordered]@{
            baud = 115200
            tx_pin = 'P0.06'
            ready = 'EAT_NRF52840_DK_READY v1'
            heartbeat = 'EAT_NRF52840_DK_HEARTBEAT'
        }
        led = [ordered]@{
            name = 'LED1'
            pin = 'P0.13'
            active_low = $true
        }
        artifacts = $artifacts
    }
    $manifestPath = Join-Path $outputDir 'manifest.json'
    $manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding utf8

    foreach ($artifact in $artifacts) {
        Write-Output "ARTIFACT=$($artifact.path)"
        Write-Output "LENGTH=$($artifact.length)"
        Write-Output "SHA256=$($artifact.sha256)"
    }
    Write-Output "MANIFEST=$manifestPath"
}
finally {
    Pop-Location
}
