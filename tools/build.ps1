# Build and test Frustracean.
#
# Cargo is not on PATH on the development machine, so it is located explicitly.
# Output follows the project's console conventions: words for status, results on
# stdout, problems on stderr, and a meaningful exit code.

[CmdletBinding()]
param(
    # Build the release profile instead of dev.
    [switch] $Release,
    # Skip the test run.
    [switch] $NoTest,
    # Allow cargo to reach the network (needed after adding a dependency).
    [switch] $Online
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

function Find-Cargo {
    $onPath = Get-Command cargo -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    $candidates = @(
        "$env:USERPROFILE\.cargo\bin\cargo.exe"
    ) + (Get-ChildItem "C:\Program Files" -Directory -Filter "Rust*" -ErrorAction SilentlyContinue |
         ForEach-Object { Join-Path $_.FullName "bin\cargo.exe" })
    foreach ($c in $candidates) {
        if (Test-Path $c) { return $c }
    }
    return $null
}

$cargo = Find-Cargo
if (-not $cargo) {
    Write-Error "ERROR: cargo not found on PATH or in the usual install locations"
    exit 2
}

Write-Output "INFO: cargo: $cargo"
Set-Location $root

$common = @()
if (-not $Online) { $common += '--offline' }

$profileArgs = @()
$profileName = 'debug'
if ($Release) {
    $profileArgs += '--release'
    $profileName = 'release'
}

Write-Output "INFO: building the $profileName profile"
& $cargo build --workspace @profileArgs @common
if ($LASTEXITCODE -ne 0) {
    Write-Error "ERROR: build failed"
    exit 3
}

if (-not $NoTest) {
    Write-Output "INFO: running tests"
    & $cargo test --workspace @common
    if ($LASTEXITCODE -ne 0) {
        Write-Error "ERROR: tests failed"
        exit 3
    }
}

$outDir = Join-Path $root "target\$profileName"
Write-Output ""
Write-Output "Artefacts"
foreach ($name in @('frustracean.exe', 'frustracean_hook.dll')) {
    $path = Join-Path $outDir $name
    if (Test-Path $path) {
        $size = (Get-Item $path).Length
        Write-Output "${name}: $path ($size bytes)"
    } else {
        Write-Output "${name}: not produced"
    }
}

Write-Output ""
Write-Output "OK: build complete"
Write-Output "Next: $outDir\frustracean.exe scan <image>"
exit 0
