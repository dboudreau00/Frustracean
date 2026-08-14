# Regenerate the README's terminal screenshots from real output.
#
# Every image under docs/screenshots is produced by running the tool and piping
# what it actually printed through tools/termshot.js. Nothing is hand-written,
# so a screenshot cannot drift away from the tool's behaviour without showing up
# as a text diff.
#
# Run after any change to console output:
#     powershell -File tools/screenshots.ps1

[CmdletBinding()]
param(
    # Allow cargo to reach the network.
    [switch] $Online
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Find-Tool([string[]] $candidates, [string] $name) {
    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c)) { return $c }
    }
    $onPath = Get-Command $name -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    return $null
}

$cargo = Find-Tool @(
    "$env:USERPROFILE\.cargo\bin\cargo.exe"
) 'cargo'
if (-not $cargo) {
    $cargo = (Get-ChildItem "C:\Program Files" -Directory -Filter "Rust*" -ErrorAction SilentlyContinue |
              ForEach-Object { Join-Path $_.FullName "bin\cargo.exe" } |
              Where-Object { Test-Path $_ } | Select-Object -First 1)
}
$node = Find-Tool @("C:\Program Files\nodejs\node.exe") 'node'

if (-not $cargo) { Write-Error "ERROR: cargo not found"; exit 2 }
if (-not $node)  { Write-Error "ERROR: node not found";  exit 2 }

Write-Output "INFO: cargo: $cargo"
Write-Output "INFO: node: $node"

$common = @()
if (-not $Online) { $common += '--offline' }

Write-Output "INFO: building release binaries"
& $cargo build --workspace --release @common
if ($LASTEXITCODE -ne 0) { Write-Error "ERROR: build failed"; exit 3 }

$shots = Join-Path $root 'docs\screenshots'
New-Item -ItemType Directory -Force -Path $shots | Out-Null
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) "frustracean-shots"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

$exe = '.\target\release\frustracean.exe'
$testbedExe = '.\target\release\frustracean-testbed.exe'
$testbedDll = '.\target\release\frustracean_testbed_payload.dll'

# Each entry: output name, displayed command, argument list.
$shotList = @(
    @{ name = 'scan';   cmd = 'frustracean scan sample.exe';
       args = @('scan', $testbedExe) },
    @{ name = 'deps';   cmd = 'frustracean deps sample.exe';
       args = @('deps', $exe) },
    @{ name = 'map';    cmd = 'frustracean map sample.exe';
       args = @('map', $testbedExe) },
    # `--no-xrefs` keeps this to the symbol path. The cross-reference fallback
    # is the more impressive capability but it resolves a dozen low-confidence
    # candidates, which makes for a worse picture than it does a story.
    @{ name = 'plan';   cmd = 'frustracean plan sample.dll --no-xrefs';
       args = @('plan', $testbedDll, '--no-xrefs') },
    @{ name = 'replay'; cmd = 'frustracean replay capture/trace.jsonl --plan plan.json';
       args = @('replay', 'docs/examples/testbed-trace.jsonl', '--plan', 'docs/examples/testbed-plan.json') },
    @{ name = 'stats';  cmd = 'frustracean stats capture/blobs/stage0-packed.bin';
       args = @('stats', (Join-Path $tmp 'stage0-packed.bin')) }
)

# The `stats` shot needs a real blob; the testbed produces one.
Write-Output "INFO: dumping testbed stage buffers"
& $testbedExe --dump $tmp | Out-Null

foreach ($shot in $shotList) {
    $txt = Join-Path $tmp "$($shot.name).txt"
    Write-Output "INFO: capturing $($shot.name)"
    # stderr is merged in deliberately: WARNING and ERROR lines are part of what
    # the tool says, and a screenshot that hid them would misrepresent it.
    #
    # `$ErrorActionPreference` has to be relaxed around the call. Under 'Stop',
    # PowerShell turns any native-command stderr output into a terminating
    # error - so a tool that correctly writes a warning to stderr would abort
    # its own screenshot run.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & $exe @($shot.args) 2>&1 | Out-File -FilePath $txt -Encoding utf8
    $ErrorActionPreference = $previous

    & $node (Join-Path $root 'tools\termshot.js') $txt (Join-Path $shots "$($shot.name).svg") $shot.cmd
    if ($LASTEXITCODE -ne 0) { Write-Error "ERROR: termshot failed for $($shot.name)"; exit 3 }
}

Write-Output ""
Write-Output "OK: screenshots regenerated in docs\screenshots"
exit 0
