param(
    [switch]$Sign
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$desktopRoot = Split-Path -Parent $scriptRoot
$cargoManifest = Join-Path $desktopRoot "src-tauri/Cargo.toml"
$releaseExe = Join-Path $desktopRoot "src-tauri/target/release/regex-isolator-desktop.exe"
$releasePdb = Join-Path $desktopRoot "src-tauri/target/release/regex_isolator_desktop.pdb"
$artifactDir = Join-Path $desktopRoot "artifacts/portable"
$artifactExe = Join-Path $artifactDir "regex-isolator-desktop.exe"
$artifactPdb = Join-Path $artifactDir "regex_isolator_desktop.pdb"
$signScript = Join-Path $scriptRoot "sign-windows-artifact.ps1"

Push-Location $desktopRoot
try {
    Write-Host "Generating icon assets..."
    & powershell -ExecutionPolicy Bypass -File (Join-Path $scriptRoot "generate-icons.ps1")
    if ($LASTEXITCODE -ne 0) {
        throw "Icon generation failed."
    }

    Write-Host "Building frontend..."
    & npm run build
    if ($LASTEXITCODE -ne 0) {
        throw "Frontend build failed."
    }

    Write-Host "Building release executable..."
    & cargo build --release --manifest-path $cargoManifest
    if ($LASTEXITCODE -ne 0) {
        throw "Cargo release build failed."
    }
}
finally {
    Pop-Location
}

if (-not (Test-Path $releaseExe)) {
    throw "Release executable was not produced at $releaseExe"
}

New-Item -ItemType Directory -Force -Path $artifactDir | Out-Null
Copy-Item $releaseExe $artifactExe -Force

if (Test-Path $releasePdb) {
    Copy-Item $releasePdb $artifactPdb -Force
}

$shouldSign = $Sign.IsPresent -or [bool]$env:WINDOWS_CERT_THUMBPRINT
if ($shouldSign) {
    Write-Host "Signing portable executable..."
    & powershell -ExecutionPolicy Bypass -File $signScript -Path $artifactExe
    if ($LASTEXITCODE -ne 0) {
        throw "Code signing failed."
    }
}

Write-Host "Portable artifact ready: $artifactExe"
