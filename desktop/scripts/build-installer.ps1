param(
    [switch]$Sign
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$desktopRoot = Split-Path -Parent $scriptRoot
$bundleDir = Join-Path $desktopRoot "src-tauri/target/release/bundle/nsis"
$artifactDir = Join-Path $desktopRoot "artifacts/installer"
$signScript = Join-Path $scriptRoot "sign-windows-artifact.ps1"

Push-Location $desktopRoot
try {
    Write-Host "Generating icon assets..."
    & powershell -ExecutionPolicy Bypass -File (Join-Path $scriptRoot "generate-icons.ps1")
    if ($LASTEXITCODE -ne 0) {
        throw "Icon generation failed."
    }

    Write-Host "Building NSIS installer..."
    & npm run build:installer:nsis
    if ($LASTEXITCODE -ne 0) {
        throw "NSIS installer build failed."
    }
}
finally {
    Pop-Location
}

if (-not (Test-Path $bundleDir)) {
    throw "Installer bundle directory was not produced at $bundleDir"
}

$setupExe = Get-ChildItem -Path $bundleDir -Filter "*-setup.exe" -File |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 1

if (-not $setupExe) {
    throw "No NSIS setup executable was produced in $bundleDir"
}

New-Item -ItemType Directory -Force -Path $artifactDir | Out-Null
$artifactExe = Join-Path $artifactDir $setupExe.Name
Copy-Item $setupExe.FullName $artifactExe -Force

$shouldSign = $Sign.IsPresent -or [bool]$env:WINDOWS_CERT_THUMBPRINT
if ($shouldSign) {
    Write-Host "Signing installer executable..."
    & powershell -ExecutionPolicy Bypass -File $signScript -Path $artifactExe
    if ($LASTEXITCODE -ne 0) {
        throw "Code signing failed."
    }
}

Write-Host "Installer artifact ready: $artifactExe"