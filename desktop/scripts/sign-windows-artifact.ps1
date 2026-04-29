param(
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [string]$SigntoolPath = $env:SIGNTOOL_PATH,
    [string]$CertificateThumbprint = $env:WINDOWS_CERT_THUMBPRINT,
    [string]$TimestampUrl = $(if ($env:WINDOWS_TIMESTAMP_URL) { $env:WINDOWS_TIMESTAMP_URL } else { "http://timestamp.digicert.com" })
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Test-Path $Path)) {
    throw "Artifact not found: $Path"
}

if (-not $SigntoolPath) {
    throw "SIGNTOOL_PATH is required to sign artifacts."
}

if (-not (Test-Path $SigntoolPath)) {
    throw "signtool.exe not found at $SigntoolPath"
}

if (-not $CertificateThumbprint) {
    throw "WINDOWS_CERT_THUMBPRINT is required to sign artifacts."
}

$arguments = @(
    "sign",
    "/sha1", $CertificateThumbprint,
    "/fd", "sha256",
    "/td", "sha256",
    "/tr", $TimestampUrl,
    $Path
)

& $SigntoolPath @arguments
if ($LASTEXITCODE -ne 0) {
    throw "signtool.exe failed with exit code $LASTEXITCODE"
}

Write-Host "Signed artifact: $Path"
