Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$PdfiumRevision = '7543'
$Architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
$Asset = switch ($Architecture) {
    'x64' { 'pdfium-win-x64.tgz' }
    'arm64' { 'pdfium-win-arm64.tgz' }
    'x86' { 'pdfium-win-x86.tgz' }
    default { throw "Unsupported Windows architecture for PDFium: $Architecture" }
}
$ExpectedSha256 = switch ($Asset) {
    'pdfium-win-x64.tgz' { '0b08b606792a6cc593426efdefc6622611bce446d9e0270743846956ea1554ca' }
    'pdfium-win-arm64.tgz' { 'bb4a00113494e25bbee52d3d63b7f4ecf0de2d277b7de75ba9a1d5b987a74509' }
    'pdfium-win-x86.tgz' { '25c635e70037c6a20a33126a812a63e891c70974982a2e00112b7aaa07eb3832' }
    default { throw "No checksum is pinned for $Asset" }
}

$Workspace = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$CacheRoot = Join-Path $Workspace '.pdfium'
$ArchiveDirectory = Join-Path $CacheRoot 'archives'
$Archive = Join-Path $ArchiveDirectory $Asset
$Extracted = Join-Path (Join-Path $CacheRoot $PdfiumRevision) ([System.IO.Path]::GetFileNameWithoutExtension([System.IO.Path]::GetFileNameWithoutExtension($Asset)))
$ExtractedLibrary = Join-Path $Extracted 'bin\pdfium.dll'
$Current = Join-Path $CacheRoot 'current'
$CurrentLibrary = Join-Path $Current 'pdfium.dll'

New-Item -ItemType Directory -Force $ArchiveDirectory, $Extracted, $Current | Out-Null

$ArchiveIsValid = (Test-Path -LiteralPath $Archive) -and ((Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash.ToLowerInvariant() -eq $ExpectedSha256)
if (-not $ArchiveIsValid) {
    if (Test-Path -LiteralPath $Archive) {
        Remove-Item -LiteralPath $Archive
    }
    $Url = "https://github.com/bblanchon/pdfium-binaries/releases/download/chromium/$PdfiumRevision/$Asset"
    Invoke-WebRequest -Headers @{ 'User-Agent' = 'Stirling-PDF-Rust-Port' } -Uri $Url -OutFile $Archive
    $ActualSha256 = (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ActualSha256 -ne $ExpectedSha256) {
        Remove-Item -LiteralPath $Archive
        throw "Checksum mismatch for ${Asset}: expected $ExpectedSha256, received $ActualSha256"
    }
}

if (-not (Test-Path -LiteralPath $ExtractedLibrary)) {
    tar -xzf $Archive -C $Extracted
    if ($LASTEXITCODE -ne 0) {
        throw "Could not extract $Archive"
    }
}
if (-not (Test-Path -LiteralPath $ExtractedLibrary)) {
    throw "The PDFium archive did not contain $ExtractedLibrary"
}

Copy-Item -LiteralPath $ExtractedLibrary -Destination $CurrentLibrary -Force
Copy-Item -LiteralPath (Join-Path $Extracted 'LICENSE') -Destination (Join-Path $Current 'LICENSE') -Force
if (Test-Path -LiteralPath (Join-Path $Extracted 'licenses')) {
    Copy-Item -LiteralPath (Join-Path $Extracted 'licenses') -Destination $Current -Recurse -Force
}

Write-Output $CurrentLibrary
