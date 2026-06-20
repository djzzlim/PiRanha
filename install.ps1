# PiRanha installer (Windows) — installs the `piranha` launcher binary.
# Usage: irm https://raw.githubusercontent.com/h4ckologic/PiRanha/main/install.ps1 | iex
#
# Params:
#   -Source        Install from source via bun (installs bun if needed)
#   -Binary        Always install the prebuilt binary
#   -Ref <ref>     Install a specific tag/commit/branch

param(
    [switch]$Source,
    [switch]$Binary,
    [string]$Ref = ""
)

$ErrorActionPreference = "Stop"

$Repo = if ($env:PIRANHA_REPO) { $env:PIRANHA_REPO } else { "h4ckologic/PiRanha" }
$InstallDir = if ($env:PIRANHA_INSTALL_DIR) { $env:PIRANHA_INSTALL_DIR } else { Join-Path $HOME ".local\bin" }
$MinBun = "1.3.14"

function Have-Cmd($name) { $null -ne (Get-Command $name -ErrorAction SilentlyContinue) }

Write-Host ""
Write-Host "  PiRanha - the autonomous bug-bounty swarm" -ForegroundColor Cyan
Write-Host ""

# A ref implies source install (releases are only cut for tags).
$mode = ""
if ($Source) { $mode = "source" }
elseif ($Binary) { $mode = "binary" }
elseif ($Ref -ne "") { $mode = "source" }

function Install-ViaBun {
    if (-not (Have-Cmd "bun")) {
        Write-Host "Installing bun..."
        irm https://bun.sh/install.ps1 | iex
        $env:PATH = "$HOME\.bun\bin;$env:PATH"
    }
    if (-not (Have-Cmd "git")) { throw "git is required for the source install." }

    $tmp = Join-Path $env:TEMP ("piranha-" + [guid]::NewGuid().ToString())
    try {
        if ($Ref -ne "") {
            git clone --depth 1 --branch $Ref "https://github.com/$Repo.git" $tmp 2>$null
            if ($LASTEXITCODE -ne 0) {
                git clone "https://github.com/$Repo.git" $tmp
                Push-Location $tmp; git checkout $Ref; Pop-Location
            }
        } else {
            git clone --depth 1 "https://github.com/$Repo.git" $tmp
        }
        if (-not (Test-Path (Join-Path $tmp "cli\piranha.ts"))) { throw "Expected launcher at $tmp\cli\piranha.ts" }
        bun install -g $tmp
        if ($LASTEXITCODE -ne 0) { throw "Failed to install from source." }
        Write-Host "`nInstalled piranha via bun" -ForegroundColor Green
    } finally {
        if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
    }
}

function Install-Binary {
    $arch = $env:PROCESSOR_ARCHITECTURE
    switch ($arch) {
        "AMD64" { $a = "x64" }
        "ARM64" { $a = "arm64" }
        default { throw "Unsupported architecture: $arch (use -Source)" }
    }
    # Only x64 binaries are published for Windows; arm64 falls back to source.
    if ($a -ne "x64") { Write-Host "No prebuilt Windows $a binary; use -Source."; throw "unsupported" }

    $headers = @{ "User-Agent" = "piranha-cli" }
    if ($Ref -ne "") {
        $rel = Invoke-RestMethod -Headers $headers "https://api.github.com/repos/$Repo/releases/tags/$Ref"
    } else {
        $rel = Invoke-RestMethod -Headers $headers "https://api.github.com/repos/$Repo/releases/latest"
    }
    $tag = $rel.tag_name
    if (-not $tag) { throw "Failed to fetch release tag." }
    Write-Host "Using version: $tag"

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $url = "https://github.com/$Repo/releases/download/$tag/piranha-windows-x64.exe"
    $dest = Join-Path $InstallDir "piranha.exe"
    Write-Host "Downloading piranha-windows-x64.exe..."
    Invoke-WebRequest -Uri $url -OutFile $dest
    Write-Host "`nInstalled piranha to $dest" -ForegroundColor Green

    if ($env:PATH -notlike "*$InstallDir*") {
        Write-Host "Add $InstallDir to your PATH." -ForegroundColor Yellow
    }
}

switch ($mode) {
    "source" { Install-ViaBun }
    "binary" { Install-Binary }
    default {
        if (Have-Cmd "bun") { Install-ViaBun } else { Install-Binary }
    }
}

Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. piranha doctor"
Write-Host "  2. piranha install"
Write-Host "  3. piranha hunt https://your-target.com"
Write-Host ""
Write-Host "Authorized testing only. Configure scope before hunting." -ForegroundColor Red
