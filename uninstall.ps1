# PiRanha uninstaller (Windows)

$ErrorActionPreference = "Stop"

$InstallDir = if ($env:PIRANHA_INSTALL_DIR) { $env:PIRANHA_INSTALL_DIR } else { Join-Path $HOME ".local\bin" }
$Dest = Join-Path $InstallDir "piranha.exe"

Write-Host "`n  Uninstalling PiRanha...`n" -ForegroundColor Cyan

if (Test-Path $Dest) {
    Write-Host "Removing binary at $Dest..."
    Remove-Item -Force $Dest
} else {
    Write-Host "Binary not found at $Dest." -ForegroundColor Yellow
}

Write-Host "Removing installed skills..."
$skillDirs = @(
    "$HOME\.claude\skills\BugBountyFramework",
    "$HOME\.omp\agent\skills\piranha",
    "$HOME\.omp\skills\piranha",
    "$HOME\.omp\agent\skills\PiRanha",
    "$HOME\.omp\skills\PiRanha",
    "$HOME\.pi\agent\skills\piranha",
    "$HOME\.pi\skills\piranha",
    "$HOME\.pi\agent\skills\PiRanha",
    "$HOME\.pi\skills\PiRanha"
)

foreach ($dir in $skillDirs) {
    if (Test-Path $dir) {
        Remove-Item -Recurse -Force $dir
    }
}

Write-Host "`nPiRanha has been uninstalled." -ForegroundColor Green
Write-Host "Note: Session data and logs in ~/.claude/MEMORY/BugBounty were kept intact." -ForegroundColor Gray
Write-Host ""
