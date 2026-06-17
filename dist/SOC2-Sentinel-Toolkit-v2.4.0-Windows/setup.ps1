# Adds bin\sentinel.exe to the current user's PATH (optional).
$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$Bin = Join-Path $Root "bin"
$Exe = Join-Path $Bin "sentinel.exe"

if (-not (Test-Path $Exe)) {
    Write-Host "sentinel.exe not found at $Exe"
    Write-Host "Run scripts\build-consumer-package.ps1 to build, or use pip install -e ."
    exit 1
}

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$entries = $userPath -split ";" | Where-Object { $_ -and $_.Trim() -ne "" }
if ($entries -contains $Bin) {
    Write-Host "Already on PATH: $Bin"
} else {
    $newPath = ($entries + $Bin) -join ";"
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    Write-Host "Added to user PATH: $Bin"
    Write-Host "Open a new terminal, then run: sentinel run-all --provider mock"
}

Write-Host ""
Write-Host "Tip: run collectors from the toolkit folder so data\ and policies\ resolve correctly."