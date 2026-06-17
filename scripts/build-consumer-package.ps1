# Builds bin\sentinel.exe and dist\SOC2-Sentinel-Toolkit-v2.3.0-Windows.zip
param(
    [switch]$SkipExe,
    [switch]$SkipZip
)

$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent
$Version = "2.4.0"
$DistDir = Join-Path $Root "dist"
$StageName = "SOC2-Sentinel-Toolkit-v$Version-Windows"
$StageDir = Join-Path $DistDir $StageName
$ZipPath = Join-Path $DistDir "${StageName}.zip"
$BinDir = Join-Path $Root "bin"

Set-Location $Root

function Ensure-PyInstaller {
    $py = Get-Command python -ErrorAction SilentlyContinue
    if (-not $py) { throw "Python not found on PATH." }
    python -m pip install --quiet pyinstaller
}

function Build-Exe {
    Write-Host "Building sentinel.exe (one-file, may take a few minutes)..."
    Ensure-PyInstaller
    New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
    python -m PyInstaller --noconfirm --clean --distpath $BinDir --workpath (Join-Path $Root "build\pyinstaller") build\sentinel.spec
    if (-not (Test-Path (Join-Path $BinDir "sentinel.exe"))) {
        throw "PyInstaller did not produce bin\sentinel.exe"
    }
    Write-Host "OK: bin\sentinel.exe"
}

function Copy-Stage {
    if (Test-Path $StageDir) { Remove-Item $StageDir -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $StageDir | Out-Null

    $include = @(
        "bin", "data", "docs", "policies", "scripts", "sentinel", "tests\fixtures",
        "README.md", "QUICKSTART-BUYER.md", "LICENSE", "pyproject.toml",
        "sentinel.yaml.example", "run-demo.bat", "setup.ps1"
    )

    foreach ($item in $include) {
        $src = Join-Path $Root $item
        if (-not (Test-Path $src)) {
            if ($item -eq "bin") { continue }
            Write-Warning "Skipping missing: $item"
            continue
        }
        $dest = Join-Path $StageDir $item
        $parent = Split-Path $dest -Parent
        if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
        Copy-Item $src $dest -Recurse -Force
    }

    # Strip dev artifacts from staged sentinel package
    Get-ChildItem $StageDir -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem $StageDir -Recurse -Directory -Filter "*.egg-info" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}

function Test-StagedExe {
    $exe = Join-Path $StageDir "bin\sentinel.exe"
    if (-not (Test-Path $exe)) { return }
    Push-Location $StageDir
    try {
        & $exe run encryption_status --provider mock | Out-Null
        Write-Host "Smoke test passed: run encryption_status --provider mock"
    } finally {
        Pop-Location
    }
}

function Build-Zip {
    if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }
    New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
    Compress-Archive -Path $StageDir -DestinationPath $ZipPath -CompressionLevel Optimal
    $sizeMb = [math]::Round((Get-Item $ZipPath).Length / 1MB, 1)
    Write-Host "OK: $ZipPath ($sizeMb MB)"
}

if (-not $SkipExe) {
    Build-Exe
} elseif (-not (Test-Path (Join-Path $BinDir "sentinel.exe"))) {
    Write-Warning "SkipExe set and bin\sentinel.exe missing - zip will ship without exe (pip install path only)."
}

Copy-Stage
Test-StagedExe

if (-not $SkipZip) {
    Build-Zip
}

Write-Host ""
Write-Host "Consumer package ready. Upload dist\${StageName}.zip to Gumroad."