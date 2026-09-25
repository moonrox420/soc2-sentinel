# Builds bin\sentinel.exe and dist\SOC2-Sentinel-Toolkit-v2.5.0-Windows.zip
param(
    [switch]$SkipExe,
    [switch]$SkipZip
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$Root = Split-Path $PSScriptRoot -Parent
$Version = "2.5.0"
$DistDir = Join-Path $Root "dist"
$StageName = "SOC2-Sentinel-Toolkit-v$Version-Windows"
$StageDir = Join-Path $DistDir $StageName
$ZipPath = Join-Path $DistDir "${StageName}.zip"
$BinDir = Join-Path $Root "bin"

Set-Location $Root

function Assert-PyInstaller {
    $py = Get-Command python -ErrorAction SilentlyContinue
    if (-not $py) { throw "Python not found on PATH." }
    python -m pip install --quiet pyinstaller
}

function Build-Exe {
    Write-Host "Building sentinel.exe (one-file, may take a few minutes)..."
    Assert-PyInstaller
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
        "bin", "docs", "policies", "scripts", "sentinel",
        "README.md", "QUICKSTART-BUYER.md", "LICENSE", "pyproject.toml",
        "sentinel.yaml.example", "setup.ps1"
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

    # Explicitly stage only static data files to prevent local runtime telemetry leaks
    $stagedDataDir = Join-Path $StageDir "data"
    New-Item -ItemType Directory -Force -Path $stagedDataDir | Out-Null
    $staticDataFiles = @(
        "attck-mapping.csv",
        "cmmc-l2-controls-110.csv",
        "controls-matrix.csv",
        "evidence-schema.json",
        "l3-enhanced-controls.csv",
        "zero-trust-pillars.csv"
    )
    foreach ($f in $staticDataFiles) {
        $srcF = Join-Path $Root "data\$f"
        if (Test-Path $srcF) {
            Copy-Item $srcF (Join-Path $stagedDataDir $f) -Force
        }
    }
    $notionDir = Join-Path $Root "data\notion-import"
    if (Test-Path $notionDir) {
        Copy-Item $notionDir (Join-Path $stagedDataDir "notion-import") -Recurse -Force
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
        & $exe --version | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Executable --version smoke test failed with exit code $LASTEXITCODE"
        }
        & $exe --help | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Executable --help smoke test failed with exit code $LASTEXITCODE"
        }
        Write-Host "Smoke test passed: sentinel.exe --version and --help"
    } finally {
        Pop-Location
    }
}

function Test-StagedLauncher {
    $exe = Join-Path $StageDir "bin\sentinel.exe"
    if (-not (Test-Path $exe)) { return }
    Push-Location $StageDir
    try {
        $launcherOutput = ("q" | & $exe 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) {
            throw "Double-click launcher smoke test failed with exit code $LASTEXITCODE"
        }
        if ($launcherOutput -notmatch "SOC2 Sentinel Toolkit") {
            throw "Double-click launcher did not render the interactive menu"
        }
        Write-Host "Smoke test passed: no-argument Windows launcher"
    } finally {
        Pop-Location
    }
}


function Build-Zip {
    if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }
    New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
    # Archive the toolkit contents, not the staging directory itself. Windows'
    # "Extract All" already creates a folder named after the ZIP, so including
    # $StageDir here would produce a confusing duplicate nested folder.
    Compress-Archive -Path (Join-Path $StageDir "*") -DestinationPath $ZipPath -CompressionLevel Optimal
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
Test-StagedLauncher

if (-not $SkipZip) {
    Build-Zip
}

Write-Host ""
Write-Host "Consumer package ready. Upload dist\${StageName}.zip to Gumroad."