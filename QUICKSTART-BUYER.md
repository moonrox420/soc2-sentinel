# SOC2 Sentinel Toolkit v2.5 — Quick Start (Windows)

No Python install required. Unzip anywhere (e.g. `C:\SOC2-Sentinel`).

## 1. Launch the software

Double-click **`bin\sentinel.exe`**. The Windows executable opens an interactive menu where you can:

- Run the built-in mock demo
- Validate AWS, GCP, Azure, or mock credentials
- Run all evidence collectors
- View command-line help

The executable stays open until you choose Exit.

For a one-click mock run, `run-demo.bat` is also included as an optional convenience.

From PowerShell, the same executable can be used directly:

```powershell
.\bin\sentinel.exe run-all --provider mock
```

Evidence appears under `evidence\<today>\<control_id>\report.json`.

## 2. Common commands

```powershell
# Single collector
.\bin\sentinel.exe run encryption_status --provider mock

# CMMC L2 self-assessment roll-up (110 practices)
.\bin\sentinel.exe report --input data\cmmc-l2-controls-110.csv --mode cmmc

# Zero Trust maturity report
.\bin\sentinel.exe report --input data\zero-trust-pillars.csv --mode zt
```

## 3. Validate before first cloud run

```powershell
.\bin\sentinel.exe validate --provider mock
.\bin\sentinel.exe validate --provider aws   # after credentials configured
```

## 4. AWS (when ready)

1. Create a read-only IAM role per `docs\AWS_IAM_POLICY.json`
2. Set credentials (`AWS_PROFILE` or env vars)
3. Run: `.\bin\sentinel.exe run-all --provider aws`
4. Verify integrity: `.\bin\sentinel.exe verify evidence\<date>\`

GCP and Azure: see `docs\GCP_SETUP.md` and `docs\AZURE_SETUP.md`.

## 5. Configuration (optional)

Copy `sentinel.yaml.example` to `sentinel.yaml` to tune thresholds, opt-in encryption, or continue-on-error for `run-all`.

Security details: `docs\SECURITY.md`

## 5. Optional: add to PATH

Run once as your user (not admin required):

```powershell
.\setup.ps1
```

Then open a **new** terminal and use `sentinel` from any folder (still run from toolkit root for relative paths like `data\`).

## 6. Python developers

If you prefer a venv instead of the bundled exe:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
sentinel run-all --provider mock
```

## 7. Support files

| Folder | Contents |
|--------|----------|
| `policies/` | 17 policy templates |
| `docs/` | DFARS, CMMC, NIST, setup guides |
| `data/` | Control matrices, Notion import CSVs |
| `scripts/` | Notion import helper |

Full index: `docs\MASTER_REFERENCE_v2.3.md`

**Disclaimer:** Templates and automation only — not legal advice or certification guarantee.