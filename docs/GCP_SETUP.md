# GCP Provider Setup

Configure Google Cloud credentials for SOC2 Sentinel collectors.

> **Disclaimer:** Follow your organization's cloud security policies. This guide is operational documentation, not legal or certification advice.

## Prerequisites

- GCP project with billing enabled
- `Owner` or custom role sufficient for read-only APIs below
- Python dependencies installed: `pip install -e .`

## Required APIs

Enable in **APIs & Services → Library**:

| API | Used for |
|-----|----------|
| Cloud Storage API | `encryption_status`, `retention_check` |
| Cloud Logging API | `log_aggregator` |
| Cloud Asset Inventory API | Full `iam_access_review` export (recommended) |
| Cloud Resource Manager API | Project metadata |

```bash
gcloud services enable storage.googleapis.com logging.googleapis.com \
  cloudasset.googleapis.com cloudresourcemanager.googleapis.com
```

## Authentication

### Option A: Application Default Credentials (development)

```bash
gcloud auth application-default login
export GOOGLE_CLOUD_PROJECT="your-project-id"
```

Windows PowerShell:

```powershell
$env:GOOGLE_CLOUD_PROJECT = "your-project-id"
```

### Option B: Service account (CI / production)

1. **IAM & Admin → Service Accounts → Create**
   - Name: `soc2-sentinel-readonly`
2. Grant roles (read-only):

Custom role `soc2SentinelViewer` (v2.5) — minimum permissions:

| Permission area | APIs / permissions |
|-----------------|-------------------|
| IAM | `cloudasset.assets.searchAllIamPolicies`, `iam.serviceAccounts.list`, `iam.serviceAccountKeys.list` |
| Logging | `logging.sinks.list`, `logging.buckets.list`, `logging.entries.list` |
| Org policy | `orgpolicy.policy.get` |
| Encryption | `storage.buckets.get`, `cloudkms.cryptoKeys.list` |
| Backup | `compute.snapshots.list`, `sql.backupRuns.list` |

Or use bundled roles:

| Role | Purpose |
|------|---------|
| `roles/storage.objectViewer` | Bucket encryption and lifecycle |
| `roles/logging.viewer` | Log sinks and metrics |
| `roles/cloudasset.viewer` | IAM policy export |
| `roles/cloudkms.viewer` | KMS rotation status |
| `roles/compute.viewer` | Compute snapshots |

3. Create JSON key **only if** your security policy allows key-based auth; prefer Workload Identity Federation for CI.

```bash
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/sa-key.json"
export GOOGLE_CLOUD_PROJECT="your-project-id"
```

### Option C: Workload Identity (GKE / GitHub Actions)

Use federation instead of long-lived keys. Document the federation binding in your SSP.

## Verify installation

```bash
sentinel validate --provider gcp
sentinel run log_aggregator --provider gcp
sentinel run encryption_status --provider gcp
sentinel run-all --provider gcp
```

Evidence writes to `evidence/<date>/<control_id>/report.json`.

## Collector behavior on GCP

| Collector | GCP data source | Notes |
|-----------|-----------------|-------|
| `iam_access_review` | Cloud Asset IAM + SA keys | Live principals; orphaned = keys >90d |
| `log_aggregator` | Sinks, buckets, `entries.list` | Real coverage via Asset inventory |
| `config_drift` | Org Policy + firewall rules | No fabricated MFA % |
| `encryption_status` | GCS + Cloud KMS | Uniform access / CMEK; KMS rotation |
| `retention_check` | GCS lifecycle | `buckets_missing_lifecycle` metric |
| `resilience_testing` | Compute snapshots + SQL backups | Fails honestly without backup evidence |

## Security recommendations

- Scope service account to single project unless org-wide review is required
- Deny `roles/owner` and `roles/editor` for the collector principal
- Rotate keys every 90 days if keys are unavoidable
- Log service account usage in Cloud Audit Logs

## Troubleshooting

| Error | Fix |
|-------|-----|
| `GCP provider requires GOOGLE_CLOUD_PROJECT` | Set `GOOGLE_CLOUD_PROJECT` env var |
| `403 Forbidden` on storage | Add `storage.objectViewer` |
| Empty IAM CSV | Enable Cloud Asset Inventory API |
| `DefaultCredentialsError` | Run `gcloud auth application-default login` |

## Defense / CUI notes

For defense contractors and regulated SaaS workloads on GCP, ensure CUI workloads reside in authorized projects. Run collectors only against in-scope projects. Automated output supports CMMC self-assessment—it does not replace assessor validation or GCC High contractual requirements where applicable.