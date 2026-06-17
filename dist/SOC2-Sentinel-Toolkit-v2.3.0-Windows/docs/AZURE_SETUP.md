# Azure Provider Setup

Configure Microsoft Azure credentials for SOC2 Sentinel collectors.

> **Disclaimer:** Align with your tenant security policies. This document is not legal advice or a certification guarantee.

## Prerequisites

- Azure subscription with Reader access (or custom role below)
- Azure CLI installed (optional, for login)
- Python package installed: `pip install -e .`

## Authentication methods

SOC2 Sentinel uses `DefaultAzureCredential` from `azure-identity`.

### Option A: Azure CLI (local development)

```bash
az login
az account set --subscription "YOUR_SUBSCRIPTION_ID"
```

PowerShell:

```powershell
$env:AZURE_SUBSCRIPTION_ID = "YOUR_SUBSCRIPTION_ID"
```

### Option B: Service principal

```bash
az ad sp create-for-rbac --name soc2-sentinel-readonly --role Reader \
  --scopes /subscriptions/YOUR_SUBSCRIPTION_ID
```

Set environment variables:

```bash
export AZURE_SUBSCRIPTION_ID="YOUR_SUBSCRIPTION_ID"
export AZURE_TENANT_ID="YOUR_TENANT_ID"
export AZURE_CLIENT_ID="YOUR_CLIENT_ID"
export AZURE_CLIENT_SECRET="YOUR_CLIENT_SECRET"
```

### Option C: Managed Identity (Azure VM / App Service / GitHub OIDC)

Assign a user-assigned or system-managed identity with Reader on the subscription. No secrets required—preferred for CI.

## Minimum permissions

Built-in **Reader** role on the target subscription covers:

- Storage account encryption settings (`encryption_status`)
- Resource enumeration

For enhanced evidence, add:

| Role / Permission | Purpose |
|-------------------|---------|
| `Microsoft.Authorization/roleAssignments/read` | IAM-style reviews |
| Log Analytics Reader | `log_aggregator` workspace queries |
| Security Reader | Defender alerts (manual correlation) |

Create a custom role if Reader is too broad for your governance model.

## Verify

```bash
sentinel run encryption_status --provider azure
sentinel run log_aggregator --provider azure
sentinel run-all --provider azure
```

## Collector behavior on Azure

| Collector | Azure data source | Notes |
|-----------|-------------------|-------|
| `iam_access_review` | Placeholder export | Use Microsoft Graph for full Entra ID role evidence |
| `log_aggregator` | Activity Log / diagnostic settings | Supplement with Log Analytics queries |
| `config_drift` | Baseline metrics | Pair with Azure Policy compliance export |
| `encryption_status` | Storage account encryption | Blob service encryption flag |
| `retention_check` | Storage lifecycle management | Manual policy review may be needed |

## Microsoft Graph supplement (recommended)

For CC6.1-quality IAM evidence:

1. Register app in Entra ID
2. Grant **Application** permissions: `Directory.Read.All`, `RoleManagement.Read.Directory` (admin consent)
3. Export role assignments quarterly
4. Store alongside Sentinel `iam_access_review` output

This step is manual in v1.6.0; Graph export is documented for honest completeness.

## Troubleshooting

| Error | Fix |
|-------|-----|
| `AZURE_SUBSCRIPTION_ID` missing | Set subscription env var |
| `Azure.Identity.AuthenticationFailed` | Re-login `az login` or verify SP secret |
| Empty storage list | Confirm Reader on subscription scope |
| Subscription not found | `az account list` — verify ID |

## Security recommendations

- Never assign Contributor or Owner to collector identities
- Use separate subscription or management group scoping for multi-tenant vendors
- Enable diagnostic settings on storage and Key Vault
- Prefer managed identity over client secrets

## Defense / CUI notes

Azure Government or GCC High may be required for certain CUI workloads. Point collectors only at authorized subscriptions. Sentinel automation supports readiness activities for defense contractors—it does not attest FedRAMP or CMMC certification on your behalf.