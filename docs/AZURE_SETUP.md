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

App registration (v2.5 Graph collectors):

| Graph application permission | Purpose |
|------------------------------|---------|
| `Directory.Read.All` | Directory role assignments |
| `Policy.Read.All` | Conditional access policies |
| `AuditLog.Read.All` | Sign-in activity |
| `RoleManagement.Read.Directory` | Privileged role detection |
| `UserAuthenticationMethod.Read.All` | MFA registration (`authenticationMethods/userRegistrationDetails`) |

ARM + Resource Graph:

| Permission | Purpose |
|------------|---------|
| Reader on subscription | Storage, Recovery Services |
| `Microsoft.ResourceGraph/resources/read` | NSG port 80, diagnostic coverage % |
| `Microsoft.Resources/deployments/read` | Change management queries |

Create a custom role if Reader is too broad for your governance model.

## Verify

```bash
sentinel validate --provider azure
sentinel run encryption_status --provider azure
sentinel run log_aggregator --provider azure
sentinel run-all --provider azure
```

## Collector behavior on Azure

| Collector | Azure data source | Notes |
|-----------|-------------------|-------|
| `iam_access_review` | Microsoft Graph | Directory roles + sign-in activity |
| `log_aggregator` | Resource Graph diagnostics | Real `log_coverage_percent` |
| `config_drift` | Resource Graph NSG + Graph MFA | No hardcoded 100% MFA |
| `encryption_status` | Storage + disk encryption sets | Resource Graph disk query |
| `retention_check` | Storage management policies | `accounts_missing_lifecycle` |
| `resilience_testing` | Recovery Services backup jobs | No fabricated backup hours |

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