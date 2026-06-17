# Authentication & Access Policy

**Version:** 2.1  
**Owner:** Security & Compliance  
**Effective Date:** [EFFECTIVE_DATE]  
**Applies to:** [ORGANIZATION_NAME]

> **Disclaimer:** This template supports compliance readiness. It is not legal advice and does not guarantee certification outcomes.

## Purpose

Establish authentication standards for users, administrators, and service principals accessing [ORGANIZATION_NAME] systems. Aligns with SOC 2 CC6.1/CC6.2, NIST 800-171 IA controls, and CMMC L2 identification requirements.

## Scope

Covers workforce SSO, cloud console login, API keys, OAuth applications, VPN, and application-level authentication for production and staging environments.

## Roles and Responsibilities

| Role | Responsibility |
|------|----------------|
| **Identity Administrator** | Configures IdP, MFA policies, passwordless where supported |
| **Application Owners** | Enforce SSO and block local-only admin accounts |
| **Security Operations** | Investigates failed login anomalies and lockout events |
| **Developers** | Rotate service credentials; never embed secrets in source code |

## Procedures

1. **Single sign-on (SSO)** is required for all workforce access to SaaS and cloud consoles where supported.
2. **Multi-factor authentication (MFA)** is mandatory for administrators, remote access, and any account with production data access.
3. **Password standards** follow NIST SP 800-63B guidance: minimum 14 characters where passwords are used; ban common passwords.
4. **Service accounts** use scoped IAM roles, short-lived tokens, or vault-managed secrets—never long-lived root keys.
5. **Session management** enforces idle timeout (≤15 minutes for admin consoles) and re-authentication for sensitive actions.
6. **Failed login lockout** triggers after defined thresholds; unlock requires verified identity.
7. **Legacy authentication** (basic auth, unencrypted LDAP) is prohibited for systems processing confidential or CUI data.
8. **Annual authentication review** validates MFA coverage, SSO coverage, and elimination of shared credentials.

## Evidence Hooks (SOC2 Sentinel)

| Collector | Metric / Artifact | Control Mapping |
|-----------|-------------------|-----------------|
| `config_drift` | `mfa_enforcement_percent`, `weak_auth_methods` | CC6.2 — credential and auth config |
| `iam_access_review` | Active key inventory | CC6.1 — credential lifecycle |

Example: `sentinel run config_drift --provider aws --control-id CC6.2`

## Review Cadence

- **Policy review:** Annually  
- **MFA compliance scan:** Monthly via `config_drift`  
- **IdP configuration audit:** Semi-annually

## CUI / Defense Contractor Notes

For CUI environments, enforce phishing-resistant MFA (FIDO2/WebAuthn or PIV/CAC where applicable). Document authentication flows in your System Security Plan (SSP). Automated MFA percentage from Sentinel supplements—but does not replace—manual review of IdP conditional access policies.

## Related Documents

- `access-control-policy-v2.3.md`
- `encryption-key-management-policy-v2.3.md`
- `docs/SETUP.md` (collector commands)