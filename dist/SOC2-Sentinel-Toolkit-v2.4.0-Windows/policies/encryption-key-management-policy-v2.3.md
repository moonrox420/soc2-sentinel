# Encryption & Key Management Policy

**Version:** 2.3  
**Owner:** Security Engineering  
**Effective Date:** [EFFECTIVE_DATE]  
**Applies to:** [ORGANIZATION_NAME]

> **Disclaimer:** This template supports compliance readiness. It is not legal advice and does not guarantee certification outcomes.

## Purpose

Protect [ORGANIZATION_NAME] data at rest and in transit through approved cryptographic controls and key lifecycle management. Maps to SOC 2 C1.2, NIST 800-171 SC-13/SC-28, and CMMC L2 encryption practices.

## Scope

TLS certificates, cloud KMS/HSM keys, database TDE, disk encryption, application-level encryption, secrets management, and code-signing keys.

## Roles and Responsibilities

| Role | Responsibility |
|------|----------------|
| **Security Engineering** | Defines crypto standards and key ceremonies |
| **Platform Team** | Implements cloud KMS policies and rotation |
| **Developers** | Use approved libraries; never roll custom crypto |
| **Compliance** | Tracks FIPS and contractual encryption requirements |

## Procedures

1. **Approved algorithms:** AES-256-GCM at rest; TLS 1.2+ (1.3 preferred) in transit; reject legacy ciphers (3DES, RC4, SSLv3).
2. **Key generation** uses CSPRNG or cloud HSM; private keys never stored in plaintext repositories.
3. **Key rotation** for customer-managed KMS keys at least annually; immediate rotation after suspected compromise.
4. **Access to keys** follows least privilege; decrypt permissions logged and reviewed quarterly.
5. **Certificate management** automates renewal; expired certs remediated within 24 hours of detection.
6. **Secrets** stored in approved vault; `.env` files and CI logs must not contain production secrets.
7. **Weak endpoint detection** tracked via `config_drift` (`weak_tls_listeners`) and `encryption_status`.
8. **Destruction** of retired keys follows documented ceremony with witness for Restricted-tier keys.

## Evidence Hooks (SOC2 Sentinel)

| Collector | Metrics | Control Mapping |
|-----------|---------|-----------------|
| `encryption_status` | `encrypted_at_rest`, `fips_compliant_keys`, `keys_pending_rotation` | C1.2 |
| `config_drift` | `weak_tls_listeners`, `open_http_listeners` | C1.2 / SC-8 |
| `iam_access_review` | KMS admin privileged accounts | CC6.1 |

Command: `sentinel run encryption_status --provider aws`

## Review Cadence

- **Encryption posture scan:** Monthly  
- **Key rotation audit:** Quarterly  
- **Policy review:** Annually

## CUI / Defense Contractor Notes

Contracts may require FIPS 140-validated modules (e.g., AWS KMS in FIPS endpoints). Track `fips_compliant_keys` and document exceptions in SSP. Sentinel identifies unencrypted S3/RDS resources—it does not certify FIPS compliance; validate with cloud provider documentation and assessor guidance.

## Related Documents

- `secure-transmission-policy-v2.1.md`
- `data-classification-policy-v2.0.md`
- `docs/AWS_IAM_POLICY.json`