# Secure Transmission Policy

**Version:** 2.1  
**Owner:** Security Engineering  
**Effective Date:** [EFFECTIVE_DATE]  
**Applies to:** [ORGANIZATION_NAME]

> **Disclaimer:** This template supports compliance readiness. It is not legal advice and does not guarantee certification outcomes.

## Purpose

Ensure data transmitted across networks by [ORGANIZATION_NAME] is protected against interception and tampering. Supports SOC 2 C1.2/CC6.7, NIST 800-171 SC-8, and CMMC L2 transmission confidentiality and integrity requirements.

## Scope

HTTPS APIs, VPN tunnels, email with sensitive attachments, file transfers, webhooks, inter-service mesh traffic, and administrative remote sessions.

## Roles and Responsibilities

| Role | Responsibility |
|------|----------------|
| **Network / Platform Engineering** | Enforces TLS termination, mTLS where required |
| **Application Teams** | Disable plaintext endpoints; pin minimum TLS versions |
| **Security Operations** | Monitors certificate expiry and cipher downgrade attempts |
| **Vendors** | Must support TLS 1.2+ for integrations handling Confidential+ data |

## Procedures

1. **TLS 1.2 minimum** (1.3 preferred) for all external and internal APIs carrying Confidential or Restricted data.
2. **HTTP redirect** forces HTTPS; port 80 listeners serving sensitive paths are prohibited in production.
3. **Certificate authority** uses trusted public CAs or internal PKI with documented trust chain.
4. **Cipher suites** follow Mozilla Intermediate or cloud provider modern policies; weak policies (pre-2016 AWS policies) remediated.
5. **VPN and admin access** requires MFA and encrypted tunnels; split tunneling disabled for Restricted environments.
6. **Email transmission** of Confidential+ data uses encrypted channels (S/MIME, secure portal)—not unencrypted attachments.
7. **API authentication** uses OAuth 2.0/OIDC or signed requests; API keys rotated every 90 days.
8. **Quarterly scan** reviews load balancer listeners and open ports via `config_drift` and `encryption_status`.

## Evidence Hooks (SOC2 Sentinel)

| Collector | Metrics | Control Mapping |
|-----------|---------|-----------------|
| `config_drift` | `open_http_listeners`, `weak_tls_listeners` | CC6.7 / SC-8 |
| `encryption_status` | `tls_endpoints_checked`, `weak_cipher_endpoints` | C1.2 |
| `log_aggregator` | TLS/certificate change audit events | CC7.1 |

Example: `sentinel run config_drift --provider aws`

## Review Cadence

- **TLS configuration scan:** Monthly  
- **Certificate inventory review:** Quarterly  
- **Policy review:** Annually

## CUI / Defense Contractor Notes

Transmission of CUI outside authorized environments requires encryption and approved transfer mechanisms per contract. Document allowed network paths in SSP. Automated detection of weak TLS policies is a starting point—penetration testing may be required for CMMC assessment.

## Related Documents

- `encryption-key-management-policy-v2.3.md`
- `authentication-access-policy-v2.1.md`
- `docs/NIST_800_171_CROSSWALK.md` (SC family)