# Micro-Segmentation Policy

**Version:** 1.0  
**Owner:** Platform Engineering / Security Architecture  
**Effective Date:** [EFFECTIVE_DATE]  
**Applies to:** [ORGANIZATION_NAME]

> **Disclaimer:** This template supports NIST 800-171 SC family controls, CMMC L3 enhanced practices (e.g., 3.13.6e), and Zero Trust network pillar maturity. It does not guarantee network isolation effectiveness without validation testing. Not legal advice.

## Purpose

Define how [ORGANIZATION_NAME] segments networks and workloads to limit lateral movement, enforce deny-by-default connectivity, and protect CUI boundaries in cloud and hybrid environments.

## Scope

Production VPCs/VNets, Kubernetes clusters, serverless workloads, VPN/ZTNA entry points, and inter-service communication paths processing confidential or CUI data.

## Roles and Responsibilities

| Role | Responsibility |
|------|----------------|
| **Security Architecture** | Defines segmentation zones and approved traffic flows |
| **Platform Engineering** | Implements security groups, NSGs, NACLs, service mesh policies |
| **Network Operations** | Maintains flow logs and reviews permitted paths quarterly |
| **Security Operations** | Hunts for segmentation drift; escalates unauthorized flows |
| **Change Advisory Board** | Approves new cross-zone connectivity |

## Segmentation zones (define for your environment)

| Zone | Description | Default policy | CUI allowed? |
|------|-------------|----------------|--------------|
| **Z0 — Public edge** | Load balancers, WAF, CDN | Allow inbound 443 only | No |
| **Z1 — Application** | App tiers, APIs | Deny by default; allow from Z0 | No direct CUI store |
| **Z2 — Data** | Databases, object stores with CUI | Deny by default; allow from Z1 only | Yes |
| **Z3 — Management** | Bastion, CI/CD, admin tools | Deny by default; MFA + JIT access | No CUI storage |
| **Z4 — Corporate** | Office/VPN users | Route via ZTNA; no direct Z2 | No |

Customize zone names and boundaries in your SSP network diagram.

## Procedures

1. **Deny-by-default** applies to all new security groups, NSGs, and firewall rules; permit rules require documented business justification and CAB approval.
2. **CUI data stores** reside only in Z2 (or equivalent); no direct internet ingress to Z2.
3. **East-west traffic** between zones requires explicit allow rules; implicit wide-open `0.0.0.0/0` within production is prohibited except documented exceptions with expiry.
4. **Micro-segmentation within zones** separates workloads by application tier (e.g., frontend cannot reach database port except via defined service account).
5. **Flow logging** is enabled on all production VPCs/VNets; logs retained per `data-retention-disposal-policy-v2.2.md`.
6. **Quarterly flow review** validates permitted paths against architecture diagram; undocumented flows are remediated or formally excepted.
7. **ZTNA/VPN** is the only approved remote access path to Z1–Z3; split tunneling to production is disabled.
8. **Container workloads** use network policies (Kubernetes) or service mesh mTLS for inter-pod segmentation where deployed.
9. **Drift detection** runs monthly via `config_drift` for security group and TLS listener changes.
10. **Exceptions** require Security Architecture approval, compensating controls, and expiration date ≤ 90 days unless renewed.

## Evidence Hooks (SOC2 Sentinel)

| Collector | Artifact | Control Mapping |
|-----------|----------|-----------------|
| `config_drift` | Security group / NSG rule findings, TLS exposure | 3.13.6, 3.13.8 — SC family |
| `log_aggregator` | VPC flow log / network log coverage | 3.14.6 — SI monitoring |
| `zt_continuous_verification` | Continuous verification posture summary | ZT-03 Network pillar |

```bash
sentinel run config_drift --provider aws
sentinel run zt_continuous_verification --provider aws
```

**Honest limitation:** Sentinel detects configuration drift and logging gaps—it does not perform live penetration testing or validate that segmentation blocks actual attack paths. Pair with annual network segmentation test or red team exercise.

## Zero Trust alignment

See `docs/ZERO_TRUST_FRAMEWORK.md` — Network / Environment pillar (ZT-03). Target maturity: **Advanced** for CUI environments.

| Maturity | Characteristics |
|----------|-----------------|
| Basic | Flat VPC with coarse security groups |
| Intermediate | Zoned architecture; flow logs enabled |
| Advanced | Deny-by-default; documented flows; ZTNA; quarterly review |

## Review Cadence

- **Architecture diagram update:** Upon material network change  
- **Flow review:** Quarterly  
- **Drift scan:** Monthly (`config_drift`)  
- **Policy review:** Annually

## CUI / Defense Contractor Notes

CMMC L3 enhanced control **3.13.6e** requires deny-by-default networking with documented permitted flows. Map your zones to SSP Section [NETWORK_SECTION]. Shared cloud provider network controls (PE/SC inheritance) must be documented in shared responsibility matrix.

## Related Documents

- `docs/ZERO_TRUST_FRAMEWORK.md`
- `docs/MITRE_ATTCK_COVERAGE.md` — lateral movement techniques
- `secure-transmission-policy-v2.1.md`
- `system-monitoring-policy-v2.0.md`
- `change-management-policy-v2.4.md`