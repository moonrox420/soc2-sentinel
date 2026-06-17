# NIST SP 800-172 Crosswalk

Maps **NIST SP 800-172** enhanced security requirements to base NIST 800-171 controls, SOC2 Sentinel collectors, toolkit policies, and honest implementation gaps.

> **Disclaimer:** NIST 800-172 applies to organizations requiring protection against advanced persistent threats. This crosswalk supports **CMMC Level 3 preparation**—not a formal 800-172 assessment. Consult your C3PAO and agency AO for scoping. Not legal advice.

---

## Purpose

800-172 **enhances** selected 800-171 controls with additional requirements. CMMC L3 assesses both the 110 base practices and applicable enhanced requirements.

Source seed: `data/l3-enhanced-controls.csv`

---

## Enhanced requirements matrix

| Enhanced ID | Base 800-171 | Family | Requirement | Collector / policy | Seed status | Gap notes |
|-------------|--------------|--------|-------------|-------------------|-------------|-----------|
| **3.1.3e** | 3.1.3 | AC | Enhanced CUI flow control | Manual; `data-classification-policy-v2.0.md` | Not Met | DLP and data flow diagrams required |
| **3.1.12e** | 3.1.12 | AC | Enhanced remote access monitoring | `log_aggregator` | Not Met | VPN/ZTNA session audit incomplete |
| **3.5.3e** | 3.5.3 | IA | MFA for all users (local + network) | `config_drift` | Met | Extend to all SaaS via IdP review |
| **3.5.4e** | 3.5.4 | IA | Replay-resistant authentication | `config_drift` (partial) | Not Met | Explicit Kerberos/TLS validation manual |
| **3.11.3e** | 3.11.3 | RA | Risk-based vulnerability remediation | Manual | Not Met | VA scanner + SLA tracking needed |
| **3.11.6e** | 3.11.2 | RA | Threat hunting | `log_aggregator` + playbook | Not Met | Formal hunting program required |
| **3.13.4e** | 3.13.4 | SC | Enhanced shared resource isolation | `config_drift` | Not Met | Container/VM runtime validation |
| **3.13.6e** | 3.13.6 | SC | Deny-by-default networking | `config_drift`, `micro-segmentation-policy.md` | Not Met | Flow documentation + quarterly review |
| **3.13.8e** | 3.13.8 | SC | Enhanced cryptographic protection in transit | `encryption_status`, `config_drift` | Met | Internal mesh encryption on roadmap |
| **3.14.2e** | 3.14.2 | SI | Enhanced malicious code protection | Manual | Not Met | Centralized EDR reporting |
| **3.14.6e** | 3.14.6 | SI | Enhanced system monitoring | `log_aggregator`, `zt_continuous_verification` | Met | SIEM use cases under development |
| **3.14.7e** | 3.14.7 | SI | Enhanced unauthorized use detection | `log_aggregator` | Met | UEBA platform evaluation in progress |

---

## Family grouping

### Access Control enhancements

| Control | Enhancement focus | Implementation path |
|---------|-------------------|---------------------|
| 3.1.3e | CUI flow between sources/destinations | Data flow diagrams; DLP; `micro-segmentation-policy.md` |
| 3.1.12e | Remote session monitoring and audit | ZTNA logging; VPN session exports to SIEM |

### Identification and Authentication enhancements

| Control | Enhancement focus | Implementation path |
|---------|-------------------|---------------------|
| 3.5.3e | MFA for **all** users | `config_drift` + IdP conditional access audit |
| 3.5.4e | Replay-resistant mechanisms | TLS 1.2+; modern auth protocols; manual validation |

### Risk Assessment enhancements

| Control | Enhancement focus | Implementation path |
|---------|-------------------|---------------------|
| 3.11.3e | Prioritized vulnerability remediation | VA tool; risk-based SLAs; POA&M |
| 3.11.6e | Threat hunting | `threat-hunting-playbook.md`; monthly hunts |

### System and Communications Protection enhancements

| Control | Enhancement focus | Implementation path |
|---------|-------------------|---------------------|
| 3.13.4e | Shared resource isolation | Container policies; hypervisor separation evidence |
| 3.13.6e | Deny-by-default; allow by exception | `micro-segmentation-policy.md`; flow reviews |
| 3.13.8e | Enhanced encryption in transit | `encryption_status`; TLS audit via `config_drift` |

### System and Information Integrity enhancements

| Control | Enhancement focus | Implementation path |
|---------|-------------------|---------------------|
| 3.14.2e | Malicious code at entry/exit points | EDR deployment; email/web gateway |
| 3.14.6e | Automated continuous monitoring | `log_aggregator`; SIEM |
| 3.14.7e | Unauthorized use detection | Log analysis; UEBA (manual platform) |

---

## Relationship to 800-171 crosswalk

Base 800-171 family mapping: `docs/NIST_800_171_CROSSWALK.md`

| 800-171 family | 800-172 enhanced controls in seed |
|----------------|-----------------------------------|
| AC | 3.1.3e, 3.1.12e |
| IA | 3.5.3e, 3.5.4e |
| RA | 3.11.3e, 3.11.6e |
| SC | 3.13.4e, 3.13.6e, 3.13.8e |
| SI | 3.14.2e, 3.14.6e, 3.14.7e |

Not all 800-172 enhancements appear in the seed CSV—verify full 800-172 catalog against your SSP scope.

---

## Supply chain (800-171 3.12.4 + L3 context)

800-172 may apply additional scrutiny to supply chain under agency programs. Toolkit support:

- `policies/supply-chain-risk-management-policy.md`
- `docs/templates/vendor-security-questionnaire.md`
- `data/notion-import/vendor-assessment-seed.csv`

**Sentinel scope:** Customer-side cloud configuration only.

---

## Maturity targets

Seed CSV includes **Maturity Target** per enhanced control (Intermediate / Advanced). Align with Zero Trust pillar targets in `data/zero-trust-pillars.csv`.

```bash
sentinel report --input data/zero-trust-pillars.csv --mode zt
```

---

## Honest limitations

| Capability | v2.3 status |
|------------|-------------|
| Enhanced control tracking CSV | ✅ Seed provided |
| Automated 800-172 validation | ❌ Manual assessment required |
| Threat hunting automation | ❌ Playbook only |
| VA scanner integration | ❌ Future release |
| L3 certification | ❌ Requires C3PAO |

---

## Related documents

- `docs/CMMC_L3_OVERVIEW.md`
- `docs/NIST_800_171_CROSSWALK.md`
- `docs/ZERO_TRUST_FRAMEWORK.md`
- `docs/MITRE_ATTCK_COVERAGE.md`
- `data/l3-enhanced-controls.csv`

---

*Crosswalk version 2.3 — SOC2 Sentinel Toolkit.*