# CMMC Level 3 Overview

Orientation guide for organizations pursuing **CMMC Level 3** — NIST SP 800-171 practices plus **NIST SP 800-172** enhanced security requirements.

> **Disclaimer:** CMMC L3 certification requires C3PAO assessment against the full L3 practice set. This toolkit provides **preparation materials and partial automation**—not L3 certification. Enhanced control seed data in `data/l3-enhanced-controls.csv` is a starting template; customize for your SSP. Not legal advice.

---

## CMMC level comparison

| Level | Practices | Assessment | Typical use |
|-------|-----------|------------|-------------|
| **L1** | 17 (FAR 52.204-21) | Self-assessment | Federal contract basics |
| **L2** | 110 (800-171) | C3PAO triennial | CUI on non-federal systems |
| **L3** | 110 + 800-172 enhanced | C3PAO triennial | Highest priority CUI programs |

SOC2 Sentinel v2.3 focuses on **L2 self-assessment automation** with L3 **roadmap** documentation. L3 requires capabilities beyond current collectors (threat hunting program, advanced segmentation validation, UEBA, etc.).

---

## What L3 adds beyond L2

NIST 800-172 **enhanced security requirements** address advanced persistent threat scenarios. Selected enhanced controls in the toolkit seed:

| Enhanced ID | Base | Family | Title | Seed status |
|-------------|------|--------|-------|-------------|
| 3.1.3e | 3.1.3 | AC | Enhanced CUI flow control | Not Met — manual DLP/flow mapping |
| 3.1.12e | 3.1.12 | AC | Enhanced remote access monitoring | Not Met — partial `log_aggregator` |
| 3.5.3e | 3.5.3 | IA | MFA for all users | Met — `config_drift` |
| 3.5.4e | 3.5.4 | IA | Replay-resistant authentication | Not Met |
| 3.11.3e | 3.11.3 | RA | Enhanced vulnerability remediation | Not Met |
| 3.11.6e | 3.11.2 | RA | Threat hunting | Not Met — see threat hunting playbook |
| 3.13.4e | 3.13.4 | SC | Enhanced shared resource protection | Not Met |
| 3.13.6e | 3.13.6 | SC | Deny-by-default networking | Not Met — `micro-segmentation-policy.md` |
| 3.13.8e | 3.13.8 | SC | Enhanced crypto in transit | Met — `encryption_status`, `config_drift` |
| 3.14.2e | 3.14.2 | SI | Enhanced malicious code protection | Not Met — EDR integration manual |
| 3.14.6e | 3.14.6 | SI | Enhanced system monitoring | Met — `log_aggregator` |
| 3.14.7e | 3.14.7 | SI | Enhanced unauthorized use detection | Met — partial; UEBA manual |

Source: `data/l3-enhanced-controls.csv`

**Honest count:** Seed shows **4 Met**, **8 Not Met** — illustrative only. Your maturity will differ.

---

## L3 capability domains

### 1. Advanced access and CUI flow

- Document all CUI data flows (sources, destinations, authorizations)
- Deploy DLP or equivalent for CUI tagging and egress control
- Enhanced remote session audit (VPN/ZTNA logs)

**Toolkit:** `micro-segmentation-policy.md`, `data-classification-policy-v2.0.md`

### 2. Threat hunting and analytics

- Formal threat hunting program (not just SIEM alerts)
- Hunt hypotheses tied to ATT&CK techniques
- Monthly hunts using `docs/templates/threat-hunting-playbook.md`

**Toolkit:** `docs/MITRE_ATTCK_COVERAGE.md`, `log_aggregator` + IAM exports

### 3. Network micro-segmentation

- Deny-by-default with documented permitted flows
- Quarterly flow review
- ZTNA for remote access

**Toolkit:** `policies/micro-segmentation-policy.md`, `config_drift`

### 4. Continuous verification

- Never-trust-always-verify between annual assessments
- Monthly `zt_continuous_verification` collector

**Toolkit:** `policies/continuous-verification-procedure.md`, `docs/ZERO_TRUST_FRAMEWORK.md`

### 5. Supply chain depth

- Enhanced vendor scrutiny for CUI-touching suppliers
- Subcontractor CMMC flow-down evidence

**Toolkit:** `supply-chain-risk-management-policy.md`, `vendor-security-questionnaire.md`

---

## L3 preparation roadmap

| Phase | Timeline | Activities |
|-------|----------|------------|
| **Foundation** | Months 1–3 | Close L2 POA&M; achieve ≥85% L2 Met; SSP v1.0 |
| **Enhanced controls** | Months 4–6 | Implement 3.13.6e segmentation; 3.11.6e hunting program; 3.1.3e DLP |
| **Validation** | Months 7–9 | Mock L3 interviews; red team or segmentation test; ZT maturity Advanced |
| **C3PAO** | Month 10+ | Engage C3PAO with L3 scope; evidence freeze |

Detailed L2 prep: `docs/C3PAO_PREP_30_60_90.md`

---

## Sentinel automation at L3

| L3 need | v2.3 coverage | Gap |
|---------|---------------|-----|
| MFA all users | `config_drift` | IdP export for non-cloud apps |
| Encryption in transit | `config_drift`, `encryption_status` | Internal service mesh |
| Continuous monitoring | `log_aggregator`, `zt_continuous_verification` | SIEM correlation rules |
| Threat hunting | Playbook + exports | No automated hunt engine |
| Segmentation | `config_drift` drift | No live penetration test |
| Vulnerability remediation | Manual | VA scanner integration future |

---

## Assessment expectations

C3PAO L3 assessment includes:

- Document review (SSP, policies, POA&M)
- Interviews with control owners
- Technical testing (sampled)—may include configuration validation
- 800-172 enhanced requirement verification

**This toolkit does not replace** C3PAO technical testing or expert witness testimony.

---

## Related documents

- `docs/CMMC_L2_CONTROLS_REFERENCE.md`
- `docs/NIST_800_172_CROSSWALK.md`
- `docs/ZERO_TRUST_FRAMEWORK.md`
- `docs/MITRE_ATTCK_COVERAGE.md`
- `data/l3-enhanced-controls.csv`

---

*Overview version 2.3 — SOC2 Sentinel Toolkit.*