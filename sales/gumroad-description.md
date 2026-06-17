# SOC2 Sentinel Toolkit — Gumroad Product Description

## Headline

**SOC2 Sentinel Toolkit v2.3** — Evidence automation, 110 CMMC practices, DFARS 72-hour IR, ATT&CK hunts, and Zero Trust maturity for defense contractors and regulated SaaS.

---

## Short description (160 chars)

Automate SOC 2 & CMMC evidence on AWS/GCP/Azure. 7 collectors, 17 policies, DFARS DIBNet templates, ATT&CK playbook, ZT maturity CLI. Honest compliance docs.

---

## Full description

Stop rebuilding compliance documentation from scratch every audit cycle.

**SOC2 Sentinel Toolkit v2.3.0** is a Python-based evidence automation package designed for small security teams at **defense contractors and regulated SaaS** companies who need repeatable proof—not another generic policy PDF bundle with no tooling behind it.

### What you get

**🔧 Working CLI automation (7 collectors)**
- `sentinel run-all --provider mock` — test without cloud credentials
- Collectors: `iam_access_review`, `log_aggregator`, `config_drift`, `encryption_status`, `retention_check`, `resilience_testing`, `zt_continuous_verification`
- JSON evidence bundles validated against included schema
- CMMC self-assessment: `sentinel report --input data/cmmc-l2-controls-110.csv --mode cmmc`
- Zero Trust maturity: `sentinel report --input data/zero-trust-pillars.csv --mode zt`

**📋 17 versioned policy templates**
- Core library: access, auth, privileged access, monitoring, change, risk, backup, BC, classification, encryption, transmission, retention
- **v2.3:** incident response, micro-segmentation, continuous verification, supply chain risk
- Each includes evidence hooks tied to real collectors—not fictional integrations

**📚 Implementation documentation**
- `MASTER_REFERENCE_v2.3.md` — complete index
- CMMC L2 (110 practices) + L3 overview + 800-172 crosswalk
- **DFARS 7012** — expanded procedure with classification criteria, 7-step 72h workflow, 90-day preservation, mermaid decision tree, flow-down
- **MITRE ATT&CK** coverage map + threat hunting playbook
- **Zero Trust** seven-pillar framework
- Notion setup for 7 databases (CMMC, incidents, vendors, pre-assessment, ATT&CK, ZT)
- C3PAO 30/60/90 prep, executive summary template

**📝 Operational templates**
- DIBNet report fields (redacted)
- Annual DFARS tabletop record
- Threat hunting queries (log/IAM exports)
- Vendor security questionnaire

**☁️ Multi-cloud support**
- AWS (full collector coverage)
- GCP and Azure (core collectors with documented supplements)

### Who this is for

✅ 10–200 person teams preparing for SOC 2, customer security reviews, or CMMC L2/L3  
✅ Engineers who want `pip install -e .` and real output in `evidence/`  
✅ Compliance leads who need Notion-ready CSV imports for 110 CMMC practices  
✅ Defense contractors needing DFARS tabletop and DIBNet field templates  

❌ Not for organizations expecting a turnkey "get certified" button  
❌ Not a replacement for a C3PAO, auditor, or legal counsel  

### Requirements

- Python 3.10+
- Optional: AWS/GCP/Azure credentials for live scans
- Optional: Notion workspace for control tracking

### Honest disclaimers

- **Not legal advice.** Policies are templates—customize with your counsel.
- **Not a certification guarantee.** CMMC certification requires authorized C3PAO assessment.
- **Not a managed SOC.** Collectors gather configuration evidence; they don't monitor 24/7.
- **Not DFARS filing automation.** Templates support preparation; FSO/Legal submit DIBNet.
- **No fictional case studies.** Examples use generic defense contractor and SaaS scenarios only.
- **Seed CMMC score is illustrative.** Default CSV shows 22/110 Met via automation—you must implement the rest.

### What success looks like

After setup, you run one command monthly, drop JSON into your evidence folder, track CMMC X/110 in Notion, run annual DFARS tabletops with documented records, and brief leadership with ATT&CK and ZT maturity metrics—instead of manually exporting IAM users into spreadsheets at 11 PM before an audit.

### License

MIT — use internally, modify for your org, no per-seat tax.

### Support

Documentation-first product. Community email/support as described on your purchase receipt. No guaranteed SLA unless you purchase a separate support tier.

---

## Tags / keywords

`soc2` `cmmc` `nist-800-171` `nist-800-172` `dfars-7012` `dibnet` `zero-trust` `mitre-attck` `compliance` `aws-security` `devsecops` `evidence-automation` `defense-contractor` `cui` `security-policies` `threat-hunting`

## Pricing note (seller)

Position against $5k+ GRC platforms for **teams that outgrew spreadsheets** but aren't ready for enterprise GRC spend. v2.3 scope justifies premium over v1.x.