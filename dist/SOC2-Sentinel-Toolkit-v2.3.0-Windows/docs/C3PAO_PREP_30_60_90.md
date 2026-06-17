# C3PAO Preparation — 30 / 60 / 90 Day Plan

A practical readiness timeline for **defense contractors and regulated SaaS** organizations pursuing CMMC Level 2 certification via C3PAO assessment.

> **Disclaimer:** This plan supports preparation only. It does not guarantee assessment success, certification, or contract award. Only an authorized C3PAO can perform CMMC Level 2 certification assessments.

## Assumptions

- Target: CMMC Level 2 (NIST 800-171 alignment)
- Environment: Cloud-hosted production (AWS, GCP, and/or Azure)
- Toolkit: SOC2 Sentinel v1.6.0 installed (`pip install -e .`)

---

## Days 1–30: Foundation

### Week 1 — Scope and governance

- [ ] Define **assessment boundary** (systems processing FCI/CUI)
- [ ] Assign **SSP author** and **evidence custodian**
- [ ] Replace `[ORGANIZATION_NAME]` in all `policies/` documents
- [ ] Executive sign-off on policy set (version control in Git)

### Week 2 — Baseline automation

```bash
pip install -e .
sentinel run-all --provider mock   # validate pipeline
sentinel run-all --provider aws    # or gcp/azure per environment
python scripts/generate_controls_csv.py
```

- [ ] Import `data/controls-matrix.csv` to Notion (`docs/NOTION_SETUP.md`)
- [ ] Map each control to **Met / Not Met / POA&M / N/A**

### Week 3 — Gap identification

- [ ] Review all `yellow` and `red` entries in `evidence/**/report.json`
- [ ] Create POA&M for: orphaned IAM accounts, unencrypted buckets, missing log sinks, weak TLS
- [ ] Document manual evidence gaps (AT, PS, PE, IR tabletop)

### Week 4 — SSP draft

- [ ] Complete SSP sections referencing `NIST_800_171_CROSSWALK.md`
- [ ] Attach policy PDFs and first monthly evidence bundle
- [ ] Schedule internal mock interview with engineering leads

**Day 30 exit criteria:** SSP draft v0.8, POA&M with owners, first full `run-all` evidence set stored immutably.

---

## Days 31–60: Remediation and evidence hardening

### Technical remediation priorities

| Priority | Source | Typical fix |
|----------|--------|-------------|
| P1 | `encryption_status` | Enable SSE-KMS on unencrypted S3/RDS |
| P1 | `log_aggregator` | Enable multi-region CloudTrail / centralized logging |
| P2 | `iam_access_review` | Disable orphaned accounts; reduce standing privilege |
| P2 | `config_drift` | Enforce MFA; upgrade TLS policies |
| P3 | `retention_check` | Add lifecycle rules to backup/log buckets |

### Process evidence

- [ ] Quarterly access review **signed attestations**
- [ ] Change management tickets linked to deployments (last 90 days)
- [ ] Security awareness training completion report
- [ ] Incident response tabletop **attendance sheet** (`DFARS_7012_INCIDENT_PROCEDURE.md`)

### Week 6 — Self-assessment

```bash
sentinel report --input data/controls-matrix.csv --output-dir reports/
```

- [ ] Target ≥85% Met (excluding justified N/A) before engaging C3PAO
- [ ] Close or formally risk-accept all **critical** POA&M items

### Week 7–8 — Vendor and cloud inheritance

- [ ] Collect SOC 2 / FedRAMP / ISO letters for critical subprocessors
- [ ] Document cloud shared responsibility matrix
- [ ] Verify CUI storage regions match contract requirements

**Day 60 exit criteria:** POA&M P1/P2 closed, two consecutive monthly `run-all` exports, `sentinel report` score documented.

---

## Days 61–90: C3PAO engagement readiness

### Week 9 — Pre-assessment package

Prepare a single **evidence index** (spreadsheet or Notion) linking:

| Evidence type | Location | Control families |
|---------------|----------|------------------|
| Automated JSON/CSV | `evidence/YYYY-MM-DD/` | AC, AU, CM, IA, MP, SC |
| Policies | `policies/` | All |
| SSP | Internal doc repo | All |
| POA&M | Notion database | CA, RA |
| IR procedure | `docs/DFARS_7012_INCIDENT_PROCEDURE.md` | IR |

### Week 10 — Mock assessment

- [ ] Walk C3PAO-style interviews with system owners
- [ ] Verify evidence **retrieval time** <15 minutes per control family
- [ ] Confirm no CUI in unauthorized tools (email, personal Notion, etc.)

### Week 11 — C3PAO selection

- [ ] Verify C3PAO is **authorized** on Cyber AB marketplace
- [ ] Provide scope diagram, user counts, and data types
- [ ] Agree on assessment window and point-of-contact

### Week 12 — Final hygiene

```bash
sentinel run-all --provider aws --output-base ./c3pao-evidence-final/
```

- [ ] Freeze evidence snapshot 5 business days before on-site/remote assessment
- [ ] Brief executives on **findings response** process (no guarantee of zero findings)

**Day 90 exit criteria:** C3PAO scheduled, evidence index complete, final frozen bundle, internal mock completed.

---

## What Sentinel does NOT cover

- Legal interpretation of DFARS clauses
- Physical security walkthrough
- Penetration testing
- Personnel screening records
- Formal certification issuance

## Recommended metrics dashboard

Track monthly:

- `overall_score_percent` from `sentinel report`
- Count of open POA&M items by severity
- `log_coverage_percent` and `mfa_enforcement_percent`
- Days since last quarterly access review

## Honest expectation setting

Most first-time assessments surface findings. A structured 90-day plan reduces surprises—it does not eliminate them. Budget engineering time for remediation and avoid marketing certification until the C3PAO issues a result.