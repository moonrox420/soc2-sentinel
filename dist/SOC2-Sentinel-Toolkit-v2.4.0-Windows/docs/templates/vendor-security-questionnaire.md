# Vendor Security Assessment Questionnaire

**Organization:** [ORGANIZATION_NAME]  
**Assessment ID:** [VSA-YYYY-NNN]  
**Vendor name:** [VENDOR_NAME]  
**Service description:** [BRIEF DESCRIPTION]  
**Assessor:** [NAME, TITLE]  
**Assessment date:** [YYYY-MM-DD]  
**Next review date:** [YYYY-MM-DD + 12 months]

> **Disclaimer:** This questionnaire supports supply chain risk management under NIST 800-171 **3.12.4** and CMMC practices. It is a template—not a substitute for FedRAMP authorization review, SOC 2 report analysis by qualified personnel, or contractual negotiation. SOC2 Sentinel validates **your** cloud controls, not vendor infrastructure. Not legal advice.

---

## Section A — Vendor profile

| Field | Response |
|-------|----------|
| **Legal entity name** | |
| **HQ country** | |
| **Subprocessors used?** | [Yes / No — list if yes] |
| **Service category** | [SaaS / IaaS / PaaS / Professional services / Hardware] |
| **Contract type** | [MSA / SOW / Reseller / Open marketplace] |
| **Annual contract value** | [Optional — for risk tiering] |
| **Business criticality** | [Critical / High / Medium / Low] |

---

## Section B — Data and CUI exposure

| Question | Response | Evidence requested |
|----------|----------|-------------------|
| Will vendor process, store, or transmit **CUI**? | [Yes / No / Metadata only] | Data flow diagram |
| Will vendor access **production** systems? | [Yes / No] | Access method (VPN, SSO, API) |
| Data residency requirements met? | [Yes / No / N/A] | Region list |
| Encryption at rest for customer data? | [Yes / No] | Algorithm, key management |
| Encryption in transit? | [Yes / No] | TLS version |
| Customer-managed keys (CMK/BYOK) supported? | [Yes / No / N/A] | |
| Data return / deletion on termination? | [Yes / No] | DPA clause reference |
| Subprocessor notification process? | [Yes / No] | |

**CUI determination:** [Approved / Denied / Conditional — Security Lead sign-off]

---

## Section C — Certifications and attestations

| Certification | Status | Report date | Assessor notes |
|---------------|--------|-------------|----------------|
| **SOC 2 Type II** | [Yes / No / In progress] | | Bridge letter acceptable? |
| **ISO 27001** | [Yes / No] | | |
| **FedRAMP** | [None / Moderate / High / In process] | | Match service to authorization boundary |
| **CMMC** | [Level / N/A] | | Vendor's own CMMC if defense supplier |
| **PCI DSS** | [Yes / No / N/A] | | |
| **HIPAA BAA** | [Yes / No / N/A] | | |

**Request:** Most recent SOC 2 report (NDA), FedRAMP package or CSR excerpt, penetration test summary (redacted).

**Honest note:** A vendor SOC 2 report covers **their** controls at a point in time. You remain responsible for customer-side configuration (Sentinel scope).

---

## Section D — Identity and access

| Question | Compliant? | Notes |
|----------|------------|-------|
| SSO (SAML/OIDC) supported for admin access? | [Y/N] | |
| MFA required for all vendor admin consoles? | [Y/N] | |
| Role-based access with least privilege? | [Y/N] | |
| Access reviews performed by vendor (frequency)? | | |
| Named support personnel for your account? | [Y/N] | |
| Vendor access to your tenant logged and reviewable? | [Y/N] | |

**Sentinel hook:** Your IAM and MFA posture is validated by `iam_access_review` and `config_drift`—not vendor responses alone.

---

## Section E — Logging, monitoring, and incident response

| Question | Compliant? | Notes |
|----------|------------|-------|
| Audit logs available to customer? | [Y/N] | Export format, retention |
| Security incident notification SLA | | Hours/days |
| DFARS 7012 flow-down clause acceptable? | [Y/N / N/A] | Legal review |
| Breach notification within contractual window? | [Y/N] | |
| Vendor maintains IR plan? | [Y/N] | Summary requested |
| Participation in customer IR exercises? | [Y/N / N/A] | |

---

## Section F — Configuration and vulnerability management

| Question | Compliant? | Notes |
|----------|------------|-------|
| Patch management SLA for critical CVEs | | Days |
| Vulnerability scan results shared? | [Y/N] | |
| Secure SDLC / SAST/DAST? | [Y/N] | |
| Change notification for breaking security changes? | [Y/N] | |
| Penetration test frequency | | Annual? |

---

## Section G — Business continuity and resilience

| Question | Compliant? | Notes |
|----------|------------|-------|
| Documented BCP/DR plan? | [Y/N] | |
| RTO/RPO stated for service? | | |
| Geographic redundancy? | [Y/N] | |
| Backup encryption? | [Y/N] | Cross-check with `encryption_status` on your backups |
| Last DR test date | | |

---

## Section H — Legal and contractual

| Item | Status | Reference |
|------|--------|-----------|
| **NDA executed** | [Y/N] | |
| **DPA / BAA signed** | [Y/N / N/A] | |
| **SLA with security exhibits** | [Y/N] | |
| **Right to audit clause** | [Y/N] | |
| **Insurance (cyber liability)** | [Y/N] | Coverage amount |
| **Export control / ITAR** | [Y/N / N/A] | |
| **Flow-down to subcontractors** | [Y/N] | |

---

## Section I — Shared responsibility mapping

Document which NIST 800-171 families are **inherited** vs. **customer responsibility**.

| Family | Inherited | Customer | Evidence |
|--------|-----------|----------|----------|
| AC | [Partial / Full / None] | | |
| AU | | | |
| IA | | | |
| SC | | | |
| PE | [Typically inherited for cloud] | | Provider attestation |
| SI | | | |

**SSP appendix reference:** [Section ID]

---

## Section J — Risk scoring

| Factor | Weight | Score (1–5) | Weighted |
|--------|--------|-------------|----------|
| CUI exposure | 30% | | |
| Access to production | 20% | | |
| Certification strength | 20% | | |
| Incident history | 15% | | |
| Concentration / lock-in | 15% | | |
| **Total** | 100% | | |

| Rating | Range | Action |
|--------|-------|--------|
| **Low** | 1.0 – 2.0 | Annual review |
| **Medium** | 2.1 – 3.5 | Annual review + remediation plan |
| **High** | 3.6 – 4.5 | Quarterly review; executive approval |
| **Critical** | 4.6 – 5.0 | Do not onboard without compensating controls and Legal approval |

**Overall risk rating:** [Low / Medium / High / Critical]

---

## Section K — Remediation and approval

| Finding | Severity | Remediation | Owner | Due date |
|---------|----------|-------------|-------|----------|
| | | | | |

| Decision | |
|----------|--|
| **Approved to onboard / continue** | [Yes / No / Conditional] |
| **Conditions** | |
| **Approver** | [Security Lead / Executive] |
| **Date** | |

---

## Section L — Evidence attachments checklist

- [ ] SOC 2 Type II report (under NDA)
- [ ] FedRAMP authorization letter or marketplace listing (if applicable)
- [ ] Completed vendor security questionnaire (this document)
- [ ] DPA / BAA executed copy
- [ ] Shared responsibility matrix
- [ ] Architecture / data flow diagram
- [ ] Insurance certificate (if required)

Store in secure vendor folder—not public Notion unless SSP authorizes.

---

## Related documents

- `policies/supply-chain-risk-management-policy.md`
- `data/notion-import/vendor-assessment-seed.csv`
- `docs/NIST_800_172_CROSSWALK.md` (enhanced supply chain controls)
- `docs/NOTION_SETUP.md` — Vendor Assessment database

---

*Template version 2.3 — SOC2 Sentinel Toolkit.*