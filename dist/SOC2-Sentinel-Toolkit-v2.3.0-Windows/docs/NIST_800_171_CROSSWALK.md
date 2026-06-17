# NIST 800-171 Rev 2 Crosswalk

Maps NIST SP 800-171 **14 control families** to SOC2 Sentinel collectors, toolkit policies, and honest implementation notes.

> **Disclaimer:** This crosswalk supports self-assessment preparation. It is not a substitute for a formal NIST 800-171 assessment, SSP, or C3PAO-led CMMC evaluation.

## 14 control families

| # | Family | Code | Primary NIST intent | SOC2 Sentinel collectors | Toolkit policy | Implementation notes |
|---|--------|------|---------------------|--------------------------|----------------|----------------------|
| 1 | Access Control | AC | Limit system access to authorized users and transactions | `iam_access_review`, `config_drift` | `access-control-policy-v2.3.md`, `privileged-access-policy-v2.2.md` | Automated IAM export covers account inventory; manual evidence still needed for account creation approvals and session termination records. |
| 2 | Awareness and Training | AT | Ensure personnel are trained on security risks | Manual | — (organizational) | No automated collector; maintain training LMS exports and annual sign-off sheets. |
| 3 | Audit and Accountability | AU | Create, protect, and review audit records | `log_aggregator`, `retention_check` | `system-monitoring-policy-v2.0.md` | Validates logging coverage and retention alignment; does not replace SIEM rule documentation or log review tickets. |
| 4 | Configuration Management | CM | Establish baseline configurations and change control | `config_drift`, `log_aggregator` | `change-management-policy-v2.4.md` | Detects weak TLS, MFA gaps, and config recorder status; CAB minutes and change tickets remain manual. |
| 5 | Identification and Authentication | IA | Identify users and authenticate before access | `config_drift`, `iam_access_review` | `authentication-access-policy-v2.1.md` | MFA percentage from AWS IAM snapshot; IdP conditional access policies require separate export. |
| 6 | Incident Response | IR | Detect, respond, recover from incidents | Manual (+ `log_aggregator` signals) | See `DFARS_7012_INCIDENT_PROCEDURE.md` | Collectors surface control failures; IR playbooks, tabletop results, and DIBNET reporting are procedural. |
| 7 | Maintenance | MA | Perform maintenance with controlled tools | Manual | — | Patch cadence and maintenance logs are outside Sentinel scope in v1.6.0. |
| 8 | Media Protection | MP | Protect and sanitize system media | `encryption_status`, `retention_check` | `data-classification-policy-v2.0.md`, `data-retention-disposal-policy-v2.2.md` | Encryption at rest scans; physical media sanitization requires facility records. |
| 9 | Personnel Security | PS | Screen and protect personnel | Manual | — | HR background checks and termination checklists are organizational controls. |
| 10 | Physical Protection | PE | Limit physical access | Manual | — | Cloud-first orgs document provider inheritance; office access logs are manual. |
| 11 | Risk Assessment | RA | Assess operational risk | `run-all` status summary | `risk-management-policy-v2.1.md` | Monthly collector runs feed risk register; formal RA workshop output is manual. |
| 12 | Security Assessment | CA | Periodically assess security controls | `self_assessment_report` (`sentinel report`) | `CMMC_L2_SELF_ASSESSMENT.md` | Generates score from controls CSV; not equivalent to independent assessment. |
| 13 | System and Communications Protection | SC | Protect boundaries and encrypt communications | `encryption_status`, `config_drift` | `secure-transmission-policy-v2.1.md`, `encryption-key-management-policy-v2.3.md` | TLS listener and encryption-at-rest checks; network segmentation evidence is manual. |
| 14 | System and Information Integrity | SI | Identify and remediate flaws; monitor security alerts | `log_aggregator`, `config_drift` | `monitoring-alerting-policy.md` | Alert coverage metrics; vulnerability scanning and malware protection require separate tools. |

## Collector quick reference

```bash
sentinel run-all --provider aws
sentinel report --input data/controls-matrix.csv
```

## CMMC Level 2 alignment

CMMC L2 practices map to NIST 800-171 controls. Families with **strong** Sentinel automation: AC, AU, CM (partial), IA (partial), MP (partial), SC, SI (partial).

Families requiring **mostly manual** evidence: AT, IR (process), MA, PS, PE.

## CUI / defense contractor guidance

- Document **shared responsibility** for PE and physical controls when using hyperscale cloud
- Map each `red`/`yellow` Sentinel status to a POA&M entry with 800-171 control ID
- Do not claim 800-171 compliance based solely on automated scans
- Consult your C3PAO or agency AO for assessment scope

## Related documents

- `docs/C3PAO_PREP_30_60_90.md`
- `docs/CMMC_L2_SELF_ASSESSMENT.md`
- `docs/DFARS_7012_INCIDENT_PROCEDURE.md`
- `policies/` — versioned policy templates