# System Monitoring Policy

**Version:** 2.0  
**Owner:** Security Operations  
**Effective Date:** [EFFECTIVE_DATE]  
**Applies to:** [ORGANIZATION_NAME]

> **Disclaimer:** This template supports compliance readiness. It is not legal advice and does not guarantee certification outcomes.

## Purpose

Ensure [ORGANIZATION_NAME] continuously monitors information systems for security events, performance anomalies, and control failures. Maps to SOC 2 CC7.1/CC7.2, NIST 800-171 AU family, and CMMC L2 audit and accountability practices.

## Scope

Production and staging workloads, cloud control planes, identity providers, endpoints (where MDM deployed), network ingress/egress, and security tooling pipelines.

## Roles and Responsibilities

| Role | Responsibility |
|------|----------------|
| **Security Operations** | Operates SIEM, triages alerts, maintains detection rules |
| **Platform Engineering** | Ensures agents, log forwarders, and exporters are healthy |
| **Engineering Teams** | Instrument applications; remediate monitoring gaps |
| **Compliance** | Archives evidence bundles for audit periods |

## Procedures

1. **Centralized logging** aggregates authentication, administrative, network, and application events to a tamper-resistant store.
2. **Log retention** meets legal, contractual, and `retention_check` policy minimums (typically ≥365 days for security logs).
3. **Clock synchronization** uses NTP across all monitored systems; drift >5 seconds is remediated.
4. **Coverage targets:** ≥95% of in-scope resources must forward logs; gaps documented with remediation plan.
5. **Health checks** validate log pipeline daily; failed forwarders escalate within 4 business hours.
6. **Configuration monitoring** tracks security-relevant changes via cloud config recorders and IaC drift detection.
7. **Vulnerability and integrity signals** (where deployed) feed the same correlation environment.
8. **Evidence export** runs monthly via SOC2 Sentinel collectors and is stored with immutable timestamps.

## Evidence Hooks (SOC2 Sentinel)

| Collector | Metrics | Control Mapping |
|-----------|---------|-----------------|
| `log_aggregator` | `log_coverage_percent`, `active_trails`, `max_gap_hours` | CC7.1 — system monitoring |
| `config_drift` | `unapproved_changes`, configuration recorder status | CC6.2 / CC7.1 — change visibility |
| `retention_check` | Log bucket lifecycle compliance | C1.4 — retention alignment |

Command: `sentinel run log_aggregator --provider aws`

## Review Cadence

- **Coverage review:** Monthly  
- **Detection rule tuning:** Quarterly  
- **Policy review:** Annually

## CUI / Defense Contractor Notes

CUI environments require audit record generation for privileged actions and failed access attempts. Ensure CloudTrail-equivalent logging is enabled in all regions processing defense-related data. Gaps flagged by `max_gap_hours` or inactive trails should be prioritized in POA&M entries.

## Related Documents

- `monitoring-alerting-policy.md`
- `data-retention-disposal-policy-v2.2.md`
- `docs/DFARS_7012_INCIDENT_PROCEDURE.md`