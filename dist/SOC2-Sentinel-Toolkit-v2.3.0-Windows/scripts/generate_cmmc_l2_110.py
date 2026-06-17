#!/usr/bin/env python3
"""Generate CMMC Level 2 control CSVs — all 110 NIST SP 800-171 Rev 2 requirements."""
from __future__ import annotations

import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
NOTION = DATA / "notion-import"

FIELDNAMES = [
    "Requirement ID",
    "Family",
    "Requirement Title",
    "Full Requirement Text",
    "CMMC L2 Status",
    "Evidence Strength",
    "Linked SOC2 Control",
    "Automation Hook",
    "Implementation Statement",
    "Owner",
]

# fmt: off
# NIST SP 800-171 Rev 2 — 110 security requirements (3.1.1 through 3.14.7)
NIST_800_171_R2: list[tuple[str, str, str, str]] = [
    # 3.1 Access Control (22)
    ("3.1.1", "Access Control", "Limit System Access",
     "Limit system access to authorized users, processes acting on behalf of authorized users, and devices (including other systems)."),
    ("3.1.2", "Access Control", "Limit Transactions and Functions",
     "Limit system access to the types of transactions and functions that authorized users are permitted to execute."),
    ("3.1.3", "Access Control", "Control CUI Flow",
     "Control the flow of CUI in accordance with approved authorizations."),
    ("3.1.4", "Access Control", "Separation of Duties",
     "Separate the duties of individuals to reduce the risk of malevolent activity without collusion."),
    ("3.1.5", "Access Control", "Least Privilege",
     "Employ the principle of least privilege, including for specific security functions and privileged accounts."),
    ("3.1.6", "Access Control", "Non-Privileged Accounts for Nonsecurity Functions",
     "Use non-privileged accounts or roles when accessing nonsecurity functions."),
    ("3.1.7", "Access Control", "Privileged Function Control",
     "Prevent non-privileged users from executing privileged functions and capture the execution of such functions in audit logs."),
    ("3.1.8", "Access Control", "Unsuccessful Logon Attempts",
     "Limit unsuccessful logon attempts."),
    ("3.1.9", "Access Control", "Privacy and Security Notices",
     "Provide privacy and security notices consistent with applicable CUI rules."),
    ("3.1.10", "Access Control", "Session Lock",
     "Use session lock with pattern-hiding displays to prevent access and viewing of data after a period of inactivity."),
    ("3.1.11", "Access Control", "Session Termination",
     "Terminate (automatically) a user session after a defined condition."),
    ("3.1.12", "Access Control", "Remote Access Session Control",
     "Monitor and control remote access sessions."),
    ("3.1.13", "Access Control", "Cryptographic Protection of Remote Access",
     "Employ cryptographic mechanisms to protect the confidentiality of remote access sessions."),
    ("3.1.14", "Access Control", "Managed Remote Access Points",
     "Route remote access via managed access control points."),
    ("3.1.15", "Access Control", "Authorize Remote Privileged Commands",
     "Authorize remote execution of privileged commands and remote access to security-relevant information."),
    ("3.1.16", "Access Control", "Authorize Wireless Access",
     "Authorize wireless access prior to allowing such connections."),
    ("3.1.17", "Access Control", "Protect Wireless Access",
     "Protect wireless access using authentication and encryption."),
    ("3.1.18", "Access Control", "Mobile Device Connection Control",
     "Control connection of mobile devices."),
    ("3.1.19", "Access Control", "Encrypt CUI on Mobile Devices",
     "Encrypt CUI on mobile devices and mobile computing platforms."),
    ("3.1.20", "Access Control", "External System Connections",
     "Verify and control/limit connections to and use of external systems."),
    ("3.1.21", "Access Control", "Portable Storage on External Systems",
     "Limit use of portable storage devices on external systems."),
    ("3.1.22", "Access Control", "Publicly Accessible Systems",
     "Control CUI posted or processed on publicly accessible systems."),
    # 3.2 Awareness and Training (3)
    ("3.2.1", "Awareness and Training", "Security Awareness",
     "Ensure that managers, systems administrators, and users of organizational systems are made aware of the security risks associated with their activities and of the applicable policies, standards, and procedures related to the security of those systems."),
    ("3.2.2", "Awareness and Training", "Role-Based Training",
     "Ensure that personnel are trained to carry out their assigned information security-related duties and responsibilities."),
    ("3.2.3", "Awareness and Training", "Insider Threat Awareness",
     "Provide security awareness training on recognizing and reporting potential indicators of insider threat."),
    # 3.3 Audit and Accountability (9)
    ("3.3.1", "Audit and Accountability", "Audit Log Creation and Retention",
     "Create and retain system audit logs and records to the extent needed to enable the monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity."),
    ("3.3.2", "Audit and Accountability", "User Accountability",
     "Ensure that the actions of individual system users can be uniquely traced to those users, so they can be held accountable for their actions."),
    ("3.3.3", "Audit and Accountability", "Review and Update Logged Events",
     "Review and update logged events."),
    ("3.3.4", "Audit and Accountability", "Audit Logging Failure Alerts",
     "Alert in the event of an audit logging process failure."),
    ("3.3.5", "Audit and Accountability", "Audit Correlation and Reporting",
     "Correlate audit record review, analysis, and reporting processes for investigation and response to indications of unlawful, unauthorized, suspicious, or unusual activity."),
    ("3.3.6", "Audit and Accountability", "Audit Reduction and Report Generation",
     "Provide audit record reduction and report generation to support on-demand analysis and reporting."),
    ("3.3.7", "Audit and Accountability", "Authoritative Time Source",
     "Provide a system capability that compares and synchronizes internal system clocks with an authoritative source to generate time stamps for audit records."),
    ("3.3.8", "Audit and Accountability", "Protect Audit Information",
     "Protect audit information and audit logging tools from unauthorized access, modification, and deletion."),
    ("3.3.9", "Audit and Accountability", "Limit Audit Management",
     "Limit management of audit logging functionality to a subset of privileged users."),
    # 3.4 Configuration Management (9)
    ("3.4.1", "Configuration Management", "Baseline Configuration and Inventory",
     "Establish and maintain baseline configurations and inventories of organizational systems (including hardware, software, firmware, and documentation) throughout the respective system development life cycles."),
    ("3.4.2", "Configuration Management", "Security Configuration Settings",
     "Establish and enforce security configuration settings for information technology products employed in organizational systems."),
    ("3.4.3", "Configuration Management", "Change Tracking and Approval",
     "Track, review, approve or disapprove, and log changes to organizational systems."),
    ("3.4.4", "Configuration Management", "Security Impact Analysis",
     "Analyze the security impact of changes prior to implementation."),
    ("3.4.5", "Configuration Management", "Access Restrictions for Changes",
     "Define, document, approve, and enforce physical and logical access restrictions associated with changes to organizational systems."),
    ("3.4.6", "Configuration Management", "Least Functionality",
     "Employ the principle of least functionality by configuring organizational systems to provide only essential capabilities."),
    ("3.4.7", "Configuration Management", "Restrict Nonessential Functions",
     "Restrict, disable, or prevent the use of nonessential programs, functions, ports, protocols, and services."),
    ("3.4.8", "Configuration Management", "Application Execution Policy",
     "Apply deny-by-exception (blacklisting) policy to prevent the use of unauthorized software or deny-all, permit-by-exception (whitelisting) policy to allow the execution of authorized software."),
    ("3.4.9", "Configuration Management", "User-Installed Software",
     "Control and monitor user-installed software."),
    # 3.5 Identification and Authentication (11)
    ("3.5.1", "Identification and Authentication", "User and Device Identification",
     "Identify system users, processes acting on behalf of users, and devices."),
    ("3.5.2", "Identification and Authentication", "User and Device Authentication",
     "Authenticate (or verify) the identities of users, processes, or devices, as a prerequisite to allowing access to organizational systems."),
    ("3.5.3", "Identification and Authentication", "Multifactor Authentication",
     "Use multifactor authentication for local and network access to privileged accounts and for network access to non-privileged accounts."),
    ("3.5.4", "Identification and Authentication", "Replay-Resistant Authentication",
     "Employ replay-resistant authentication mechanisms for network access to privileged and non-privileged accounts."),
    ("3.5.5", "Identification and Authentication", "Identifier Reuse Prevention",
     "Prevent reuse of identifiers for a defined period."),
    ("3.5.6", "Identification and Authentication", "Disable Inactive Identifiers",
     "Disable identifiers after a defined period of inactivity."),
    ("3.5.7", "Identification and Authentication", "Password Complexity",
     "Enforce a minimum password complexity and change of characters when new passwords are created."),
    ("3.5.8", "Identification and Authentication", "Password Reuse Prohibition",
     "Prohibit password reuse for a specified number of generations."),
    ("3.5.9", "Identification and Authentication", "Temporary Password Management",
     "Allow temporary password use for system logons with an immediate change to a permanent password."),
    ("3.5.10", "Identification and Authentication", "Cryptographically Protected Passwords",
     "Store and transmit only cryptographically-protected passwords."),
    ("3.5.11", "Identification and Authentication", "Obscure Authentication Feedback",
     "Obscure feedback of authentication information."),
    # 3.6 Incident Response (3)
    ("3.6.1", "Incident Response", "Incident Handling Capability",
     "Establish an operational incident-handling capability for organizational systems that includes preparation, detection, analysis, containment, recovery, and user response activities."),
    ("3.6.2", "Incident Response", "Incident Tracking and Reporting",
     "Track, document, and report incidents to designated officials and/or authorities both internal and external to the organization."),
    ("3.6.3", "Incident Response", "Incident Response Testing",
     "Test the organizational incident response capability."),
    # 3.7 Maintenance (6)
    ("3.7.1", "Maintenance", "System Maintenance",
     "Perform maintenance on organizational systems."),
    ("3.7.2", "Maintenance", "Maintenance Tool Controls",
     "Provide controls on the tools, techniques, mechanisms, and personnel used to conduct system maintenance."),
    ("3.7.3", "Maintenance", "Off-Site Maintenance Sanitization",
     "Ensure equipment removed for off-site maintenance is sanitized of any CUI."),
    ("3.7.4", "Maintenance", "Media Inspection for Malicious Code",
     "Check media containing diagnostic and test programs for malicious code before the media are used in organizational systems."),
    ("3.7.5", "Maintenance", "Nonlocal Maintenance Authentication",
     "Require multifactor authentication to establish nonlocal maintenance sessions via external network connections and terminate such connections when nonlocal maintenance is complete."),
    ("3.7.6", "Maintenance", "Supervise Maintenance Personnel",
     "Supervise the maintenance activities of maintenance personnel without required access authorization."),
    # 3.8 Media Protection (9)
    ("3.8.1", "Media Protection", "Protect System Media",
     "Protect (i.e., physically control and securely store) system media containing CUI, both paper and digital."),
    ("3.8.2", "Media Protection", "Limit Media Access",
     "Limit access to CUI on system media to authorized users."),
    ("3.8.3", "Media Protection", "Media Sanitization",
     "Sanitize or destroy system media containing CUI before disposal or release for reuse."),
    ("3.8.4", "Media Protection", "Media Marking",
     "Mark media with necessary CUI markings and distribution limitations."),
    ("3.8.5", "Media Protection", "Media Transport Accountability",
     "Control access to media containing CUI and maintain accountability for media during transport outside of controlled areas."),
    ("3.8.6", "Media Protection", "Cryptographic Protection During Transport",
     "Implement cryptographic mechanisms to protect the confidentiality of CUI stored on digital media during transport unless otherwise protected by alternative physical safeguards."),
    ("3.8.7", "Media Protection", "Removable Media Control",
     "Control the use of removable media on system components."),
    ("3.8.8", "Media Protection", "Portable Storage Device Prohibition",
     "Prohibit the use of portable storage devices when such devices have no identifiable owner."),
    ("3.8.9", "Media Protection", "Backup CUI Protection",
     "Protect the confidentiality of backup CUI at storage locations."),
    # 3.9 Personnel Security (2)
    ("3.9.1", "Personnel Security", "Personnel Screening",
     "Screen individuals prior to authorizing access to organizational systems containing CUI."),
    ("3.9.2", "Personnel Security", "Personnel Actions",
     "Ensure that organizational systems containing CUI are protected during and after personnel actions such as terminations and transfers."),
    # 3.10 Physical Protection (6)
    ("3.10.1", "Physical Protection", "Limit Physical Access",
     "Limit physical access to organizational systems, equipment, and the respective operating environments to authorized individuals."),
    ("3.10.2", "Physical Protection", "Protect and Monitor Facilities",
     "Protect and monitor the physical facility and support infrastructure for organizational systems."),
    ("3.10.3", "Physical Protection", "Visitor Escort and Monitoring",
     "Escort visitors and monitor visitor activity."),
    ("3.10.4", "Physical Protection", "Physical Access Audit Logs",
     "Maintain audit logs of physical access."),
    ("3.10.5", "Physical Protection", "Physical Access Device Management",
     "Control and manage physical access devices."),
    ("3.10.6", "Physical Protection", "Alternate Work Site Safeguards",
     "Enforce safeguarding measures for CUI at alternate work sites."),
    # 3.11 Risk Assessment (3)
    ("3.11.1", "Risk Assessment", "Periodic Risk Assessment",
     "Periodically assess the risk to organizational operations (including mission, functions, image, or reputation), organizational assets, and individuals, resulting from the operation of organizational systems and the associated processing, storage, or transmission of CUI."),
    ("3.11.2", "Risk Assessment", "Vulnerability Scanning",
     "Scan for vulnerabilities in organizational systems and applications periodically and when new vulnerabilities affecting those systems and applications are identified."),
    ("3.11.3", "Risk Assessment", "Vulnerability Remediation",
     "Remediate vulnerabilities in accordance with risk assessments."),
    # 3.12 Security Assessment (4)
    ("3.12.1", "Security Assessment", "Security Control Assessment",
     "Periodically assess the security controls in organizational systems to determine if the controls are effective in their application."),
    ("3.12.2", "Security Assessment", "Plan of Action and Milestones",
     "Develop and implement plans of action designed to correct deficiencies and reduce or eliminate vulnerabilities in organizational systems."),
    ("3.12.3", "Security Assessment", "Continuous Monitoring",
     "Monitor security controls on an ongoing basis to ensure the continued effectiveness of the controls."),
    ("3.12.4", "Security Assessment", "System Security Plan",
     "Develop, document, and periodically update system security plans that describe system boundaries, system environments of operation, how security requirements are implemented, and the relationships with or connections to other systems."),
    # 3.13 System and Communications Protection (16)
    ("3.13.1", "System and Communications Protection", "Boundary Protection",
     "Monitor, control, and protect communications (i.e., information transmitted or received by organizational systems) at the external boundaries and key internal boundaries of organizational systems."),
    ("3.13.2", "System and Communications Protection", "Security Engineering Principles",
     "Employ architectural designs, software development techniques, and systems engineering principles that promote effective information security within organizational systems."),
    ("3.13.3", "System and Communications Protection", "Separate User and Management Functionality",
     "Separate user functionality from system management functionality."),
    ("3.13.4", "System and Communications Protection", "Shared Resource Protection",
     "Prevent unauthorized and unintended information transfer via shared system resources."),
    ("3.13.5", "System and Communications Protection", "Publicly Accessible System Separation",
     "Implement subnetworks for publicly accessible system components that are physically or logically separated from internal networks."),
    ("3.13.6", "System and Communications Protection", "Deny by Default Network Traffic",
     "Deny network communications traffic by default and allow network communications traffic by exception (i.e., deny all, permit by exception)."),
    ("3.13.7", "System and Communications Protection", "Split Tunneling Prevention",
     "Prevent remote devices from simultaneously establishing non-remote connections with organizational systems and communicating via some other connection to resources in external networks (i.e., split tunneling)."),
    ("3.13.8", "System and Communications Protection", "Cryptographic Protection in Transit",
     "Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission unless otherwise protected by alternative physical safeguards."),
    ("3.13.9", "System and Communications Protection", "Session Termination",
     "Terminate network connections associated with communications sessions at the end of the sessions or after a defined period of inactivity."),
    ("3.13.10", "System and Communications Protection", "Cryptographic Key Management",
     "Establish and manage cryptographic keys for cryptography employed in organizational systems."),
    ("3.13.11", "System and Communications Protection", "FIPS-Validated Cryptography",
     "Employ FIPS-validated cryptography when used to protect the confidentiality of CUI."),
    ("3.13.12", "System and Communications Protection", "Collaborative Computing Device Control",
     "Prohibit remote activation of collaborative computing devices and provide indication of devices in use to users present at the device."),
    ("3.13.13", "System and Communications Protection", "Mobile Code Control",
     "Control and monitor the use of mobile code."),
    ("3.13.14", "System and Communications Protection", "VoIP Control",
     "Control and monitor the use of Voice over Internet Protocol (VoIP) technologies."),
    ("3.13.15", "System and Communications Protection", "Session Authenticity",
     "Protect the authenticity of communications sessions."),
    ("3.13.16", "System and Communications Protection", "CUI at Rest Protection",
     "Protect the confidentiality of CUI at rest."),
    # 3.14 System and Information Integrity (7)
    ("3.14.1", "System and Information Integrity", "Flaw Remediation",
     "Identify, report, and correct information and information system flaws in a timely manner."),
    ("3.14.2", "System and Information Integrity", "Malicious Code Protection",
     "Provide protection from malicious code at appropriate locations within organizational systems."),
    ("3.14.3", "System and Information Integrity", "Security Alerts and Advisories",
     "Monitor system security alerts and advisories and take action in response."),
    ("3.14.4", "System and Information Integrity", "Malicious Code Updates",
     "Update malicious code protection mechanisms when new releases are available."),
    ("3.14.5", "System and Information Integrity", "Periodic and Real-Time Malware Scanning",
     "Perform periodic scans of organizational systems and real-time scans of files from external sources as files are downloaded, opened, or executed."),
    ("3.14.6", "System and Information Integrity", "System Monitoring",
     "Monitor organizational systems, including inbound and outbound communications traffic, for unusual or unauthorized activities or conditions."),
    ("3.14.7", "System and Information Integrity", "Identify Unauthorized Use",
     "Identify unauthorized use of organizational systems."),
]
# fmt: on

# ~20 technical controls with Sentinel automation — Met/Strong
AUTOMATION_OVERRIDES: dict[str, dict[str, str]] = {
    "3.1.1": {
        "CMMC L2 Status": "Met",
        "Evidence Strength": "Strong",
        "Linked SOC2 Control": "CC6.1",
        "Automation Hook": "iam_access_review",
        "Implementation Statement": "Quarterly IAM export validates authorized user inventory; orphaned accounts flagged for remediation.",
        "Owner": "Security Engineering",
    },
    "3.1.5": {
        "CMMC L2 Status": "Met",
        "Evidence Strength": "Strong",
        "Linked SOC2 Control": "CC6.3",
        "Automation Hook": "iam_access_review",
        "Implementation Statement": "Privileged and standing admin accounts reviewed quarterly; least-privilege enforced via IAM policy analysis.",
        "Owner": "Security Engineering",
    },
    "3.1.7": {
        "CMMC L2 Status": "Met",
        "Evidence Strength": "Strong",
        "Linked SOC2 Control": "CC6.3",
        "Automation Hook": "iam_access_review; log_aggregator",
        "Implementation Statement": "Privileged function execution captured in CloudTrail/admin audit logs; non-privileged role separation validated.",
        "Owner": "Security Engineering",
    },
    "3.1.8": {
        "CMMC L2 Status": "Met",
        "Evidence Strength": "Strong",
        "Linked SOC2 Control": "CC6.2",
        "Automation Hook": "config_drift",
        "Implementation Statement": "Account lockout and failed-auth thresholds monitored via identity provider and IAM configuration drift checks.",
        "Owner": "Security Engineering",
    },
    "3.3.1": {
        "CMMC L2 Status": "Met",
        "Evidence Strength": "Strong",
        "Linked SOC2 Control": "CC7.1",
        "Automation Hook": "log_aggregator",
        "Implementation Statement": "Centralized logging with completeness metrics; audit records retained per policy via log sink validation.",
        "Owner": "Security Engineering",
    },
    "3.3.2": {
        "CMMC L2 Status": "Met",
        "Evidence Strength": "Strong",
        "Linked SOC2 Control": "CC7.1",
        "Automation Hook": "log_aggregator",
        "Implementation Statement": "Unique user attribution verified through IAM identity linkage in audit log exports.",
        "Owner": "Security Engineering",
    },
    "3.3.5": {
        "CMMC L2 Status": "Met",
        "Evidence Strength": "Adequate",
        "Linked SOC2 Control": "CC7.2",
        "Automation Hook": "log_aggregator",
        "Implementation Statement": "Log aggregation enables correlation of security events; SIEM rule documentation maintained separately.",
        "Owner": "Security Engineering",
    },
    "3.3.8": {
        "CMMC L2 Status": "Met",
        "Evidence Strength": "Strong",
        "Linked SOC2 Control": "CC7.1",
        "Automation Hook": "log_aggregator",
        "Implementation Statement": "Log bucket encryption and access policies validated; tamper-evident storage enforced.",
        "Owner": "Security Engineering",
    },
    "3.4.1": {
        "CMMC L2 Status": "Met",
        "Evidence Strength": "Adequate",
        "Linked SOC2 Control": "CC8.1",
        "Automation Hook": "config_drift",
        "Implementation Statement": "Infrastructure configuration snapshots establish baseline; drift detection surfaces unauthorized changes.",
        "Owner": "Platform Engineering",
    },
    "3.4.2": {
        "CMMC L2 Status": "Met",
        "Evidence Strength": "Strong",
        "Linked SOC2 Control": "CC8.1",
        "Automation Hook": "config_drift",
        "Implementation Statement": "Security configuration settings (MFA, TLS, encryption) continuously validated against hardened baselines.",
        "Owner": "Platform Engineering",
    },
    "3.4.3": {
        "CMMC L2 Status": "Met",
        "Evidence Strength": "Adequate",
        "Linked SOC2 Control": "CC8.1",
        "Automation Hook": "config_drift",
        "Implementation Statement": "Configuration changes detected via drift monitoring; CAB tickets required for production changes.",
        "Owner": "Platform Engineering",
    },
    "3.5.1": {
        "CMMC L2 Status": "Met",
        "Evidence Strength": "Strong",
        "Linked SOC2 Control": "CC6.1",
        "Automation Hook": "iam_access_review",
        "Implementation Statement": "User, service account, and device identity inventory exported and reconciled quarterly.",
        "Owner": "Security Engineering",
    },
    "3.5.2": {
        "CMMC L2 Status": "Met",
        "Evidence Strength": "Strong",
        "Linked SOC2 Control": "CC6.2",
        "Automation Hook": "config_drift",
        "Implementation Statement": "Authentication mechanisms validated; SSO and federation configuration monitored for drift.",
        "Owner": "Security Engineering",
    },
    "3.5.3": {
        "CMMC L2 Status": "Met",
        "Evidence Strength": "Strong",
        "Linked SOC2 Control": "CC6.2",
        "Automation Hook": "config_drift",
        "Implementation Statement": "MFA enforcement percentage tracked across human and privileged accounts; gaps flagged automatically.",
        "Owner": "Security Engineering",
    },
    "3.5.10": {
        "CMMC L2 Status": "Met",
        "Evidence Strength": "Adequate",
        "Linked SOC2 Control": "CC6.2",
        "Automation Hook": "config_drift",
        "Implementation Statement": "Password storage and transmission validated via TLS and identity provider configuration checks.",
        "Owner": "Security Engineering",
    },
    "3.8.9": {
        "CMMC L2 Status": "Met",
        "Evidence Strength": "Strong",
        "Linked SOC2 Control": "C1.2",
        "Automation Hook": "encryption_status; retention_check",
        "Implementation Statement": "Backup storage encryption validated; retention policies enforced on backup buckets.",
        "Owner": "Platform Engineering",
    },
    "3.12.1": {
        "CMMC L2 Status": "Met",
        "Evidence Strength": "Adequate",
        "Linked SOC2 Control": "CC7.2",
        "Automation Hook": "self_assessment_report",
        "Implementation Statement": "Monthly self-assessment report scores control effectiveness from automated evidence collection.",
        "Owner": "Compliance",
    },
    "3.13.8": {
        "CMMC L2 Status": "Met",
        "Evidence Strength": "Strong",
        "Linked SOC2 Control": "C1.3",
        "Automation Hook": "encryption_status; config_drift",
        "Implementation Statement": "TLS 1.2+ enforced on public endpoints; weak cipher configurations flagged by drift scanner.",
        "Owner": "Platform Engineering",
    },
    "3.13.11": {
        "CMMC L2 Status": "Met",
        "Evidence Strength": "Strong",
        "Linked SOC2 Control": "C1.2",
        "Automation Hook": "encryption_status",
        "Implementation Statement": "FIPS-validated encryption algorithms verified on storage and KMS configurations.",
        "Owner": "Platform Engineering",
    },
    "3.13.16": {
        "CMMC L2 Status": "Met",
        "Evidence Strength": "Strong",
        "Linked SOC2 Control": "C1.2",
        "Automation Hook": "encryption_status",
        "Implementation Statement": "Encryption-at-rest posture validated across S3, RDS, EBS, and managed database services.",
        "Owner": "Platform Engineering",
    },
    "3.14.6": {
        "CMMC L2 Status": "Met",
        "Evidence Strength": "Strong",
        "Linked SOC2 Control": "CC7.1",
        "Automation Hook": "log_aggregator",
        "Implementation Statement": "Inbound/outbound traffic monitoring via VPC flow logs and centralized log completeness checks.",
        "Owner": "Security Engineering",
    },
    "3.14.7": {
        "CMMC L2 Status": "Met",
        "Evidence Strength": "Strong",
        "Linked SOC2 Control": "CC7.1",
        "Automation Hook": "log_aggregator",
        "Implementation Statement": "Unauthorized access patterns detected through audit log analysis and anomaly alerting.",
        "Owner": "Security Engineering",
    },
}

DEFAULT_ROW = {
    "CMMC L2 Status": "Not Met",
    "Evidence Strength": "Missing",
    "Linked SOC2 Control": "",
    "Automation Hook": "Manual",
    "Implementation Statement": "Not yet implemented; requires policy, process, or technical control deployment.",
    "Owner": "",
}


def build_rows() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for req_id, family, title, text in NIST_800_171_R2:
        row = {
            "Requirement ID": req_id,
            "Family": family,
            "Requirement Title": title,
            "Full Requirement Text": text,
            **DEFAULT_ROW,
        }
        if req_id in AUTOMATION_OVERRIDES:
            row.update(AUTOMATION_OVERRIDES[req_id])
        rows.append(row)
    return rows


def write_csv(path: Path, rows: list[dict[str, str]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def notion_subset(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    """Export automated / Met controls for Notion dashboard import."""
    return [
        r for r in rows
        if r["Automation Hook"] != "Manual" or r["CMMC L2 Status"] == "Met"
    ]


def main() -> int:
    rows = build_rows()
    expected = 110
    if len(rows) != expected:
        print(f"ERROR: Expected {expected} requirements, got {len(rows)}", file=sys.stderr)
        return 1

    full_path = DATA / "cmmc-l2-controls-110.csv"
    notion_path = NOTION / "cmmc-l2-controls.csv"
    write_csv(full_path, rows, FIELDNAMES)
    subset = notion_subset(rows)
    write_csv(notion_path, subset, FIELDNAMES)

    met_count = sum(1 for r in rows if r["CMMC L2 Status"] == "Met")
    print(f"Wrote {len(rows)} requirements to {full_path}")
    print(f"Wrote {len(subset)} Notion subset rows to {notion_path}")
    print(f"Automated/Met controls: {met_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())