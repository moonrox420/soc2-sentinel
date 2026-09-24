"""GitHub VCS Compliance Connector for SOC2-Sentinel.

Collects, verifies, and formats VCS evidence for SOC 2 Type II controls:
- CC7.1 / CC8.1: Change Management (Branch protection, PR review requirements, approvals).
- CC6.8 / CC7.1: Vulnerability & Dependency Management (Dependabot / SCA alerts, SLA breaches).
- CC6.1 / CC6.6: Secret scanning, commit signature enforcement.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class BranchProtectionStatus:
    """Status of branch protection rules on target branch."""
    branch: str
    protected: bool
    enforce_admins: bool
    required_approving_review_count: int
    dismiss_stale_reviews: bool
    require_code_owner_reviews: bool
    required_status_checks: List[str]
    require_signed_commits: bool
    allows_force_pushes: bool
    allows_deletions: bool

    def is_compliant_for_soc2(self, min_approvals: int = 1) -> bool:
        """SOC 2 CC8.1 requires peer reviews, no unreviewed direct pushes."""
        return (
            self.protected
            and self.required_approving_review_count >= min_approvals
            and self.dismiss_stale_reviews
            and not self.allows_force_pushes
            and not self.allows_deletions
        )


@dataclass
class VulnerabilityAlertSummary:
    """Summary of open security vulnerabilities."""
    total_open: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    critical_sla_breaches: int = 0  # > 7 days old
    high_sla_breaches: int = 0      # > 30 days old


@dataclass
class SecurityFeaturesStatus:
    """Security features enabled on the repository."""
    secret_scanning_enabled: bool
    secret_scanning_push_protection_enabled: bool
    dependabot_alerts_enabled: bool
    dependabot_security_updates_enabled: bool
    code_scanning_enabled: bool


@dataclass
class GitHubComplianceReport:
    """Complete VCS compliance evidence snapshot."""
    repository: str
    timestamp: str
    default_branch: str
    branch_protection: BranchProtectionStatus
    security_features: SecurityFeaturesStatus
    dependabot_summary: VulnerabilityAlertSummary
    secret_scanning_alerts_open: int
    compliant: bool
    findings: List[str] = field(default_factory=list)
    raw_evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to JSON-serializable dictionary."""
        return {
            "repository": self.repository,
            "timestamp": self.timestamp,
            "default_branch": self.default_branch,
            "branch_protection": {
                "branch": self.branch_protection.branch,
                "protected": self.branch_protection.protected,
                "enforce_admins": self.branch_protection.enforce_admins,
                "required_approving_review_count": self.branch_protection.required_approving_review_count,
                "dismiss_stale_reviews": self.branch_protection.dismiss_stale_reviews,
                "require_code_owner_reviews": self.branch_protection.require_code_owner_reviews,
                "required_status_checks": self.branch_protection.required_status_checks,
                "require_signed_commits": self.branch_protection.require_signed_commits,
                "allows_force_pushes": self.branch_protection.allows_force_pushes,
                "allows_deletions": self.branch_protection.allows_deletions,
            },
            "security_features": {
                "secret_scanning_enabled": self.security_features.secret_scanning_enabled,
                "secret_scanning_push_protection_enabled": self.security_features.secret_scanning_push_protection_enabled,
                "dependabot_alerts_enabled": self.security_features.dependabot_alerts_enabled,
                "dependabot_security_updates_enabled": self.security_features.dependabot_security_updates_enabled,
                "code_scanning_enabled": self.security_features.code_scanning_enabled,
            },
            "dependabot_summary": {
                "total_open": self.dependabot_summary.total_open,
                "critical": self.dependabot_summary.critical,
                "high": self.dependabot_summary.high,
                "medium": self.dependabot_summary.medium,
                "low": self.dependabot_summary.low,
                "critical_sla_breaches": self.dependabot_summary.critical_sla_breaches,
                "high_sla_breaches": self.dependabot_summary.high_sla_breaches,
            },
            "secret_scanning_alerts_open": self.secret_scanning_alerts_open,
            "compliant": self.compliant,
            "findings": self.findings,
            "raw_evidence": self.raw_evidence,
        }


class GitHubConnector:
    """Connector to audit GitHub repositories for SOC 2 Type II compliance."""

    def __init__(
        self,
        repo: str,
        token: Optional[str] = None,
        api_url: str = "https://api.github.com",
        mock: bool = False,
    ) -> None:
        self.repo = repo.strip("/")
        self.token = token or os.getenv("GITHUB_TOKEN", "")
        self.api_url = api_url.rstrip("/")
        self.mock = mock

    def _make_request(self, endpoint: str) -> Optional[Dict[str, Any] | List[Any]]:
        """Perform an authenticated GitHub API request."""
        if self.mock or not self.token:
            return None

        url = f"{self.api_url}/repos/{self.repo}/{endpoint.lstrip('/')}"
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "SOC2-Sentinel-VCS-Connector",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        if not url.startswith(("https://", "http://")):
            raise ValueError(f"Invalid URL scheme in {url}")

        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=10) as response:  # nosec B310
                payload = response.read().decode("utf-8")
                res: Dict[str, Any] | List[Any] = json.loads(payload)
                return res
        except urllib.error.HTTPError as err:
            logger.warning("GitHub API HTTP %d for %s: %s", err.code, url, err.reason)
            return None
        except Exception as ex:
            logger.error("GitHub API request failed for %s: %s", url, ex)
            return None

    def _get_mock_report(self) -> GitHubComplianceReport:
        """Provide a compliant mock snapshot for testing or offline operation."""
        branch_prot = BranchProtectionStatus(
            branch="main",
            protected=True,
            enforce_admins=True,
            required_approving_review_count=2,
            dismiss_stale_reviews=True,
            require_code_owner_reviews=True,
            required_status_checks=["ci/build", "security/sast", "security/trivy"],
            require_signed_commits=True,
            allows_force_pushes=False,
            allows_deletions=False,
        )
        sec_features = SecurityFeaturesStatus(
            secret_scanning_enabled=True,
            secret_scanning_push_protection_enabled=True,
            dependabot_alerts_enabled=True,
            dependabot_security_updates_enabled=True,
            code_scanning_enabled=True,
        )
        dep_summary = VulnerabilityAlertSummary(
            total_open=1,
            critical=0,
            high=0,
            medium=1,
            low=0,
            critical_sla_breaches=0,
            high_sla_breaches=0,
        )
        return GitHubComplianceReport(
            repository=self.repo or "enterprise-org/soc2-sentinel",
            timestamp=datetime.now(timezone.utc).isoformat(),
            default_branch="main",
            branch_protection=branch_prot,
            security_features=sec_features,
            dependabot_summary=dep_summary,
            secret_scanning_alerts_open=0,
            compliant=True,
            findings=[],
            raw_evidence={"mock": True, "source": "synthetic_soc2_benchmark"},
        )

    def audit(self, default_branch: str = "main") -> GitHubComplianceReport:
        """Perform full compliance assessment on the repository."""
        if self.mock:
            return self._get_mock_report()

        findings: List[str] = []
        raw_evidence: Dict[str, Any] = {}

        if not self.token:
            findings.append("CRITICAL: GitHub API token (GITHUB_TOKEN) is not configured; live VCS compliance audit cannot be authenticated.")

        # 1. Branch Protection
        bp_data = self._make_request(f"branches/{default_branch}/protection")
        raw_evidence["branch_protection"] = bp_data

        if not bp_data or not isinstance(bp_data, dict):
            findings.append(f"CRITICAL: Branch protection is not configured or inaccessible for '{default_branch}'.")
            branch_prot = BranchProtectionStatus(
                branch=default_branch,
                protected=False,
                enforce_admins=False,
                required_approving_review_count=0,
                dismiss_stale_reviews=False,
                require_code_owner_reviews=False,
                required_status_checks=[],
                require_signed_commits=False,
                allows_force_pushes=True,
                allows_deletions=True,
            )
        else:
            req_reviews = bp_data.get("required_pull_request_reviews") or {}
            status_checks = bp_data.get("required_status_checks") or {}
            admin_enforce = bp_data.get("enforce_admins") or {}

            branch_prot = BranchProtectionStatus(
                branch=default_branch,
                protected=True,
                enforce_admins=bool(admin_enforce.get("enabled", False)),
                required_approving_review_count=int(req_reviews.get("required_approving_review_count", 0)),
                dismiss_stale_reviews=bool(req_reviews.get("dismiss_stale_reviews", False)),
                require_code_owner_reviews=bool(req_reviews.get("require_code_owner_reviews", False)),
                required_status_checks=list(status_checks.get("contexts", [])),
                require_signed_commits=bool(bp_data.get("required_signatures", {}).get("enabled", False)),
                allows_force_pushes=bool(bp_data.get("allow_force_pushes", {}).get("enabled", False)),
                allows_deletions=bool(bp_data.get("allow_deletions", {}).get("enabled", False)),
            )

            if branch_prot.required_approving_review_count < 1:
                findings.append(f"HIGH: Branch '{default_branch}' does not require pull request peer reviews.")
            if not branch_prot.dismiss_stale_reviews:
                findings.append(f"MEDIUM: Stale PR approval dismissal is disabled on '{default_branch}'.")
            if branch_prot.allows_force_pushes:
                findings.append(f"HIGH: Force pushes are allowed on branch '{default_branch}'.")
            if branch_prot.allows_deletions:
                findings.append(f"HIGH: Branch deletions are allowed on '{default_branch}'.")

        # 2. Repo Security Features (Secret scanning, Dependabot)
        repo_data = self._make_request("")
        raw_evidence["repo_info"] = repo_data

        sec_features = SecurityFeaturesStatus(
            secret_scanning_enabled=False,
            secret_scanning_push_protection_enabled=False,
            dependabot_alerts_enabled=False,
            dependabot_security_updates_enabled=False,
            code_scanning_enabled=False,
        )

        if isinstance(repo_data, dict):
            sec_meta = repo_data.get("security_and_analysis") or {}
            sec_scan = sec_meta.get("secret_scanning") or {}
            sec_push = sec_meta.get("secret_scanning_push_protection") or {}
            dep_sec = sec_meta.get("dependabot_security_updates") or {}

            sec_features.secret_scanning_enabled = sec_scan.get("status") == "enabled"
            sec_features.secret_scanning_push_protection_enabled = sec_push.get("status") == "enabled"
            sec_features.dependabot_security_updates_enabled = dep_sec.get("status") == "enabled"

            if not sec_features.secret_scanning_enabled:
                findings.append("HIGH: Secret scanning is not enabled on the repository.")
            if not sec_features.secret_scanning_push_protection_enabled:
                findings.append("MEDIUM: Push protection for secret scanning is disabled.")

        # 3. Dependabot Alerts & SLA
        dep_alerts = self._make_request("dependabot/alerts?state=open")
        raw_evidence["dependabot_alerts"] = dep_alerts
        dep_summary = VulnerabilityAlertSummary()

        if isinstance(dep_alerts, list):
            sec_features.dependabot_alerts_enabled = True
            dep_summary.total_open = len(dep_alerts)
            now_dt = datetime.now(timezone.utc)

            for alert in dep_alerts:
                if not isinstance(alert, dict):
                    continue
                sec_advisory = alert.get("security_advisory") or {}
                severity = str(sec_advisory.get("severity", "low")).lower()
                created_at_str = alert.get("created_at")

                days_open = 0
                if created_at_str:
                    try:
                        created_dt = datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
                        days_open = (now_dt - created_dt).days
                    except Exception:
                        days_open = 0

                if severity == "critical":
                    dep_summary.critical += 1
                    if days_open > 7:
                        dep_summary.critical_sla_breaches += 1
                elif severity == "high":
                    dep_summary.high += 1
                    if days_open > 30:
                        dep_summary.high_sla_breaches += 1
                elif severity == "medium":
                    dep_summary.medium += 1
                else:
                    dep_summary.low += 1

            if dep_summary.critical_sla_breaches > 0:
                findings.append(f"CRITICAL: {dep_summary.critical_sla_breaches} Critical Dependabot alerts exceed 7-day remediation SLA.")
            if dep_summary.high_sla_breaches > 0:
                findings.append(f"HIGH: {dep_summary.high_sla_breaches} High Dependabot alerts exceed 30-day remediation SLA.")

        # 4. Secret Scanning Alerts
        sec_alerts = self._make_request("secret-scanning/alerts?state=open")
        raw_evidence["secret_scanning_alerts"] = sec_alerts
        open_secrets = len(sec_alerts) if isinstance(sec_alerts, list) else 0

        if open_secrets > 0:
            findings.append(f"CRITICAL: {open_secrets} unmitigated secrets detected in repository codebase.")

        compliant = len([f for f in findings if f.startswith("CRITICAL:") or f.startswith("HIGH:")]) == 0

        return GitHubComplianceReport(
            repository=self.repo,
            timestamp=datetime.now(timezone.utc).isoformat(),
            default_branch=default_branch,
            branch_protection=branch_prot,
            security_features=sec_features,
            dependabot_summary=dep_summary,
            secret_scanning_alerts_open=open_secrets,
            compliant=compliant,
            findings=findings,
            raw_evidence=raw_evidence,
        )
