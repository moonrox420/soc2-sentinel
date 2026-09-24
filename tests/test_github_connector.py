"""Unit tests for GitHub VCS Compliance Connector."""

import pytest

from sentinel.connectors.github import (
    BranchProtectionStatus,
    GitHubComplianceReport,
    GitHubConnector,
)


def test_branch_protection_compliance_logic() -> None:
    compliant_bp = BranchProtectionStatus(
        branch="main",
        protected=True,
        enforce_admins=True,
        required_approving_review_count=1,
        dismiss_stale_reviews=True,
        require_code_owner_reviews=True,
        required_status_checks=["ci/test"],
        require_signed_commits=True,
        allows_force_pushes=False,
        allows_deletions=False,
    )
    assert compliant_bp.is_compliant_for_soc2(min_approvals=1) is True

    # Violates if force push is allowed
    bad_bp = BranchProtectionStatus(
        branch="main",
        protected=True,
        enforce_admins=True,
        required_approving_review_count=1,
        dismiss_stale_reviews=True,
        require_code_owner_reviews=True,
        required_status_checks=[],
        require_signed_commits=False,
        allows_force_pushes=True,
        allows_deletions=False,
    )
    assert bad_bp.is_compliant_for_soc2(min_approvals=1) is False


def test_github_connector_mock_mode() -> None:
    connector = GitHubConnector(repo="my-org/soc2-app", mock=True)
    report = connector.audit()

    assert isinstance(report, GitHubComplianceReport)
    assert report.compliant is True
    assert report.default_branch == "main"
    assert report.branch_protection.protected is True
    assert report.security_features.secret_scanning_enabled is True
    assert report.dependabot_summary.critical_sla_breaches == 0

    d = report.to_dict()
    assert "branch_protection" in d
    assert "security_features" in d
    assert "dependabot_summary" in d


def test_github_connector_unauthenticated_fallback() -> None:
    connector = GitHubConnector(repo="my-org/unauthed-app", token="")
    assert connector.mock is True
    report = connector.audit()
    assert report.compliant is True


def test_github_connector_live_request_mocking(monkeypatch: pytest.MonkeyPatch) -> None:
    connector = GitHubConnector(repo="acme/api", token="ghp_fake_token", mock=False)

    def mock_make_request(endpoint: str):
        if "branches/main/protection" in endpoint:
            return {
                "required_pull_request_reviews": {
                    "required_approving_review_count": 2,
                    "dismiss_stale_reviews": True,
                    "require_code_owner_reviews": True,
                },
                "required_status_checks": {"contexts": ["ci/test"]},
                "enforce_admins": {"enabled": True},
                "required_signatures": {"enabled": True},
                "allow_force_pushes": {"enabled": False},
                "allow_deletions": {"enabled": False},
            }
        elif endpoint == "":
            return {
                "security_and_analysis": {
                    "secret_scanning": {"status": "enabled"},
                    "secret_scanning_push_protection": {"status": "enabled"},
                    "dependabot_security_updates": {"status": "enabled"},
                }
            }
        elif "dependabot/alerts" in endpoint:
            return [
                {
                    "created_at": "2020-01-01T00:00:00Z",
                    "security_advisory": {"severity": "critical"},
                },
                {
                    "created_at": "2020-01-01T00:00:00Z",
                    "security_advisory": {"severity": "high"},
                },
                {
                    "created_at": "2026-01-01T00:00:00Z",
                    "security_advisory": {"severity": "low"},
                },
            ]
        elif "secret-scanning/alerts" in endpoint:
            return [{"secret_type": "aws_access_key"}]
        return None

    monkeypatch.setattr(connector, "_make_request", mock_make_request)
    report = connector.audit(default_branch="main")

    assert report.branch_protection.protected is True
    assert report.dependabot_summary.critical == 1
    assert report.dependabot_summary.critical_sla_breaches == 1
    assert report.dependabot_summary.high_sla_breaches == 1
    assert report.secret_scanning_alerts_open == 1
    assert report.compliant is False  # Because critical SLA breaches and open secrets exist
    assert len(report.findings) > 0


def test_github_connector_unprotected_branch_handling(monkeypatch: pytest.MonkeyPatch) -> None:
    connector = GitHubConnector(repo="acme/insecure-repo", token="ghp_fake_token", mock=False)

    def mock_make_request(endpoint: str):
        # Returns None simulating 404 on branch protection
        return None

    monkeypatch.setattr(connector, "_make_request", mock_make_request)
    report = connector.audit(default_branch="main")
    assert report.branch_protection.protected is False
    assert report.compliant is False
    assert any("Branch protection is not configured" in f for f in report.findings)
