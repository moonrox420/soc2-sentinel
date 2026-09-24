from __future__ import annotations

import logging
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from sentinel.config import SentinelConfig
from sentinel.providers import get_provider

logger = logging.getLogger("sentinel.onboarding")

AWS_MINIMAL_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "SentinelIAMRead",
            "Effect": "Allow",
            "Action": [
                "iam:ListUsers",
                "iam:ListAccessKeys",
                "iam:ListMFADevices",
                "iam:GenerateCredentialReport",
                "iam:GetCredentialReport",
            ],
            "Resource": "*",
        },
        {
            "Sid": "SentinelLoggingAndConfig",
            "Effect": "Allow",
            "Action": [
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetTrailStatus",
                "logs:DescribeLogGroups",
                "config:DescribeComplianceByConfigRule",
                "config:DescribeConfigurationRecorders",
                "ec2:DescribeSecurityGroups",
            ],
            "Resource": "*",
        },
        {
            "Sid": "SentinelEncryptionAndResilience",
            "Effect": "Allow",
            "Action": [
                "kms:ListKeys",
                "kms:DescribeKey",
                "acm:ListCertificates",
                "acm:DescribeCertificate",
                "s3:ListAllMyBuckets",
                "s3:GetBucketLifecycleConfiguration",
                "backup:ListBackupJobs",
                "backup:ListBackupVaults",
            ],
            "Resource": "*",
        },
    ],
}

GCP_MINIMAL_ROLES = [
    "roles/cloudasset.viewer",
    "roles/logging.viewer",
    "roles/cloudkms.viewer",
    "roles/storage.objectViewer",
    "roles/compute.viewer",
]

AZURE_MINIMAL_ROLES = [
    "Reader",
    "Security Reader",
    "Microsoft.Insights/diagnosticSettings/read",
    "Microsoft.DataProtection/backupVaults/backupJobs/read",
]


@dataclass
class ProviderHealthCheck:
    provider: str
    status: (
        str  # "READY", "CONFIG_REQUIRED", "CREDENTIALS_MISSING", "PERMISSION_DENIED"
    )
    identity: str | None
    account_or_project: str | None
    region: str | None
    checks_passed: list[str] = field(default_factory=list)
    checks_failed: list[str] = field(default_factory=list)
    remediation_steps: list[str] = field(default_factory=list)
    policy_snippet: dict[str, Any] | str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def diagnose_aws(config: SentinelConfig | None = None) -> ProviderHealthCheck:
    passed: list[str] = []
    failed: list[str] = []
    remediation: list[str] = []

    has_env = bool(
        (
            os.environ.get("AWS_ACCESS_KEY_ID")
            and os.environ.get("AWS_SECRET_ACCESS_KEY")
        )
        or os.environ.get("AWS_PROFILE")
        or (Path.home() / ".aws" / "credentials").exists()
    )

    if not has_env:
        return ProviderHealthCheck(
            provider="aws",
            status="CREDENTIALS_MISSING",
            identity=None,
            account_or_project=None,
            region=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
            checks_passed=[],
            checks_failed=[
                "AWS credentials not detected in environment or ~/.aws/credentials"
            ],
            remediation_steps=[
                "Configure AWS CLI: run 'aws configure'",
                "Or set environment variables: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY",
                "Attach the minimal IAM policy below to the IAM User or IAM Role",
            ],
            policy_snippet=AWS_MINIMAL_POLICY,
        )

    try:
        provider = get_provider("aws", config)
        provider.validate_credentials()
        identity = (
            os.environ.get("AWS_ROLE_ARN")
            or os.environ.get("AWS_PROFILE")
            or "Active IAM Session"
        )
        passed.append("STS Credential validation successful")
        passed.append(f"Connected: {identity}")
        return ProviderHealthCheck(
            provider="aws",
            status="READY",
            identity=identity,
            account_or_project=os.environ.get("AWS_ACCOUNT_ID", "Active"),
            region=getattr(
                provider, "region", os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
            ),
            checks_passed=passed,
            checks_failed=[],
            remediation_steps=[],
            policy_snippet=None,
        )
    except Exception as exc:
        failed.append(f"AWS connection error: {exc}")
        remediation.append(
            "Check AWS credentials and ensure policy has sts:GetCallerIdentity permission"
        )
        return ProviderHealthCheck(
            provider="aws",
            status="PERMISSION_DENIED",
            identity=None,
            account_or_project=None,
            region=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
            checks_passed=passed,
            checks_failed=failed,
            remediation_steps=remediation,
            policy_snippet=AWS_MINIMAL_POLICY,
        )


def diagnose_gcp(config: SentinelConfig | None = None) -> ProviderHealthCheck:
    passed: list[str] = []
    failed: list[str] = []
    remediation: list[str] = []

    has_creds = bool(
        os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        or (
            Path.home() / ".config" / "gcloud" / "application_default_credentials.json"
        ).exists()
    )
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GCP_PROJECT")

    if not has_creds:
        return ProviderHealthCheck(
            provider="gcp",
            status="CREDENTIALS_MISSING",
            identity=None,
            account_or_project=project_id,
            region="global",
            checks_passed=[],
            checks_failed=["Google Cloud Application Default Credentials not detected"],
            remediation_steps=[
                "Run 'gcloud auth application-default login' to authorize locally",
                "Or set GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json",
                "Set GOOGLE_CLOUD_PROJECT=<your-project-id>",
                f"Grant service account roles: {', '.join(GCP_MINIMAL_ROLES)}",
            ],
            policy_snippet={"roles": GCP_MINIMAL_ROLES},
        )

    try:
        provider = get_provider("gcp", config)
        provider.validate_credentials()
        identity = (
            os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
            or "Application Default Credentials"
        )
        passed.append("GCP Application Default Credentials valid")
        passed.append(f"Connected: {identity}")
        return ProviderHealthCheck(
            provider="gcp",
            status="READY",
            identity=identity,
            account_or_project=project_id or "Configured Project",
            region="global",
            checks_passed=passed,
            checks_failed=[],
            remediation_steps=[],
            policy_snippet=None,
        )
    except Exception as exc:
        failed.append(f"GCP connection error: {exc}")
        remediation.append(
            "Run 'gcloud auth application-default login' and verify project permissions"
        )
        return ProviderHealthCheck(
            provider="gcp",
            status="PERMISSION_DENIED",
            identity=None,
            account_or_project=project_id,
            region="global",
            checks_passed=passed,
            checks_failed=failed,
            remediation_steps=remediation,
            policy_snippet={"roles": GCP_MINIMAL_ROLES},
        )


def diagnose_azure(config: SentinelConfig | None = None) -> ProviderHealthCheck:
    passed: list[str] = []
    failed: list[str] = []
    remediation: list[str] = []

    has_sp = bool(
        os.environ.get("AZURE_CLIENT_ID")
        and os.environ.get("AZURE_CLIENT_SECRET")
        and os.environ.get("AZURE_TENANT_ID")
    )
    sub_id = os.environ.get("AZURE_SUBSCRIPTION_ID")

    if not has_sp and not sub_id:
        return ProviderHealthCheck(
            provider="azure",
            status="CREDENTIALS_MISSING",
            identity=None,
            account_or_project=None,
            region="global",
            checks_passed=[],
            checks_failed=[
                "Azure Service Principal or Azure CLI login credentials not detected"
            ],
            remediation_steps=[
                "Run 'az login' for interactive CLI authentication",
                "Or set AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID",
                f"Assign subscription roles: {', '.join(AZURE_MINIMAL_ROLES)}",
            ],
            policy_snippet={"roles": AZURE_MINIMAL_ROLES},
        )

    try:
        provider = get_provider("azure", config)
        provider.validate_credentials()
        identity = os.environ.get("AZURE_CLIENT_ID") or "Azure CLI Context"
        passed.append("Azure credential validation successful")
        passed.append(f"Connected: {identity}")
        return ProviderHealthCheck(
            provider="azure",
            status="READY",
            identity=identity,
            account_or_project=sub_id or "Active Subscription",
            region="global",
            checks_passed=passed,
            checks_failed=[],
            remediation_steps=[],
            policy_snippet=None,
        )
    except Exception as exc:
        failed.append(f"Azure connection error: {exc}")
        remediation.append("Set AZURE_SUBSCRIPTION_ID and execute 'az login'")
        return ProviderHealthCheck(
            provider="azure",
            status="PERMISSION_DENIED",
            identity=None,
            account_or_project=sub_id,
            region="global",
            checks_passed=passed,
            checks_failed=failed,
            remediation_steps=remediation,
            policy_snippet={"roles": AZURE_MINIMAL_ROLES},
        )


def diagnose_all_providers(
    config: SentinelConfig | None = None,
) -> dict[str, dict[str, Any]]:
    """Run full real-time diagnostic preflight across AWS, GCP, and Azure."""
    return {
        "aws": diagnose_aws(config).to_dict(),
        "gcp": diagnose_gcp(config).to_dict(),
        "azure": diagnose_azure(config).to_dict(),
    }


def generate_minimal_policy(provider: str) -> dict[str, Any]:
    """Generate minimal least-privilege IAM policy or role assignment payload for the target provider."""
    p = provider.lower()
    if p == "aws":
        return AWS_MINIMAL_POLICY
    elif p == "gcp":
        return {"roles": GCP_MINIMAL_ROLES}
    elif p == "azure":
        return {"roles": AZURE_MINIMAL_ROLES}
    raise ValueError(f"Unsupported provider for policy generation: '{provider}'. Supported: aws, gcp, azure")
