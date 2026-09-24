
# --- Consolidated from test_providers_init.py ---

from sentinel.config import SentinelConfig
from sentinel.providers import get_provider
from sentinel.providers.mock import MockProvider


def test_get_provider_mock():
    p = get_provider("mock", SentinelConfig())
    assert isinstance(p, MockProvider)


def test_get_provider_unknown():
    import pytest

    with pytest.raises(SystemExit):
        get_provider("unknown", SentinelConfig())


# --- Consolidated from test_providers_unit.py ---
"""Direct unit tests for provider modules using mocks to raise coverage."""

from unittest.mock import patch

from sentinel.providers.aws.provider import AwsProvider
from sentinel.providers.azure.provider import AzureProvider
from sentinel.providers.gcp.provider import GcpProvider


def test_aws_provider_delegates():
    p = AwsProvider(region="us-east-1")
    with patch("sentinel.providers.aws.iam.iam_access_snapshot") as mock:
        mock.return_value = {"collection_quality": "complete", "errors": []}
        snap = p.iam_access_snapshot()
    assert snap["collection_quality"] == "complete"


def test_gcp_provider_delegates():
    with patch("sentinel.providers.gcp._client.GcpContext.validate_credentials"):
        p = GcpProvider(project_id="proj")
    with patch("sentinel.providers.gcp.logging.log_monitoring_snapshot") as mock:
        mock.return_value = {"collection_quality": "partial", "errors": []}
        snap = p.log_monitoring_snapshot()
    assert snap["collection_quality"] == "partial"


def test_azure_provider_delegates():
    with patch("sentinel.providers.azure._client.ResourceManagementClient"):
        with patch("sentinel.providers.azure._client.StorageManagementClient"):
            with patch("sentinel.providers.azure._client.DefaultAzureCredential"):
                p = AzureProvider(subscription_id="00000000-0000-0000-0000-000000000001")
    with patch("sentinel.providers.azure.encryption.encryption_snapshot") as mock:
        mock.return_value = {"collection_quality": "complete", "errors": []}
        snap = p.encryption_snapshot()
    assert snap["collection_quality"] == "complete"


# --- Consolidated from test_providers_errors.py ---
import pytest

from sentinel.errors import ProviderError


def test_mock_missing_fixture_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "sentinel.providers.mock._FIXTURES",
        tmp_path / "missing-fixtures",
    )
    provider = MockProvider()
    with pytest.raises(ProviderError):
        provider.validate_credentials()


# --- Consolidated from test_providers_aws_direct.py ---

from sentinel.providers.aws._client import AwsClients


def test_aws_validate_credentials():
    with patch.object(AwsClients, "validate_credentials") as mock:
        p = AwsProvider(region="us-east-1")
        p.validate_credentials()
        mock.assert_called_once()


def test_aws_all_snapshot_methods():
    p = AwsProvider(region="us-east-1")
    stub = {"collection_quality": "complete", "errors": [], "partial": False}
    patches = {
        "iam_access_snapshot": "sentinel.providers.aws.provider.aws_iam.iam_access_snapshot",
        "log_monitoring_snapshot": "sentinel.providers.aws.provider.aws_logging.log_monitoring_snapshot",
        "config_and_auth_snapshot": "sentinel.providers.aws.provider.aws_config.config_and_auth_snapshot",
        "encryption_snapshot": "sentinel.providers.aws.provider.aws_encryption.encryption_snapshot",
        "retention_snapshot": "sentinel.providers.aws.provider.aws_retention.retention_snapshot",
        "resilience_snapshot": "sentinel.providers.aws.provider.aws_resilience.resilience_snapshot",
        "zt_verification_snapshot": "sentinel.providers.aws.provider.aws_zt",
    }
    for attr, target in patches.items():
        with patch(target, return_value=stub):
            assert getattr(p, attr)()["collection_quality"] == "complete"


# --- Consolidated from test_aws_config.py ---
from unittest.mock import MagicMock

from sentinel.providers.aws.config import config_and_auth_snapshot


def test_mfa_counts_from_users():
    ctx = AwsClients(region="us-east-1")
    user_page = {"Users": [{"UserName": "alice"}]}
    with patch.object(ctx, "client") as mock_client:
        iam = MagicMock()
        iam.get_paginator.return_value.paginate.return_value = [user_page]
        iam.list_mfa_devices.return_value = {"MFADevices": []}
        ec2 = MagicMock()
        ec2.get_paginator.return_value.paginate.return_value = []
        elbv2 = MagicMock()
        elbv2.get_paginator.return_value.paginate.return_value = []
        cfg = MagicMock()
        cfg.describe_config_rules.return_value = {"ConfigRules": []}
        cfg.get_compliance_summary_by_config_rule.return_value = {
            "ComplianceSummaries": []
        }
        mock_client.side_effect = lambda service: {
            "iam": iam,
            "ec2": ec2,
            "elbv2": elbv2,
            "config": cfg,
        }[service]
        with patch(
            "sentinel.cloud.call_with_retry",
            side_effect=lambda fn, **kw: fn(),
        ):
            snap = config_and_auth_snapshot(ctx)

    assert snap["weak_auth_methods"] >= 1
    assert snap["mfa_enforcement_percent"] is None
    assert snap["mfa_registered_percent"] < 100.0


# --- Consolidated from test_aws_encryption.py ---
import boto3
from moto import mock_aws

from sentinel.providers.aws.encryption import encryption_snapshot


@mock_aws
def test_s3_unencrypted_bucket_found():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-unencrypted-bucket")
    ctx = AwsClients(region="us-east-1")
    snap = encryption_snapshot(ctx)
    assert snap["unencrypted_cui_count"] >= 1
    assert snap["tls_endpoints_checked"] >= 0


# --- Consolidated from test_aws_encryption_full.py ---



def test_kms_and_acm_paths():
    ctx = AwsClients(region="us-east-1")
    with patch.object(ctx, "client") as mock_client:
        s3 = MagicMock()
        s3.list_buckets.return_value = {"Buckets": [{"Name": "b1"}]}
        type("E", (Exception,), {})()
        from botocore.exceptions import ClientError

        s3.get_bucket_encryption.side_effect = ClientError(
            {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError"}}, "GetBucketEncryption"
        )
        rds = MagicMock()
        rds.describe_db_instances.return_value = {"DBInstances": [{"DBInstanceIdentifier": "db1", "StorageEncrypted": True}]}
        kms = MagicMock()
        kms.list_keys.return_value = {"Keys": [{"KeyId": "k1"}]}
        kms.describe_key.return_value = {
            "KeyMetadata": {"KeyManager": "CUSTOMER", "KeyState": "Enabled", "KeySpec": "SYMMETRIC_DEFAULT"}
        }
        kms.get_key_rotation_status.return_value = {"KeyRotationEnabled": True}
        acm = MagicMock()
        acm.list_certificates.return_value = {"CertificateSummaryList": []}
        elbv2 = MagicMock()
        elbv2.describe_ssl_policies.return_value = {"SslPolicies": [{"Name": "ELBSecurityPolicy-TLS-1-2-2016-01"}]}
        mock_client.side_effect = lambda s: {"s3": s3, "rds": rds, "kms": kms, "acm": acm, "elbv2": elbv2}[s]
        with patch("sentinel.cloud.call_with_retry", side_effect=lambda fn, **kw: fn()):
            snap = encryption_snapshot(ctx)
    assert snap["fips_compliant_keys"] >= 1
    assert snap["weak_cipher_endpoints"] >= 1


# --- Consolidated from test_aws_iam.py ---
from moto import mock_aws

from sentinel.providers.aws.iam import iam_access_snapshot


@mock_aws
def test_credential_report_is_not_access_review_age():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="alice")
    iam.generate_credential_report()

    ctx = AwsClients(region="us-east-1")
    snap = iam_access_snapshot(ctx)

    assert snap["days_since_last_review"] is None
    assert "max_credential_age_days" in snap
    assert snap["collection_quality"] in {"complete", "partial"}


# --- Consolidated from test_aws_logging.py ---

from sentinel.providers.aws.logging import log_monitoring_snapshot


def test_no_trails_sets_coverage_error():
    ctx = AwsClients(region="us-east-1")
    with patch.object(ctx, "client") as mock_client:
        trails = MagicMock()
        trails.describe_trails.return_value = {"trailList": []}
        mock_client.return_value = trails
        with patch("sentinel.cloud.call_with_retry", side_effect=lambda fn, **kw: fn()):
            snap = log_monitoring_snapshot(ctx)
    assert snap.get("log_coverage_percent") is None
    assert any(e.get("code") == "NoTrails" for e in snap.get("errors", []))


def test_trail_logging_coverage():
    ctx = AwsClients(region="us-east-1")
    trail = {"TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/t1", "Name": "t1", "IsMultiRegionTrail": True}
    with patch.object(ctx, "client") as mock_client:
        trails = MagicMock()
        trails.describe_trails.return_value = {"trailList": [trail]}
        trails.get_trail_status.return_value = {
            "IsLogging": True,
            "LatestDeliveryTime": __import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        }
        cfg = MagicMock()
        cfg.describe_configuration_recorders.return_value = {"ConfigurationRecorders": []}
        logs = MagicMock()
        logs.describe_log_groups.return_value = {"logGroups": [{"retentionInDays": 30}]}
        trails.lookup_events.return_value = {"Events": []}

        def client_factory(svc):
            return {"cloudtrail": trails, "config": cfg, "logs": logs}[svc]

        mock_client.side_effect = client_factory
        with patch("sentinel.cloud.call_with_retry", side_effect=lambda fn, **kw: fn()):
            snap = log_monitoring_snapshot(ctx)
    assert snap.get("log_coverage_percent") == 100.0


# --- Consolidated from test_aws_resilience.py ---

from moto import mock_aws

from sentinel.providers.aws.resilience import resilience_snapshot


def test_no_backup_jobs_returns_failed_quality():
    ctx = AwsClients(region="us-east-1")
    with patch.object(ctx, "client") as mock_client:
        backup = MagicMock()
        backup.list_backup_jobs.return_value = {"BackupJobs": []}
        backup.list_restore_jobs.return_value = {"RestoreJobs": []}
        rds = MagicMock()
        rds.describe_db_snapshots.return_value = {"DBSnapshots": []}
        mock_client.side_effect = lambda s: {"backup": backup, "rds": rds}[s]
        with patch("sentinel.cloud.call_with_retry", side_effect=lambda fn, **kw: fn()):
            snap = resilience_snapshot(ctx)
    assert snap.get("last_backup_hours_ago") is None
    assert any(e.get("code") == "NoBackupEvidence" for e in snap.get("errors", []))


@mock_aws
def test_rds_snapshot_drives_backup_hours():
    import boto3

    rds = boto3.client("rds", region_name="us-east-1")
    rds.create_db_instance(
        DBInstanceIdentifier="db-1",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="password123",
        AllocatedStorage=20,
    )
    rds.create_db_snapshot(DBSnapshotIdentifier="snap-1", DBInstanceIdentifier="db-1")
    ctx = AwsClients(region="us-east-1")
    with patch("sentinel.cloud.call_with_retry", side_effect=lambda fn, **kw: fn()):
        snap = resilience_snapshot(ctx)
    assert snap.get("last_backup_hours_ago") is not None


# --- Consolidated from test_aws_retention.py ---
from moto import mock_aws

from sentinel.providers.aws.retention import retention_snapshot


@mock_aws
def test_bucket_missing_lifecycle():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="no-lifecycle-bucket")
    ctx = AwsClients(region="us-east-1")
    snap = retention_snapshot(ctx)
    assert snap["buckets_missing_lifecycle"] >= 1


# --- Consolidated from test_aws_zt.py ---

from moto import mock_aws

from sentinel.providers.aws._zt import zt_verification_snapshot


@mock_aws
def test_zt_derives_pillar_scores():
    ctx = AwsClients(region="us-east-1")
    with patch("sentinel.providers.aws.iam.iam_access_snapshot") as mock_iam:
        with patch("sentinel.providers.aws.encryption.encryption_snapshot") as mock_enc:
            with patch("sentinel.providers.aws.config.config_and_auth_snapshot") as mock_cfg:
                mock_iam.return_value = {
                    "users": [{"privileged": True}],
                    "orphaned_accounts": 0,
                    "days_since_last_review": 10,
                    "errors": [],
                    "collection_quality": "complete",
                }
                mock_enc.return_value = {
                    "unencrypted_cui_count": 0,
                    "errors": [],
                    "collection_quality": "complete",
                }
                mock_cfg.return_value = {
                    "mfa_enforcement_percent": 100.0,
                    "open_http_listeners": 0,
                    "weak_tls_listeners": 0,
                    "errors": [],
                    "collection_quality": "complete",
                }
                snap = zt_verification_snapshot(ctx)
    assert "pillar_scores" in snap
    assert snap["encryption_status"] == "green"


# --- Consolidated from test_azure_iam.py ---

from sentinel.providers.azure._client import AzureContext
from sentinel.providers.azure.iam import iam_access_snapshot


def test_graph_drives_assignments():
    ctx = AzureContext(subscription_id="00000000-0000-0000-0000-000000000001")
    roles = {"value": [{"id": "role-1", "displayName": "Global Administrator"}]}
    members = {"value": [{"userPrincipalName": "admin@contoso.com", "id": "u1"}]}
    with patch.object(ctx, "graph_get", side_effect=[roles, members, None]):
        snap = iam_access_snapshot(ctx)
    assert snap["privileged_count"] >= 1
    assert snap["total_identities"] >= 1


# --- Consolidated from test_azure_modules.py ---

from sentinel.providers.azure.config import config_and_auth_snapshot
from sentinel.providers.azure.encryption import encryption_snapshot
from sentinel.providers.azure.logging import log_monitoring_snapshot
from sentinel.providers.azure.retention import retention_snapshot


def _ctx():
    with patch("sentinel.providers.azure._client.ResourceManagementClient"):
        with patch("sentinel.providers.azure._client.StorageManagementClient"):
            with patch("sentinel.providers.azure._client.DefaultAzureCredential"):
                return AzureContext(
                    subscription_id="00000000-0000-0000-0000-000000000001"
                )


def test_azure_logging_does_not_claim_resource_coverage():
    ctx = _ctx()
    with patch("azure.mgmt.monitor.MonitorManagementClient") as mock_mon:
        mock_mon.return_value.diagnostic_settings.list.return_value = [MagicMock()]
        with patch(
            "sentinel.cloud.call_with_retry",
            side_effect=lambda fn, **kw: fn(),
        ):
            snap = log_monitoring_snapshot(ctx)

    assert snap["log_coverage_percent"] is None
    assert snap["subscription_diagnostic_settings_count"] == 1
    assert any(error["code"] == "CoverageUnavailable" for error in snap["errors"])


def test_azure_encryption_storage():
    ctx = _ctx()
    account = MagicMock()
    account.name = "acct1"
    account.encryption.services.blob.enabled = True
    ctx.storage.storage_accounts.list = MagicMock(return_value=[account])
    with patch("azure.mgmt.resourcegraph.ResourceGraphClient") as mock_rg:
        mock_rg.return_value.resources.return_value = MagicMock(data=[])
        with patch.object(ctx, "graph_get", return_value={"value": []}), patch(
            "sentinel.cloud.call_with_retry",
            side_effect=lambda fn, **kw: fn(),
        ):
            snap = encryption_snapshot(ctx)
    assert snap["total_confidential_resources"] >= 1


def test_azure_retention_no_policy():
    ctx = _ctx()
    account = MagicMock()
    account.name = "acct1"
    account.id = (
        "/subscriptions/s/resourceGroups/rg/providers/"
        "Microsoft.Storage/storageAccounts/acct1"
    )
    ctx.storage.storage_accounts.list = MagicMock(return_value=[account])

    def _raise():
        raise Exception("not found")

    ctx.storage.management_policies.get = MagicMock(side_effect=_raise)
    with patch("sentinel.cloud.call_with_retry", side_effect=lambda fn, **kw: fn()):
        snap = retention_snapshot(ctx)
    assert snap["accounts_missing_lifecycle"] >= 1 or snap.get("errors")


def test_azure_config_mfa_registration_is_not_enforcement():
    ctx = _ctx()
    mfa = {
        "value": [
            {"isMfaRegistered": True},
            {"isMfaRegistered": False},
        ]
    }
    with patch("azure.mgmt.resourcegraph.ResourceGraphClient") as mock_rg:
        mock_rg.return_value.resources.return_value = MagicMock(data=[])
        with patch.object(ctx, "graph_get", return_value=mfa), patch(
            "sentinel.cloud.call_with_retry",
            side_effect=lambda fn, **kw: fn(),
        ):
            snap = config_and_auth_snapshot(ctx)

    assert snap["mfa_enforcement_percent"] is None
    assert snap["mfa_registered_percent"] == 50.0


# --- Consolidated from test_azure_resilience.py ---
from datetime import datetime, timezone

from sentinel.providers.azure.resilience import resilience_snapshot


def _completed_backup_job():
    job = MagicMock()
    job.properties.status = "Completed"
    job.properties.operation = "Backup"
    job.properties.end_time = datetime.now(timezone.utc)
    return job


def test_recovery_services_backup_jobs():
    ctx = AzureContext(
        subscription_id="00000000-0000-0000-0000-000000000001"
    )
    mock_vault = MagicMock()
    mock_vault.name = "vault1"
    mock_vault.id = (
        "/subscriptions/sub/resourceGroups/rg/providers/"
        "Microsoft.RecoveryServices/vaults/vault1"
    )

    with patch(
        "azure.mgmt.recoveryservicesbackup.RecoveryServicesBackupClient"
    ) as mock_cls:
        inst = mock_cls.return_value
        inst.backup_vaults.list_in_subscription.return_value = [mock_vault]
        inst.backup_jobs.list.return_value = [_completed_backup_job()]
        inst.backup_protected_items.list.return_value = []
        snap = resilience_snapshot(ctx)

    assert snap["last_backup_hours_ago"] is not None
    assert snap["backup_jobs_success_30d"] >= 1


def test_backup_success_does_not_imply_restore_or_failover():
    ctx = AzureContext(
        subscription_id="00000000-0000-0000-0000-000000000001"
    )
    mock_vault = MagicMock()
    mock_vault.name = "vault1"
    mock_vault.id = (
        "/subscriptions/sub/resourceGroups/rg/providers/"
        "Microsoft.RecoveryServices/vaults/vault1"
    )

    with patch(
        "azure.mgmt.recoveryservicesbackup.RecoveryServicesBackupClient"
    ) as mock_cls:
        inst = mock_cls.return_value
        inst.backup_vaults.list_in_subscription.return_value = [mock_vault]
        inst.backup_jobs.list.return_value = [_completed_backup_job()]
        inst.backup_protected_items.list.return_value = []
        snap = resilience_snapshot(ctx)

    assert snap["last_restore_test_days_ago"] is None
    assert snap["failover_test_days_ago"] is None
    assert snap["failover_test_passed"] is None
    assert snap["collection_quality"] == "partial"
    assert any(
        error["code"] == "FailoverTestNotCollected"
        for error in snap["errors"]
    )


# --- Consolidated from test_azure_zt.py ---

from sentinel.providers.azure._zt import zt_verification_snapshot


def test_azure_zt_merge():
    with patch("sentinel.providers.azure._client.ResourceManagementClient"):
        with patch("sentinel.providers.azure._client.StorageManagementClient"):
            with patch("sentinel.providers.azure._client.DefaultAzureCredential"):
                from sentinel.providers.azure._client import AzureContext

                ctx = AzureContext(subscription_id="00000000-0000-0000-0000-000000000001")
    with patch("sentinel.providers.azure.iam.iam_access_snapshot") as mock_iam:
        with patch("sentinel.providers.azure.encryption.encryption_snapshot") as mock_enc:
            with patch("sentinel.providers.azure.config.config_and_auth_snapshot") as mock_cfg:
                mock_iam.return_value = {"orphaned_accounts": 0, "privileged_count": 1, "errors": [], "collection_quality": "complete"}
                mock_enc.return_value = {"unencrypted_cui_count": 1, "errors": [], "collection_quality": "complete"}
                mock_cfg.return_value = {"mfa_enforcement_percent": 80.0, "errors": [], "collection_quality": "partial"}
                snap = zt_verification_snapshot(ctx)
    assert snap["encryption_status"] == "red"


# --- Consolidated from test_gcp_config_direct.py ---

from sentinel.providers.gcp._client import GcpContext
from sentinel.providers.gcp.config import config_and_auth_snapshot


def test_gcp_config_firewall_http():
    ctx = GcpContext(project_id="test-project")
    policy = MagicMock()
    policy.name = "constraints/test"
    rule = MagicMock()
    rule.enforce = False
    policy.rules = [rule]
    fw = MagicMock()
    fw.direction = "INGRESS"
    allow = MagicMock()
    allow.I_p_protocol = "tcp"
    allow.ports = ["80"]
    fw.allowed = [allow]
    with patch("google.cloud.orgpolicy_v2.OrgPolicyClient") as mock_org:
        mock_org.return_value.list_policies.return_value = [policy]
        with patch("google.cloud.compute_v1.FirewallsClient") as mock_fw_client:
            mock_fw_client.return_value.list.return_value = [fw]
            with patch("sentinel.cloud.call_with_retry", side_effect=lambda fn, **kw: fn()):
                snap = config_and_auth_snapshot(ctx)
    assert snap["open_http_listeners"] >= 1
    assert snap["issues"] >= 1


# --- Consolidated from test_gcp_iam.py ---

from sentinel.providers.gcp.iam import iam_access_snapshot


def test_asset_api_drives_user_counts():
    ctx = GcpContext(project_id="test-project")
    mock_policy = MagicMock()
    mock_policy.policy.bindings = [
        MagicMock(role="roles/owner", members=["user:admin@test.com"]),
    ]
    with patch("google.cloud.asset_v1.AssetServiceClient") as mock_client:
        mock_client.return_value.search_all_iam_policies.return_value = [mock_policy]
        with patch("google.cloud.iam_admin_v1.IAMClient") as mock_iam:
            mock_iam.return_value.list_service_accounts.return_value = []
            snap = iam_access_snapshot(ctx)
    assert snap["total_identities"] >= 1
    assert snap["privileged_count"] >= 1


# --- Consolidated from test_gcp_modules.py ---

from sentinel.providers.gcp.encryption import encryption_snapshot
from sentinel.providers.gcp.logging import log_monitoring_snapshot
from sentinel.providers.gcp.retention import retention_snapshot


def _ctx():
    return GcpContext(project_id="test-project", credentials=MagicMock())


def test_gcp_logging_uses_observed_signals_only():
    ctx = _ctx()
    mock_sink = MagicMock()
    mock_sink.name = "_Required"
    mock_sink.destination = "logging.googleapis.com/projects/test-project"

    with patch("google.cloud.logging.Client") as mock_log:
        inst = mock_log.return_value
        inst.list_sinks.return_value = [mock_sink]
        inst.list_entries.return_value = []
        with patch(
            "google.cloud.logging_v2.services.config_service_v2.ConfigServiceV2Client"
        ) as mock_config:
            mock_bucket = MagicMock()
            mock_bucket.retention_days = 30
            mock_config.return_value.list_buckets.return_value = [mock_bucket]
            with patch(
                "sentinel.cloud.call_with_retry",
                side_effect=lambda fn, **kw: fn(),
            ):
                snap = log_monitoring_snapshot(ctx)

    assert snap["active_trails"] == 1
    assert snap["log_coverage_percent"] is None
    assert snap["required_sink_present"] is True
    assert snap["log_bucket_retention_days"] == [30]
    assert any(error["code"] == "CoverageUnavailable" for error in snap["errors"])


def test_gcp_encryption_buckets():
    ctx = _ctx()
    bucket = MagicMock()
    bucket.name = "b1"
    bucket.default_kms_key_name = (
        "projects/p/locations/l/keyRings/k/cryptoKeys/c"
    )
    bucket.iam_configuration.uniform_bucket_level_access_enabled = True
    with patch("google.cloud.storage.Client") as mock_st:
        mock_st.return_value.list_buckets.return_value = [bucket]
        with patch("google.cloud.kms.KeyManagementServiceClient") as mock_kms:
            key = MagicMock()
            key.rotation_period = "86400s"
            mock_kms.return_value.list_crypto_keys.return_value = [key]
            with patch(
                "sentinel.cloud.call_with_retry",
                side_effect=lambda fn, **kw: fn(),
            ):
                snap = encryption_snapshot(ctx)
    assert snap["encrypted_at_rest"] >= 1


def test_gcp_retention_missing_rules():
    ctx = _ctx()
    bucket = MagicMock()
    bucket.name = "b1"
    bucket.lifecycle_rules = []
    with patch("google.cloud.storage.Client") as mock_st:
        mock_st.return_value.list_buckets.return_value = [bucket]
        with patch(
            "sentinel.cloud.call_with_retry",
            side_effect=lambda fn, **kw: fn(),
        ):
            snap = retention_snapshot(ctx)
    assert snap["buckets_missing_lifecycle"] == 1


def test_gcp_config_org_policy_does_not_claim_mfa_enforcement():
    ctx = _ctx()
    policy = MagicMock()
    policy.name = "constraints/compute.disableSerialPortAccess"
    rule = MagicMock()
    rule.enforce = True
    policy.rules = [rule]

    with patch("google.cloud.orgpolicy_v2.OrgPolicyClient") as mock_org:
        mock_org.return_value.list_policies.return_value = [policy]
        with patch("google.cloud.compute_v1.FirewallsClient") as mock_fw:
            mock_fw.return_value.list.return_value = []
            with patch(
                "sentinel.cloud.call_with_retry",
                side_effect=lambda fn, **kw: fn(),
            ):
                snap = config_and_auth_snapshot(ctx)

    assert snap["mfa_enforcement_percent"] is None
    assert snap["org_policy_violations"] == 0


# --- Consolidated from test_gcp_resilience.py ---

from sentinel.providers.gcp.resilience import resilience_snapshot


def test_compute_snapshot_timestamp():
    ctx = GcpContext(project_id="test-project", credentials=MagicMock())
    mock_snap = MagicMock()
    mock_snap.creation_timestamp = datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.000000+00:00"
    )
    with patch("google.cloud.compute_v1.SnapshotsClient") as mock_compute:
        mock_compute.return_value.list.return_value = [mock_snap]
        with patch("googleapiclient.discovery.build") as mock_build:
            mock_build.return_value.instances.return_value.list.return_value.execute.return_value = {
                "items": []
            }
            with patch("sentinel.cloud.call_with_retry", side_effect=lambda fn, **kw: fn()):
                snap = resilience_snapshot(ctx)
    assert snap.get("last_backup_hours_ago") is not None
    assert snap["backup_jobs_success_30d"] >= 1


# --- Consolidated from test_gcp_resilience_sql.py ---



def test_sql_backup_run_timestamp():
    ctx = GcpContext(project_id="test-project", credentials=MagicMock())
    with patch("google.cloud.compute_v1.SnapshotsClient") as mock_compute:
        mock_compute.return_value.list.return_value = []
        with patch("googleapiclient.discovery.build") as mock_build:
            service = MagicMock()
            service.instances.return_value.list.return_value.execute.return_value = {
                "items": [{"name": "sql-1"}]
            }
            end = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
            service.backupRuns.return_value.list.return_value.execute.return_value = {
                "items": [{"status": "SUCCESSFUL", "endTime": end}]
            }
            mock_build.return_value = service
            with patch("sentinel.cloud.call_with_retry", side_effect=lambda fn, **kw: fn()):
                snap = resilience_snapshot(ctx)
    assert snap.get("last_backup_hours_ago") is not None
    assert snap["backup_jobs_success_30d"] >= 1


# --- Consolidated from test_gcp_zt.py ---

from sentinel.providers.gcp._zt import zt_verification_snapshot


def test_gcp_zt_merge():
    ctx = GcpContext(project_id="p")
    with patch("sentinel.providers.gcp.iam.iam_access_snapshot") as mock_iam:
        with patch("sentinel.providers.gcp.encryption.encryption_snapshot") as mock_enc:
            with patch("sentinel.providers.gcp.config.config_and_auth_snapshot") as mock_cfg:
                mock_iam.return_value = {"orphaned_accounts": 1, "privileged_count": 2, "errors": [], "collection_quality": "complete"}
                mock_enc.return_value = {"unencrypted_cui_count": 0, "errors": [], "collection_quality": "complete"}
                mock_cfg.return_value = {"mfa_enforcement_percent": 100.0, "errors": [], "collection_quality": "complete"}
                snap = zt_verification_snapshot(ctx)
    assert snap["encryption_status"] == "green"
