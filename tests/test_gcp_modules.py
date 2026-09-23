from unittest.mock import MagicMock, patch

from sentinel.providers.gcp._client import GcpContext
from sentinel.providers.gcp.config import config_and_auth_snapshot
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
