from unittest.mock import patch

from sentinel.providers.gcp._zt import zt_verification_snapshot
from sentinel.providers.gcp._client import GcpContext


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