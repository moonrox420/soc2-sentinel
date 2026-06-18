from unittest.mock import MagicMock, patch

from sentinel.providers.gcp.config import config_and_auth_snapshot
from sentinel.providers.gcp._client import GcpContext


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