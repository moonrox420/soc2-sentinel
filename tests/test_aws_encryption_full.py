from unittest.mock import MagicMock, patch

from sentinel.providers.aws.encryption import encryption_snapshot
from sentinel.providers.aws._client import AwsClients


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