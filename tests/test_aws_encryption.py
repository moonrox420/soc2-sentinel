import boto3
from moto import mock_aws

from sentinel.providers.aws.encryption import encryption_snapshot
from sentinel.providers.aws._client import AwsClients


@mock_aws
def test_s3_unencrypted_bucket_found():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-unencrypted-bucket")
    ctx = AwsClients(region="us-east-1")
    snap = encryption_snapshot(ctx)
    assert snap["unencrypted_cui_count"] >= 1
    assert snap["tls_endpoints_checked"] >= 0