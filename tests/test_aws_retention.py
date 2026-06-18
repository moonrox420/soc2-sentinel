import boto3
from moto import mock_aws

from sentinel.providers.aws.retention import retention_snapshot
from sentinel.providers.aws._client import AwsClients


@mock_aws
def test_bucket_missing_lifecycle():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="no-lifecycle-bucket")
    ctx = AwsClients(region="us-east-1")
    snap = retention_snapshot(ctx)
    assert snap["buckets_missing_lifecycle"] >= 1