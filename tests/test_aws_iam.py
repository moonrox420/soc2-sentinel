import boto3
from moto import mock_aws

from sentinel.providers.aws.iam import iam_access_snapshot
from sentinel.providers.aws._client import AwsClients


@mock_aws
def test_credential_report_drives_review_days():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="alice")
    iam.generate_credential_report()
    ctx = AwsClients(region="us-east-1")
    snap = iam_access_snapshot(ctx)
    assert "days_since_last_review" in snap
    assert snap.get("days_since_last_review") != 45
    assert snap["collection_quality"] in {"complete", "partial"}