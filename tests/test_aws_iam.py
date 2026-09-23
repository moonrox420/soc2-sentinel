import boto3
from moto import mock_aws

from sentinel.providers.aws._client import AwsClients
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
