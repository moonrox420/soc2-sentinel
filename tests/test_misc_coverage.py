from pathlib import Path
from unittest.mock import patch

import pytest

from sentinel.cloud import call_with_retry, is_retryable_error, snapshot_errors
from sentinel.errors import ProviderError, ValidationError
from sentinel.paths import evidence_root, install_root
from sentinel.providers import get_provider
from sentinel.config import ProviderConfig, SentinelConfig


def test_snapshot_errors_helper():
    data = snapshot_errors("a", "", "b")
    assert data["partial"] is True
    assert data["errors"] == ["a", "b"]


def test_is_retryable_connection():
    assert is_retryable_error(ConnectionError("down")) is True


def test_call_with_retry_non_retryable():
    def boom():
        raise ValueError("nope")

    with pytest.raises(ValueError):
        call_with_retry(boom, max_attempts=1, operation="test")


def test_paths_helpers():
    assert install_root().exists()
    assert "evidence" in str(evidence_root(Path.cwd()))


def test_error_types():
    err = ValidationError("bad", details={"x": 1})
    assert err.to_dict()["message"] == "bad"
    prov = ProviderError("cloud down")
    assert prov.message == "cloud down"


def test_get_provider_clouds():
    cfg = SentinelConfig(
        provider=ProviderConfig(
            aws_region="us-east-1",
            gcp_project_id="proj",
            azure_subscription_id="00000000-0000-0000-0000-000000000001",
        )
    )
    with patch("sentinel.providers.aws.provider.AwsProvider.validate_credentials"):
        assert get_provider("aws", cfg).name == "aws"
    with patch("sentinel.providers.gcp.provider.GcpProvider.validate_credentials"):
        assert get_provider("gcp", cfg).name == "gcp"
    with patch("sentinel.providers.azure.provider.AzureProvider.validate_credentials"):
        assert get_provider("azure", cfg).name == "azure"