from __future__ import annotations

from unittest.mock import MagicMock, patch

from sentinel.onboarding import (
    diagnose_all_providers,
    diagnose_aws,
    diagnose_azure,
    diagnose_gcp,
    diagnose_mock,
)


def test_diagnose_mock():
    res = diagnose_mock()
    assert res.provider == "mock"
    assert res.status == "READY"
    assert "Offline" in (res.identity or "")
    assert res.policy_snippet is None
    d = res.to_dict()
    assert d["status"] == "READY"


def test_diagnose_aws_missing_creds(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    with patch("pathlib.Path.exists", return_value=False):
        res = diagnose_aws()
        assert res.provider == "aws"
        assert res.status == "CREDENTIALS_MISSING"
        assert res.policy_snippet is not None
        assert "Statement" in res.policy_snippet


def test_diagnose_aws_valid_creds(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test-key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-secret")
    monkeypatch.setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:user/sentinel")
    mock_prov = MagicMock()
    mock_prov.validate_credentials.return_value = None
    with patch("sentinel.onboarding.get_provider", return_value=mock_prov):
        res = diagnose_aws()
        assert res.status == "READY"
        assert "123456789012" in (res.identity or "")


def test_diagnose_aws_invalid_creds(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test-key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-secret")
    mock_prov = MagicMock()
    mock_prov.validate_credentials.side_effect = Exception("SignatureDoesNotMatch")
    with patch("sentinel.onboarding.get_provider", return_value=mock_prov):
        res = diagnose_aws()
        assert res.status == "PERMISSION_DENIED"


def test_diagnose_gcp_missing_creds(monkeypatch):
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    with patch("pathlib.Path.exists", return_value=False):
        res = diagnose_gcp()
        assert res.status == "CREDENTIALS_MISSING"
        assert "roles" in res.policy_snippet


def test_diagnose_gcp_valid_creds(monkeypatch):
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/path/to/key.json")
    mock_prov = MagicMock()
    mock_prov.validate_credentials.return_value = None
    with patch("sentinel.onboarding.get_provider", return_value=mock_prov):
        res = diagnose_gcp()
        assert res.status == "READY"


def test_diagnose_azure_missing_creds(monkeypatch):
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    res = diagnose_azure()
    assert res.status == "CREDENTIALS_MISSING"


def test_diagnose_azure_valid_creds(monkeypatch):
    monkeypatch.setenv("AZURE_CLIENT_ID", "sp-id")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "sp-secret")
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant-id")
    mock_prov = MagicMock()
    mock_prov.validate_credentials.return_value = None
    with patch("sentinel.onboarding.get_provider", return_value=mock_prov):
        res = diagnose_azure()
        assert res.status == "READY"


def test_diagnose_all_providers():
    all_diag = diagnose_all_providers()
    assert "aws" in all_diag
    assert "gcp" in all_diag
    assert "azure" in all_diag
    assert "mock" in all_diag
    assert all_diag["mock"]["status"] == "READY"
