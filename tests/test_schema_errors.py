import pytest

from sentinel.errors import ValidationError
from sentinel.schema import utc_now_iso, validate_evidence


def _base(**overrides):
    payload = {
        "control_id": "CC6.1",
        "collection_timestamp": utc_now_iso(),
        "status": "green",
        "collection_quality": "complete",
        "metrics": {},
        "evidence_artifacts": ["report.json"],
        "findings": [],
        "errors": [],
        "notes": "ok",
        "provider": "mock",
    }
    payload.update(overrides)
    return payload


def test_complete_requires_artifacts():
    with pytest.raises(ValidationError, match="evidence_artifacts"):
        validate_evidence(_base(evidence_artifacts=[]))


def test_complete_rejects_critical_errors():
    with pytest.raises(ValidationError, match="critical errors"):
        validate_evidence(
            _base(errors=[{"code": "X", "message": "fail", "severity": "critical"}])
        )


def test_findings_require_severity():
    with pytest.raises(ValidationError, match="severity"):
        validate_evidence(_base(findings=[{"issue": "bad"}]))


def test_failed_allows_empty_artifacts():
    validate_evidence(
        _base(collection_quality="failed", evidence_artifacts=[], status="red")
    )