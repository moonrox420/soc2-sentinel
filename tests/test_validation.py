import pytest

from sentinel.errors import ValidationError
from sentinel.validation import (
    resolve_safe_output_base,
    sanitize_artifact_name,
    sanitize_control_id,
)


def test_sanitize_control_id_rejects_traversal():
    with pytest.raises(ValidationError):
        sanitize_control_id("../etc/passwd")


def test_sanitize_control_id_accepts_known():
    assert sanitize_control_id("CC6.1") == "CC6.1"


def test_sanitize_artifact_name_rejects_parent():
    with pytest.raises(ValidationError):
        sanitize_artifact_name("../report.json")


def test_resolve_safe_output_base_writable(tmp_path):
    resolved = resolve_safe_output_base(tmp_path)
    assert resolved == tmp_path.resolve()


# --- Consolidated from test_validation_extended.py ---


def test_control_id_reserved():
    with pytest.raises(ValidationError):
        sanitize_control_id("CON", strict_allowlist=False)


def test_artifact_invalid_format():
    with pytest.raises(ValidationError):
        sanitize_artifact_name("bad name with spaces")


def test_control_id_empty():
    with pytest.raises(ValidationError):
        sanitize_control_id("", strict_allowlist=False)


# --- Consolidated from test_validation_paths.py ---


def test_output_base_not_directory(tmp_path):
    f = tmp_path / "file.txt"
    f.write_text("x", encoding="utf-8")
    with pytest.raises(ValidationError, match="not a directory"):
        resolve_safe_output_base(f)


def test_artifact_empty_name():
    with pytest.raises(ValidationError):
        sanitize_artifact_name("")


# --- Consolidated from test_validation_strict.py ---


def test_unknown_control_rejected_by_default():
    with pytest.raises(ValidationError, match="not in known controls"):
        sanitize_control_id("CUSTOM-999", strict_allowlist=True)


def test_unknown_control_allowed_when_disabled():
    assert sanitize_control_id("CUSTOM-999", strict_allowlist=False) == "CUSTOM-999"


def test_known_control_passes():
    assert sanitize_control_id("CC6.1", strict_allowlist=True) == "CC6.1"


# --- Consolidated from test_schema_errors.py ---

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
