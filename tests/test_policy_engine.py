"""Unit tests for Safe Expression Evaluator and Declarative Policy Engine."""

import json
from pathlib import Path

import pytest

from sentinel.policy.engine import (
    PolicyEngine,
    SafeExpressionEvaluator,
    get_default_policy_engine,
)
from sentinel.policy.models import PolicyReport, PolicyRule


def test_safe_expression_evaluator_literals_and_arithmetic() -> None:
    evaluator = SafeExpressionEvaluator()
    assert evaluator.evaluate("1 + 2 == 3", {}) is True
    assert evaluator.evaluate("10 * 5 > 40", {}) is True
    assert evaluator.evaluate("100 / 2 == 50", {}) is True
    assert evaluator.evaluate("10 % 3 == 1", {}) is True
    assert evaluator.evaluate("10 - 4 == 6", {}) is True
    assert evaluator.evaluate("-5 < 0", {}) is True
    assert evaluator.evaluate("+5 > 0", {}) is True
    assert evaluator.evaluate("'prod' in ['prod', 'staging']", {}) is True
    assert evaluator.evaluate("'dev' not in ['prod', 'staging']", {}) is True
    assert evaluator.evaluate("True and not False", {}) is True
    assert evaluator.evaluate("False or True", {}) is True
    assert evaluator.evaluate("score >= 90.0", {"score": 95.5}) is True
    assert evaluator.evaluate("score <= 90.0", {"score": 95.5}) is False
    assert evaluator.evaluate("score != 100.0", {"score": 95.5}) is True
    assert evaluator.evaluate("val is None", {"val": None}) is True
    assert evaluator.evaluate("val is not None", {"val": 123}) is True


def test_safe_expression_evaluator_nested_dict_and_subscript_access() -> None:
    evaluator = SafeExpressionEvaluator()
    state = {
        "iam": {"mfa_enforced": True, "root_active": False},
        "s3": {"buckets": ["logs", "backups"]},
        "counts": [10, 20, 30],
        "tags": {"env": "production"},
    }
    assert (
        evaluator.evaluate(
            "iam.mfa_enforced == True and iam.root_active == False", state
        )
        is True
    )
    assert evaluator.evaluate("'logs' in s3.buckets", state) is True
    assert evaluator.evaluate("counts[0] == 10", state) is True
    assert evaluator.evaluate("tags['env'] == 'production'", state) is True
    assert evaluator.evaluate("non_existent is None", state) is True


def test_safe_expression_evaluator_rejects_unsafe_operations() -> None:
    evaluator = SafeExpressionEvaluator()

    with pytest.raises(ValueError, match="Forbidden syntax"):
        evaluator.evaluate("__import__('os').system('echo 1')", {})

    with pytest.raises(ValueError, match="Forbidden syntax"):
        evaluator.evaluate("len([1, 2, 3]) == 3", {})

    with pytest.raises(ValueError, match="Forbidden syntax"):
        evaluator.evaluate("open('test.txt')", {})

    with pytest.raises(ValueError, match="Invalid policy expression syntax"):
        evaluator.evaluate("invalid syntax %$@#", {})


def test_policy_engine_evaluation_and_skip(tmp_path: Path) -> None:
    engine = PolicyEngine()
    assert len(engine.rules) > 0

    # Test full evaluation with mock collector evidence
    collector_data = {
        "iam_access_review": {
            "metrics": {
                "mfa_enforced_percentage": 100.0,
                "orphaned_accounts": 0,
                "privilege_creep_findings": 0,
                "quarterly_access_review_conducted": True,
            }
        },
        "config_drift": {
            "metrics": {
                "critical_unapproved_changes": 0,
                "unauthorized_security_group_changes": 0,
            }
        },
        "encryption_status": {
            "metrics": {
                "all_storage_encrypted": True,
                "unencrypted_data_stores": 0,
                "kms_cmk_rotation_enabled": True,
            }
        },
    }

    report = engine.evaluate(collector_data, provider="aws")
    assert isinstance(report, PolicyReport)
    assert report.rules_evaluated > 0
    assert report.rules_passed > 0
    assert report.rules_skipped > 0
    assert report.compliance_score > 0.0

    d = report.to_dict()
    assert "compliance_score" in d
    assert "results" in d
    assert len(d["results"]) > 0
    assert d["results"][0]["rule_id"] != ""


def test_policy_engine_rule_registration_and_file_loading(tmp_path: Path) -> None:
    custom_rule = PolicyRule(
        rule_id="CUSTOM-NET-001",
        name="Block Ingress Port 22",
        description="SSH port 22 must not be exposed to 0.0.0.0/0",
        category="Network Security",
        severity="CRITICAL",
        collector_target="config_drift",
        condition="open_ssh_ports == 0",
        frameworks={"soc2": ["CC6.6"]},
    )
    engine = PolicyEngine(custom_rules=[custom_rule])
    assert "CUSTOM-NET-001" in engine.rules

    # Test JSON rule file loading
    rules_file = tmp_path / "rules.json"
    rules_file.write_text(
        json.dumps(
            [
                {
                    "rule_id": "CUSTOM-FILE-002",
                    "name": "Audit Logging",
                    "description": "Ensure audit logs are retained >= 365 days",
                    "category": "Logging",
                    "severity": "HIGH",
                    "collector_target": "log_aggregator",
                    "condition": "retention_days >= 365",
                }
            ]
        ),
        encoding="utf-8",
    )

    loaded = engine.load_rules_from_file(rules_file)
    assert loaded == 1
    assert "CUSTOM-FILE-002" in engine.rules

    # Singleton check
    default_eng = get_default_policy_engine()
    assert isinstance(default_eng, PolicyEngine)
