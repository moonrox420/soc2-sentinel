from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class PolicyRule:
    """Declarative Policy-as-Code compliance rule definition."""
    rule_id: str
    name: str
    description: str
    category: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    collector_target: str  # e.g., "iam_access_review", "config_drift", "github_vcs", etc.
    condition: str  # Safe boolean expression, e.g., "orphaned_accounts == 0"
    frameworks: dict[str, list[str]] = field(default_factory=dict)
    remediation_summary: str = ""
    remediation_playbook: str = ""
    enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RuleEvaluationResult:
    """Individual rule evaluation outcome."""
    rule_id: str
    name: str
    category: str
    severity: str
    status: str  # "PASS", "FAIL", "SKIPPED", "ERROR"
    condition: str
    message: str
    actual_metrics: dict[str, Any] = field(default_factory=dict)
    frameworks: dict[str, list[str]] = field(default_factory=dict)
    remediation_summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PolicyReport:
    """Full policy execution evaluation report."""
    timestamp: str
    tenant_id: str
    provider: str
    rules_evaluated: int
    rules_passed: int
    rules_failed: int
    rules_skipped: int
    compliance_score: float  # 0.0 to 100.0%
    critical_failures: list[str] = field(default_factory=list)
    results: list[RuleEvaluationResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.rules_failed == 0

    @property
    def violations(self) -> list[RuleEvaluationResult]:
        return [r for r in self.results if r.status == "FAIL"]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["passed"] = self.passed
        return d
