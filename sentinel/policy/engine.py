from __future__ import annotations

import ast
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinel.policy.models import PolicyReport, PolicyRule, RuleEvaluationResult
from sentinel.tenancy import get_current_tenant

logger = logging.getLogger("sentinel.policy")


class SafeExpressionEvaluator:
    """Evaluates boolean condition expressions over metric dictionaries using safe AST traversal."""

    ALLOWED_NODES = (
        ast.Expression,
        ast.Compare,
        ast.BoolOp,
        ast.UnaryOp,
        ast.BinOp,
        ast.Name,
        ast.Constant,
        ast.Attribute,
        ast.Subscript,
        ast.List,
        ast.Tuple,
        ast.Dict,
        ast.Index,
        ast.Load,
        # Comparison operators
        ast.Eq,
        ast.NotEq,
        ast.Lt,
        ast.LtE,
        ast.Gt,
        ast.GtE,
        ast.In,
        ast.NotIn,
        ast.Is,
        ast.IsNot,
        # Boolean operators
        ast.And,
        ast.Or,
        ast.Not,
        # Math operators
        ast.Add,
        ast.Sub,
        ast.Mult,
        ast.Div,
        ast.Mod,
        ast.USub,
        ast.UAdd,
    )

    @classmethod
    def evaluate(cls, expression_str: str, context: dict[str, Any]) -> bool:
        """Parse and evaluate expression against context without eval()."""
        try:
            tree = ast.parse(expression_str.strip(), mode="eval")
        except SyntaxError as e:
            raise ValueError(
                f"Invalid policy expression syntax: {expression_str}"
            ) from e

        # Validate that no disallowed AST nodes exist (e.g., Call, Import, Lambda, Exec)
        for node in ast.walk(tree):
            if not isinstance(node, cls.ALLOWED_NODES):
                raise ValueError(
                    f"Forbidden syntax in policy expression: {type(node).__name__}"
                )

        return bool(cls._eval_node(tree.body, context))

    @classmethod
    def _eval_node(cls, node: ast.AST, context: dict[str, Any]) -> Any:
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            if node.id == "True":
                return True
            if node.id == "False":
                return False
            if node.id == "None":
                return None
            return context.get(node.id)

        if isinstance(node, ast.Attribute):
            val = cls._eval_node(node.value, context)
            if isinstance(val, dict):
                return val.get(node.attr)
            return getattr(val, node.attr, None)

        if isinstance(node, ast.Subscript):
            val = cls._eval_node(node.value, context)
            key = cls._eval_node(node.slice, context)
            if isinstance(val, (dict, list, tuple)):
                try:
                    return val[key]
                except (KeyError, IndexError, TypeError):
                    return None
            return None

        if isinstance(node, ast.UnaryOp):
            operand = cls._eval_node(node.operand, context)
            if isinstance(node.op, ast.Not):
                return not operand
            if isinstance(node.op, ast.USub):
                return -operand
            if isinstance(node.op, ast.UAdd):
                return +operand

        if isinstance(node, ast.BinOp):
            left = cls._eval_node(node.left, context)
            right = cls._eval_node(node.right, context)
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            if isinstance(node.op, ast.Div):
                return left / right if right != 0 else 0
            if isinstance(node.op, ast.Mod):
                return left % right if right != 0 else 0

        if isinstance(node, ast.BoolOp):
            if isinstance(node.op, ast.And):
                return all(cls._eval_node(v, context) for v in node.values)
            if isinstance(node.op, ast.Or):
                return any(cls._eval_node(v, context) for v in node.values)

        if isinstance(node, ast.Compare):
            left = cls._eval_node(node.left, context)
            for op, comparator in zip(node.ops, node.comparators):
                right = cls._eval_node(comparator, context)
                if isinstance(op, ast.Eq):
                    if not (left == right):
                        return False
                elif isinstance(op, ast.NotEq):
                    if not (left != right):
                        return False
                elif isinstance(op, ast.Lt):
                    if left is None or right is None or not (left < right):
                        return False
                elif isinstance(op, ast.LtE):
                    if left is None or right is None or not (left <= right):
                        return False
                elif isinstance(op, ast.Gt):
                    if left is None or right is None or not (left > right):
                        return False
                elif isinstance(op, ast.GtE):
                    if left is None or right is None or not (left >= right):
                        return False
                elif isinstance(op, ast.In):
                    if right is None or left not in right:
                        return False
                elif isinstance(op, ast.NotIn):
                    if right is not None and left in right:
                        return False
                elif isinstance(op, ast.Is):
                    if left is not right:
                        return False
                elif isinstance(op, ast.IsNot):
                    if left is right:
                        return False
                left = right
            return True

        if isinstance(node, (ast.List, ast.Tuple)):
            return [cls._eval_node(e, context) for e in node.elts]

        if isinstance(node, ast.Dict):
            return {
                cls._eval_node(k, context): cls._eval_node(v, context)
                for k, v in zip(node.keys, node.values)
                if k is not None
            }

        raise ValueError(f"Unsupported AST node: {type(node).__name__}")


# Core out-of-the-box enterprise compliance rules mapped to AICPA TSC
DEFAULT_ENTERPRISE_RULES: list[PolicyRule] = [
    PolicyRule(
        rule_id="SEC-IAM-001",
        name="MFA Enforcement Across All Console Identities",
        description="Verify that Multi-Factor Authentication is 100% enforced on all human and administrator identities.",
        category="Security",
        severity="CRITICAL",
        collector_target="iam_access_review",
        condition="mfa_enforced_percentage >= 100.0",
        frameworks={
            "soc2": ["CC6.1", "CC6.2"],
            "nist": ["3.5.3"],
            "cmmc": ["IA.L2-3.5.3"],
            "zt": ["ZT-01"],
        },
        remediation_summary="Enable mandatory MFA / WebAuthn conditional access policies across all identity providers.",
        remediation_playbook="docs/playbooks/iam-mfa-enforcement.md",
    ),
    PolicyRule(
        rule_id="SEC-IAM-002",
        name="Zero Orphaned Identity Accounts",
        description="Ensure inactive accounts (>90d) are promptly deprovisioned from cloud and identity directories.",
        category="Security",
        severity="HIGH",
        collector_target="iam_access_review",
        condition="orphaned_accounts == 0",
        frameworks={
            "soc2": ["CC6.1"],
            "nist": ["3.1.1", "3.1.2"],
            "cmmc": ["AC.L2-3.1.1"],
            "zt": ["ZT-01"],
        },
        remediation_summary="Deprovision all orphaned users identified in the IAM access review report.",
        remediation_playbook="docs/playbooks/iam-deprovisioning.md",
    ),
    PolicyRule(
        rule_id="SEC-IAM-003",
        name="Timely Access Review Cadence",
        description="User access review must be performed within the 90-day SLA window.",
        category="Security",
        severity="MEDIUM",
        collector_target="iam_access_review",
        condition="review_days <= 90",
        frameworks={"soc2": ["CC6.1"], "nist": ["3.1.2"], "cmmc": ["AC.L2-3.1.2"]},
        remediation_summary="Conduct and sign off on a quarterly user access review.",
        remediation_playbook="docs/playbooks/access-reviews.md",
    ),
    PolicyRule(
        rule_id="SEC-LOG-001",
        name="Continuous Immutable Audit Logging Active",
        description="Ensure central audit trails are continuously active and recording control plane events.",
        category="Security",
        severity="CRITICAL",
        collector_target="log_aggregator",
        condition="log_streams >= 1 and completeness >= 95.0",
        frameworks={
            "soc2": ["CC7.1"],
            "nist": ["3.3.1", "3.3.2"],
            "cmmc": ["AU.L2-3.3.1"],
            "zt": ["ZT-06"],
        },
        remediation_summary="Enable multi-region CloudTrail, Azure Activity Log diagnostics, or GCP Audit Logs.",
        remediation_playbook="docs/playbooks/logging-setup.md",
    ),
    PolicyRule(
        rule_id="SEC-LOG-002",
        name="Audit Log Retention Minimum 365 Days",
        description="Audit log stores must enforce retention rules retaining records for at least 1 year.",
        category="Security",
        severity="HIGH",
        collector_target="log_aggregator",
        condition="retention_days >= 365",
        frameworks={"soc2": ["CC7.1"], "nist": ["3.3.8"], "cmmc": ["AU.L2-3.3.8"]},
        remediation_summary="Update log group or storage bucket lifecycle to maintain a 365-day retention window.",
        remediation_playbook="docs/playbooks/log-retention.md",
    ),
    PolicyRule(
        rule_id="SEC-NET-001",
        name="Zero Unrestricted Ingress Security Groups",
        description="Security groups must not allow open ingress (0.0.0.0/0) on sensitive administrative ports.",
        category="Security",
        severity="CRITICAL",
        collector_target="config_drift",
        condition="open_sgs == 0",
        frameworks={
            "soc2": ["CC6.6", "CC6.2"],
            "nist": ["3.13.1"],
            "cmmc": ["SC.L2-3.13.1"],
            "zt": ["ZT-04"],
        },
        remediation_summary="Restrict ingress rules to authorized corporate CIDR blocks or VPN gateways.",
        remediation_playbook="docs/playbooks/network-security.md",
    ),
    PolicyRule(
        rule_id="SEC-CRY-001",
        name="Universal Encryption at Rest Enforced",
        description="All storage buckets, databases, and block volumes containing sensitive data must be encrypted.",
        category="Confidentiality",
        severity="CRITICAL",
        collector_target="encryption_status",
        condition="unencrypted_stores == 0 and at_rest_pct >= 100.0",
        frameworks={
            "soc2": ["C1.1", "C1.2"],
            "nist": ["3.13.16"],
            "cmmc": ["SC.L2-3.13.16"],
            "zt": ["ZT-05"],
        },
        remediation_summary="Enable KMS/AES-256 encryption on all unencrypted volumes and database instances.",
        remediation_playbook="docs/playbooks/encryption-at-rest.md",
    ),
    PolicyRule(
        rule_id="SEC-CRY-002",
        name="TLS 1.2+ Transit Encryption Enforced",
        description="Web services and APIs must enforce modern cryptographic cipher suites and reject TLS < 1.2.",
        category="Confidentiality",
        severity="HIGH",
        collector_target="encryption_status",
        condition="transit_pct >= 100.0",
        frameworks={
            "soc2": ["C1.2"],
            "nist": ["3.13.8"],
            "cmmc": ["SC.L2-3.13.8"],
            "zt": ["ZT-05"],
        },
        remediation_summary="Upgrade load balancer SSL policies to TLS 1.2 or TLS 1.3 only.",
        remediation_playbook="docs/playbooks/tls-configuration.md",
    ),
    PolicyRule(
        rule_id="SEC-VCS-001",
        name="Branch Protection & Mandatory PR Approvals",
        description="Default production branch must enforce code reviews, approval gates, and status checks.",
        category="Change Management",
        severity="CRITICAL",
        collector_target="github_vcs",
        condition="branch_protection_enforced == True and required_approvals >= 1",
        frameworks={
            "soc2": ["CC8.1"],
            "nist": ["3.4.1", "3.4.2"],
            "cmmc": ["CM.L2-3.4.1"],
        },
        remediation_summary="Configure GitHub branch protection rule requiring pull request approvals before merge.",
        remediation_playbook="docs/playbooks/vcs-branch-protection.md",
    ),
    PolicyRule(
        rule_id="SEC-VCS-002",
        name="Zero Critical Unresolved Vulnerabilities (SCA)",
        description="Software composition analysis (SCA) must show zero unpatched critical vulnerabilities past SLA.",
        category="Security",
        severity="HIGH",
        collector_target="github_vcs",
        condition="critical_vulnerabilities == 0",
        frameworks={"soc2": ["CC7.1"], "nist": ["3.14.1"], "cmmc": ["SI.L2-3.14.1"]},
        remediation_summary="Patch or upgrade vulnerable dependencies flagged by Dependabot/Snyk.",
        remediation_playbook="docs/playbooks/vulnerability-management.md",
    ),
    PolicyRule(
        rule_id="SEC-RES-001",
        name="Verified 24-Hour Backup Execution",
        description="Automated backup jobs must have successfully completed within the last 24 hours.",
        category="Availability",
        severity="HIGH",
        collector_target="resilience_testing",
        condition="success_24h >= 1",
        frameworks={
            "soc2": ["A1.2"],
            "nist": ["3.11.1"],
            "cmmc": ["RE.L2-3.11.1"],
            "zt": ["ZT-07"],
        },
        remediation_summary="Investigate failed backup jobs in AWS Backup / Azure Backup / GCP snapshots.",
        remediation_playbook="docs/playbooks/backup-recovery.md",
    ),
    PolicyRule(
        rule_id="SEC-RES-002",
        name="Periodic Disaster Recovery Restore Testing (90-Day SLA)",
        description="A verified restore test from backup must be recorded within the 90-day SLA window.",
        category="Availability",
        severity="HIGH",
        collector_target="resilience_testing",
        condition="restore_tested_90d == True",
        frameworks={
            "soc2": ["A1.3", "A1.2"],
            "nist": ["3.11.1"],
            "cmmc": ["RE.L2-3.11.1"],
        },
        remediation_summary="Perform a test restore drill and record completion timestamp in Sentinel.",
        remediation_playbook="docs/playbooks/restore-drills.md",
    ),
]


class PolicyEngine:
    """Evaluates declarative policy rules across collector metric payloads."""

    def __init__(self, custom_rules: list[PolicyRule] | None = None) -> None:
        self.rules: dict[str, PolicyRule] = {
            r.rule_id: r for r in DEFAULT_ENTERPRISE_RULES
        }
        if custom_rules:
            for r in custom_rules:
                self.rules[r.rule_id] = r

    def register_rule(self, rule: PolicyRule) -> None:
        """Register or override a policy rule."""
        self.rules[rule.rule_id] = rule

    def load_rules_from_file(self, file_path: Path) -> int:
        """Load external policy rules from a JSON file."""
        if not file_path.exists():
            return 0
        try:
            content = json.loads(file_path.read_text(encoding="utf-8"))
            count = 0
            if isinstance(content, list):
                for item in content:
                    rule = PolicyRule(**item)
                    self.register_rule(rule)
                    count += 1
            return count
        except Exception as e:
            logger.error("Failed loading policy rules from %s: %s", file_path, e)
            return 0

    def evaluate(
        self, collector_data: dict[str, dict[str, Any]], provider: str = "unknown"
    ) -> PolicyReport:
        """Evaluate all active rules against collector telemetry."""
        now_iso = datetime.now(timezone.utc).isoformat()
        tenant = get_current_tenant()

        results: list[RuleEvaluationResult] = []
        passed = 0
        failed = 0
        skipped = 0
        critical_failures: list[str] = []

        # Build unified metrics index by collector target
        metrics_by_target: dict[str, dict[str, Any]] = {}
        for coll_name, payload in collector_data.items():
            metrics = payload.get("metrics", {})
            metrics_by_target[coll_name] = metrics
            ctrl_id = payload.get("control_id")
            if ctrl_id:
                metrics_by_target[ctrl_id] = metrics

        for rule in self.rules.values():
            if not rule.enabled:
                continue

            # Look up telemetry payload for this rule's collector target
            target_metrics = metrics_by_target.get(rule.collector_target)
            if target_metrics is None:
                # Target collector was not executed or produced no evidence
                results.append(
                    RuleEvaluationResult(
                        rule_id=rule.rule_id,
                        name=rule.name,
                        category=rule.category,
                        severity=rule.severity,
                        status="SKIPPED",
                        condition=rule.condition,
                        message=f"No evidence collected for target '{rule.collector_target}'",
                        actual_metrics={},
                        frameworks=rule.frameworks,
                        remediation_summary=rule.remediation_summary,
                    )
                )
                skipped += 1
                continue

            try:
                is_compliant = SafeExpressionEvaluator.evaluate(
                    rule.condition, target_metrics
                )
                if is_compliant:
                    status = "PASS"
                    message = "Condition satisfied"
                    passed += 1
                else:
                    status = "FAIL"
                    message = f"Evaluation failed: {rule.condition}"
                    failed += 1
                    if rule.severity == "CRITICAL":
                        critical_failures.append(f"{rule.rule_id}: {rule.name}")
            except Exception as exc:
                status = "ERROR"
                message = f"Evaluation error: {exc}"
                failed += 1

            results.append(
                RuleEvaluationResult(
                    rule_id=rule.rule_id,
                    name=rule.name,
                    category=rule.category,
                    severity=rule.severity,
                    status=status,
                    condition=rule.condition,
                    message=message,
                    actual_metrics=target_metrics,
                    frameworks=rule.frameworks,
                    remediation_summary=rule.remediation_summary,
                )
            )

        evaluated = passed + failed
        compliance_score = (
            round((passed / evaluated * 100.0), 1) if evaluated > 0 else 0.0
        )

        return PolicyReport(
            timestamp=now_iso,
            tenant_id=tenant.tenant_id,
            provider=provider,
            rules_evaluated=len(results),
            rules_passed=passed,
            rules_failed=failed,
            rules_skipped=skipped,
            compliance_score=compliance_score,
            critical_failures=critical_failures,
            results=results,
        )


_DEFAULT_ENGINE = PolicyEngine()


def get_default_policy_engine() -> PolicyEngine:
    return _DEFAULT_ENGINE
