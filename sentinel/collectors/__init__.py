from sentinel.collectors.config_drift import collect_config_drift
from sentinel.collectors.encryption_status import collect_encryption_status
from sentinel.collectors.iam_access_review import collect_iam_access_review
from sentinel.collectors.log_aggregator import collect_log_aggregator
from sentinel.collectors.resilience_testing import collect_resilience_testing
from sentinel.collectors.retention_check import collect_retention_check
from sentinel.collectors.self_assessment_report import (
    generate_self_assessment_report as generate_self_assessment_report,
)
from sentinel.collectors.zt_continuous_verification import collect_zt_continuous_verification

__all__ = ["COLLECTORS", "generate_self_assessment_report"]

COLLECTORS = {
    "iam_access_review": collect_iam_access_review,
    "log_aggregator": collect_log_aggregator,
    "config_drift": collect_config_drift,
    "encryption_status": collect_encryption_status,
    "retention_check": collect_retention_check,
    "resilience_testing": collect_resilience_testing,
    "zt_continuous_verification": collect_zt_continuous_verification,
}