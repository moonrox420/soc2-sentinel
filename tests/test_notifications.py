"""Unit tests for Compliance Alerting and Webhooks."""

from sentinel.notifications import (
    AlertSeverity,
    ComplianceAlert,
    NotificationManager,
)


def test_compliance_alert_formatters() -> None:
    alert = ComplianceAlert(
        title="Unencrypted S3 Bucket Detected",
        message="Bucket 'prod-logs-storage' does not enforce AES-256 KMS encryption.",
        severity=AlertSeverity.CRITICAL,
        control_id="C1.2",
        details={"bucket": "prod-logs-storage"},
    )

    # Slack BlockKit format
    slack = alert.format_slack()
    assert "attachments" in slack
    assert slack["attachments"][0]["color"] == "#ef4444"

    # Teams MessageCard format
    teams = alert.format_teams()
    assert teams["@type"] == "MessageCard"
    assert "C1.2" in str(teams["sections"])

    # PagerDuty Events v2 format
    pd = alert.format_pagerduty(routing_key="test-key")
    assert pd["routing_key"] == "test-key"
    assert pd["payload"]["severity"] == "critical"

    # Generic format
    gen = alert.format_generic()
    assert gen["alert"] == "Unencrypted S3 Bucket Detected"
    assert gen["severity"] == "CRITICAL"


def test_notification_manager_url_validation_and_send() -> None:
    alert = ComplianceAlert(
        title="Test Alert",
        message="System health check",
    )

    # Rejects invalid URL scheme safely
    assert NotificationManager.send_webhook("ftp://invalid.com/hook", alert) is False
    assert NotificationManager.send_webhook("file:///etc/passwd", alert) is False

    # Handling connection error safely without raising uncaught exceptions
    assert NotificationManager.send_webhook("http://127.0.0.1:65510/webhook", alert, timeout=0.5) is False
