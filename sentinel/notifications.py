"""Compliance Alerting & Ticketing Integrations (Slack, Teams, PagerDuty, Jira).

Dispatches real-time notifications for policy failures, configuration drift,
unmitigated security vulnerabilities, and access certification campaign deadlines.
"""

from __future__ import annotations

import enum
import json
import logging
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sentinel.tenancy import get_current_tenant_id

logger = logging.getLogger("sentinel.notifications")


class NotificationChannel(str, enum.Enum):
    """Supported alerting and workflow destinations."""

    SLACK = "slack"
    TEAMS = "teams"
    PAGERDUTY = "pagerduty"
    GENERIC_WEBHOOK = "webhook"
    JIRA = "jira"
    LINEAR = "linear"


class AlertSeverity(str, enum.Enum):
    """Alert priority level."""

    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


@dataclass
class ComplianceAlert:
    """Standardized compliance violation and monitoring notification."""

    title: str
    message: str
    severity: AlertSeverity = AlertSeverity.WARNING
    control_id: Optional[str] = None
    tenant_id: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def __post_init__(self) -> None:
        if self.tenant_id is None:
            self.tenant_id = get_current_tenant_id()

    def format_slack(self) -> Dict[str, Any]:
        """Generate Slack BlockKit JSON message."""
        color = (
            "#ef4444"
            if self.severity == AlertSeverity.CRITICAL
            else "#f59e0b" if self.severity == AlertSeverity.WARNING else "#3b82f6"
        )
        ctrl_text = f" | Control: *{self.control_id}*" if self.control_id else ""
        return {
            "attachments": [
                {
                    "color": color,
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": f"[{self.severity.value}] {self.title}",
                                "emoji": True,
                            },
                        },
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"*Tenant:* `{self.tenant_id}`{ctrl_text}\n{self.message}",
                            },
                        },
                    ],
                }
            ]
        }

    def format_teams(self) -> Dict[str, Any]:
        """Generate Microsoft Teams MessageCard JSON."""
        color = (
            "EF4444"
            if self.severity == AlertSeverity.CRITICAL
            else "F59E0B" if self.severity == AlertSeverity.WARNING else "3B82F6"
        )
        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color,
            "summary": self.title,
            "title": f"[{self.severity.value}] {self.title}",
            "sections": [
                {
                    "facts": [
                        {"name": "Tenant", "value": self.tenant_id or "default"},
                        {"name": "Control", "value": self.control_id or "N/A"},
                        {"name": "Timestamp", "value": self.timestamp},
                    ],
                    "text": self.message,
                }
            ],
        }

    def format_pagerduty(self, routing_key: str = "sentinel") -> Dict[str, Any]:
        """Generate PagerDuty Events API v2 payload."""
        return {
            "routing_key": routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": f"[{self.tenant_id}] {self.title}: {self.message}",
                "severity": (
                    "critical" if self.severity == AlertSeverity.CRITICAL else "warning"
                ),
                "source": "soc2-sentinel",
                "component": self.control_id or "compliance",
                "custom_details": self.details,
            },
        }

    def format_generic(self) -> Dict[str, Any]:
        """Standard JSON payload for generic webhooks, Jira, or Linear."""
        return {
            "alert": self.title,
            "description": self.message,
            "severity": self.severity.value,
            "control_id": self.control_id,
            "tenant_id": self.tenant_id,
            "timestamp": self.timestamp,
            "details": self.details,
        }

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class NotificationManager:
    """Dispatches compliance alerts to webhooks with network resilience."""

    @classmethod
    def send_webhook(
        cls,
        webhook_url: str,
        alert: ComplianceAlert,
        channel: NotificationChannel = NotificationChannel.GENERIC_WEBHOOK,
        auth_token: Optional[str] = None,
        timeout: float = 5.0,
    ) -> bool:
        """Send formatted alert payload to target webhook URL."""
        if not webhook_url.startswith(("http://", "https://")):
            logger.warning("Invalid webhook URL scheme: %s", webhook_url)
            return False

        if channel == NotificationChannel.SLACK:
            payload = alert.format_slack()
        elif channel == NotificationChannel.TEAMS:
            payload = alert.format_teams()
        elif channel == NotificationChannel.PAGERDUTY:
            payload = alert.format_pagerduty()
        else:
            payload = alert.format_generic()

        raw_bytes = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "SOC2-Sentinel-Notifier/2.5",
        }
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        req = urllib.request.Request(
            webhook_url, data=raw_bytes, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
                return bool(200 <= resp.status < 300)
        except Exception as ex:
            logger.warning("Webhook dispatch to %s failed: %s", webhook_url, ex)
            return False
