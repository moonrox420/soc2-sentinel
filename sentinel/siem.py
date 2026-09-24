"""SOC2 Sentinel — Enterprise SIEM Exporter & Log Forwarding Engine.

Streams and exports RFC 5424 compliant audit records, configuration drift alerts,
and compliance scorecard telemetry to Splunk HEC, Datadog Logs, Syslog, and webhooks.
"""

from __future__ import annotations

import hmac
import json
import logging
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
from pathlib import Path
from typing import Any

logger = logging.getLogger("sentinel.siem")


class SIEMTargetType(str, Enum):
    SPLUNK_HEC = "SPLUNK_HEC"
    DATADOG = "DATADOG"
    SYSLOG_RFC5424 = "SYSLOG_RFC5424"
    GENERIC_WEBHOOK = "GENERIC_WEBHOOK"
    NDJSON_FILE = "NDJSON_FILE"


@dataclass
class SIEMEvent:
    event_id: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    event_type: str = (
        "COMPLIANCE_AUDIT"  # "COMPLIANCE_AUDIT" | "DRIFT_ALERT" | "VAULT_SEAL" | "ACCESS_REVIEW"
    )
    severity: str = "INFO"  # "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    source: str = "soc2-sentinel"
    host: str = field(default_factory=lambda: socket.gethostname())
    data: dict[str, Any] = field(default_factory=dict)

    def to_rfc5424(self) -> str:
        """Format as RFC 5424 Syslog standard."""
        # PRI = facility (16 = local0) * 8 + severity (6 = info, 4 = warning, 3 = error)
        sev_map = {"INFO": 6, "LOW": 5, "MEDIUM": 4, "HIGH": 3, "CRITICAL": 2}
        pri = 16 * 8 + sev_map.get(self.severity, 6)
        msg = json.dumps(self.data)
        return f"<{pri}>1 {self.timestamp} {self.host} {self.source} - {self.event_id} {msg}"

    def to_ecs(self) -> dict[str, Any]:
        """Format as Elastic Common Schema (ECS) / Splunk compatible dictionary."""
        return {
            "@timestamp": self.timestamp,
            "event": {
                "id": self.event_id,
                "kind": "alert" if self.severity in ("HIGH", "CRITICAL") else "event",
                "category": ["compliance", "security"],
                "type": [self.event_type.lower()],
                "severity": self.severity,
            },
            "host": {"name": self.host},
            "service": {"name": self.source},
            "sentinel": self.data,
        }


class SIEMExporter:
    """Dispatches compliance audit events to enterprise SIEM and telemetry platforms."""

    def __init__(self, base_dir: Path | str = "data") -> None:
        self.base_dir = Path(base_dir)
        self.audit_log_path = self.base_dir / "sentinel_audit.jsonl"

    def read_unforwarded_events(self, limit: int = 500) -> list[SIEMEvent]:
        """Read audit events from local audit log."""
        events: list[SIEMEvent] = []
        if not self.audit_log_path.exists():
            return events

        try:
            with open(self.audit_log_path, "r", encoding="utf-8") as f:
                for idx, line in enumerate(f):
                    if idx >= limit:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        event = SIEMEvent(
                            event_id=f"audit-{record.get('timestamp', idx)}",
                            timestamp=record.get(
                                "timestamp",
                                datetime.now(timezone.utc).isoformat(),
                            ),
                            event_type=record.get("event", "AUDIT_RECORD"),
                            severity=record.get("severity", "INFO"),
                            data=record,
                        )
                        events.append(event)
                    except Exception as parse_err:
                        logger.debug("Skipping unparseable audit line: %s", parse_err)
        except Exception as e:
            logger.error("Failed reading audit log for SIEM: %s", e)

        return events

    def export_to_ndjson_file(self, output_path: Path | str, limit: int = 1000) -> int:
        """Export events to local NDJSON file for file-based log forwarders."""
        events = self.read_unforwarded_events(limit=limit)
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            for ev in events:
                f.write(json.dumps(ev.to_ecs()) + "\n")
        logger.info("Exported %d SIEM events to %s", len(events), out)
        return len(events)

    def forward_to_splunk_hec(
        self,
        endpoint_url: str,
        hec_token: str,
        events: list[SIEMEvent] | None = None,
        timeout_seconds: int = 10,
    ) -> tuple[bool, int, str]:
        """Send events to Splunk HTTP Event Collector (HEC)."""
        if not endpoint_url.startswith(("http://", "https://")):
            return False, 0, "Invalid endpoint URL scheme"

        if events is None:
            events = self.read_unforwarded_events(limit=100)

        if not events:
            return True, 0, "No events to forward"

        # Splunk HEC expects NDJSON of { "event": {...}, "sourcetype": "_json" }
        payload_lines = []
        for ev in events:
            hec_item = {
                "time": datetime.fromisoformat(
                    ev.timestamp.replace("Z", "+00:00")
                ).timestamp(),
                "host": ev.host,
                "source": ev.source,
                "sourcetype": "soc2_sentinel:audit",
                "event": ev.data,
            }
            payload_lines.append(json.dumps(hec_item))

        body = "\n".join(payload_lines).encode("utf-8")
        headers = {
            "Authorization": f"Splunk {hec_token}",
            "Content-Type": "application/json",
            "User-Agent": "SOC2-Sentinel-SIEM/2.5.0",
        }

        req = urllib.request.Request(
            endpoint_url, data=body, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(
                req, timeout=timeout_seconds
            ) as resp:  # nosec B310
                resp_code = resp.getcode()
                if 200 <= resp_code < 300:
                    return (
                        True,
                        len(events),
                        f"Successfully posted {len(events)} events to Splunk",
                    )
                return False, 0, f"Splunk returned status code {resp_code}"
        except urllib.error.HTTPError as e:
            return False, 0, f"Splunk HTTP error {e.code}: {e.reason}"
        except Exception as e:
            return False, 0, f"Splunk connection failed: {e}"

    def forward_to_datadog(
        self,
        api_key: str,
        site: str = "datadoghq.com",
        events: list[SIEMEvent] | None = None,
        timeout_seconds: int = 10,
    ) -> tuple[bool, int, str]:
        """Send events to Datadog Logs API."""
        endpoint_url = f"https://http-intake.logs.{site}/api/v2/logs"

        if events is None:
            events = self.read_unforwarded_events(limit=100)

        if not events:
            return True, 0, "No events to forward"

        dd_payload = []
        for ev in events:
            dd_payload.append(
                {
                    "ddsource": "soc2-sentinel",
                    "ddtags": f"env:production,severity:{ev.severity.lower()}",
                    "hostname": ev.host,
                    "service": "sentinel-compliance",
                    "message": json.dumps(ev.data),
                }
            )

        body = json.dumps(dd_payload).encode("utf-8")
        headers = {
            "DD-API-KEY": api_key,
            "Content-Type": "application/json",
            "User-Agent": "SOC2-Sentinel-SIEM/2.5.0",
        }

        req = urllib.request.Request(
            endpoint_url, data=body, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(
                req, timeout=timeout_seconds
            ) as resp:  # nosec B310
                resp_code = resp.getcode()
                if 200 <= resp_code < 300:
                    return (
                        True,
                        len(events),
                        f"Successfully posted {len(events)} events to Datadog",
                    )
                return False, 0, f"Datadog returned status code {resp_code}"
        except urllib.error.HTTPError as e:
            return False, 0, f"Datadog HTTP error {e.code}: {e.reason}"
        except Exception as e:
            return False, 0, f"Datadog connection failed: {e}"

    def forward_to_webhook(
        self,
        webhook_url: str,
        secret_key: str = "",
        events: list[SIEMEvent] | None = None,
        timeout_seconds: int = 10,
    ) -> tuple[bool, int, str]:
        """Send events to a generic webhook endpoint with HMAC signature."""
        if not webhook_url.startswith(("http://", "https://")):
            return False, 0, "Invalid webhook URL scheme"

        if events is None:
            events = self.read_unforwarded_events(limit=50)

        if not events:
            return True, 0, "No events to forward"

        payload = {
            "sentinel_version": "2.5.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_count": len(events),
            "events": [ev.to_ecs() for ev in events],
        }
        body = json.dumps(payload, indent=2).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "SOC2-Sentinel-SIEM/2.5.0",
        }
        if secret_key:
            sig = hmac.new(secret_key.encode("utf-8"), body, sha256).hexdigest()
            headers["X-Sentinel-Signature"] = f"sha256={sig}"

        req = urllib.request.Request(
            webhook_url, data=body, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(
                req, timeout=timeout_seconds
            ) as resp:  # nosec B310
                resp_code = resp.getcode()
                if 200 <= resp_code < 300:
                    return (
                        True,
                        len(events),
                        f"Delivered {len(events)} events to webhook",
                    )
                return False, 0, f"Webhook returned status code {resp_code}"
        except urllib.error.HTTPError as e:
            return False, 0, f"Webhook HTTP error {e.code}: {e.reason}"
        except Exception as e:
            return False, 0, f"Webhook delivery failed: {e}"
