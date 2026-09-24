"""Enterprise SIEM & Telemetry Forwarder for SOC 2 Type II Auditing.

Implements RFC 5424 compliant syslog formatting and multi-sink event forwarding
(Syslog UDP/TCP, HTTP Webhook, File, In-Memory Ring Buffer) for compliance logging,
security monitoring, and audit trail aggregation (CC7.2, CC7.3).
"""

from __future__ import annotations

import collections
import json
import logging
import os
import socket
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any, Deque, Dict, List, Optional

from sentinel.auth import get_current_user
from sentinel.tenancy import get_current_tenant

logger = logging.getLogger(__name__)


class SyslogSeverity(IntEnum):
    """RFC 5424 Syslog Severity levels."""
    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFORMATIONAL = 6
    DEBUG = 7


class SyslogFacility(IntEnum):
    """RFC 5424 Syslog Facility codes."""
    KERN = 0
    USER = 1
    MAIL = 2
    DAEMON = 3
    AUTH = 4
    SYSLOG = 5
    LPR = 6
    NEWS = 7
    UUCP = 8
    CRON = 9
    AUTHPRIV = 10
    FTP = 11
    LOCAL0 = 16
    LOCAL1 = 17
    LOCAL2 = 18
    LOCAL3 = 19
    LOCAL4 = 20
    LOCAL5 = 21
    LOCAL6 = 22
    LOCAL7 = 23


@dataclass
class AuditEvent:
    """Canonical audit and telemetry event."""
    action: str
    resource: str
    outcome: str = "SUCCESS"  # SUCCESS, FAILURE, DENIED
    severity: SyslogSeverity = SyslogSeverity.INFORMATIONAL
    facility: SyslogFacility = SyslogFacility.AUTHPRIV
    tenant_id: Optional[str] = None
    user_id: Optional[str] = None
    role: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    event_id: str = field(default_factory=lambda: os.urandom(8).hex())

    def __post_init__(self) -> None:
        """Autofill context if not explicitly provided."""
        if self.tenant_id is None:
            t = get_current_tenant()
            self.tenant_id = t.tenant_id if hasattr(t, "tenant_id") else str(t)
        elif hasattr(self.tenant_id, "tenant_id"):
            self.tenant_id = getattr(self.tenant_id, "tenant_id")
        elif not isinstance(self.tenant_id, str):
            self.tenant_id = str(self.tenant_id)

        if self.user_id is None:
            user = get_current_user()
            self.user_id = user.user_id
            self.role = user.role.name if self.role is None else self.role

    def to_rfc5424(self, app_name: str = "soc2-sentinel", hostname: Optional[str] = None) -> str:
        """Format the event as an RFC 5424 Syslog string."""
        pri = (int(self.facility) * 8) + int(self.severity)
        version = "1"
        ts = self.timestamp.isoformat(timespec="milliseconds")
        host = hostname or socket.gethostname() or "-"
        proc_id = str(os.getpid())
        msg_id = self.action.upper().replace(" ", "_")

        # Format structured data [sentinel@54321 k="v" ...]
        sd_params = [
            f'tenant_id="{self.tenant_id or "unknown"}"',
            f'user_id="{self.user_id or "anonymous"}"',
            f'role="{self.role or "unknown"}"',
            f'action="{self.action}"',
            f'resource="{self.resource}"',
            f'outcome="{self.outcome}"',
            f'event_id="{self.event_id}"',
        ]
        structured_data = f"[sentinel@54321 {' '.join(sd_params)}]"

        msg_body = json.dumps(self.details) if self.details else f"Action {self.action} on {self.resource} -> {self.outcome}"
        return f"<{pri}>{version} {ts} {host} {app_name} {proc_id} {msg_id} {structured_data} {msg_body}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to standard dictionary."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "action": self.action,
            "resource": self.resource,
            "outcome": self.outcome,
            "severity": self.severity.name,
            "facility": self.facility.name,
            "tenant_id": self.tenant_id,
            "user_id": self.user_id,
            "role": self.role,
            "details": self.details,
        }


class BaseTelemetrySink:
    """Base interface for all telemetry export sinks."""
    def send(self, event: AuditEvent) -> bool:
        raise NotImplementedError


class MemorySink(BaseTelemetrySink):
    """In-memory circular ring buffer sink for testing, inspection, and dashboard feeds."""
    def __init__(self, max_size: int = 1000) -> None:
        self.events: Deque[AuditEvent] = collections.deque(maxlen=max_size)
        self._lock = threading.Lock()

    def send(self, event: AuditEvent) -> bool:
        with self._lock:
            self.events.append(event)
        return True

    def get_events(self, limit: int = 100, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            evs = list(self.events)
        if tenant_id:
            evs = [e for e in evs if e.tenant_id == tenant_id]
        return [e.to_dict() for e in reversed(evs[-limit:])]

    def clear(self) -> None:
        with self._lock:
            self.events.clear()


class FileSink(BaseTelemetrySink):
    """Appends RFC 5424 or JSON audit logs to a designated local file."""
    def __init__(self, filepath: str, as_json: bool = False) -> None:
        self.filepath = filepath
        self.as_json = as_json
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)

    def send(self, event: AuditEvent) -> bool:
        with self._lock:
            try:
                with open(self.filepath, "a", encoding="utf-8") as f:
                    if self.as_json:
                        f.write(json.dumps(event.to_dict()) + "\n")
                    else:
                        f.write(event.to_rfc5424() + "\n")
                return True
            except Exception as ex:
                logger.error("Failed to write audit event to file %s: %s", self.filepath, ex)
                return False


class HttpSink(BaseTelemetrySink):
    """Sends JSON telemetry events to an external SIEM endpoint (Splunk, Datadog, Webhook)."""
    def __init__(self, endpoint_url: str, auth_token: Optional[str] = None, timeout: float = 5.0) -> None:
        self.endpoint_url = endpoint_url
        self.auth_token = auth_token
        self.timeout = timeout

    def send(self, event: AuditEvent) -> bool:
        headers = {"Content-Type": "application/json"}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        if not self.endpoint_url.startswith(("http://", "https://")):
            logger.warning("HttpSink invalid endpoint scheme: %s", self.endpoint_url)
            return False

        data = json.dumps(event.to_dict()).encode("utf-8")
        req = urllib.request.Request(self.endpoint_url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # nosec B310
                return bool(200 <= resp.status < 300)
        except Exception as ex:
            logger.warning("HttpSink failed to deliver telemetry to %s: %s", self.endpoint_url, ex)
            return False


class SyslogSink(BaseTelemetrySink):
    """Sends RFC 5424 syslog messages over UDP or TCP to a SIEM forwarder."""
    def __init__(self, host: str = "127.0.0.1", port: int = 514, protocol: str = "UDP") -> None:
        self.host = host
        self.port = port
        self.protocol = protocol.upper()

    def send(self, event: AuditEvent) -> bool:
        msg = event.to_rfc5424().encode("utf-8")
        try:
            if self.protocol == "UDP":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(msg, (self.host, self.port))
                sock.close()
                return True
            elif self.protocol == "TCP":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3.0)
                sock.connect((self.host, self.port))
                sock.sendall(msg + b"\n")
                sock.close()
                return True
        except Exception as ex:
            logger.debug("SyslogSink delivery error (%s:%d): %s", self.host, self.port, ex)
            return False
        return False


class TelemetryManager:
    """Global manager for telemetry dispatch across configured sinks."""
    def __init__(self) -> None:
        self.sinks: List[BaseTelemetrySink] = []
        self._memory_sink = MemorySink(max_size=1000)
        self.add_sink(self._memory_sink)

    def add_sink(self, sink: BaseTelemetrySink) -> None:
        self.sinks.append(sink)

    def clear_sinks(self) -> None:
        self.sinks.clear()
        self.add_sink(self._memory_sink)

    def emit(
        self,
        action: str,
        resource: str,
        outcome: str = "SUCCESS",
        severity: SyslogSeverity = SyslogSeverity.INFORMATIONAL,
        facility: SyslogFacility = SyslogFacility.AUTHPRIV,
        details: Optional[Dict[str, Any]] = None,
        tenant_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> AuditEvent:
        """Create and publish an audit event to all registered sinks."""
        event = AuditEvent(
            action=action,
            resource=resource,
            outcome=outcome,
            severity=severity,
            facility=facility,
            details=details or {},
            tenant_id=tenant_id,
            user_id=user_id,
        )
        for sink in self.sinks:
            try:
                sink.send(event)
            except Exception as ex:
                logger.error("Telemetry sink %s failed: %s", type(sink).__name__, ex)
        return event

    def get_recent_events(self, limit: int = 100, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve recent audit events from memory sink."""
        return self._memory_sink.get_events(limit=limit, tenant_id=tenant_id)


# Global singleton instance
TELEMETRY = TelemetryManager()
