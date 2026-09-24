"""Enterprise SIEM & Telemetry Forwarder for SOC 2 Type II Auditing.

Implements RFC 5424 compliant syslog formatting and multi-sink event forwarding
(Syslog UDP/TCP, HTTP Webhook, File, In-Memory Ring Buffer) for compliance logging,
security monitoring, and audit trail aggregation (CC7.2, CC7.3).
"""

from __future__ import annotations

import atexit
import collections
import hashlib
import hmac
import json
import logging
import os
import queue
import random
import socket
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path
from typing import Any, Callable, Deque, Dict, List, Optional, Set

from sentinel.auth import get_current_user
from sentinel.tenancy import get_current_tenant

logger = logging.getLogger("sentinel.telemetry")


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

    def signature_digest(self, secret: str = "") -> str:
        """Compute cryptographic integrity digest (SHA-256 HMAC or hash) for non-repudiation."""
        canonical = json.dumps(
            {
                "event_id": self.event_id,
                "timestamp": self.timestamp.isoformat(),
                "action": self.action,
                "resource": self.resource,
                "outcome": self.outcome,
                "tenant_id": self.tenant_id,
                "user_id": self.user_id,
                "details": self.details,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if secret:
            return hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
        return hashlib.sha256(canonical).hexdigest()

    def to_rfc5424(
        self, app_name: str = "soc2-sentinel", hostname: Optional[str] = None
    ) -> str:
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

        msg_body = (
            json.dumps(self.details)
            if self.details
            else f"Action {self.action} on {self.resource} -> {self.outcome}"
        )
        return f"<{pri}>{version} {ts} {host} {app_name} {proc_id} {msg_id} {structured_data} {msg_body}"

    def to_ecs(self) -> Dict[str, Any]:
        """Convert event to Elastic Common Schema (ECS) format."""
        return {
            "@timestamp": self.timestamp.isoformat(),
            "event": {
                "id": self.event_id,
                "action": self.action,
                "outcome": self.outcome.lower(),
                "severity": int(self.severity),
                "category": ["compliance", "audit"],
                "kind": "event",
            },
            "user": {
                "id": self.user_id,
                "roles": [self.role] if self.role else [],
            },
            "organization": {
                "id": self.tenant_id,
            },
            "service": {
                "name": "soc2-sentinel",
            },
            "sentinel": {
                "resource": self.resource,
                "facility": self.facility.name,
                "details": self.details,
            },
        }

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
        """Send a single audit event."""
        raise NotImplementedError

    def send_batch(self, events: List[AuditEvent]) -> int:
        """Send a batch of audit events. Returns count of successfully sent events."""
        success = 0
        for ev in events:
            if self.send(ev):
                success += 1
        return success

    def flush(self) -> None:
        """Flush any pending buffered events."""
        pass

    def close(self) -> None:
        """Release underlying socket or file resources."""
        pass


class MemorySink(BaseTelemetrySink):
    """In-memory circular ring buffer sink for testing, inspection, and dashboard feeds."""

    def __init__(self, max_size: int = 1000) -> None:
        self.events: Deque[AuditEvent] = collections.deque(maxlen=max_size)
        self._lock = threading.Lock()

    def send(self, event: AuditEvent) -> bool:
        with self._lock:
            self.events.append(event)
        return True

    def get_events(
        self, limit: int = 100, tenant_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        with self._lock:
            evs = list(self.events)
        if tenant_id:
            evs = [e for e in evs if e.tenant_id == tenant_id]
        return [e.to_dict() for e in reversed(evs[-limit:])]

    def clear(self) -> None:
        with self._lock:
            self.events.clear()


class FileSink(BaseTelemetrySink):
    """Appends RFC 5424 or JSON audit logs to a designated local file with size-based rotation."""

    def __init__(
        self,
        filepath: str | Path,
        as_json: bool = True,
        max_bytes: int = 50 * 1024 * 1024,  # 50 MB
        backup_count: int = 5,
    ) -> None:
        self.filepath = Path(filepath)
        self.as_json = as_json
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self._lock = threading.Lock()
        self.filepath.parent.mkdir(parents=True, exist_ok=True)

    def _rotate_if_needed(self) -> None:
        if not self.filepath.exists():
            return
        if self.filepath.stat().st_size < self.max_bytes:
            return

        for i in range(self.backup_count - 1, 0, -1):
            sfn = self.filepath.with_suffix(f"{self.filepath.suffix}.{i}")
            dfn = self.filepath.with_suffix(f"{self.filepath.suffix}.{i + 1}")
            if sfn.exists():
                if dfn.exists():
                    dfn.unlink()
                sfn.rename(dfn)

        dfn = self.filepath.with_suffix(f"{self.filepath.suffix}.1")
        if dfn.exists():
            dfn.unlink()
        self.filepath.rename(dfn)

    def send(self, event: AuditEvent) -> bool:
        with self._lock:
            try:
                self._rotate_if_needed()
                with open(self.filepath, "a", encoding="utf-8") as f:
                    if self.as_json:
                        f.write(json.dumps(event.to_dict()) + "\n")
                    else:
                        f.write(event.to_rfc5424() + "\n")
                return True
            except Exception as ex:
                logger.error(
                    "Failed to write audit event to file %s: %s", self.filepath, ex
                )
                return False

    def send_batch(self, events: List[AuditEvent]) -> int:
        if not events:
            return 0
        with self._lock:
            try:
                self._rotate_if_needed()
                with open(self.filepath, "a", encoding="utf-8") as f:
                    for event in events:
                        if self.as_json:
                            f.write(json.dumps(event.to_dict()) + "\n")
                        else:
                            f.write(event.to_rfc5424() + "\n")
                return len(events)
            except Exception as ex:
                logger.error(
                    "Failed to batch write audit events to %s: %s", self.filepath, ex
                )
                return 0


class HttpSink(BaseTelemetrySink):
    """Sends JSON telemetry events to an external SIEM endpoint (Splunk, Datadog, Webhook) with retries."""

    def __init__(
        self,
        endpoint_url: str,
        auth_token: Optional[str] = None,
        timeout: float = 5.0,
        max_retries: int = 3,
        signing_secret: Optional[str] = None,
    ) -> None:
        self.endpoint_url = endpoint_url
        self.auth_token = auth_token
        self.timeout = timeout
        self.max_retries = max_retries
        self.signing_secret = signing_secret

    def _post(self, payload: bytes, is_batch: bool = False) -> bool:
        if not self.endpoint_url.startswith(("http://", "https://")):
            logger.warning("HttpSink invalid endpoint scheme: %s", self.endpoint_url)
            return False

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "soc2-sentinel-telemetry/2.5.0",
        }
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        if self.signing_secret:
            sig = hmac.new(
                self.signing_secret.encode("utf-8"), payload, hashlib.sha256
            ).hexdigest()
            headers["X-Sentinel-Signature"] = f"sha256={sig}"

        for attempt in range(1, self.max_retries + 1):
            req = urllib.request.Request(
                self.endpoint_url, data=payload, headers=headers, method="POST"
            )
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # nosec B310
                    if 200 <= resp.status < 300:
                        return True
            except Exception as ex:
                if attempt == self.max_retries:
                    logger.warning(
                        "HttpSink failed delivery to %s after %d attempts: %s",
                        self.endpoint_url,
                        attempt,
                        ex,
                    )
                else:
                    sleep_time = (0.2 * (2**attempt)) + random.uniform(0.01, 0.1)
                    time.sleep(sleep_time)

        return False

    def send(self, event: AuditEvent) -> bool:
        data = json.dumps(event.to_dict()).encode("utf-8")
        return self._post(data, is_batch=False)

    def send_batch(self, events: List[AuditEvent]) -> int:
        if not events:
            return 0
        data = json.dumps([e.to_dict() for e in events]).encode("utf-8")
        if self._post(data, is_batch=True):
            return len(events)
        return 0


class SyslogSink(BaseTelemetrySink):
    """Sends RFC 5424 syslog messages over UDP or persistent TCP connection to a SIEM collector."""

    def __init__(
        self, host: str = "127.0.0.1", port: int = 514, protocol: str = "UDP"
    ) -> None:
        self.host = host
        self.port = port
        self.protocol = protocol.upper()
        self._lock = threading.Lock()
        self._tcp_sock: Optional[socket.socket] = None
        self._udp_sock: Optional[socket.socket] = None

    def _get_udp_sock(self) -> socket.socket:
        if self._udp_sock is None:
            self._udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return self._udp_sock

    def _get_tcp_sock(self) -> socket.socket:
        if self._tcp_sock is not None:
            return self._tcp_sock
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        sock.connect((self.host, self.port))
        self._tcp_sock = sock
        return self._tcp_sock

    def _reset_tcp(self) -> None:
        if self._tcp_sock:
            try:
                self._tcp_sock.close()
            except Exception:
                pass
            self._tcp_sock = None

    def send(self, event: AuditEvent) -> bool:
        msg = event.to_rfc5424().encode("utf-8")
        with self._lock:
            try:
                if self.protocol == "UDP":
                    sock = self._get_udp_sock()
                    sock.sendto(msg, (self.host, self.port))
                    return True
                elif self.protocol == "TCP":
                    try:
                        sock = self._get_tcp_sock()
                        sock.sendall(msg + b"\n")
                        return True
                    except (socket.error, OSError):
                        self._reset_tcp()
                        sock = self._get_tcp_sock()
                        sock.sendall(msg + b"\n")
                        return True
            except Exception as ex:
                logger.debug(
                    "SyslogSink delivery error (%s:%d): %s", self.host, self.port, ex
                )
                return False
        return False

    def close(self) -> None:
        with self._lock:
            self._reset_tcp()
            if self._udp_sock:
                try:
                    self._udp_sock.close()
                except Exception:
                    pass
                self._udp_sock = None


class TelemetryManager:
    """Enterprise asynchronous telemetry dispatcher and live pub/sub streaming engine."""

    def __init__(self, enable_worker: bool = True) -> None:
        self.sinks: List[BaseTelemetrySink] = []
        self._memory_sink = MemorySink(max_size=1000)
        self._subscribers: Set[Callable[[AuditEvent], None]] = set()
        self._sub_lock = threading.Lock()
        self._sink_lock = threading.Lock()

        # Add memory ring buffer by default
        self.add_sink(self._memory_sink)

        # Persistent Write-Ahead Log Sink
        wal_path = os.getenv("SENTINEL_AUDIT_LOG_PATH", "data/sentinel_telemetry.jsonl")
        self._file_sink = FileSink(filepath=wal_path, as_json=True)
        self.add_sink(self._file_sink)

        # Optional auto-configured sinks from environment
        syslog_host = os.getenv("SENTINEL_SYSLOG_HOST")
        if syslog_host:
            syslog_port = int(os.getenv("SENTINEL_SYSLOG_PORT", "514"))
            syslog_proto = os.getenv("SENTINEL_SYSLOG_PROTOCOL", "UDP")
            self.add_sink(
                SyslogSink(host=syslog_host, port=syslog_port, protocol=syslog_proto)
            )

        http_url = os.getenv("SENTINEL_SIEM_HTTP_URL")
        if http_url:
            http_token = os.getenv("SENTINEL_SIEM_HTTP_TOKEN")
            self.add_sink(HttpSink(endpoint_url=http_url, auth_token=http_token))

        # Asynchronous dispatch queue and background worker
        self._queue: queue.Queue[Optional[AuditEvent]] = queue.Queue(maxsize=10000)
        self._running = False
        self._worker_thread: Optional[threading.Thread] = None

        if enable_worker:
            self._start_worker()

        atexit.register(self.shutdown)

    def _start_worker(self) -> None:
        if self._running:
            return
        self._running = True
        self._worker_thread = threading.Thread(
            target=self._worker_loop, name="sentinel-telemetry-worker", daemon=True
        )
        self._worker_thread.start()

    def _worker_loop(self) -> None:
        while self._running:
            try:
                first = self._queue.get(timeout=0.2)
                if first is None:
                    self._queue.task_done()
                    break

                batch = [first]
                while len(batch) < 50:
                    try:
                        item = self._queue.get_nowait()
                        if item is None:
                            self._queue.task_done()
                            break
                        batch.append(item)
                    except queue.Empty:
                        break

                with self._sink_lock:
                    sinks = list(self.sinks)

                for sink in sinks:
                    try:
                        sink.send_batch(batch)
                    except Exception as ex:
                        logger.error(
                            "Async telemetry dispatch to %s failed: %s",
                            type(sink).__name__,
                            ex,
                        )

                for _ in batch:
                    self._queue.task_done()

            except queue.Empty:
                continue
            except Exception as ex:
                logger.error("Telemetry worker loop encountered an error: %s", ex)

    def add_sink(self, sink: BaseTelemetrySink) -> None:
        with self._sink_lock:
            if sink not in self.sinks:
                self.sinks.append(sink)

    def remove_sink(self, sink: BaseTelemetrySink) -> None:
        with self._sink_lock:
            if sink in self.sinks:
                self.sinks.remove(sink)

    def clear_sinks(self) -> None:
        with self._sink_lock:
            self.sinks.clear()
            self.sinks.append(self._memory_sink)

    def subscribe(self, callback: Callable[[AuditEvent], None]) -> Callable[[], None]:
        """Register a real-time listener callback for streaming events."""
        with self._sub_lock:
            self._subscribers.add(callback)

        def unsubscribe() -> None:
            with self._sub_lock:
                self._subscribers.discard(callback)

        return unsubscribe

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
        """Create and asynchronously publish an audit event to all registered sinks and subscribers."""
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

        # Immediate broadcast to real-time subscribers (SSE, Live CLI stream)
        with self._sub_lock:
            subs = list(self._subscribers)
        for sub in subs:
            try:
                sub(event)
            except Exception as ex:
                logger.debug("Real-time telemetry subscriber error: %s", ex)

        # Enqueue for asynchronous persistence and SIEM dispatch
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            # Fallback synchronous write to prevent audit trail loss on high load
            logger.warning("Telemetry queue full, performing synchronous fallback dispatch")
            with self._sink_lock:
                for sink in self.sinks:
                    try:
                        sink.send(event)
                    except Exception as ex:
                        logger.error("Fallback telemetry sink failed: %s", ex)

        return event

    def emit_sync(
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
        """Create and synchronously publish an audit event to all sinks."""
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

        with self._sub_lock:
            subs = list(self._subscribers)
        for sub in subs:
            try:
                sub(event)
            except Exception as ex:
                logger.debug("Real-time subscriber error: %s", ex)

        with self._sink_lock:
            for sink in self.sinks:
                try:
                    sink.send(event)
                except Exception as ex:
                    logger.error("Telemetry sink %s failed: %s", type(sink).__name__, ex)

        return event

    def flush(self, timeout: float = 5.0) -> None:
        """Wait for pending queued telemetry events to be drained and flushed."""
        try:
            self._queue.join()
        except Exception:
            pass
        with self._sink_lock:
            for sink in self.sinks:
                try:
                    sink.flush()
                except Exception:
                    pass

    def get_recent_events(
        self, limit: int = 100, tenant_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve recent audit events from memory sink."""
        return self._memory_sink.get_events(limit=limit, tenant_id=tenant_id)

    def shutdown(self) -> None:
        """Gracefully drain and close the telemetry engine."""
        if not self._running:
            return
        self._running = False
        try:
            self._queue.put_nowait(None)
        except Exception:
            pass
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
        with self._sink_lock:
            for sink in self.sinks:
                try:
                    sink.close()
                except Exception:
                    pass


# Global singleton instance
TELEMETRY = TelemetryManager()
