from __future__ import annotations

import logging
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinel.audit import append_audit_event
from sentinel.cli import RUN_ALL_MAPPING
from sentinel.collectors import COLLECTORS
from sentinel.config import SentinelConfig
from sentinel.drift import detect_configuration_drift
from sentinel.providers import get_provider
from sentinel.telemetry import TELEMETRY

logger = logging.getLogger("sentinel.daemon")


@dataclass
class DaemonStatus:
    running: bool
    interval_seconds: int
    provider: str
    last_run_timestamp: str | None
    next_run_timestamp: str | None
    total_runs_completed: int
    last_run_errors: list[str]
    last_drift_count: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ContinuousMonitoringDaemon:
    def __init__(
        self,
        *,
        provider_name: str = "aws",
        interval_seconds: int = 3600,
        output_base: Path | None = None,
        config: SentinelConfig | None = None,
    ) -> None:
        self.provider_name = provider_name
        self.interval_seconds = max(10, interval_seconds)
        self.output_base = output_base or Path.cwd()
        self.config = config
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

        self._running = False
        self._last_run_timestamp: str | None = None
        self._next_run_timestamp: str | None = None
        self._total_runs = 0
        self._last_errors: list[str] = []
        self._last_drift_count = 0

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._running

    def get_status(self) -> DaemonStatus:
        with self._lock:
            return DaemonStatus(
                running=self._running,
                interval_seconds=self.interval_seconds,
                provider=self.provider_name,
                last_run_timestamp=self._last_run_timestamp,
                next_run_timestamp=self._next_run_timestamp,
                total_runs_completed=self._total_runs,
                last_run_errors=list(self._last_errors),
                last_drift_count=self._last_drift_count,
            )

    def start(self) -> None:
        with self._lock:
            if self._running:
                logger.warning("Daemon is already running")
                return
            self._stop_event.clear()
            self._running = True
            self._thread = threading.Thread(
                target=self._run_loop, daemon=True, name="sentinel-daemon"
            )
            self._thread.start()
            logger.info(
                "Continuous monitoring daemon started (interval=%ds, provider=%s)",
                self.interval_seconds,
                self.provider_name,
            )

    def stop(self, timeout: float = 5.0) -> None:
        with self._lock:
            if not self._running:
                return
            self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        with self._lock:
            self._running = False
            logger.info("Continuous monitoring daemon stopped")

    def run_once_now(self) -> dict[str, Any]:
        """Trigger an immediate run synchronously."""
        return self._execute_cycle()

    def _execute_cycle(self) -> dict[str, Any]:
        now_iso = datetime.now(timezone.utc).isoformat()
        logger.info(
            "Daemon executing scheduled compliance collection cycle for provider '%s'",
            self.provider_name,
        )
        errors: list[str] = []

        try:
            prov = get_provider(self.provider_name, self.config)
        except (Exception, SystemExit) as exc:
            err = f"Failed initializing provider {self.provider_name}: {exc}"
            logger.error(err)
            with self._lock:
                self._last_errors = [err]
                self._last_run_timestamp = now_iso
            return {"status": "error", "error": err}

        for collector_name, control_id in RUN_ALL_MAPPING.items():
            func = COLLECTORS.get(collector_name)
            if not func:
                continue
            try:
                func(
                    provider=prov,
                    base=self.output_base,
                    control_id=control_id,
                    config=self.config,
                )
            except Exception as exc:
                msg = f"Collector {collector_name} failed: {exc}"
                logger.warning(msg)
                errors.append(msg)

        drift_count = 0
        try:
            drift_report = detect_configuration_drift(
                self.output_base / "evidence", record_audit=True
            )
            drift_count = drift_report.total_drift_items
        except Exception as exc:
            logger.warning("Drift detection error: %s", exc)

        with self._lock:
            self._last_run_timestamp = now_iso
            self._total_runs += 1
            self._last_errors = errors
            self._last_drift_count = drift_count

        try:
            append_audit_event(
                base=self.output_base,
                command="daemon_cycle",
                provider=self.provider_name,
                outcome="success" if not errors else "partial",
                details={
                    "errors_count": len(errors),
                    "drift_count": drift_count,
                    "run_number": self._total_runs,
                },
            )
            TELEMETRY.emit(
                action="DAEMON_CYCLE_COMPLETED",
                resource=f"provider/{self.provider_name}",
                outcome="SUCCESS" if not errors else "PARTIAL",
                details={
                    "errors_count": len(errors),
                    "drift_count": drift_count,
                    "run_number": self._total_runs,
                },
            )
        except Exception as exc:
            logger.debug("Failed writing daemon audit event: %s", exc)

        return {
            "status": "completed",
            "timestamp": now_iso,
            "errors": errors,
            "drift_count": drift_count,
        }

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            next_run_ts = datetime.fromtimestamp(
                time.time() + self.interval_seconds, timezone.utc
            ).isoformat()
            with self._lock:
                self._next_run_timestamp = next_run_ts

            try:
                self._execute_cycle()
            except Exception as exc:
                logger.error("Daemon cycle unhandled exception: %s", exc, exc_info=True)

            if self._stop_event.wait(timeout=self.interval_seconds):
                break
