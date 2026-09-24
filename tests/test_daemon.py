from __future__ import annotations

from pathlib import Path

from sentinel.daemon import ContinuousMonitoringDaemon, DaemonStatus


def test_daemon_lifecycle(tmp_path: Path):
    daemon = ContinuousMonitoringDaemon(
        provider_name="mock",
        interval_seconds=10,
        output_base=tmp_path,
    )
    assert not daemon.is_running
    status = daemon.get_status()
    assert isinstance(status, DaemonStatus)
    assert not status.running

    daemon.start()
    assert daemon.is_running
    # Second start is no-op
    daemon.start()

    daemon.stop(timeout=2.0)
    assert not daemon.is_running


def test_daemon_run_once_now(tmp_path: Path):
    daemon = ContinuousMonitoringDaemon(
        provider_name="mock",
        interval_seconds=10,
        output_base=tmp_path,
    )
    res = daemon.run_once_now()
    assert res["status"] == "completed"
    assert "timestamp" in res
    assert daemon.get_status().total_runs_completed == 1


def test_daemon_error_handling(tmp_path: Path):
    daemon = ContinuousMonitoringDaemon(
        provider_name="invalid-provider",
        interval_seconds=10,
        output_base=tmp_path,
    )
    res = daemon.run_once_now()
    assert res["status"] == "error"
    assert len(daemon.get_status().last_run_errors) > 0
