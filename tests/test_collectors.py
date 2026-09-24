import json
from pathlib import Path

import pytest

from sentinel.collectors import COLLECTORS
from sentinel.collectors.self_assessment_report import generate_self_assessment_report
from sentinel.providers.mock import MockProvider
from sentinel.schema import validate_evidence


@pytest.fixture
def tmp_base(tmp_path):
    return tmp_path


def test_all_collectors_mock(tmp_base):
    provider = MockProvider()
    defaults = {
        "iam_access_review": "CC6.1",
        "log_aggregator": "CC7.1",
        "config_drift": "CC6.2",
        "encryption_status": "C1.2",
        "retention_check": "C1.4",
        "resilience_testing": "A1.2",
        "zt_continuous_verification": "ZT-1",
    }
    for name, fn in COLLECTORS.items():
        path = fn(provider, control_id=defaults[name], base=tmp_base)
        assert path.exists()
        payload = json.loads(path.read_text(encoding="utf-8"))
        validate_evidence(payload)
        assert payload["provider"] == "mock"


def test_log_aggregator_cui_export(tmp_base):
    provider = MockProvider()
    path = COLLECTORS["log_aggregator"](provider, base=tmp_base)
    cui_file = path.parent / "cui_events_export.json"
    assert cui_file.exists()
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload.get("cui_scoped") is True
    assert "T1078" in payload.get("attck_tags", [])


def test_self_assessment_cmmc_110(tmp_path):
    root = Path(__file__).resolve().parents[1]
    sample = root / "data" / "cmmc-l2-controls-110.csv"
    if not sample.exists():
        pytest.skip("cmmc-l2-controls-110.csv not generated yet")
    json_path, md_path = generate_self_assessment_report(
        sample, output_dir=tmp_path / "out", mode="cmmc"
    )
    report = json.loads(json_path.read_text(encoding="utf-8"))
    assert report["total_controls"] == 110
    assert report["met"] >= 20
    assert md_path.exists()


def test_self_assessment_zt(tmp_path):
    root = Path(__file__).resolve().parents[1]
    sample = root / "data" / "zero-trust-pillars.csv"
    if not sample.exists():
        pytest.skip("zero-trust-pillars.csv missing")
    json_path, _ = generate_self_assessment_report(
        sample, output_dir=tmp_path / "out", mode="zt"
    )
    report = json.loads(json_path.read_text(encoding="utf-8"))
    assert report["mode"] == "zt"
    assert report["total_controls"] == 7


def test_cmmc_generator_row_count():
    root = Path(__file__).resolve().parents[1]
    csv_path = root / "data" / "cmmc-l2-controls-110.csv"
    if not csv_path.exists():
        pytest.skip("cmmc csv missing")
    lines = csv_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 111  # header + 110 rows


# --- Consolidated from test_collectors_extended.py ---
import json

from sentinel.collectors import COLLECTORS
from sentinel.config import SentinelConfig
from sentinel.providers.mock import MockProvider


def test_all_collectors_have_collection_quality(tmp_path):
    provider = MockProvider()
    defaults = {
        "iam_access_review": "CC6.1",
        "log_aggregator": "CC7.1",
        "config_drift": "CC6.2",
        "encryption_status": "C1.2",
        "retention_check": "C1.4",
        "resilience_testing": "A1.2",
        "zt_continuous_verification": "ZT-1",
    }
    cfg = SentinelConfig()
    cfg.validation.strict_allowlist = True
    for name, fn in COLLECTORS.items():
        path = fn(provider, control_id=defaults[name], base=tmp_path, config=cfg)
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert "collection_quality" in payload
        assert "errors" in payload
        assert (tmp_path / "evidence").exists()
        manifest_backup = list((tmp_path / "evidence").rglob("manifests/*.json"))
        assert manifest_backup


# --- Consolidated from test_resilience_collector.py ---
import json

from sentinel.collectors.resilience_testing import collect_resilience_testing
from sentinel.config import SentinelConfig
from sentinel.providers.base import Provider


class PartialResilienceProvider(Provider):
    name = "mock"

    def validate_credentials(self) -> None:
        pass

    def resilience_snapshot(self):
        return {
            "last_backup_hours_ago": 12,
            "last_restore_test_days_ago": 120,
            "failover_test_passed": False,
            "backup_jobs_failed_30d": 2,
            "errors": [
                {
                    "code": "Partial",
                    "message": "x",
                    "severity": "medium",
                }
            ],
            "collection_quality": "partial",
            "partial": True,
        }

    def iam_access_snapshot(self):
        raise NotImplementedError

    def log_monitoring_snapshot(self):
        raise NotImplementedError

    def config_and_auth_snapshot(self):
        raise NotImplementedError

    def encryption_snapshot(self):
        raise NotImplementedError

    def retention_snapshot(self):
        raise NotImplementedError

    def zt_verification_snapshot(self):
        raise NotImplementedError


def test_resilience_collector_partial(tmp_path):
    path = collect_resilience_testing(
        PartialResilienceProvider(),
        base=tmp_path,
        config=SentinelConfig(),
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["collection_quality"] == "partial"
    assert payload["status"] in {"yellow", "red"}


class UnknownTestEvidenceProvider(PartialResilienceProvider):
    def resilience_snapshot(self):
        return {
            "last_backup_hours_ago": 4,
            "last_restore_test_days_ago": None,
            "last_successful_restore_days_ago": None,
            "failover_test_passed": None,
            "backup_jobs_failed_30d": 0,
            "errors": [
                {
                    "code": "FailoverTestNotCollected",
                    "message": "not measured",
                    "severity": "high",
                }
            ],
            "collection_quality": "partial",
            "partial": True,
        }


def test_resilience_collector_handles_unknown_test_evidence(tmp_path):
    path = collect_resilience_testing(
        UnknownTestEvidenceProvider(),
        base=tmp_path,
        config=SentinelConfig(),
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["status"] == "red"

    issues = {finding["issue"] for finding in payload["findings"]}
    assert "restore-test evidence unavailable" in issues
    assert "failover-test evidence unavailable" in issues


# --- Consolidated from test_cloud_retry.py ---
import pytest

from sentinel.cloud import call_with_retry


def test_call_with_retry_eventually_succeeds():
    attempts = {"count": 0}

    def flaky() -> str:
        attempts["count"] += 1
        if attempts["count"] < 2:
            raise ConnectionError("temporary")
        return "ok"

    assert call_with_retry(flaky, max_attempts=3, operation="test") == "ok"


def test_call_with_retry_non_retryable_raises():
    def fail() -> None:
        raise ValueError("bad input")

    with pytest.raises(ValueError):
        call_with_retry(fail, max_attempts=3, operation="test")


# --- Consolidated from test_helpers_extended.py ---
from sentinel.collectors._helpers import (
    failure_payload,
    sanitize_csv_export,
    worst_status,
    write_failure_evidence,
)
from sentinel.config import SentinelConfig


def test_failure_payload_shape():
    p = failure_payload(control_id="CC6.1", provider_name="mock", collector="x", error="boom")
    assert p["collection_quality"] == "failed"
    assert p["errors"][0]["code"] == "CollectionFailed"


def test_sanitize_csv_export():
    csv_text = sanitize_csv_export([{"name": "=evil", "val": 1}])
    assert "'=evil" in csv_text


def test_write_failure_evidence(tmp_path):
    path = write_failure_evidence(
        control_id="CC6.1",
        provider_name="mock",
        collector="test",
        error="fail",
        base=tmp_path,
        config=SentinelConfig(),
    )
    assert path.name == "report.json"


def test_worst_status_order():
    assert worst_status("green", "yellow", "red") == "red"


# --- Consolidated from test_misc_coverage.py ---
from pathlib import Path
from unittest.mock import patch

import pytest

from sentinel.cloud import call_with_retry, is_retryable_error, snapshot_errors
from sentinel.config import ProviderConfig, SentinelConfig
from sentinel.errors import ProviderError, ValidationError
from sentinel.paths import evidence_root, install_root
from sentinel.providers import get_provider


def test_snapshot_errors_helper():
    data = snapshot_errors("a", "", "b")
    assert data["partial"] is True
    assert data["errors"] == ["a", "b"]


def test_is_retryable_connection():
    assert is_retryable_error(ConnectionError("down")) is True


def test_call_with_retry_non_retryable():
    def boom():
        raise ValueError("nope")

    with pytest.raises(ValueError):
        call_with_retry(boom, max_attempts=1, operation="test")


def test_paths_helpers():
    assert install_root().exists()
    assert "evidence" in str(evidence_root(Path.cwd()))


def test_error_types():
    err = ValidationError("bad", details={"x": 1})
    assert err.to_dict()["message"] == "bad"
    prov = ProviderError("cloud down")
    assert prov.message == "cloud down"


def test_get_provider_clouds():
    cfg = SentinelConfig(
        provider=ProviderConfig(
            aws_region="us-east-1",
            gcp_project_id="proj",
            azure_subscription_id="00000000-0000-0000-0000-000000000001",
        )
    )
    with patch("sentinel.providers.aws.provider.AwsProvider.validate_credentials"):
        assert get_provider("aws", cfg).name == "aws"
    with patch("sentinel.providers.gcp.provider.GcpProvider.validate_credentials"):
        assert get_provider("gcp", cfg).name == "gcp"
    with patch("sentinel.providers.azure.provider.AzureProvider.validate_credentials"):
        assert get_provider("azure", cfg).name == "azure"


# --- Consolidated from test_concurrent_write.py ---
import json
import threading

from sentinel.config import SentinelConfig
from sentinel.output import write_evidence
from sentinel.schema import utc_now_iso


def _payload(control_id: str):
    return {
        "control_id": control_id,
        "collection_timestamp": utc_now_iso(),
        "status": "green",
        "collection_quality": "complete",
        "metrics": {},
        "evidence_artifacts": [],
        "findings": [],
        "errors": [],
        "notes": "concurrent",
        "provider": "mock",
    }


def test_concurrent_writes_do_not_corrupt(tmp_path):
    errors: list[str] = []

    def worker(cid: str):
        try:
            write_evidence(
                _payload(cid),
                base=tmp_path,
                extra_files={"data.json": json.dumps({"id": cid})},
                config=SentinelConfig(),
            )
        except Exception as exc:
            errors.append(str(exc))

    control_ids = ["CC6.1", "CC6.2", "CC7.1"]
    threads = [threading.Thread(target=worker, args=(cid,)) for cid in control_ids]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


# --- Consolidated from test_chaos.py ---


from sentinel.collectors.iam_access_review import collect_iam_access_review
from sentinel.config import SentinelConfig
from sentinel.providers.base import Provider


class ChaosProvider(Provider):
    name = "mock"

    def validate_credentials(self) -> None:
        pass

    def iam_access_snapshot(self):
        return {
            "users": [],
            "total_identities": 0,
            "orphaned_accounts": 0,
            "privileged_count": 0,
            "errors": [{"code": "Timeout", "message": "API timeout", "severity": "high"}],
            "collection_quality": "partial",
            "partial": True,
            "csv": "",
        }

    def log_monitoring_snapshot(self):
        raise NotImplementedError

    def config_and_auth_snapshot(self):
        raise NotImplementedError

    def encryption_snapshot(self):
        raise NotImplementedError

    def retention_snapshot(self):
        raise NotImplementedError

    def resilience_snapshot(self):
        raise NotImplementedError

    def zt_verification_snapshot(self):
        raise NotImplementedError


def test_partial_collection_yellow_status(tmp_path):
    path = collect_iam_access_review(ChaosProvider(), base=tmp_path, config=SentinelConfig())
    import json

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["collection_quality"] == "partial"
    assert payload["status"] == "yellow"
    assert len(payload["errors"]) == 1


# --- Consolidated from test_phase3_integration.py ---
"""Integration tests for Phase 3 REST endpoints and CLI subcommands."""

import json
from pathlib import Path

import pytest

from sentinel.auth import Role, TokenManager, UserIdentity
from sentinel.cli import main
from sentinel.dashboard.server import DashboardHandler, DashboardServer


@pytest.fixture
def auth_token() -> str:
    user = UserIdentity(user_id="secadmin", role=Role.SUPER_ADMIN, tenant_id="default")
    return TokenManager.create_token(user)


def test_phase3_server_endpoints(tmp_path: Path, auth_token: str):
    server = DashboardServer(("127.0.0.1", 0), DashboardHandler, output_base=tmp_path)
    import threading
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    port = server.server_address[1]

    import urllib.request
    headers = {"Authorization": f"Bearer {auth_token}", "Content-Type": "application/json"}

    # 1. GET /api/trust-center
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/trust-center", headers=headers)
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode())
        assert "overall_compliance_score" in data

    # 2. GET /trust-center (HTML)
    req = urllib.request.Request(f"http://127.0.0.1:{port}/trust-center")
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        html = resp.read().decode()
        assert "<!DOCTYPE html>" in html

    # 3. GET /api/dogfood
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/dogfood", headers=headers)
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode())
        assert "compliance_score" in data

    # 4. POST /api/audit-rooms (create)
    create_body = json.dumps({
        "room_id": "REST-ROOM-001",
        "title": "REST API Room",
        "auditor_email": "auditor@rest.com",
        "period_start": "2026-09-01",
        "period_end": "2026-09-30",
    }).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/audit-rooms", data=create_body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        room_data = json.loads(resp.read().decode())
        assert room_data["room_id"] == "REST-ROOM-001"

    # 5. GET /api/audit-rooms/REST-ROOM-001
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/audit-rooms/REST-ROOM-001", headers=headers)
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        details = json.loads(resp.read().decode())
        assert details["room"]["room_id"] == "REST-ROOM-001"
        assert "crosswalk" in details

    # 6. POST /api/audit-rooms/export
    export_body = json.dumps({"room_id": "REST-ROOM-001"}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/audit-rooms/export", data=export_body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        exp_res = json.loads(resp.read().decode())
        assert exp_res["status"] == "success"

    # 7. POST /api/siem/export
    siem_body = json.dumps({"target": "NDJSON_FILE", "limit": 50}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/siem/export", data=siem_body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        siem_res = json.loads(resp.read().decode())
        assert siem_res["status"] == "exported"

    server.shutdown()
    server.server_close()


def test_phase3_cli_commands(tmp_path: Path, monkeypatch, capsys):
    # Test CLI dogfood command
    monkeypatch.setattr("sys.argv", ["sentinel", "dogfood", "--output-base", str(tmp_path), "--json"])
    main()
    captured = capsys.readouterr()
    res = json.loads(captured.out)
    assert "compliance_score" in res

    # Test CLI audit-room create & list
    monkeypatch.setattr("sys.argv", [
        "sentinel", "audit-room", "create",
        "--id", "CLI-ROOM-001",
        "--title", "CLI Audit Room",
        "--auditor", "auditor@cli.com",
        "--start", "2026-09-01",
        "--end", "2026-09-30",
        "--output-base", str(tmp_path),
    ])
    main()
    captured = capsys.readouterr()
    res = json.loads(captured.out)
    assert res["room_id"] == "CLI-ROOM-001"

    monkeypatch.setattr("sys.argv", [
        "sentinel", "audit-room", "list",
        "--output-base", str(tmp_path),
    ])
    main()
    captured = capsys.readouterr()
    rooms_list = json.loads(captured.out)
    assert len(rooms_list) >= 1

    # Test CLI trust-center view
    monkeypatch.setattr("sys.argv", [
        "sentinel", "trust-center", "view",
        "--output-base", str(tmp_path),
    ])
    main()
    captured = capsys.readouterr()
    tc_data = json.loads(captured.out)
    assert "overall_compliance_score" in tc_data

    # Test CLI siem export
    out_ndjson = tmp_path / "cli_siem.ndjson"
    monkeypatch.setattr("sys.argv", [
        "sentinel", "siem", "export",
        "--output-ndjson", str(out_ndjson),
        "--output-base", str(tmp_path),
    ])
    main()
    captured = capsys.readouterr()
    siem_out = json.loads(captured.out)
    assert siem_out["status"] == "exported"
