from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest

from sentinel.daemon import ContinuousMonitoringDaemon
from sentinel.dashboard.server import DashboardHandler, DashboardServer


@pytest.fixture(scope="module")
def server_instance(tmp_path_factory):
    base = tmp_path_factory.mktemp("server_evidence")
    # Pre-populate dummy evidence
    day_dir = base / "evidence" / "2026-09-23"
    ctrl_dir = day_dir / "CC6.1"
    ctrl_dir.mkdir(parents=True)
    payload = {"collector": "iam_access_review", "control_id": "CC6.1", "provider": "mock", "metrics": {}}
    (ctrl_dir / "evidence.json").write_text(json.dumps(payload), encoding="utf-8")
    (day_dir / "manifest.json").write_text(json.dumps({"files": {"CC6.1/evidence.json": "hash"}}), encoding="utf-8")

    daemon = ContinuousMonitoringDaemon(provider_name="mock", interval_seconds=1000, output_base=base)

    server = DashboardServer(
        ("127.0.0.1", 0),
        DashboardHandler,
        output_base=base,
        config=None,
        daemon=daemon,
    )
    port = server.server_address[1]

    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    yield f"http://127.0.0.1:{port}", base

    server.shutdown()
    server.server_close()


def test_get_root(server_instance):
    url, _ = server_instance
    resp = urllib.request.urlopen(f"{url}/")
    assert resp.status == 200
    content = resp.read().decode("utf-8")
    assert "<!DOCTYPE html>" in content
    assert "SOC2 Sentinel" in content


def test_get_status(server_instance):
    url, _ = server_instance
    resp = urllib.request.urlopen(f"{url}/api/status")
    assert resp.status == 200
    data = json.loads(resp.read().decode("utf-8"))
    assert "version" in data
    assert "pid" in data


def test_get_scorecard(server_instance):
    url, _ = server_instance
    resp = urllib.request.urlopen(f"{url}/api/scorecard")
    assert resp.status == 200
    data = json.loads(resp.read().decode("utf-8"))
    assert "overall_posture_score" in data
    assert "soc2" in data


def test_get_drift(server_instance):
    url, _ = server_instance
    resp = urllib.request.urlopen(f"{url}/api/drift")
    assert resp.status == 200
    data = json.loads(resp.read().decode("utf-8"))
    assert "drift_detected" in data


def test_get_credentials(server_instance):
    url, _ = server_instance
    resp = urllib.request.urlopen(f"{url}/api/credentials")
    assert resp.status == 200
    data = json.loads(resp.read().decode("utf-8"))
    assert "mock" in data


def test_get_evidence_list_and_file(server_instance):
    url, _ = server_instance
    resp = urllib.request.urlopen(f"{url}/api/evidence")
    assert resp.status == 200
    dates = json.loads(resp.read().decode("utf-8"))
    assert "2026-09-23" in dates

    m_resp = urllib.request.urlopen(f"{url}/api/evidence/2026-09-23/manifest.json")
    assert m_resp.status == 200
    m_data = json.loads(m_resp.read().decode("utf-8"))
    assert "files" in m_data


def test_get_report_latest(server_instance):
    url, _ = server_instance
    resp = urllib.request.urlopen(f"{url}/api/report/latest")
    assert resp.status == 200
    html = resp.read().decode("utf-8")
    assert "<!DOCTYPE html>" in html
    assert "Executive" in html


def test_post_verify(server_instance):
    url, _ = server_instance
    req = urllib.request.Request(
        f"{url}/api/verify",
        data=json.dumps({"date": "2026-09-23"}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    resp = urllib.request.urlopen(req)
    assert resp.status == 200
    data = json.loads(resp.read().decode("utf-8"))
    assert "valid" in data


def test_post_scan(server_instance):
    url, _ = server_instance
    req = urllib.request.Request(
        f"{url}/api/scan",
        data=json.dumps({"provider": "mock", "collector": "iam_access_review"}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    resp = urllib.request.urlopen(req)
    assert resp.status == 200
    data = json.loads(resp.read().decode("utf-8"))
    assert data["status"] == "ok"


def test_post_export_and_download(server_instance):
    url, _ = server_instance
    req = urllib.request.Request(
        f"{url}/api/export",
        data=b"{}",
        headers={"Content-Type": "application/json"},
    )
    resp = urllib.request.urlopen(req)
    assert resp.status == 200
    data = json.loads(resp.read().decode("utf-8"))
    assert data["status"] == "ok"
    assert "download_url" in data

    # Test download
    dl_resp = urllib.request.urlopen(f"{url}{data['download_url']}")
    assert dl_resp.status == 200
    assert dl_resp.headers.get("Content-Type") in {
        "application/zip",
        "application/octet-stream",
        "application/x-zip-compressed",
    }


def test_not_found(server_instance):
    url, _ = server_instance
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(f"{url}/api/non-existent-endpoint")
    assert exc_info.value.code == 404
