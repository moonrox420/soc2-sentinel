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


def test_get_policy_rules_and_evaluation(server_instance):
    url, _ = server_instance
    resp = urllib.request.urlopen(f"{url}/api/policy/rules")
    assert resp.status == 200
    rules = json.loads(resp.read().decode("utf-8"))
    assert isinstance(rules, list)
    assert len(rules) > 0

    req = urllib.request.Request(
        f"{url}/api/policy/evaluate",
        data=json.dumps({"state": {}}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    eval_resp = urllib.request.urlopen(req)
    assert eval_resp.status == 200
    report = json.loads(eval_resp.read().decode("utf-8"))
    assert "compliance_score" in report


def test_tenants_and_tokens_endpoints(server_instance):
    url, _ = server_instance
    # List tenants
    resp = urllib.request.urlopen(f"{url}/api/tenants")
    assert resp.status == 200
    tenants = json.loads(resp.read().decode("utf-8"))
    assert "tenants" in tenants

    # Create tenant
    req_t = urllib.request.Request(
        f"{url}/api/tenants",
        data=json.dumps({"tenant_id": "org-dashboard-test"}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    create_t_resp = urllib.request.urlopen(req_t)
    assert create_t_resp.status == 200

    # Create signed token
    req_tok = urllib.request.Request(
        f"{url}/api/tokens/create",
        data=json.dumps({"user_id": "auditor_user", "role": "AUDITOR", "tenant_id": "org-dashboard-test"}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    create_tok_resp = urllib.request.urlopen(req_tok)
    assert create_tok_resp.status == 200
    tok_data = json.loads(create_tok_resp.read().decode("utf-8"))
    assert "token" in tok_data
    assert tok_data["token"].startswith("sentinel_")


def test_vcs_and_telemetry_endpoints(server_instance):
    url, _ = server_instance
    # VCS GitHub audit
    resp_gh = urllib.request.urlopen(f"{url}/api/vcs/github?mock=true")
    assert resp_gh.status == 200
    gh_data = json.loads(resp_gh.read().decode("utf-8"))
    assert gh_data["compliant"] is True

    # Telemetry events
    resp_tel = urllib.request.urlopen(f"{url}/api/telemetry/events")
    assert resp_tel.status == 200
    tel_data = json.loads(resp_tel.read().decode("utf-8"))
    assert "events" in tel_data


def test_phase2_vault_and_vrm_endpoints(server_instance):
    url, _ = server_instance
    # 1. Vault Chain
    resp_vault = urllib.request.urlopen(f"{url}/api/vault/chain")
    assert resp_vault.status == 200
    v_data = json.loads(resp_vault.read().decode("utf-8"))
    assert "verification" in v_data

    # 2. Vault Seal
    req_seal = urllib.request.Request(
        f"{url}/api/vault/seal",
        data=json.dumps({"date": "2026-09-23"}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    seal_resp = urllib.request.urlopen(req_seal)
    assert seal_resp.status == 200
    block_data = json.loads(seal_resp.read().decode("utf-8"))
    assert "merkle_root" in block_data

    # 3. VRM Vendors
    req_vrm = urllib.request.Request(
        f"{url}/api/vendor-risk/vendors",
        data=json.dumps({
            "vendor": {
                "vendor_id": "v-dash-test",
                "name": "Cloud CDN Provider",
                "tier": "TIER_2_HIGH",
                "data_classification": "INTERNAL",
                "questionnaire": {"has_soc2_type2": True, "enforces_mfa": True},
            }
        }).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    save_v_resp = urllib.request.urlopen(req_vrm)
    assert save_v_resp.status == 200

    resp_v_list = urllib.request.urlopen(f"{url}/api/vendor-risk/vendors")
    assert resp_v_list.status == 200
    v_list = json.loads(resp_v_list.read().decode("utf-8"))
    assert len(v_list) >= 1

    resp_v_rep = urllib.request.urlopen(f"{url}/api/vendor-risk/report")
    assert resp_v_rep.status == 200
    v_rep = json.loads(resp_v_rep.read().decode("utf-8"))
    assert v_rep["control_id"] == "CC9.2"


def test_phase2_uar_and_notification_endpoints(server_instance):
    url, base = server_instance
    from sentinel.access_review import AccessReviewManager
    uar = AccessReviewManager(base)
    camp = uar.create_campaign_from_evidence(
        campaign_id="CAMP-DASH-1",
        title="Dashboard Test Campaign",
        period="2026-Q3",
        due_date="2026-10-01",
        iam_evidence={"provider": "mock"},
    )

    # List campaigns
    resp_c = urllib.request.urlopen(f"{url}/api/access-review/campaigns")
    assert resp_c.status == 200
    c_list = json.loads(resp_c.read().decode("utf-8"))
    assert len(c_list) >= 1

    # Record decision
    item_id = camp.items[0].item_id
    req_decide = urllib.request.Request(
        f"{url}/api/access-review/decide",
        data=json.dumps({"campaign_id": "CAMP-DASH-1", "item_id": item_id, "decision": "MAINTAIN"}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    dec_resp = urllib.request.urlopen(req_decide)
    assert dec_resp.status == 200

    # Notification test
    req_notif = urllib.request.Request(
        f"{url}/api/notifications/test",
        data=json.dumps({"webhook_url": "http://127.0.0.1:65520/test", "channel": "slack"}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    notif_resp = urllib.request.urlopen(req_notif)
    assert notif_resp.status == 200
