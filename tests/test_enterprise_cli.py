"""Unit tests for new Enterprise CLI subcommands."""

import json
from pathlib import Path

import pytest

from sentinel.cli import main


def test_cli_policy_list(capsys: pytest.CaptureFixture) -> None:
    import sys
    sys.argv = ["sentinel", "policy", "list"]
    main()
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert isinstance(data, list)
    assert len(data) > 0


def test_cli_policy_evaluate(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({
        "iam_access_review": {
            "metrics": {
                "mfa_enforced_percentage": 100.0,
                "orphaned_accounts": 0,
            }
        }
    }), encoding="utf-8")

    import sys
    sys.argv = ["sentinel", "policy", "evaluate", "--state-file", str(state_file)]
    try:
        main()
    except SystemExit:
        pass
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "compliance_score" in data


def test_cli_github_audit_mock(capsys: pytest.CaptureFixture) -> None:
    import sys
    sys.argv = ["sentinel", "github", "audit", "--repo", "demo/app", "--mock"]
    main()
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["compliant"] is True
    assert data["repository"] == "demo/app"


def test_cli_tenant_and_token(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    import sys
    # Tenant create
    sys.argv = ["sentinel", "tenant", "create", "cli-tenant-test", "--output-base", str(tmp_path)]
    main()
    captured = capsys.readouterr()
    t_data = json.loads(captured.out)
    assert t_data["status"] == "created"
    assert t_data["tenant_id"] == "cli-tenant-test"

    # Tenant list
    sys.argv = ["sentinel", "tenant", "list", "--output-base", str(tmp_path)]
    main()
    captured_list = capsys.readouterr()
    list_data = json.loads(captured_list.out)
    assert "cli-tenant-test" in list_data["tenants"]

    # Token create
    sys.argv = [
        "sentinel", "token", "create",
        "--user", "cli_admin",
        "--role", "SECURITY_ADMIN",
        "--tenant", "cli-tenant-test",
        "--expires", "3600",
    ]
    main()
    captured_tok = capsys.readouterr()
    tok_data = json.loads(captured_tok.out)
    assert tok_data["token"].startswith("sentinel_")
    assert tok_data["user"]["user_id"] == "cli_admin"


def test_cli_vault_seal_and_verify(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    import sys
    ev_date_dir = tmp_path / "evidence" / "2026-09-24"
    ev_date_dir.mkdir(parents=True)

    # Vault Seal
    sys.argv = ["sentinel", "vault", "seal", str(ev_date_dir), "--output-base", str(tmp_path)]
    main()
    captured_seal = capsys.readouterr()
    seal_data = json.loads(captured_seal.out)
    assert "merkle_root" in seal_data

    # Vault Verify
    sys.argv = ["sentinel", "vault", "verify", "--output-base", str(tmp_path)]
    main()
    captured_ver = capsys.readouterr()
    ver_data = json.loads(captured_ver.out)
    assert ver_data["valid"] is True
    assert ver_data["total_blocks"] == 1


def test_cli_vendor_risk_workflow(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    import sys
    # Add vendor
    sys.argv = [
        "sentinel", "vendor-risk", "add",
        "--id", "v-github",
        "--name", "GitHub Enterprise",
        "--tier", "TIER_1_CRITICAL",
        "--classification", "CONFIDENTIAL",
        "--soc2-expires", "2030-01-01T00:00:00Z",
        "--dpa", "--mfa", "--encryption",
        "--output-base", str(tmp_path),
    ]
    main()
    captured_add = capsys.readouterr()
    add_data = json.loads(captured_add.out)
    assert add_data["name"] == "GitHub Enterprise"

    # List vendors
    sys.argv = ["sentinel", "vendor-risk", "list", "--output-base", str(tmp_path)]
    main()
    captured_list = capsys.readouterr()
    list_data = json.loads(captured_list.out)
    assert len(list_data) == 1

    # Report
    sys.argv = ["sentinel", "vendor-risk", "report", "--output-base", str(tmp_path)]
    main()
    captured_rep = capsys.readouterr()
    rep_data = json.loads(captured_rep.out)
    assert rep_data["control_id"] == "CC9.2"
    assert rep_data["total_vendors"] == 1


def test_cli_access_review_workflow(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    import sys
    # Start campaign
    sys.argv = [
        "sentinel", "access-review", "start",
        "--id", "CAMP-CLI-1",
        "--title", "CLI Test Campaign",
        "--period", "2026-Q3",
        "--output-base", str(tmp_path),
    ]
    main()
    captured_start = capsys.readouterr()
    start_data = json.loads(captured_start.out)
    assert start_data["campaign_id"] == "CAMP-CLI-1"

    # List campaigns
    sys.argv = ["sentinel", "access-review", "list", "--output-base", str(tmp_path)]
    main()
    captured_list = capsys.readouterr()
    list_data = json.loads(captured_list.out)
    assert len(list_data) == 1

    # Signoff campaign
    sys.argv = [
        "sentinel", "access-review", "signoff",
        "--id", "CAMP-CLI-1",
        "--signer", "Chief Security Officer",
        "--output-base", str(tmp_path),
    ]
    main()
    captured_sign = capsys.readouterr()
    sign_data = json.loads(captured_sign.out)
    assert sign_data["status"] == "COMPLETED"
    assert "sign_off_hash" in sign_data
