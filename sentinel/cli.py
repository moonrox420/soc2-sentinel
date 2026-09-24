from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

from sentinel import __version__
from sentinel.audit import AuditTimer, append_audit_event
from sentinel.collectors import COLLECTORS
from sentinel.collectors.self_assessment_report import generate_self_assessment_report
from sentinel.config import SentinelConfig, load_config
from sentinel.errors import ProviderError, SentinelError, ValidationError
from sentinel.integrity import verify_evidence_tree
from sentinel.logging_config import configure_logging
from sentinel.paths import install_root
from sentinel.providers import get_provider
from sentinel.schema import load_schema
from sentinel.validation import resolve_safe_output_base, sanitize_control_id

logger = logging.getLogger("sentinel")

RUN_ALL_MAPPING = {
    "iam_access_review": "CC6.1",
    "log_aggregator": "CC7.1",
    "config_drift": "CC6.2",
    "encryption_status": "C1.2",
    "retention_check": "C1.4",
    "resilience_testing": "A1.2",
    "zt_continuous_verification": "ZT-1",
}

DEFAULT_CONTROL = dict(RUN_ALL_MAPPING)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=f"SOC2 Sentinel evidence automation v{__version__}"
    )
    parser.add_argument(
        "--version", action="version", version=f"SOC2 Sentinel v{__version__}"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging"
    )
    parser.add_argument(
        "--config", type=Path, default=None, help="Path to sentinel.yaml"
    )
    parser.add_argument(
        "--redact-pii", action="store_true", help="Redact PII in exports"
    )
    parser.add_argument(
        "--log-file", type=Path, default=None, help="Structured log file sink"
    )
    parser.add_argument(
        "--allow-unknown-control",
        action="store_true",
        help="Bypass strict control ID allowlist",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    validate_p = sub.add_parser(
        "validate", help="Validate config and provider credentials"
    )
    validate_p.add_argument(
        "--provider", default="aws", choices=["aws", "gcp", "azure"]
    )

    verify_p = sub.add_parser("verify", help="Verify evidence manifest integrity")
    verify_p.add_argument(
        "evidence_dir", type=Path, help="Evidence date directory to verify"
    )

    run_p = sub.add_parser("run", help="Run an evidence collector")
    run_p.add_argument("collector", choices=sorted(COLLECTORS.keys()))
    run_p.add_argument(
        "--provider", default="aws", choices=["aws", "gcp", "azure"]
    )
    run_p.add_argument("--control-id", default=None)
    run_p.add_argument("--output-base", type=Path, default=Path.cwd())
    run_p.add_argument(
        "--dry-run", action="store_true", help="Validate config/credentials only"
    )

    all_p = sub.add_parser("run-all", help="Run all collectors")
    all_p.add_argument(
        "--provider", default="aws", choices=["aws", "gcp", "azure"]
    )
    all_p.add_argument("--output-base", type=Path, default=Path.cwd())
    all_p.add_argument(
        "--dry-run", action="store_true", help="Validate config/credentials only"
    )
    all_p.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Continue run-all when a collector fails",
    )

    watch_p = sub.add_parser("watch", help="Stream real-time compliance telemetry events in live console")
    watch_p.add_argument("--output-base", type=Path, default=Path.cwd())

    report_p = sub.add_parser("report", help="Generate assessment report")
    report_p.add_argument("--input", type=Path, required=True)
    report_p.add_argument("--output-dir", type=Path, default=None)
    report_p.add_argument("--mode", default="cmmc", choices=["cmmc", "zt"])

    serve_p = sub.add_parser(
        "serve", help="Launch interactive compliance dashboard web UI"
    )
    serve_p.add_argument("--host", default="127.0.0.1", help="Host address to bind")
    serve_p.add_argument("--port", type=int, default=8080, help="Port to listen on")
    serve_p.add_argument(
        "--output-base", type=Path, default=Path.cwd(), help="Evidence output directory"
    )
    serve_p.add_argument(
        "--provider", default="aws", choices=["aws", "gcp", "azure"]
    )
    serve_p.add_argument(
        "--daemon",
        action="store_true",
        help="Enable continuous background polling daemon",
    )
    serve_p.add_argument(
        "--interval",
        "--poll-interval",
        dest="poll_interval",
        type=int,
        default=None,
        help="Continuous daemon interval in seconds (auto-enables daemon)",
    )
    serve_p.add_argument(
        "--no-browser", action="store_true", help="Do not open default browser"
    )

    dash_p = sub.add_parser("dashboard", help="Alias for 'serve'")
    dash_p.add_argument("--host", default="127.0.0.1")
    dash_p.add_argument("--port", type=int, default=8080)
    dash_p.add_argument("--output-base", type=Path, default=Path.cwd())
    dash_p.add_argument(
        "--provider", default="aws", choices=["aws", "gcp", "azure"]
    )
    dash_p.add_argument("--daemon", action="store_true")
    dash_p.add_argument(
        "--interval",
        "--poll-interval",
        dest="poll_interval",
        type=int,
        default=None,
        help="Continuous daemon interval in seconds (auto-enables daemon)",
    )
    dash_p.add_argument("--no-browser", action="store_true")

    score_p = sub.add_parser(
        "scorecard", help="Display multi-framework compliance posture scorecard"
    )
    score_p.add_argument("--output-base", type=Path, default=Path.cwd())
    score_p.add_argument("--date", default=None, help="Evidence date folder")
    score_p.add_argument("--provider", default=None)

    drift_p = sub.add_parser(
        "drift", help="Detect configuration drift between evidence snapshots"
    )
    drift_p.add_argument("--output-base", type=Path, default=Path.cwd())
    drift_p.add_argument("--baseline", default=None, help="Baseline date")
    drift_p.add_argument("--current", default=None, help="Current date")

    pack_p = sub.add_parser(
        "audit-pack",
        help="Generate executive HTML report and signed evidence ZIP archive",
    )
    pack_p.add_argument(
        "evidence_dir", type=Path, help="Evidence date directory to package"
    )
    pack_p.add_argument(
        "--output-dir", type=Path, default=None, help="Directory to save generated ZIP"
    )

    # Enterprise Extensions: Policy, VCS, Multi-Tenant, RBAC Tokens
    policy_p = sub.add_parser(
        "policy", help="Evaluate declarative compliance policy rules"
    )
    policy_sub = policy_p.add_subparsers(dest="policy_command", required=True)
    policy_eval_p = policy_sub.add_parser(
        "evaluate", help="Evaluate policy rules against evidence state"
    )
    policy_eval_p.add_argument(
        "--state-file", type=Path, default=None, help="JSON state file to evaluate"
    )
    policy_eval_p.add_argument(
        "--rules-file", type=Path, default=None, help="Optional custom rules YAML/JSON"
    )
    policy_sub.add_parser("list", help="List default enterprise policy rules")

    github_p = sub.add_parser(
        "github", help="Audit GitHub repository for SOC 2 VCS controls"
    )
    github_sub = github_p.add_subparsers(dest="github_command", required=True)
    gh_audit_p = github_sub.add_parser(
        "audit", help="Audit repository branch protection and security features"
    )
    gh_audit_p.add_argument(
        "--repo", default="enterprise-org/soc2-sentinel", help="GitHub repo owner/name"
    )
    gh_audit_p.add_argument("--branch", default="main", help="Target branch to audit")
    gh_audit_p.add_argument(
        "--token", default=None, help="GitHub PAT token (or GITHUB_TOKEN env var)"
    )

    tenant_p = sub.add_parser("tenant", help="Manage multi-tenant isolated workspaces")
    tenant_sub = tenant_p.add_subparsers(dest="tenant_command", required=True)
    tenant_list_p = tenant_sub.add_parser(
        "list", help="List registered tenant workspaces"
    )
    tenant_list_p.add_argument("--output-base", type=Path, default=Path.cwd())
    tenant_create_p = tenant_sub.add_parser(
        "create", help="Create a new tenant workspace"
    )
    tenant_create_p.add_argument("slug", help="Unique alphanumeric tenant slug")
    tenant_create_p.add_argument("--output-base", type=Path, default=Path.cwd())

    token_p = sub.add_parser(
        "token", help="Manage cryptographically signed RBAC tokens"
    )
    token_sub = token_p.add_subparsers(dest="token_command", required=True)
    token_create_p = token_sub.add_parser(
        "create", help="Generate a signed bearer token"
    )
    token_create_p.add_argument("--user", default="admin", help="User identifier")
    token_create_p.add_argument(
        "--role",
        default="SUPER_ADMIN",
        choices=[
            "SUPER_ADMIN",
            "SECURITY_ADMIN",
            "COMPLIANCE_OFFICER",
            "AUDITOR",
            "SYSTEM_USER",
        ],
        help="RBAC role assigned to the token",
    )
    token_create_p.add_argument(
        "--tenant", default="default", help="Tenant workspace ID"
    )
    token_create_p.add_argument(
        "--expires", type=int, default=86400, help="Expiration in seconds"
    )

    # Phase 2: Vault, VRM, UAR, Notifications
    vault_p = sub.add_parser(
        "vault", help="Cryptographic evidence chain-of-custody ledger"
    )
    vault_sub = vault_p.add_subparsers(dest="vault_command", required=True)
    vault_verify_p = vault_sub.add_parser(
        "verify", help="Verify unbroken cryptographic chain integrity"
    )
    vault_verify_p.add_argument(
        "--tenant", default="default", help="Tenant workspace ID"
    )
    vault_verify_p.add_argument("--output-base", type=Path, default=Path.cwd())
    vault_seal_p = vault_sub.add_parser(
        "seal", help="Seal evidence run into blockchain ledger"
    )
    vault_seal_p.add_argument(
        "evidence_dir", type=Path, help="Evidence run date folder"
    )
    vault_seal_p.add_argument("--tenant", default="default")
    vault_seal_p.add_argument("--output-base", type=Path, default=Path.cwd())

    vrm_p = sub.add_parser(
        "vendor-risk", help="Third-party vendor risk assessment & SOC 2 CC9.2"
    )
    vrm_sub = vrm_p.add_subparsers(dest="vrm_command", required=True)
    vrm_list_p = vrm_sub.add_parser(
        "list", help="List registered vendor risk assessments"
    )
    vrm_list_p.add_argument("--output-base", type=Path, default=Path.cwd())
    vrm_report_p = vrm_sub.add_parser(
        "report", help="Generate SOC 2 CC9.2 vendor risk audit report"
    )
    vrm_report_p.add_argument("--output-base", type=Path, default=Path.cwd())
    vrm_add_p = vrm_sub.add_parser(
        "add", help="Add or update a third-party vendor assessment"
    )
    vrm_add_p.add_argument("--id", required=True, help="Unique vendor identifier")
    vrm_add_p.add_argument("--name", required=True, help="Vendor legal name")
    vrm_add_p.add_argument(
        "--tier",
        default="TIER_3_MEDIUM",
        choices=["TIER_1_CRITICAL", "TIER_2_HIGH", "TIER_3_MEDIUM", "TIER_4_LOW"],
    )
    vrm_add_p.add_argument(
        "--classification",
        default="INTERNAL",
        choices=["RESTRICTED", "CONFIDENTIAL", "INTERNAL", "PUBLIC"],
    )
    vrm_add_p.add_argument(
        "--soc2-expires", default=None, help="SOC 2 expiration ISO date"
    )
    vrm_add_p.add_argument("--dpa", action="store_true", help="DPA executed")
    vrm_add_p.add_argument("--mfa", action="store_true", help="MFA enforced")
    vrm_add_p.add_argument(
        "--encryption", action="store_true", help="Encryption at rest verified"
    )
    vrm_add_p.add_argument("--output-base", type=Path, default=Path.cwd())

    onboarding_p = sub.add_parser(
        "onboarding",
        help="Cloud onboarding diagnostics & minimal IAM policy generation",
    )
    onboarding_p.add_argument(
        "--provider", required=True, choices=["aws", "gcp", "azure"]
    )
    onboarding_p.add_argument("--format", default="json", choices=["json", "text"])

    uar_p = sub.add_parser(
        "access-review", help="User Access Review & Certification Campaign Manager"
    )
    uar_sub = uar_p.add_subparsers(dest="uar_command", required=True)
    uar_list_p = uar_sub.add_parser("list", help="List access certification campaigns")
    uar_list_p.add_argument("--output-base", type=Path, default=Path.cwd())
    uar_start_p = uar_sub.add_parser(
        "start", help="Start new UAR campaign from IAM evidence"
    )
    uar_start_p.add_argument(
        "--id", required=True, help="Campaign identifier, e.g. 2026-Q3-IAM"
    )
    uar_start_p.add_argument("--title", required=True, help="Campaign title")
    uar_start_p.add_argument("--period", default="2026-Q3", help="Review period")
    uar_start_p.add_argument("--due-date", default="2026-10-15", help="Review deadline")
    uar_start_p.add_argument(
        "--evidence-file", type=Path, default=None, help="Path to IAM evidence JSON"
    )
    uar_start_p.add_argument("--output-base", type=Path, default=Path.cwd())
    uar_decide_p = uar_sub.add_parser(
        "decide", help="Record reviewer decision on entitlement"
    )
    uar_decide_p.add_argument("--id", required=True, help="Campaign identifier")
    uar_decide_p.add_argument("--item-id", required=True, help="Access item ID")
    uar_decide_p.add_argument(
        "--decision", required=True, choices=["MAINTAIN", "REVOKE", "MODIFY"]
    )
    uar_decide_p.add_argument(
        "--reviewer", default="Security Officer", help="Reviewer identifier"
    )
    uar_decide_p.add_argument("--notes", default="", help="Review notes")
    uar_decide_p.add_argument("--output-base", type=Path, default=Path.cwd())
    uar_sign_p = uar_sub.add_parser(
        "signoff", help="Cryptographically sign and complete campaign"
    )
    uar_sign_p.add_argument("--id", required=True, help="Campaign identifier")
    uar_sign_p.add_argument(
        "--signer", default="Security Officer", help="Signatory name"
    )
    uar_sign_p.add_argument(
        "--secret", default=None, help="Optional signing key for HMAC digest"
    )
    uar_sign_p.add_argument("--output-base", type=Path, default=Path.cwd())

    notify_p = sub.add_parser(
        "notify", help="Dispatch compliance violation alerts to webhooks"
    )
    notify_p.add_argument("--webhook", required=True, help="Target webhook URL")
    notify_p.add_argument(
        "--channel",
        default="webhook",
        choices=["slack", "teams", "pagerduty", "webhook"],
    )
    notify_p.add_argument("--title", default="Compliance Alert", help="Alert title")
    notify_p.add_argument("--message", required=True, help="Alert body message")
    notify_p.add_argument(
        "--severity", default="WARNING", choices=["INFO", "WARNING", "CRITICAL"]
    )
    notify_p.add_argument("--control", default=None, help="Associated control ID")

    # Phase 3: Audit Rooms, Dogfooding, Trust Center, SIEM
    ar_p = sub.add_parser(
        "audit-room", help="Auditor Portal and time-bounded audit room manager"
    )
    ar_sub = ar_p.add_subparsers(dest="audit_room_command", required=True)
    ar_list_p = ar_sub.add_parser("list", help="List active and historical audit rooms")
    ar_list_p.add_argument("--output-base", type=Path, default=Path.cwd())
    ar_create_p = ar_sub.add_parser(
        "create", help="Create scoped audit room for external auditor"
    )
    ar_create_p.add_argument(
        "--id", required=True, help="Audit room ID, e.g. 2026-TYPE2-PWC"
    )
    ar_create_p.add_argument("--title", required=True, help="Audit room title")
    ar_create_p.add_argument(
        "--auditor", default="auditor@firm.com", help="Auditor contact email"
    )
    ar_create_p.add_argument(
        "--start", required=True, help="Audit period start YYYY-MM-DD"
    )
    ar_create_p.add_argument("--end", required=True, help="Audit period end YYYY-MM-DD")
    ar_create_p.add_argument(
        "--expires-days", type=int, default=90, help="Room validity in days"
    )
    ar_create_p.add_argument("--notes", default="", help="Auditor notes")
    ar_create_p.add_argument("--output-base", type=Path, default=Path.cwd())
    ar_export_p = ar_sub.add_parser(
        "export", help="Export self-contained auditor ZIP package"
    )
    ar_export_p.add_argument("--id", required=True, help="Audit room ID")
    ar_export_p.add_argument(
        "--output-zip", type=Path, default=None, help="Destination ZIP file path"
    )
    ar_export_p.add_argument("--output-base", type=Path, default=Path.cwd())

    dogfood_p = sub.add_parser(
        "dogfood", help="Evaluate Sentinel's own SOC 2 Type II compliance posture"
    )
    dogfood_p.add_argument(
        "--strict",
        action="store_true",
        help="Fail if compliance score < 95%% or any check fails",
    )
    dogfood_p.add_argument(
        "--json", action="store_true", help="Output full JSON report"
    )
    dogfood_p.add_argument("--output-base", type=Path, default=Path.cwd())

    tc_p = sub.add_parser(
        "trust-center", help="Enterprise Security & Trust Center operations"
    )
    tc_sub = tc_p.add_subparsers(dest="trust_center_command", required=True)
    tc_view_p = tc_sub.add_parser(
        "view", help="View current Trust Center security metrics"
    )
    tc_view_p.add_argument("--output-base", type=Path, default=Path.cwd())
    tc_export_p = tc_sub.add_parser(
        "export-html", help="Generate standalone Trust Center HTML file"
    )
    tc_export_p.add_argument(
        "--output-file",
        type=Path,
        default=Path("TRUST_CENTER.html"),
        help="Destination HTML path",
    )
    tc_export_p.add_argument("--output-base", type=Path, default=Path.cwd())

    siem_p = sub.add_parser(
        "siem", help="Export and stream RFC 5424 audit logs to SIEM platforms"
    )
    siem_sub = siem_p.add_subparsers(dest="siem_command", required=True)
    siem_exp_p = siem_sub.add_parser(
        "export", help="Export audit logs to local NDJSON file"
    )
    siem_exp_p.add_argument(
        "--output-ndjson",
        type=Path,
        default=Path("siem_export.ndjson"),
        help="Output NDJSON file",
    )
    siem_exp_p.add_argument(
        "--limit", type=int, default=500, help="Max records to export"
    )
    siem_exp_p.add_argument("--output-base", type=Path, default=Path.cwd())
    siem_fwd_p = siem_sub.add_parser(
        "forward", help="Forward audit events to live SIEM endpoint"
    )
    siem_fwd_p.add_argument(
        "--target",
        required=True,
        choices=["splunk", "datadog", "webhook"],
        help="SIEM target type",
    )
    siem_fwd_p.add_argument("--url", default="", help="Splunk HEC or Webhook URL")
    siem_fwd_p.add_argument(
        "--token", default="", help="Splunk HEC token or Datadog API key"
    )
    siem_fwd_p.add_argument(
        "--limit", type=int, default=100, help="Max records to stream"
    )
    siem_fwd_p.add_argument("--output-base", type=Path, default=Path.cwd())

    return parser


def _run_interactive_command(args: list[str]) -> int:
    original_argv = list(sys.argv)
    try:
        sys.argv = [original_argv[0], *args]
        try:
            main()
            return 0
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 1
    finally:
        sys.argv = original_argv


def _prompt_provider() -> str | None:
    choices = {
        "1": "aws",
        "2": "gcp",
        "3": "azure",
        "aws": "aws",
        "gcp": "gcp",
        "azure": "azure",
    }
    while True:
        print()
        print("Choose cloud provider:")
        print("  1. AWS (Amazon Web Services)")
        print("  2. GCP (Google Cloud Platform)")
        print("  3. Azure (Microsoft Azure)")
        print("  Q. Back")
        choice = input("Provider: ").strip().lower()
        if choice in {"q", "quit", "back"}:
            return None
        provider = choices.get(choice)
        if provider:
            return provider
        print("Invalid provider choice.")


def _windows_launcher(parser: argparse.ArgumentParser) -> None:
    root = install_root()
    previous_cwd = Path.cwd()
    os.chdir(root)
    try:
        while True:
            print()
            print("=" * 60)
            print(f"SOC2 Sentinel Toolkit v{__version__}")
            print("=" * 60)
            print("  1. Run live audit (AWS)")
            print("  2. Validate provider credentials")
            print("  3. Run all collectors")
            print("  4. Show command-line help")
            print("  Q. Exit")
            print()
            choice = input("Select an option: ").strip().lower()

            if choice in {"q", "quit", "exit", "0"}:
                print("Closing SOC2 Sentinel.")
                return

            if choice == "1":
                command = [
                    "run-all",
                    "--provider",
                    "aws",
                    "--output-base",
                    str(root),
                    "--continue-on-error",
                ]
                exit_code = _run_interactive_command(command)
            elif choice == "2":
                provider = _prompt_provider()
                if provider is None:
                    continue
                exit_code = _run_interactive_command(
                    ["validate", "--provider", provider]
                )
            elif choice == "3":
                provider = _prompt_provider()
                if provider is None:
                    continue
                command = [
                    "run-all",
                    "--provider",
                    provider,
                    "--output-base",
                    str(root),
                    "--continue-on-error",
                ]
                exit_code = _run_interactive_command(command)
            elif choice == "4":
                parser.print_help()
                exit_code = 0
            else:
                print("Invalid choice.")
                continue

            print()
            if exit_code == 0:
                print("Operation completed.")
            else:
                print(f"Operation finished with exit code {exit_code}.")
            input("Press Enter to return to the menu...")
    except (EOFError, KeyboardInterrupt):
        print()
        print("Closing SOC2 Sentinel.")
    finally:
        os.chdir(previous_cwd)


def _handle_frozen_windows_no_args(parser: argparse.ArgumentParser) -> bool:
    """Launch an interactive menu when the packaged Windows EXE is double-clicked."""
    if len(sys.argv) != 1:
        return False
    if sys.platform != "win32" or not getattr(sys, "frozen", False):
        return False

    _windows_launcher(parser)
    return True


def _apply_cli_overrides(
    cfg: SentinelConfig, args: argparse.Namespace
) -> SentinelConfig:
    if getattr(args, "redact_pii", False):
        cfg.evidence.redact_pii = True
    if getattr(args, "continue_on_error", False):
        cfg.run_all.continue_on_error = True
    if getattr(args, "allow_unknown_control", False):
        cfg.validation.strict_allowlist = False
    if getattr(args, "log_file", None):
        cfg.logging.file = str(args.log_file)
    return cfg


def _startup_validate(cfg: SentinelConfig, args: argparse.Namespace) -> dict[str, Any]:
    warnings = cfg.validate()
    report: dict[str, Any] = {
        "version": __version__,
        "config_valid": True,
        "warnings": warnings,
        "schema_path": str(install_root() / "data" / "evidence-schema.json"),
    }
    load_schema()
    if getattr(args, "output_base", None) is not None:
        resolve_safe_output_base(args.output_base)
    if getattr(args, "control_id", None):
        sanitize_control_id(
            args.control_id,
            strict_allowlist=cfg.validation.strict_allowlist,
        )
    return report


def _run_collector(
    name: str,
    *,
    provider_name: str,
    cfg: SentinelConfig,
    output_base: Path,
    control_id: str | None = None,
) -> Path:
    provider = get_provider(provider_name, cfg)
    control = control_id or DEFAULT_CONTROL[name]
    if control_id:
        sanitize_control_id(control, strict_allowlist=cfg.validation.strict_allowlist)
    timer = AuditTimer()
    try:
        path = COLLECTORS[name](
            provider,
            control_id=control,
            base=output_base,
            config=cfg,
        )
        append_audit_event(
            base=output_base,
            command="run",
            provider=provider_name,
            control_id=control,
            collector=name,
            outcome="success",
            duration_ms=timer.duration_ms,
        )
        return path
    except SentinelError as exc:
        append_audit_event(
            base=output_base,
            command="run",
            provider=provider_name,
            control_id=control,
            collector=name,
            outcome="error",
            duration_ms=timer.duration_ms,
            details=exc.to_dict(),
        )
        raise


def main() -> None:
    parser = _parser()
    if _handle_frozen_windows_no_args(parser):
        return
    args = parser.parse_args()

    try:
        cfg = load_config(args.config)
        cfg = _apply_cli_overrides(cfg, args)
    except ValidationError as exc:
        logger.error("%s", exc.message)
        sys.exit(2)

    configure_logging(verbose=args.verbose, log_file=cfg.logging.file)

    try:
        health = _startup_validate(cfg, args)
    except ValidationError as exc:
        logger.error("%s", exc.message)
        sys.exit(2)

    if args.command == "validate":
        provider_name = args.provider or "aws"
        try:
            get_provider(provider_name, cfg)
            health["provider"] = provider_name
            health["provider_status"] = "ok"
        except ProviderError as exc:
            health["provider"] = provider_name
            health["provider_status"] = "error"
            health["provider_error"] = exc.message
            print(json.dumps(health, indent=2))
            sys.exit(1)
        print(json.dumps(health, indent=2))
        return

    if args.command == "verify":
        result = verify_evidence_tree(args.evidence_dir)
        print(json.dumps(result, indent=2))
        if result.get("failed"):
            sys.exit(1)
        return

    if args.command == "watch":
        import time

        from sentinel.telemetry import TELEMETRY, AuditEvent

        print("=== SOC2 Sentinel Real-Time Telemetry Stream ===")
        print("Streaming continuous compliance, audit, and drift events... (Ctrl+C to stop)\n")

        def _on_live_event(event: AuditEvent) -> None:
            ts = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{ts}] [{event.severity.name:7s}] {event.action:25s} -> {event.resource} ({event.outcome})")
            if event.details:
                print(f"    Details: {json.dumps(event.details)}")

        unsub = TELEMETRY.subscribe(_on_live_event)
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\nStopped real-time telemetry stream.")
        finally:
            unsub()
        return

    output_base = getattr(args, "output_base", None)
    if output_base is not None:
        try:
            resolve_safe_output_base(output_base)
        except ValidationError as exc:
            logger.error("%s", exc.message)
            sys.exit(2)

    if args.command in {"run", "run-all"}:
        provider_name = args.provider
        try:
            get_provider(provider_name, cfg)
            if args.dry_run:
                print(
                    json.dumps(
                        {
                            "dry_run": True,
                            "provider": provider_name,
                            "status": "ok",
                            **health,
                        },
                        indent=2,
                    )
                )
                return
        except ProviderError as exc:
            logger.error("%s", exc.message)
            sys.exit(1)

    if args.command == "report":
        try:
            json_path, md_path = generate_self_assessment_report(
                args.input, output_dir=args.output_dir, mode=args.mode
            )
            print(
                json.dumps({"json": str(json_path), "markdown": str(md_path)}, indent=2)
            )
        except ValidationError as exc:
            logger.error("%s", exc.message)
            sys.exit(2)
        return

    if args.command in {"serve", "dashboard"}:
        from sentinel.dashboard.server import run_dashboard_server

        enable_daemon = bool(args.daemon or (args.poll_interval is not None))
        interval = args.poll_interval if args.poll_interval is not None else 3600

        run_dashboard_server(
            host=args.host,
            port=args.port,
            output_base=args.output_base,
            config=cfg,
            enable_daemon=enable_daemon,
            daemon_interval=interval,
            provider=args.provider,
            open_browser=not args.no_browser,
        )
        return

    if args.command == "scorecard":
        from sentinel.scoring import compute_compliance_scorecard

        ev_base = (args.output_base / "evidence") if args.output_base else None
        sc = compute_compliance_scorecard(
            ev_base, date_str=args.date, provider=args.provider
        )
        print(json.dumps(sc.to_dict(), indent=2))
        return

    if args.command == "drift":
        from sentinel.drift import detect_configuration_drift

        ev_base = (args.output_base / "evidence") if args.output_base else None
        dr = detect_configuration_drift(
            ev_base, baseline_date=args.baseline, current_date=args.current
        )
        print(json.dumps(dr.to_dict(), indent=2))
        return

    if args.command == "audit-pack":
        from sentinel.reporting import export_audit_pack

        try:
            zip_p = export_audit_pack(args.evidence_dir, output_dir=args.output_dir)
            print(json.dumps({"status": "ok", "audit_pack_zip": str(zip_p)}, indent=2))
        except Exception as exc:
            logger.error("%s", exc)
            sys.exit(1)
        return

    if args.command == "policy":
        from sentinel.policy import PolicyEngine

        engine = PolicyEngine()
        if args.policy_command == "list":
            print(json.dumps([r.to_dict() for r in engine.rules.values()], indent=2))
            return
        elif args.policy_command == "evaluate":
            state = {}
            if args.state_file and args.state_file.exists():
                try:
                    state = json.loads(args.state_file.read_text(encoding="utf-8"))
                except Exception as ex:
                    logger.error("Failed to read state file: %s", ex)
                    sys.exit(1)
            report = engine.evaluate(state)
            print(json.dumps(report.to_dict(), indent=2))
            if report.rules_failed > 0:
                sys.exit(1)
            return

    if args.command == "github":
        from sentinel.connectors.github import GitHubConnector

        if args.github_command == "audit":
            connector = GitHubConnector(
                repo=args.repo,
                token=args.token,
            )
            gh_report = connector.audit(default_branch=args.branch)
            print(json.dumps(gh_report.to_dict(), indent=2))
            if not gh_report.compliant:
                sys.exit(1)
            return

    if args.command == "tenant":
        from sentinel.tenancy import TenantStorageManager

        mgr = TenantStorageManager(args.output_base)
        if args.tenant_command == "list":
            print(json.dumps({"tenants": mgr.list_tenants()}, indent=2))
            return
        elif args.tenant_command == "create":
            try:
                t_ctx = mgr.create_tenant(args.slug)
                print(
                    json.dumps(
                        {
                            "status": "created",
                            "tenant_id": t_ctx.tenant_id,
                            "paths": t_ctx.to_dict(),
                        },
                        indent=2,
                    )
                )
                return
            except Exception as ex:
                logger.error("Failed creating tenant: %s", ex)
                sys.exit(1)

    if args.command == "token":
        from sentinel.auth import Role, TokenManager, UserIdentity

        if args.token_command == "create":
            role_enum = getattr(Role, args.role, Role.SYSTEM_USER)
            user_identity = UserIdentity(
                user_id=args.user, role=role_enum, tenant_id=args.tenant
            )
            token = TokenManager.create_token(
                user_identity, expires_in_seconds=args.expires
            )
            print(
                json.dumps({"token": token, "user": user_identity.to_dict()}, indent=2)
            )
            return

    if args.command == "vault":
        from sentinel.vault import EvidenceVault

        vault = EvidenceVault(args.output_base)
        if args.vault_command == "verify":
            res = vault.verify_chain(tenant_id=args.tenant)
            print(json.dumps(res, indent=2))
            if not res.get("valid", False):
                sys.exit(1)
            return
        elif args.vault_command == "seal":
            try:
                block = vault.seal_run(args.evidence_dir, tenant_id=args.tenant)
                print(json.dumps(block.to_dict(), indent=2))
                return
            except Exception as ex:
                logger.error("Failed to seal evidence run: %s", ex)
                sys.exit(1)

    if args.command == "vendor-risk":
        from sentinel.vendor_risk import (
            DataClassification,
            SecurityQuestionnaire,
            Vendor,
            VendorRiskManager,
            VendorTier,
        )

        vrm = VendorRiskManager(args.output_base)
        if args.vrm_command == "list":
            print(json.dumps([v.to_dict() for v in vrm.list_vendors()], indent=2))
            return
        elif args.vrm_command == "report":
            vrm_report = vrm.generate_cc92_report()
            print(json.dumps(vrm_report, indent=2))
            if not vrm_report.get("compliant", False):
                sys.exit(1)
            return
        elif args.vrm_command == "add":
            q = SecurityQuestionnaire(
                has_soc2_type2=bool(args.soc2_expires),
                soc2_report_date=args.soc2_expires,
                dpa_executed=args.dpa,
                enforces_mfa=args.mfa,
                encrypts_data_at_rest=args.encryption,
            )
            vendor = Vendor(
                vendor_id=args.id,
                name=args.name,
                service_description="Enterprise vendor service",
                tier=VendorTier(args.tier),
                data_classification=DataClassification(args.classification),
                soc2_valid_until=args.soc2_expires,
                questionnaire=q,
            )
            saved = vrm.save_vendor(vendor)
            print(json.dumps(saved.to_dict(), indent=2))
            return

    if args.command == "onboarding":
        from sentinel.onboarding import diagnose_all_providers, generate_minimal_policy

        cfg = (
            load_config(args.config)
            if hasattr(args, "config") and args.config
            else SentinelConfig()
        )
        diag = diagnose_all_providers(cfg)
        prov_diag = diag.get(args.provider, {})
        policy = generate_minimal_policy(args.provider)
        result = {
            "provider": args.provider,
            "status": prov_diag.get("status", "unknown"),
            "diagnostics": prov_diag,
            "recommended_policy": policy,
        }
        if args.format == "json":
            print(json.dumps(result, indent=2))
        else:
            print(f"=== Onboarding Diagnostics: {args.provider.upper()} ===")
            print(f"Status: {prov_diag.get('status', 'unknown')}")
            for chk in prov_diag.get("checks", []):
                print(
                    f" - [{chk.get('status')}] {chk.get('name')}: {chk.get('message')}"
                )
            print("\nRecommended Minimal IAM Policy:")
            print(json.dumps(policy, indent=2))
        return

    if args.command == "access-review":
        from sentinel.access_review import AccessReviewManager, ReviewDecision

        uar = AccessReviewManager(args.output_base)
        if args.uar_command == "list":
            print(json.dumps([c.to_dict() for c in uar.list_campaigns()], indent=2))
            return
        elif args.uar_command == "start":
            iam_data = {"provider": "cli_admin", "users": []}
            if args.evidence_file and args.evidence_file.exists():
                try:
                    iam_data = json.loads(
                        args.evidence_file.read_text(encoding="utf-8")
                    )
                except Exception as ex:
                    logger.error("Failed reading evidence file: %s", ex)
                    sys.exit(1)
            else:
                # Search latest IAM collector evidence in evidence_dir if available
                ev_dir = args.output_base / "evidence"
                if ev_dir.exists():
                    latest_runs = sorted(
                        [
                            d
                            for d in ev_dir.iterdir()
                            if d.is_dir() and d.name != "manifests"
                        ],
                        key=lambda d: d.name,
                    )
                    if latest_runs:
                        iam_file = latest_runs[-1] / "CC6.1" / "report.json"
                        if not iam_file.exists():
                            iam_file = (
                                latest_runs[-1] / "iam_access_review" / "report.json"
                            )
                        if iam_file.exists():
                            try:
                                iam_data = json.loads(
                                    iam_file.read_text(encoding="utf-8")
                                )
                            except Exception:
                                pass
            try:
                camp = uar.create_campaign_from_evidence(
                    campaign_id=args.id,
                    title=args.title,
                    period=args.period,
                    due_date=args.due_date,
                    iam_evidence=iam_data,
                )
                print(json.dumps(camp.to_dict(), indent=2))
                return
            except ValueError as ve:
                logger.error("Failed to start campaign: %s", ve)
                sys.exit(1)
        elif args.uar_command == "decide":
            camp_target = uar.get_campaign(args.id)
            if camp_target is None:
                logger.error("Campaign '%s' not found", args.id)
                sys.exit(1)
            found = False
            for it in camp_target.items:
                if it.item_id == args.item_id:
                    it.record_decision(
                        decision=ReviewDecision(args.decision),
                        reviewer=args.reviewer,
                        notes=args.notes,
                    )
                    found = True
                    break
            if not found:
                logger.error(
                    "Item '%s' not found in campaign '%s'", args.item_id, args.id
                )
                sys.exit(1)
            uar.save_campaign(camp_target)
            print(json.dumps(camp_target.to_dict(), indent=2))
            return
        elif args.uar_command == "signoff":
            camp_target = uar.get_campaign(args.id)
            if camp_target is None:
                logger.error("Campaign '%s' not found", args.id)
                sys.exit(1)
            if camp_target.pending_count > 0:
                logger.error(
                    "Cannot sign off campaign '%s': %d items remain pending review decisions.",
                    args.id,
                    camp_target.pending_count,
                )
                sys.exit(1)
            try:
                sig_hash = camp_target.complete_and_sign(
                    args.signer, signing_secret=args.secret
                )
                uar.save_campaign(camp_target)
                print(
                    json.dumps(
                        {
                            "campaign_id": camp_target.campaign_id,
                            "sign_off_hash": sig_hash,
                            "status": "COMPLETED",
                        },
                        indent=2,
                    )
                )
                return
            except ValueError as ve:
                logger.error("Signoff failed: %s", ve)
                sys.exit(1)

    if args.command == "notify":
        from sentinel.notifications import (
            AlertSeverity,
            ComplianceAlert,
            NotificationChannel,
            NotificationManager,
        )

        channel = getattr(
            NotificationChannel,
            args.channel.upper(),
            NotificationChannel.GENERIC_WEBHOOK,
        )
        severity = getattr(AlertSeverity, args.severity.upper(), AlertSeverity.WARNING)
        alert = ComplianceAlert(
            title=args.title,
            message=args.message,
            severity=severity,
            control_id=args.control,
        )
        delivered = NotificationManager.send_webhook(
            webhook_url=args.webhook,
            alert=alert,
            channel=channel,
        )
        print(json.dumps({"delivered": delivered, "alert": alert.to_dict()}, indent=2))
        if not delivered:
            sys.exit(1)
        return

    if args.command == "audit-room":
        from sentinel.audit_room import AuditRoomManager

        arm = AuditRoomManager(args.output_base)
        if args.audit_room_command == "list":
            print(json.dumps([r.to_dict() for r in arm.list_rooms()], indent=2))
            return
        elif args.audit_room_command == "create":
            created_room = arm.create_room(
                room_id=args.id,
                title=args.title,
                auditor_email=args.auditor,
                period_start=args.start,
                period_end=args.end,
                expires_days=args.expires_days,
                notes=args.notes,
            )
            print(json.dumps(created_room.to_dict(), indent=2))
            return
        elif args.audit_room_command == "export":
            try:
                pkg_path = arm.export_audit_package_zip(
                    args.id, output_path=args.output_zip
                )
                print(
                    json.dumps(
                        {
                            "status": "exported",
                            "room_id": args.id,
                            "package_path": str(pkg_path),
                        },
                        indent=2,
                    )
                )
            except Exception as e:
                logger.error("Failed exporting audit room package: %s", e)
                sys.exit(1)
            return

    if args.command == "dogfood":
        from sentinel.dogfood import DogfoodAssessor

        assessor = DogfoodAssessor(args.output_base)
        dogfood_rep = assessor.run_assessment()
        if args.json:
            print(json.dumps(dogfood_rep.to_dict(), indent=2))
        else:
            print("=" * 60)
            print(
                f"SOC2 Sentinel Dogfooding Assessment — Grade: {dogfood_rep.grade} ({dogfood_rep.compliance_score:.1f}%)"
            )
            print("=" * 60)
            print(
                f"Status: {dogfood_rep.status} | Passed: {dogfood_rep.passed_checks} | Failed: {dogfood_rep.failed_checks} | Warnings: {dogfood_rep.warning_checks}"
            )
            print("-" * 60)
            for chk in dogfood_rep.checks:
                status_sym = (
                    "[PASS]"
                    if chk.status == "PASS"
                    else "[WARN]" if chk.status == "WARN" else "[FAIL]"
                )
                print(f"  {status_sym:7s} {chk.criterion:6s} {chk.title}")
                if chk.status != "PASS" and chk.remediation:
                    print(f"          Remediation: {chk.remediation}")
            print("=" * 60)

        if args.strict and (
            dogfood_rep.failed_checks > 0 or dogfood_rep.compliance_score < 95.0
        ):
            sys.exit(1)
        return

    if args.command == "trust-center":
        from sentinel.trust_center import TrustCenterManager

        tcm = TrustCenterManager(args.output_base)
        if args.trust_center_command == "view":
            print(json.dumps(tcm.get_profile().to_dict(), indent=2))
            return
        elif args.trust_center_command == "export-html":
            tc_html = tcm.generate_trust_center_html()
            args.output_file.write_text(tc_html, encoding="utf-8")
            print(
                json.dumps(
                    {"status": "exported", "file": str(args.output_file)}, indent=2
                )
            )
            return

    if args.command == "siem":
        from sentinel.siem import SIEMExporter

        siem_exp = SIEMExporter(args.output_base)
        if args.siem_command == "export":
            rec_cnt = siem_exp.export_to_ndjson_file(
                args.output_ndjson, limit=args.limit
            )
            print(
                json.dumps(
                    {
                        "status": "exported",
                        "records": rec_cnt,
                        "file": str(args.output_ndjson),
                    },
                    indent=2,
                )
            )
            return
        elif args.siem_command == "forward":
            if args.target == "splunk":
                s_ok, s_cnt, s_msg = siem_exp.forward_to_splunk_hec(
                    args.url, args.token
                )
                print(
                    json.dumps(
                        {"success": s_ok, "forwarded": s_cnt, "message": s_msg},
                        indent=2,
                    )
                )
                if not s_ok:
                    sys.exit(1)
            elif args.target == "datadog":
                d_ok, d_cnt, d_msg = siem_exp.forward_to_datadog(args.token)
                print(
                    json.dumps(
                        {"success": d_ok, "forwarded": d_cnt, "message": d_msg},
                        indent=2,
                    )
                )
                if not d_ok:
                    sys.exit(1)
            elif args.target == "webhook":
                w_ok, w_cnt, w_msg = siem_exp.forward_to_webhook(
                    args.url, secret_key=args.token
                )
                print(
                    json.dumps(
                        {"success": w_ok, "forwarded": w_cnt, "message": w_msg},
                        indent=2,
                    )
                )
                if not w_ok:
                    sys.exit(1)
            return

    if args.command == "run":
        if args.control_id:
            try:
                sanitize_control_id(
                    args.control_id,
                    strict_allowlist=cfg.validation.strict_allowlist,
                )
            except ValidationError as exc:
                logger.error("%s", exc.message)
                sys.exit(2)
        try:
            path = _run_collector(
                args.collector,
                provider_name=args.provider,
                cfg=cfg,
                output_base=args.output_base,
                control_id=args.control_id,
            )
            print(str(path))
        except SentinelError as exc:
            logger.error("%s", exc.message)
            sys.exit(1)
        return

    if args.command == "run-all":
        results: dict[str, str] = {}
        errors: dict[str, str] = {}
        timer = AuditTimer()
        for name, control in RUN_ALL_MAPPING.items():
            try:
                path = _run_collector(
                    name,
                    provider_name=args.provider,
                    cfg=cfg,
                    output_base=args.output_base,
                    control_id=control,
                )
                results[name] = str(path)
            except SentinelError as exc:
                errors[name] = exc.message
                if not cfg.run_all.continue_on_error:
                    break
        append_audit_event(
            base=args.output_base,
            command="run-all",
            provider=args.provider,
            outcome="success" if not errors else "partial" if results else "error",
            duration_ms=timer.duration_ms,
            details={"errors": errors, "completed": list(results.keys())},
        )
        summary = {"results": results, "errors": errors}
        print(json.dumps(summary, indent=2))
        if errors:
            sys.exit(1)


if __name__ == "__main__":
    main()
