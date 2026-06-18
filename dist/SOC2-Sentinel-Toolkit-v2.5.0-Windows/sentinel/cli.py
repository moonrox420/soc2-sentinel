from __future__ import annotations

import argparse
import json
import logging
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
    parser = argparse.ArgumentParser(description=f"SOC2 Sentinel evidence automation v{__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("--config", type=Path, default=None, help="Path to sentinel.yaml")
    parser.add_argument("--redact-pii", action="store_true", help="Redact PII in exports")
    parser.add_argument("--log-file", type=Path, default=None, help="Structured log file sink")
    parser.add_argument(
        "--allow-unknown-control",
        action="store_true",
        help="Bypass strict control ID allowlist",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    validate_p = sub.add_parser("validate", help="Validate config and provider credentials")
    validate_p.add_argument("--provider", default=None, choices=["aws", "gcp", "azure", "mock"])

    verify_p = sub.add_parser("verify", help="Verify evidence manifest integrity")
    verify_p.add_argument("evidence_dir", type=Path, help="Evidence date directory to verify")

    run_p = sub.add_parser("run", help="Run an evidence collector")
    run_p.add_argument("collector", choices=sorted(COLLECTORS.keys()))
    run_p.add_argument("--provider", default="mock", choices=["aws", "gcp", "azure", "mock"])
    run_p.add_argument("--control-id", default=None)
    run_p.add_argument("--output-base", type=Path, default=Path.cwd())
    run_p.add_argument("--dry-run", action="store_true", help="Validate config/credentials only")

    all_p = sub.add_parser("run-all", help="Run all collectors")
    all_p.add_argument("--provider", default="mock", choices=["aws", "gcp", "azure", "mock"])
    all_p.add_argument("--output-base", type=Path, default=Path.cwd())
    all_p.add_argument("--dry-run", action="store_true", help="Validate config/credentials only")
    all_p.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Continue run-all when a collector fails",
    )

    report_p = sub.add_parser("report", help="Generate assessment report")
    report_p.add_argument("--input", type=Path, required=True)
    report_p.add_argument("--output-dir", type=Path, default=None)
    report_p.add_argument("--mode", default="cmmc", choices=["cmmc", "zt"])
    return parser


def _apply_cli_overrides(cfg: SentinelConfig, args: argparse.Namespace) -> SentinelConfig:
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
        provider_name = args.provider or "mock"
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
                        {"dry_run": True, "provider": provider_name, "status": "ok", **health},
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
            print(json.dumps({"json": str(json_path), "markdown": str(md_path)}, indent=2))
        except ValidationError as exc:
            logger.error("%s", exc.message)
            sys.exit(2)
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