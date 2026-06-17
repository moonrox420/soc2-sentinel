from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from sentinel.audit import AuditTimer, append_audit_event
from sentinel.collectors import COLLECTORS
from sentinel.collectors.self_assessment_report import generate_self_assessment_report
from sentinel.config import SentinelConfig, load_config
from sentinel.errors import ProviderError, SentinelError, ValidationError
from sentinel.logging_config import configure_logging
from sentinel.providers import get_provider
from sentinel.validation import resolve_safe_output_base

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
    parser = argparse.ArgumentParser(description="SOC2 Sentinel evidence automation v2.4")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("--config", type=Path, default=None, help="Path to sentinel.yaml")
    parser.add_argument("--redact-pii", action="store_true", help="Redact PII in exports")
    sub = parser.add_subparsers(dest="command", required=True)

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
    return cfg


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
    configure_logging(verbose=args.verbose)

    try:
        cfg = load_config(args.config)
        cfg = _apply_cli_overrides(cfg, args)
    except ValidationError as exc:
        logger.error("%s", exc.message)
        sys.exit(2)

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
            provider = get_provider(provider_name, cfg)
            if args.dry_run:
                print(json.dumps({"dry_run": True, "provider": provider_name, "status": "ok"}, indent=2))
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