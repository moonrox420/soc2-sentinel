from __future__ import annotations

import argparse
import json
from pathlib import Path

from sentinel.collectors import COLLECTORS
from sentinel.collectors.self_assessment_report import generate_self_assessment_report
from sentinel.providers import get_provider

RUN_ALL_MAPPING = {
    "iam_access_review": "CC6.1",
    "log_aggregator": "CC7.1",
    "config_drift": "CC6.2",
    "encryption_status": "C1.2",
    "retention_check": "C1.4",
    "resilience_testing": "A1.2",
    "zt_continuous_verification": "ZT-1",
}

DEFAULT_CONTROL = {
    "iam_access_review": "CC6.1",
    "log_aggregator": "CC7.1",
    "config_drift": "CC6.2",
    "encryption_status": "C1.2",
    "retention_check": "C1.4",
    "resilience_testing": "A1.2",
    "zt_continuous_verification": "ZT-1",
}


def main() -> None:
    parser = argparse.ArgumentParser(description="SOC2 Sentinel evidence automation v2.3")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="Run an evidence collector")
    run_p.add_argument("collector", choices=sorted(COLLECTORS.keys()))
    run_p.add_argument("--provider", default="mock", choices=["aws", "gcp", "azure", "mock"])
    run_p.add_argument("--control-id", default=None)
    run_p.add_argument("--output-base", type=Path, default=Path.cwd())

    all_p = sub.add_parser("run-all", help="Run all collectors")
    all_p.add_argument("--provider", default="mock", choices=["aws", "gcp", "azure", "mock"])
    all_p.add_argument("--output-base", type=Path, default=Path.cwd())

    report_p = sub.add_parser("report", help="Generate assessment report")
    report_p.add_argument("--input", type=Path, required=True)
    report_p.add_argument("--output-dir", type=Path, default=None)
    report_p.add_argument("--mode", default="cmmc", choices=["cmmc", "zt"])

    args = parser.parse_args()

    if args.command == "report":
        json_path, md_path = generate_self_assessment_report(
            args.input, output_dir=args.output_dir, mode=args.mode
        )
        print(json.dumps({"json": str(json_path), "markdown": str(md_path)}, indent=2))
        return

    provider = get_provider(args.provider)

    if args.command == "run-all":
        results = {}
        for name, control in RUN_ALL_MAPPING.items():
            path = COLLECTORS[name](provider, control_id=control, base=args.output_base)
            results[name] = str(path)
        print(json.dumps(results, indent=2))
        return

    control_id = args.control_id or DEFAULT_CONTROL[args.collector]
    path = COLLECTORS[args.collector](provider, control_id=control_id, base=args.output_base)
    print(str(path))


if __name__ == "__main__":
    main()