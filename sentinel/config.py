from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel.errors import ValidationError


@dataclass
class EvidenceConfig:
    encrypt: bool = False
    redact_pii: bool = False


@dataclass
class ThresholdConfig:
    orphaned_accounts_red: int = 7
    orphaned_accounts_yellow: int = 3
    iam_review_days_red: int = 90


@dataclass
class ProviderConfig:
    aws_region: str | None = None
    gcp_project_id: str | None = None
    azure_subscription_id: str | None = None


@dataclass
class RunAllConfig:
    continue_on_error: bool = False


@dataclass
class SentinelConfig:
    evidence: EvidenceConfig = field(default_factory=EvidenceConfig)
    thresholds: ThresholdConfig = field(default_factory=ThresholdConfig)
    provider: ProviderConfig = field(default_factory=ProviderConfig)
    run_all: RunAllConfig = field(default_factory=RunAllConfig)
    source_path: Path | None = None


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _merge_dict(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_dict(merged[key], value)
        else:
            merged[key] = value
    return merged


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        import yaml
    except ImportError as exc:
        raise ValidationError(
            "PyYAML required to load sentinel.yaml. pip install pyyaml or use environment variables."
        ) from exc
    raw = path.read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValidationError(f"config file must be a mapping: {path}")
    return data


def load_config(path: Path | None = None) -> SentinelConfig:
    data: dict[str, Any] = {}
    config_path = path
    if config_path is None:
        candidate = Path.cwd() / "sentinel.yaml"
        if candidate.exists():
            config_path = candidate
    if config_path is not None:
        if not config_path.exists():
            raise ValidationError(f"config file not found: {config_path}")
        data = _load_yaml(config_path)

    evidence_raw = data.get("evidence", {})
    thresholds_raw = data.get("thresholds", {})
    provider_raw = data.get("provider", {})
    run_all_raw = data.get("run_all", {})

    cfg = SentinelConfig(
        evidence=EvidenceConfig(
            encrypt=_coerce_bool(evidence_raw.get("encrypt", False)),
            redact_pii=_coerce_bool(evidence_raw.get("redact_pii", False)),
        ),
        thresholds=ThresholdConfig(
            orphaned_accounts_red=int(thresholds_raw.get("orphaned_accounts_red", 7)),
            orphaned_accounts_yellow=int(thresholds_raw.get("orphaned_accounts_yellow", 3)),
            iam_review_days_red=int(thresholds_raw.get("iam_review_days_red", 90)),
        ),
        provider=ProviderConfig(
            aws_region=provider_raw.get("aws_region") or os.environ.get("AWS_REGION"),
            gcp_project_id=provider_raw.get("gcp_project_id") or os.environ.get("GOOGLE_CLOUD_PROJECT"),
            azure_subscription_id=provider_raw.get("azure_subscription_id")
            or os.environ.get("AZURE_SUBSCRIPTION_ID"),
        ),
        run_all=RunAllConfig(
            continue_on_error=_coerce_bool(run_all_raw.get("continue_on_error", False)),
        ),
        source_path=config_path,
    )
    return cfg