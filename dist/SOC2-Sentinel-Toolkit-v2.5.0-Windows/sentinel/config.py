from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel.errors import ValidationError


@dataclass
class EvidenceConfig:
    encrypt: bool = False
    redact_pii: bool = False
    manifest_backup: bool = True


@dataclass
class ThresholdConfig:
    orphaned_accounts_red: int = 7
    orphaned_accounts_yellow: int = 3
    iam_review_days_red: int = 90


@dataclass
class ValidationConfig:
    strict_allowlist: bool = True


@dataclass
class LoggingConfig:
    file: str | None = None


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
    validation: ValidationConfig = field(default_factory=ValidationConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    provider: ProviderConfig = field(default_factory=ProviderConfig)
    run_all: RunAllConfig = field(default_factory=RunAllConfig)
    source_path: Path | None = None

    def validate(self) -> list[str]:
        """Startup validation. Raises ValidationError on hard failures; returns warnings."""
        warnings: list[str] = []

        if self.evidence.encrypt:
            key = os.environ.get("SENTINEL_EVIDENCE_KEY", "").strip()
            key_file = os.environ.get("SENTINEL_EVIDENCE_KEY_FILE", "").strip()
            if not key and not key_file:
                raise ValidationError(
                    "evidence.encrypt is true but SENTINEL_EVIDENCE_KEY or "
                    "SENTINEL_EVIDENCE_KEY_FILE is not set"
                )
            if key_file and not Path(key_file).is_file():
                raise ValidationError(f"SENTINEL_EVIDENCE_KEY_FILE not found: {key_file}")

        yellow = self.thresholds.orphaned_accounts_yellow
        red = self.thresholds.orphaned_accounts_red
        if yellow < 0 or red < 0 or self.thresholds.iam_review_days_red < 0:
            raise ValidationError("threshold values must be non-negative integers")
        if yellow >= red:
            raise ValidationError(
                f"orphaned_accounts_yellow ({yellow}) must be less than "
                f"orphaned_accounts_red ({red})"
            )

        if self.source_path and self.source_path.exists() and os.name != "nt":
            mode = self.source_path.stat().st_mode
            if mode & stat.S_IROTH or mode & stat.S_IWOTH:
                warnings.append(
                    f"sentinel.yaml is world-readable ({oct(mode & 0o777)}); "
                    "recommend chmod 600"
                )
            if self.source_path.stat().st_uid != os.getuid():
                warnings.append("sentinel.yaml is not owned by the current user")

        return warnings


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _safe_int(value: Any, *, field_name: str, default: int) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"thresholds.{field_name} must be an integer") from exc


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
    validation_raw = data.get("validation", {})
    logging_raw = data.get("logging", {})
    provider_raw = data.get("provider", {})
    run_all_raw = data.get("run_all", {})

    cfg = SentinelConfig(
        evidence=EvidenceConfig(
            encrypt=_coerce_bool(evidence_raw.get("encrypt", False)),
            redact_pii=_coerce_bool(evidence_raw.get("redact_pii", False)),
            manifest_backup=_coerce_bool(evidence_raw.get("manifest_backup", True)),
        ),
        thresholds=ThresholdConfig(
            orphaned_accounts_red=_safe_int(
                thresholds_raw.get("orphaned_accounts_red"), field_name="orphaned_accounts_red", default=7
            ),
            orphaned_accounts_yellow=_safe_int(
                thresholds_raw.get("orphaned_accounts_yellow"),
                field_name="orphaned_accounts_yellow",
                default=3,
            ),
            iam_review_days_red=_safe_int(
                thresholds_raw.get("iam_review_days_red"), field_name="iam_review_days_red", default=90
            ),
        ),
        validation=ValidationConfig(
            strict_allowlist=_coerce_bool(validation_raw.get("strict_allowlist", True)),
        ),
        logging=LoggingConfig(
            file=logging_raw.get("file"),
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