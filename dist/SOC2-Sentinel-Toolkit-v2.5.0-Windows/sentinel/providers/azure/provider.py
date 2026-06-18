from __future__ import annotations

import logging
from typing import Any

from sentinel.providers.azure import config as azure_config
from sentinel.providers.azure import encryption as azure_encryption
from sentinel.providers.azure import iam as azure_iam
from sentinel.providers.azure import logging as azure_logging
from sentinel.providers.azure import resilience as azure_resilience
from sentinel.providers.azure import retention as azure_retention
from sentinel.providers.azure._client import AzureContext
from sentinel.providers.azure._zt import zt_verification_snapshot as azure_zt
from sentinel.providers.base import Provider

logger = logging.getLogger("sentinel.providers.azure")


class AzureProvider(Provider):
    name = "azure"

    def __init__(self, subscription_id: str | None = None) -> None:
        self._ctx = AzureContext(subscription_id=subscription_id)

    def validate_credentials(self) -> None:
        logger.info("validating Azure credentials", extra={"provider": "azure"})
        self._ctx.validate_credentials()
        logger.info("Azure credential validation succeeded", extra={"provider": "azure", "outcome": "ok"})

    def _fresh(self) -> AzureContext:
        return AzureContext(subscription_id=self._ctx.subscription_id)

    def iam_access_snapshot(self) -> dict[str, Any]:
        return azure_iam.iam_access_snapshot(self._fresh())

    def log_monitoring_snapshot(self) -> dict[str, Any]:
        return azure_logging.log_monitoring_snapshot(self._fresh())

    def config_and_auth_snapshot(self) -> dict[str, Any]:
        return azure_config.config_and_auth_snapshot(self._fresh())

    def encryption_snapshot(self) -> dict[str, Any]:
        return azure_encryption.encryption_snapshot(self._fresh())

    def retention_snapshot(self) -> dict[str, Any]:
        return azure_retention.retention_snapshot(self._fresh())

    def resilience_snapshot(self) -> dict[str, Any]:
        return azure_resilience.resilience_snapshot(self._fresh())

    def zt_verification_snapshot(self) -> dict[str, Any]:
        return azure_zt(self._fresh())