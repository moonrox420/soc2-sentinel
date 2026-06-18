from __future__ import annotations

import logging
from typing import Any

from sentinel.providers.base import Provider
from sentinel.providers.gcp import config as gcp_config
from sentinel.providers.gcp import encryption as gcp_encryption
from sentinel.providers.gcp import iam as gcp_iam
from sentinel.providers.gcp import logging as gcp_logging
from sentinel.providers.gcp import resilience as gcp_resilience
from sentinel.providers.gcp import retention as gcp_retention
from sentinel.providers.gcp._client import GcpContext
from sentinel.providers.gcp._zt import zt_verification_snapshot as gcp_zt

logger = logging.getLogger("sentinel.providers.gcp")


class GcpProvider(Provider):
    name = "gcp"

    def __init__(self, project_id: str | None = None) -> None:
        self._ctx = GcpContext(project_id=project_id)

    def validate_credentials(self) -> None:
        logger.info("validating GCP credentials", extra={"provider": "gcp"})
        self._ctx.validate_credentials()
        logger.info("GCP credential validation succeeded", extra={"provider": "gcp", "outcome": "ok"})

    def _fresh(self) -> GcpContext:
        return GcpContext(project_id=self._ctx.project_id)

    def iam_access_snapshot(self) -> dict[str, Any]:
        return gcp_iam.iam_access_snapshot(self._fresh())

    def log_monitoring_snapshot(self) -> dict[str, Any]:
        return gcp_logging.log_monitoring_snapshot(self._fresh())

    def config_and_auth_snapshot(self) -> dict[str, Any]:
        return gcp_config.config_and_auth_snapshot(self._fresh())

    def encryption_snapshot(self) -> dict[str, Any]:
        return gcp_encryption.encryption_snapshot(self._fresh())

    def retention_snapshot(self) -> dict[str, Any]:
        return gcp_retention.retention_snapshot(self._fresh())

    def resilience_snapshot(self) -> dict[str, Any]:
        return gcp_resilience.resilience_snapshot(self._fresh())

    def zt_verification_snapshot(self) -> dict[str, Any]:
        return gcp_zt(self._fresh())