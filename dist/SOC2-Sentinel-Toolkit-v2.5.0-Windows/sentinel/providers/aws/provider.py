from __future__ import annotations

import logging
from typing import Any

from sentinel.providers.aws import config as aws_config
from sentinel.providers.aws import encryption as aws_encryption
from sentinel.providers.aws import iam as aws_iam
from sentinel.providers.aws import logging as aws_logging
from sentinel.providers.aws import resilience as aws_resilience
from sentinel.providers.aws import retention as aws_retention
from sentinel.providers.aws._client import AwsClients
from sentinel.providers.aws._zt import zt_verification_snapshot as aws_zt
from sentinel.providers.base import Provider

logger = logging.getLogger("sentinel.providers.aws")


class AwsProvider(Provider):
    name = "aws"

    def __init__(self, region: str | None = None) -> None:
        self._ctx = AwsClients(region=region)

    def validate_credentials(self) -> None:
        logger.info("validating AWS credentials", extra={"provider": "aws"})
        self._ctx.validate_credentials()
        logger.info("AWS credential validation succeeded", extra={"provider": "aws", "outcome": "ok"})

    def _fresh_ctx(self) -> AwsClients:
        return AwsClients(region=self._ctx.region)

    def iam_access_snapshot(self) -> dict[str, Any]:
        ctx = self._fresh_ctx()
        return aws_iam.iam_access_snapshot(ctx)

    def log_monitoring_snapshot(self) -> dict[str, Any]:
        ctx = self._fresh_ctx()
        return aws_logging.log_monitoring_snapshot(ctx)

    def config_and_auth_snapshot(self) -> dict[str, Any]:
        ctx = self._fresh_ctx()
        return aws_config.config_and_auth_snapshot(ctx)

    def encryption_snapshot(self) -> dict[str, Any]:
        ctx = self._fresh_ctx()
        return aws_encryption.encryption_snapshot(ctx)

    def retention_snapshot(self) -> dict[str, Any]:
        ctx = self._fresh_ctx()
        return aws_retention.retention_snapshot(ctx)

    def resilience_snapshot(self) -> dict[str, Any]:
        ctx = self._fresh_ctx()
        return aws_resilience.resilience_snapshot(ctx)

    def zt_verification_snapshot(self) -> dict[str, Any]:
        ctx = self._fresh_ctx()
        return aws_zt(ctx)