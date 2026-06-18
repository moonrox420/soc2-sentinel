from __future__ import annotations

import logging
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

from sentinel.cloud import botocore_config, call_with_retry
from sentinel.errors import ProviderError
from sentinel.providers._snapshot import api_error

logger = logging.getLogger("sentinel.providers.aws")


class AwsClients:
    def __init__(self, region: str | None = None) -> None:
        self.region = region
        self._session = boto3.Session(region_name=region)
        self.errors: list[dict[str, Any]] = []
        self._checks_attempted = 0
        self._checks_succeeded = 0

    def client(self, service: str):
        return self._session.client(service, config=botocore_config())

    def validate_credentials(self) -> None:
        sts = self.client("sts")
        try:
            call_with_retry(
                lambda: sts.get_caller_identity(),
                operation="aws_sts_get_caller_identity",
            )
        except (ClientError, NoCredentialsError, BotoCoreError) as exc:
            raise ProviderError(
                "AWS credentials invalid or missing. Configure AWS_PROFILE or access keys."
            ) from exc

    def record_access_denied(self, service: str, exc: ClientError) -> None:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        if code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}:
            self.errors.append(
                api_error(code, str(exc), service=service, severity="high")
            )
            return
        raise ProviderError(f"AWS {service} API failed: {exc}") from exc

    def attempt(self) -> None:
        self._checks_attempted += 1

    def succeed(self) -> None:
        self._checks_succeeded += 1

    def call(
        self,
        service: str,
        operation: str,
        fn,
        *,
        access_denied_ok: bool = True,
    ) -> Any | None:
        self.attempt()
        try:
            result = call_with_retry(fn, operation=operation)
            self.succeed()
            return result
        except ClientError as exc:
            if access_denied_ok:
                code = exc.response.get("Error", {}).get("Code", "ClientError")
                self.errors.append(
                    api_error(code, str(exc), service=service, severity="high")
                )
                return None
            raise ProviderError(f"AWS {service} {operation} failed: {exc}") from exc
        except (NoCredentialsError, BotoCoreError) as exc:
            raise ProviderError(f"AWS {service} {operation} failed: {exc}") from exc
        return None