from __future__ import annotations

import logging
import os
from typing import Any

from sentinel.cloud import call_with_retry
from sentinel.errors import ProviderError
from sentinel.providers._snapshot import api_error

logger = logging.getLogger("sentinel.providers.azure")

try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.storage import StorageManagementClient
except ImportError as exc:  # pragma: no cover
    raise ProviderError(
        "Azure dependencies missing. Run: pip install azure-identity azure-mgmt-storage azure-mgmt-resource"
    ) from exc


class AzureContext:
    def __init__(self, subscription_id: str | None = None) -> None:
        self.subscription_id = subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID")
        self.errors: list[dict[str, Any]] = []
        self._checks_attempted = 0
        self._checks_succeeded = 0
        if not self.subscription_id:
            raise ProviderError(
                "Azure provider requires AZURE_SUBSCRIPTION_ID or provider.azure_subscription_id"
            )
        self.credential = DefaultAzureCredential()
        self.storage = StorageManagementClient(self.credential, self.subscription_id)
        self.resource = ResourceManagementClient(self.credential, self.subscription_id)

    def validate_credentials(self) -> None:
        try:
            call_with_retry(
                lambda: next(self.resource.resource_groups.list(), None),
                operation="azure_list_resource_groups",
            )
        except Exception as exc:
            raise ProviderError(
                f"Azure credential validation failed: {exc}. Run az login or configure service principal."
            ) from exc

    def graph_get(self, path: str) -> dict[str, Any] | None:
        import requests

        self.attempt()
        try:
            token = self.credential.get_token("https://graph.microsoft.com/.default")
            url = f"https://graph.microsoft.com/v1.0{path}"
            resp = call_with_retry(
                lambda: requests.get(
                    url,
                    headers={"Authorization": f"Bearer {token.token}"},
                    timeout=30,
                ),
                operation=f"azure_graph_{path}",
            )
            if resp.status_code == 403:
                self.errors.append(
                    api_error("AccessDenied", resp.text[:200], service="graph", severity="high")
                )
                return None
            resp.raise_for_status()
            self.succeed()
            return resp.json()
        except Exception as exc:
            self.record_error("graph", exc)
            return None

    def attempt(self) -> None:
        self._checks_attempted += 1

    def succeed(self) -> None:
        self._checks_succeeded += 1

    def record_error(self, service: str, exc: Exception, *, code: str = "ApiError") -> None:
        self.errors.append(api_error(code, str(exc), service=service, severity="high"))