from __future__ import annotations

import logging
import os
from typing import Any

from sentinel.errors import ProviderError
from sentinel.providers._snapshot import api_error

logger = logging.getLogger("sentinel.providers.gcp")


class GcpContext:
    def __init__(self, project_id: str | None = None, credentials: Any | None = None) -> None:
        resolved_project_id = project_id or os.environ.get("GOOGLE_CLOUD_PROJECT")
        self.credentials = credentials
        self.errors: list[dict[str, Any]] = []
        self._checks_attempted = 0
        self._checks_succeeded = 0
        if not resolved_project_id:
            raise ProviderError(
                "GCP provider requires GOOGLE_CLOUD_PROJECT or provider.gcp_project_id in sentinel.yaml"
            )
        self.project_id: str = resolved_project_id

    def get_credentials(self) -> Any:
        if self.credentials is not None:
            return self.credentials

        import google.auth

        credentials, _ = google.auth.default()
        if not credentials:
            raise ProviderError("GCP Application Default Credentials not found.")
        self.credentials = credentials
        return credentials

    def validate_credentials(self) -> None:
        try:
            self.get_credentials()
        except Exception as exc:
            raise ProviderError(f"GCP credential validation failed: {exc}") from exc

    def attempt(self) -> None:
        self._checks_attempted += 1

    def succeed(self) -> None:
        self._checks_succeeded += 1

    def record_error(self, service: str, exc: Exception, *, code: str = "ApiError") -> None:
        self.errors.append(api_error(code, str(exc), service=service, severity="high"))
