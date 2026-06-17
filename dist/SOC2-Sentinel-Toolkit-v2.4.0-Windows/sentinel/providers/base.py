from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class Provider(ABC):
    name: str

    def validate_credentials(self) -> None:
        """Optional preflight; cloud providers override."""

    @abstractmethod
    def iam_access_snapshot(self) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def log_monitoring_snapshot(self) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def config_and_auth_snapshot(self) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def encryption_snapshot(self) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def retention_snapshot(self) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def resilience_snapshot(self) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def zt_verification_snapshot(self) -> dict[str, Any]:
        raise NotImplementedError