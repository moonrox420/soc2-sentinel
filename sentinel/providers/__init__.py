from __future__ import annotations

from sentinel.config import ProviderConfig, SentinelConfig
from sentinel.errors import ProviderError
from sentinel.providers.aws import AwsProvider
from sentinel.providers.azure import AzureProvider
from sentinel.providers.base import Provider
from sentinel.providers.gcp import GcpProvider

PROVIDERS: dict[str, type[Provider]] = {
    "aws": AwsProvider,
    "gcp": GcpProvider,
    "azure": AzureProvider,
}


def get_provider(
    name: str, config: SentinelConfig | ProviderConfig | None = None
) -> Provider:
    """Instantiate and validate real-time cloud provider connector (AWS, GCP, Azure)."""
    p_name = name.lower()
    if p_name not in PROVIDERS:
        raise ProviderError(
            f"Unsupported provider '{name}'. Real-time supported cloud providers: aws, gcp, azure"
        )

    provider_cfg = (
        config.provider
        if isinstance(config, SentinelConfig)
        else (config or ProviderConfig())
    )

    instance: Provider
    if p_name == "aws":
        instance = AwsProvider(region=provider_cfg.aws_region)
    elif p_name == "gcp":
        instance = GcpProvider(project_id=provider_cfg.gcp_project_id)
    elif p_name == "azure":
        instance = AzureProvider(subscription_id=provider_cfg.azure_subscription_id)
    else:
        raise ProviderError(f"Provider '{name}' is not configured.")

    instance.validate_credentials()
    return instance
