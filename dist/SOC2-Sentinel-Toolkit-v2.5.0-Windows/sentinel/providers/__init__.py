from sentinel.config import ProviderConfig, SentinelConfig
from sentinel.providers.aws import AwsProvider
from sentinel.providers.azure import AzureProvider
from sentinel.providers.base import Provider
from sentinel.providers.gcp import GcpProvider
from sentinel.providers.mock import MockProvider

PROVIDERS = {
    "aws": AwsProvider,
    "gcp": GcpProvider,
    "azure": AzureProvider,
    "mock": MockProvider,
}


def get_provider(name: str, config: SentinelConfig | ProviderConfig | None = None) -> Provider:
    try:
        cls = PROVIDERS[name]
    except KeyError as exc:
        raise SystemExit(f"Unknown provider '{name}'. Use: aws, gcp, azure, mock") from exc
    provider_cfg = config.provider if isinstance(config, SentinelConfig) else (config or ProviderConfig())
    if name == "aws":
        instance = cls(region=provider_cfg.aws_region)
    elif name == "gcp":
        instance = cls(project_id=provider_cfg.gcp_project_id)
    elif name == "azure":
        instance = cls(subscription_id=provider_cfg.azure_subscription_id)
    else:
        instance = cls()
    instance.validate_credentials()
    return instance