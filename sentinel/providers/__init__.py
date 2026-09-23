from sentinel.config import ProviderConfig, SentinelConfig
from sentinel.providers.aws import AwsProvider
from sentinel.providers.azure import AzureProvider
from sentinel.providers.base import Provider
from sentinel.providers.gcp import GcpProvider
from sentinel.providers.mock import MockProvider

PROVIDERS: dict[str, type[Provider]] = {
    "aws": AwsProvider,
    "gcp": GcpProvider,
    "azure": AzureProvider,
    "mock": MockProvider,
}


def get_provider(name: str, config: SentinelConfig | ProviderConfig | None = None) -> Provider:
    if name not in PROVIDERS:
        raise SystemExit(f"Unknown provider '{name}'. Use: aws, gcp, azure, mock")
    provider_cfg = config.provider if isinstance(config, SentinelConfig) else (config or ProviderConfig())
    instance: Provider
    if name == "aws":
        instance = AwsProvider(region=provider_cfg.aws_region)
    elif name == "gcp":
        instance = GcpProvider(project_id=provider_cfg.gcp_project_id)
    elif name == "azure":
        instance = AzureProvider(subscription_id=provider_cfg.azure_subscription_id)
    else:
        instance = MockProvider()
    instance.validate_credentials()
    return instance