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


def get_provider(name: str) -> Provider:
    try:
        cls = PROVIDERS[name]
    except KeyError as exc:
        raise SystemExit(f"Unknown provider '{name}'. Use: aws, gcp, azure, mock") from exc
    return cls()