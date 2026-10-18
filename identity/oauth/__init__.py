"""Sign-in through GitHub and Google (spec SI-5). See base.py for the shared types."""

from identity.config import Settings
from identity.oauth.base import OAuthError, Profile, Provider, ProviderName
from identity.oauth.github import GitHub
from identity.oauth.google import Google

PROVIDERS: dict[str, Provider] = {"github": GitHub(), "google": Google()}


def configured_providers(settings: Settings) -> list[str]:
    """Providers with both a client id and a secret, in display order."""
    return [name for name, provider in PROVIDERS.items() if provider.configured(settings)]


__all__ = ["PROVIDERS", "OAuthError", "Profile", "Provider", "ProviderName", "configured_providers"]
