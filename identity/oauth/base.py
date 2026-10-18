"""Types shared by the OAuth providers and account resolution (spec SI-5)."""

from dataclasses import dataclass
from typing import Literal, Protocol

import httpx

from identity.config import Settings

ProviderName = Literal["github", "google"]
TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True, slots=True)
class Profile:
    """What a provider says about the person who just signed in. Provider tokens are never kept."""

    provider: ProviderName
    provider_user_id: str
    email: str | None
    # True only when the provider vouches that this person controls `email`.
    email_verified: bool
    display_name: str


class OAuthError(Exception):
    """A sign-in through a provider could not complete.

    `provider`: the provider's API refused or failed. `no_verified_email`: the provider gave no email it has
    verified, so the account cannot be found or created safely.
    """

    def __init__(self, reason: Literal["provider", "no_verified_email"], detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


class Provider(Protocol):
    name: ProviderName
    label: str

    def configured(self, settings: Settings) -> bool: ...

    def authorize_url(self, settings: Settings, state: str) -> str: ...

    async def fetch_profile(
        self, settings: Settings, code: str, client: httpx.AsyncClient | None = None
    ) -> Profile: ...
