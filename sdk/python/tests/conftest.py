"""Fixtures for the adapter tests."""

from collections.abc import Callable

import httpx
import pytest

from fakes import AUTH_URL, Clock, FakeIdentity
from vetfab_identity_adapter import AdapterConfig, IdentityAdapter


@pytest.fixture
def config() -> AdapterConfig:
    return AdapterConfig.build(auth_url=AUTH_URL, environment="development", client_id="test-service")


@pytest.fixture
def identity() -> FakeIdentity:
    return FakeIdentity()


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def make_adapter(config: AdapterConfig, identity: FakeIdentity, clock: Clock) -> Callable[[], IdentityAdapter]:
    def make() -> IdentityAdapter:
        client = httpx.AsyncClient(transport=httpx.MockTransport(identity.handler))
        return IdentityAdapter(config, http=client, clock=clock)

    return make


@pytest.fixture
def adapter(make_adapter: Callable[[], IdentityAdapter]) -> IdentityAdapter:
    return make_adapter()
