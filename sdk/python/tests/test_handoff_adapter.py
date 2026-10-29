"""The destination side of an SSO hand-off: configuration, redemption against a fake identity service, session cookie."""

import base64
import json
import logging
import uuid
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from vetfab_identity_adapter import (
    AdapterConfig,
    ConfigError,
    HandoffConfig,
    HandoffRedeemer,
    HandoffRejectedError,
    HandoffUnavailableError,
    SessionCookie,
)

AUTH = "http://localhost:8200"
SECRET, SESSION_KEY = "service-secret-value", "k" * 40
USER = uuid.uuid4()


@pytest.fixture
def adapter_config() -> AdapterConfig:
    return AdapterConfig.build(auth_url=AUTH, environment="development")


def handoff_config(adapter: AdapterConfig, **overrides: Any) -> HandoffConfig:
    values: dict[str, Any] = {
        "service_id": "ide",
        "service_secret": SECRET,
        "session_secret": SESSION_KEY,
        "app_url": "http://localhost:8301",
        **overrides,
    }
    return HandoffConfig.build(adapter, **values)


# --------------------------------------------------------------------------- configuration


def test_environment_configuration(adapter_config: AdapterConfig) -> None:
    config = HandoffConfig.from_env(
        adapter_config,
        {
            "VETFAB_SERVICE_ID": "ide",
            "VETFAB_SERVICE_SECRET": SECRET,
            "VETFAB_SESSION_SECRET": SESSION_KEY,
            "VETFAB_APP_URL": "http://localhost:8301/",
            "VETFAB_SESSION_SECONDS": "600",
        },
    )
    assert (config.service_id, config.app_url, config.session_seconds) == ("ide", "http://localhost:8301", 600)
    assert not config.secure_cookies
    assert SECRET not in repr(config) and SESSION_KEY not in repr(config)  # secrets stay out of logs and tracebacks


def test_every_problem_is_reported_at_once(adapter_config: AdapterConfig) -> None:
    with pytest.raises(ConfigError) as caught:
        HandoffConfig.from_env(adapter_config, {"VETFAB_SESSION_SECONDS": "banana"})
    message = str(caught.value)
    for name in (
        "VETFAB_SERVICE_ID",
        "VETFAB_SERVICE_SECRET",
        "VETFAB_SESSION_SECRET",
        "VETFAB_APP_URL",
        "VETFAB_SESSION_SECONDS",
    ):
        assert name in message


@pytest.mark.parametrize(
    "override",
    [
        {"session_secret": "short"},
        {"session_seconds": 10},
        {"session_seconds": 99999},
        {"app_url": "localhost:8301"},
        {"app_url": "http://localhost:8301/app"},
    ],
)
def test_unsafe_values_are_refused(adapter_config: AdapterConfig, override: dict[str, Any]) -> None:
    with pytest.raises(ConfigError):
        handoff_config(adapter_config, **override)


def test_plain_http_is_refused_when_deployed() -> None:
    deployed = AdapterConfig.build(auth_url="https://auth.example", environment="production")
    with pytest.raises(ConfigError, match="https"):
        handoff_config(deployed, app_url="http://ide.example")
    assert handoff_config(deployed, app_url="https://ide.example").secure_cookies


# --------------------------------------------------------------------------- redemption


class FakeIdentity:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.response: Callable[[httpx.Request], httpx.Response] = lambda request: httpx.Response(
            200,
            json={
                "user_id": str(USER),
                "source_service": "lms",
                "source_origin": "http://localhost:8300",
                "return_path": "/workspace/1",
            },
        )

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.response(request)


@pytest.fixture
def identity() -> FakeIdentity:
    return FakeIdentity()


@pytest.fixture
def redeemer(adapter_config: AdapterConfig, identity: FakeIdentity) -> HandoffRedeemer:
    http = httpx.AsyncClient(transport=httpx.MockTransport(identity))
    return HandoffRedeemer(adapter_config, handoff_config(adapter_config), http=http)


async def test_a_good_ticket_yields_the_person_and_where_to_go(
    redeemer: HandoffRedeemer, identity: FakeIdentity
) -> None:
    result = await redeemer.redeem("t" * 43)
    assert (result.user_id, result.source_service, result.source_origin) == (USER, "lms", "http://localhost:8300")
    assert result.return_path == "/workspace/1"
    request = identity.requests[0]
    assert (request.method, str(request.url)) == ("POST", f"{AUTH}/auth/handoff/redeem")
    assert json.loads(request.content) == {"ticket": "t" * 43}
    sent = request.headers["authorization"]
    assert base64.b64decode(sent.removeprefix("Basic ")).decode() == f"ide:{SECRET}"  # server-side credential only


@pytest.mark.parametrize("ticket", ["", "x" * 300])
async def test_malformed_tickets_never_reach_the_identity_service(
    redeemer: HandoffRedeemer, identity: FakeIdentity, ticket: str
) -> None:
    with pytest.raises(HandoffRejectedError):
        await redeemer.redeem(ticket)
    assert identity.requests == []


async def test_a_refused_ticket_is_rejected(redeemer: HandoffRedeemer, identity: FakeIdentity) -> None:
    identity.response = lambda request: httpx.Response(400, json={"error": "invalid_ticket"})
    with pytest.raises(HandoffRejectedError):
        await redeemer.redeem("t" * 43)


@pytest.mark.parametrize("status", [401, 500, 503])
async def test_other_answers_are_an_outage_not_a_bad_ticket(
    redeemer: HandoffRedeemer, identity: FakeIdentity, status: int
) -> None:
    identity.response = lambda request: httpx.Response(status, json={})
    with pytest.raises(HandoffUnavailableError):
        await redeemer.redeem("t" * 43)


async def test_a_disabled_service_is_told_its_tickets_are_refused(
    redeemer: HandoffRedeemer, identity: FakeIdentity
) -> None:
    identity.response = lambda request: httpx.Response(403, json={"error": "service_disabled"})
    with pytest.raises(HandoffRejectedError):
        await redeemer.redeem("t" * 43)


async def test_an_unreachable_identity_service_is_an_outage(redeemer: HandoffRedeemer, identity: FakeIdentity) -> None:
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    identity.response = down
    with pytest.raises(HandoffUnavailableError):
        await redeemer.redeem("t" * 43)


@pytest.mark.parametrize("body", [{}, {"user_id": "nope", "source_service": "x", "source_origin": "y"}, [], "text"])
async def test_a_malformed_answer_is_an_outage(redeemer: HandoffRedeemer, identity: FakeIdentity, body: Any) -> None:
    identity.response = lambda request: httpx.Response(200, json=body)
    with pytest.raises(HandoffUnavailableError):
        await redeemer.redeem("t" * 43)


@pytest.mark.parametrize("path", ["//evil.example", "https://evil.example", "/a\\b", "/a\nb", None, 5, "x" * 3000])
async def test_the_return_path_is_screened_again_here(
    redeemer: HandoffRedeemer, identity: FakeIdentity, path: Any
) -> None:
    body = {
        "user_id": str(USER),
        "source_service": "lms",
        "source_origin": "http://localhost:8300",
        "return_path": path,
    }
    identity.response = lambda request: httpx.Response(200, json=body)
    assert (await redeemer.redeem("t" * 43)).return_path == "/"


async def test_neither_ticket_nor_secret_is_logged(
    redeemer: HandoffRedeemer, identity: FakeIdentity, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    ticket = "ticket-value-" + "z" * 30
    identity.response = lambda request: httpx.Response(401, json={})
    with pytest.raises(HandoffUnavailableError):
        await redeemer.redeem(ticket)
    assert ticket not in caplog.text and SECRET not in caplog.text


# --------------------------------------------------------------------------- the service's own session


def test_a_session_round_trips(adapter_config: AdapterConfig) -> None:
    sessions = SessionCookie(handoff_config(adapter_config))
    identity = sessions.read(sessions.issue(USER, now=1000), now=1500)
    assert identity is not None and identity.user_id == USER and identity.expires_at == 1900
    assert sessions.name == "vf_session_ide"


def test_a_session_expires(adapter_config: AdapterConfig) -> None:
    sessions = SessionCookie(handoff_config(adapter_config, session_seconds=600))
    value = sessions.issue(USER, now=1000)
    assert sessions.read(value, now=1599) is not None
    assert sessions.read(value, now=1600) is None


def test_a_tampered_session_is_refused(adapter_config: AdapterConfig) -> None:
    sessions = SessionCookie(handoff_config(adapter_config))
    payload, signature = sessions.issue(USER).split(".")
    forged = (
        base64.urlsafe_b64encode(
            json.dumps({"sub": str(uuid.uuid4()), "svc": "ide", "iat": 0, "exp": 9_999_999_999}).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    for value in (f"{forged}.{signature}", f"{payload}.{signature[:-2]}AA", payload, "", "a.b.c", "x" * 2000, None):
        assert sessions.read(value) is None


def test_another_services_session_means_nothing_here(adapter_config: AdapterConfig) -> None:
    ide = SessionCookie(handoff_config(adapter_config))
    other_key = SessionCookie(handoff_config(adapter_config, session_secret="z" * 40))
    other_service = SessionCookie(handoff_config(adapter_config, service_id="lms"))  # same key, different service
    value = ide.issue(USER)
    assert other_key.read(value) is None
    assert other_service.read(value) is None


def test_the_cookie_is_host_only_and_secure_when_deployed() -> None:
    deployed = AdapterConfig.build(auth_url="https://auth.example", environment="production")
    sessions = SessionCookie(handoff_config(deployed, app_url="https://ide.example"))
    assert sessions.name == "__Host-vf_session_ide"
    assert sessions.cookie_attributes() == {
        "max_age": 900,
        "path": "/",
        "secure": True,
        "httponly": True,
        "samesite": "lax",
    }
