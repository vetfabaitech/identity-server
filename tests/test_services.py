"""The service registry: what IDENTITY_SERVICES may say, and what it may not."""

import hashlib
import json
from typing import Any

import pytest

from identity.services import RegistryError, parse_registry

ORIGINS = ["https://lms.example", "https://ide.example"]
HASH = hashlib.sha256(b"secret").hexdigest()


def entry(**overrides: Any) -> dict[str, Any]:
    base = {"id": "lms", "display_name": "LMS", "base_url": "https://lms.example", "secret_sha256": HASH}
    return {**base, **overrides}


def parse(*entries: dict[str, Any], deployed: bool = True, origins: list[str] = ORIGINS) -> Any:
    return parse_registry(json.dumps({"services": list(entries)}), app_origins=origins, deployed=deployed)


def test_empty_means_hand_off_is_off() -> None:
    assert parse_registry("", app_origins=ORIGINS, deployed=True).services == ()


def test_a_valid_registry_resolves_by_id_and_origin() -> None:
    registry = parse(entry(), entry(id="ide", base_url="https://ide.example", roles=["admin"]))
    lms, ide = registry.get("lms"), registry.get("ide")
    assert lms and ide
    assert registry.by_origin("https://ide.example") == ide
    assert ide.redeem_url == "https://ide.example/handoff/redeem"
    assert registry.by_origin("https://evil.example") is None
    assert registry.by_origin(None) is None
    assert [s.id for s in registry.visible_to("beta_user")] == ["lms"]
    assert [s.id for s in registry.visible_to("admin")] == ["lms", "ide"]


def test_disabled_services_do_not_resolve() -> None:
    registry = parse(entry(enabled=False))
    assert registry.get("lms") is None
    assert registry.by_origin("https://lms.example") is None
    assert registry.visible_to("admin") == []


def test_secrets_are_checked_by_hash_and_only_for_enabled_services() -> None:
    registry = parse(entry(), entry(id="ide", base_url="https://ide.example", enabled=False))
    assert registry.authenticate("lms", "secret") is not None
    assert registry.authenticate("lms", "wrong") is None
    assert registry.authenticate("nobody", "secret") is None
    assert registry.authenticate("ide", "secret") is None


@pytest.mark.parametrize(
    ("bad", "message"),
    [
        (entry(base_url="https://other.example"), "not in IDENTITY_APP_ORIGINS"),
        (entry(base_url="https://lms.example/app"), "origin"),
        (entry(base_url="http://lms.example"), "https"),
        (entry(secret_sha256="abc"), "secret_sha256"),
        (entry(secret_sha256=""), "secret_sha256"),
        (entry(id="LMS"), "id"),
        (entry(display_name=""), "display_name"),
        (entry(environment="local"), "local"),
        (entry(environment="prod"), "environment"),
        (entry(roles=["root"]), "roles"),
        (entry(enabled="yes"), "enabled"),
        (entry(callback_path="https://evil.example/x"), "callback_path"),
        (entry(callback_path="/a/../b"), "callback_path"),
    ],
)
def test_unsafe_entries_are_refused(bad: dict[str, Any], message: str) -> None:
    with pytest.raises(RegistryError, match=message):
        parse(bad)


def test_duplicates_are_refused() -> None:
    with pytest.raises(RegistryError, match="same id"):
        parse(entry(), entry(base_url="https://ide.example"))
    with pytest.raises(RegistryError, match="same base_url"):
        parse(entry(), entry(id="ide"))


@pytest.mark.parametrize("text", ["not json", "[]", '{"services": {}}', '{"services": [1]}'])
def test_malformed_documents_are_refused(text: str) -> None:
    with pytest.raises(RegistryError):
        parse_registry(text, app_origins=ORIGINS, deployed=True)


def test_local_http_services_are_fine_in_development() -> None:
    registry = parse(entry(base_url="http://localhost:8300"), deployed=False, origins=["http://localhost:8300"])
    assert registry.get("lms") is not None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("/workspace/3?x=1", "/workspace/3?x=1"),
        ("//evil.example", "/"),
        ("https://evil.example/x", "/"),
        ("/handoff/redeem", "/"),
        ("/handoff/redeem?ticket=x", "/"),
        ("/a/../../b", "/b"),
        (None, "/"),
    ],
)
def test_landing_paths_stay_on_the_service(value: str | None, expected: str) -> None:
    service = parse(entry()).get("lms")
    assert service is not None
    assert service.landing(value) == expected
