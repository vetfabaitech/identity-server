"""The trusted service registry: which Vetfab services exist, where they live, and how they prove who they are.

A hand-off may only go to a service listed here and active; its destination is `base_url + callback_path`, fixed by
the registry, never taken from a request.

Source of truth (docs/developer-portal.md): the registry lives in PostgreSQL (`identity.services`, managed through the
developer portal and `identity/registry_store.py`). `IDENTITY_SERVICES` (JSON, below) only **seeds** it: at start-up a
service that is not yet in the database is inserted from the environment; one that already is, is left exactly as the
database has it (a differing environment entry is logged, never applied). This module holds the model and the one
validation both paths share.

    {"services": [
      {"id": "lms", "display_name": "Vetfab LMS", "base_url": "https://lms.example", "environment": "production",
       "secret_sha256": "<hex SHA-256 of the service's redemption secret>"},
      {"id": "ide", "display_name": "Vetfab IDE", "base_url": "https://ide.example", "roles": ["admin"],
       "callback_path": "/handoff/redeem", "enabled": true, "secret_sha256": "..."}
    ]}

* `secret_sha256`: the service keeps the secret (VETFAB_SERVICE_SECRET) and redeems tickets with it, server to server.
  Only the hash is stored, so neither the environment nor the database holds a usable credential. A secret has 256 bits
  of entropy, so a plain SHA-256 is the right hash.
* `roles`: optional; when present only accounts with one of these `public.users.role` values see the service or may
  start a hand-off to it. That is visibility at the issuer. The destination's own authorisation still decides access.
* `environment`: `local`, `staging` or `production`, a label shown to people. `local` is refused on a deployed service.
* `return_path_prefixes`: optional; when present a hand-off may only land under one of these paths on the service.
* An env-seeded service's `base_url` must also be in IDENTITY_APP_ORIGINS. A managed service's origin joins the
  allowlist only while it is **active**, so a pending registration is never trusted with a sign-in.
"""

import hashlib
import hmac
import json
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

ENVIRONMENTS = ("local", "staging", "production")
# What an administrator may delegate: a developer can register local and staging services, never production.
DEVELOPER_ENVIRONMENTS = ("local", "staging")
ROLES = ("admin", "beta_user")
STATUSES = ("pending", "active", "disabled")
MIN_SESSION_SECONDS, MAX_SESSION_SECONDS, DEFAULT_SESSION_SECONDS = 60, 3600, 900
_ID = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_PATH = re.compile(r"^/[A-Za-z0-9._~/-]{0,128}$")
_PREFIX = re.compile(r"^/[A-Za-z0-9._~/-]{0,127}$")
_DUMMY_HASH = hashlib.sha256(b"no such service").hexdigest()


class RegistryError(ValueError):
    """A registry entry is malformed or unsafe. The message names the entry and the field."""


@dataclass(frozen=True, slots=True)
class Service:
    id: str
    display_name: str
    base_url: str
    environment: str
    enabled: bool  # the registry's view: status == "active"
    callback_path: str
    roles: tuple[str, ...]
    secret_sha256: str
    status: str = "active"
    description: str = ""
    owner_team: str = ""
    owner_user_id: UUID | None = None
    return_path_prefixes: tuple[str, ...] = ()
    session_seconds: int = DEFAULT_SESSION_SECONDS
    source: str = "bootstrap"
    previous_secret_sha256: str | None = None
    previous_secret_expires_at: float | None = None  # epoch seconds
    created_at: datetime | None = None
    updated_at: datetime | None = None

    @property
    def redeem_url(self) -> str:
        return f"{self.base_url}{self.callback_path}"

    def visible_to(self, role: str) -> bool:
        return not self.roles or role in self.roles

    def landing(self, return_path: str | None) -> str:
        """A same-origin path on this service. Anything unsafe, or the redemption route itself, becomes `/`."""
        from identity.redirects import safe_path  # deferred: redirects imports config, which imports this module

        path = safe_path(return_path, "/")
        route = self.callback_path
        if path == route or path.startswith((route + "/", route + "?", route + "#")):
            return "/"
        if self.return_path_prefixes and not any(
            path == p or path.startswith((p + "/", p + "?", p + "#")) for p in self.return_path_prefixes
        ):
            return "/"
        return path

    def accepts_secret(self, presented_hash: str, now: float | None = None) -> bool:
        """Whether a secret with this hash is currently valid: the current one, or the previous one inside its grace."""
        moment = time.time() if now is None else now
        current = hmac.compare_digest(presented_hash, self.secret_sha256)
        previous = self.previous_secret_sha256
        old = hmac.compare_digest(presented_hash, previous or _DUMMY_HASH)
        in_grace = previous is not None and self.previous_secret_expires_at is not None
        return current or (old and in_grace and moment < (self.previous_secret_expires_at or 0))


@dataclass(frozen=True, slots=True)
class Registry:
    services: tuple[Service, ...] = ()

    def get(self, service_id: str) -> Service | None:
        return next((s for s in self.services if s.id == service_id and s.enabled), None)

    def by_origin(self, origin: str | None) -> Service | None:
        return next((s for s in self.services if s.enabled and origin is not None and s.base_url == origin), None)

    def visible_to(self, role: str) -> list[Service]:
        return [s for s in self.services if s.enabled and s.visible_to(role)]

    def authenticate(self, service_id: str, secret: str, now: float | None = None) -> Service | None:
        """The active service whose secret this is. Takes the same work whether or not the service exists."""
        service = self.get(service_id)
        presented = hashlib.sha256(secret.encode()).hexdigest()
        if service is None:
            hmac.compare_digest(presented, _DUMMY_HASH)
            return None
        return service if service.accepts_secret(presented, now) else None


def _origin(entry: str, value: object) -> str:
    parts = urlsplit(value) if isinstance(value, str) else None
    if (
        parts is None
        or parts.scheme not in ("http", "https")
        or not parts.netloc
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
        or parts.username
        or parts.password
    ):
        raise RegistryError(f"{entry}: base_url must be an origin such as https://lms.example (got {value!r}).")
    default_port = {"http": 80, "https": 443}[parts.scheme]
    try:
        port = f":{parts.port}" if parts.port and parts.port != default_port else ""
    except ValueError as exc:
        raise RegistryError(f"{entry}: base_url has an invalid port.") from exc
    return f"{parts.scheme}://{parts.hostname}{port}"


def clean_fields(raw: Mapping[str, Any], *, deployed: bool, label: str, require_secret_hash: bool) -> dict[str, Any]:
    """Validates and normalises the fields of one registry entry; returns only validated values.

    Shared by the environment seed and the developer portal, so both enforce exactly the same rules. `deployed` is
    whether the identity service itself is staging or production: it refuses plain http and `local` services.
    """
    service_id = raw.get("id")
    if not isinstance(service_id, str) or not _ID.match(service_id):
        raise RegistryError(
            f"{label}: id must be lowercase letters, digits and '-' (2-32 characters, starting with a letter)."
        )
    entry = f"service {service_id!r}"
    name = raw.get("display_name")
    if not isinstance(name, str) or not name.strip() or len(name.strip()) > 60:
        raise RegistryError(f"{entry}: display_name is required (at most 60 characters).")
    base_url = _origin(entry, raw.get("base_url"))
    environment = raw.get("environment", "production" if deployed else "local")
    if environment not in ENVIRONMENTS:
        raise RegistryError(f"{entry}: environment must be one of {', '.join(ENVIRONMENTS)}.")
    callback_path = raw.get("callback_path", "/handoff/redeem")
    if (
        not isinstance(callback_path, str)
        or not _PATH.match(callback_path)
        or ".." in callback_path
        or "//" in callback_path
    ):
        raise RegistryError(f"{entry}: callback_path must be a plain path such as /handoff/redeem.")
    roles = raw.get("roles", [])
    if not isinstance(roles, list) or any(role not in ROLES for role in roles):
        raise RegistryError(f"{entry}: roles must be a list drawn from {', '.join(ROLES)}.")
    description = raw.get("description", "")
    if not isinstance(description, str) or len(description) > 500:
        raise RegistryError(f"{entry}: description must be text of at most 500 characters.")
    owner_team = raw.get("owner_team", "")
    if not isinstance(owner_team, str) or len(owner_team) > 60:
        raise RegistryError(f"{entry}: owner_team must be text of at most 60 characters.")
    prefixes = raw.get("return_path_prefixes", [])
    if (
        not isinstance(prefixes, list)
        or len(prefixes) > 20
        or any(not isinstance(p, str) or not _PREFIX.match(p) or ".." in p or "//" in p for p in prefixes)
    ):
        raise RegistryError(f"{entry}: return_path_prefixes must be up to 20 plain paths such as /workspace.")
    session_seconds = raw.get("session_seconds", DEFAULT_SESSION_SECONDS)
    if (
        isinstance(session_seconds, bool)
        or not isinstance(session_seconds, int)
        or not MIN_SESSION_SECONDS <= session_seconds <= MAX_SESSION_SECONDS
    ):
        raise RegistryError(
            f"{entry}: session_seconds must be a whole number from {MIN_SESSION_SECONDS} to {MAX_SESSION_SECONDS}."
        )
    if deployed and not base_url.startswith("https://"):
        raise RegistryError(f"{entry}: base_url must use https on a deployed service.")
    if environment == "production" and not base_url.startswith("https://"):
        raise RegistryError(f"{entry}: a production service must use https.")
    if deployed and environment == "local":
        raise RegistryError(f"{entry}: a local service cannot be registered on a deployed identity service.")
    cleaned: dict[str, Any] = {
        "id": service_id,
        "display_name": name.strip(),
        "base_url": base_url,
        "environment": environment,
        "callback_path": callback_path,
        "roles": tuple(roles),
        "description": description.strip(),
        "owner_team": owner_team.strip(),
        "return_path_prefixes": tuple(prefixes),
        "session_seconds": session_seconds,
    }
    secret_hash = raw.get("secret_sha256", "")
    if require_secret_hash or secret_hash:
        if not isinstance(secret_hash, str) or not _HEX64.match(secret_hash):
            raise RegistryError(f"{entry}: secret_sha256 must be 64 hex characters (identity-admin service-secret).")
        cleaned["secret_sha256"] = secret_hash
    return cleaned


def parse_registry(text: str, *, app_origins: list[str], deployed: bool) -> Registry:
    """Validates IDENTITY_SERVICES (the seed). An empty value is an empty registry."""
    if not text.strip():
        return Registry()
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise RegistryError("IDENTITY_SERVICES is not valid JSON.") from exc
    entries = document.get("services") if isinstance(document, dict) else None
    if not isinstance(entries, list):
        raise RegistryError('IDENTITY_SERVICES must be {"services": [...]}.')
    services: list[Service] = []
    for index, raw in enumerate(entries):
        if not isinstance(raw, dict):
            raise RegistryError(f"services[{index}] must be an object.")
        entry = f"service {raw.get('id', index)!r}"
        enabled = raw.get("enabled", True)
        if not isinstance(enabled, bool):
            raise RegistryError(f"{entry}: enabled must be true or false.")
        fields = clean_fields(raw, deployed=deployed, label=f"services[{index}]", require_secret_hash=True)
        if fields["base_url"] not in app_origins:
            raise RegistryError(
                f"{entry}: {fields['base_url']} is not in IDENTITY_APP_ORIGINS (add it, e.g. through EXTRA_APP_ORIGINS)."
            )
        services.append(
            Service(
                enabled=enabled,
                status="active" if enabled else "disabled",
                **fields,
            )
        )
    for field in ("id", "base_url"):
        values = [getattr(s, field) for s in services]
        if len(values) != len(set(values)):
            raise RegistryError(f"IDENTITY_SERVICES lists the same {field} twice.")
    return Registry(tuple(services))
