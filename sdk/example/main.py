"""A hypothetical Vetfab service that signs people in with the adapter and nothing else. Run it twice (different
ports, ids and secrets) to see two independent services and the SSO hand-off between them.

It owns no login code: the browser side is `sdk/js` (see index.html), the API side is `IdentityGuard`, and the hand-off
destination is `handoff_router`. What it does own is authorisation: who counts as a member or administrator here is this
service's decision, never the identity service's, and never another service's.

Run it against a local identity service (docs/adapter.md "Try it on localhost", docs/sso-handoff.md "Local demo"):

    VETFAB_AUTH_URL=http://localhost:8200 VETFAB_ENVIRONMENT=development \
        uv run uvicorn --app-dir sdk/example main:app --port 8300

For SSO hand-off also set VETFAB_SERVICE_ID, VETFAB_SERVICE_SECRET, VETFAB_SESSION_SECRET and VETFAB_APP_URL.
"""

import os
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from fastapi import Depends, FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from vetfab_identity_adapter import (
    AdapterConfig,
    HandoffConfig,
    HandoffRedeemer,
    IdentityAdapter,
    SessionCookie,
    VerifiedIdentity,
)
from vetfab_identity_adapter.fastapi import IdentityGuard, handoff_router

HERE = Path(__file__).resolve().parent
SDK_DIST = HERE.parent / "js" / "dist"


def _ids(name: str) -> set[UUID]:
    return {UUID(i) for i in os.environ.get(name, "").split(",") if i.strip()}


config = AdapterConfig.from_env()  # fails at start-up, naming every missing or unsafe VETFAB_AUTH_* value
adapter = IdentityAdapter(config)
# This service's own authorisation data. A real service reads its database here.
ADMINS = _ids("DEMO_ADMIN_IDS")
MEMBERS = _ids("DEMO_MEMBER_IDS")  # empty: any signed-in person is a member; set: only these (and admins) are
SERVICE_NAME = os.environ.get("DEMO_SERVICE_NAME", "Demo service")


@dataclass
class Member:
    id: UUID
    is_admin: bool


async def load_member(identity: VerifiedIdentity) -> Member | None:
    if MEMBERS and identity.user_id not in MEMBERS | ADMINS:
        return None  # not provisioned here: a valid identity is not access
    return Member(identity.user_id, identity.user_id in ADMINS)


# SSO hand-off is on when this service has an id in the identity registry.
sessions: SessionCookie | None = None
app_url: str | None = None
if os.environ.get("VETFAB_SERVICE_ID"):
    handoff_config = HandoffConfig.from_env(config, os.environ)
    app_url = handoff_config.app_url
    sessions = SessionCookie(handoff_config)

guard: IdentityGuard[Member] = IdentityGuard(adapter, load_member, sessions=sessions, app_origin=app_url)
app = FastAPI(title=SERVICE_NAME)
if sessions is not None and app_url is not None:
    redeemer = HandoffRedeemer(config, handoff_config)
    app.include_router(handoff_router(redeemer, sessions, load_member, app_origin=app_url))


@app.get("/api/me")
async def me(member: Member = Depends(guard.user)) -> dict[str, object]:
    return {"service": SERVICE_NAME, "id": str(member.id), "is_admin": member.is_admin}


@app.post("/api/note")
async def note(member: Member = Depends(guard.user)) -> dict[str, str]:
    """A state-changing request: with a cookie session it must come from this service's own origin (CSRF)."""
    return {"saved": f"by {member.id}"}


@app.get("/api/admin")
async def admin_only(member: Member = Depends(guard.require(lambda m: m.is_admin, "admin_required"))) -> dict[str, str]:
    return {"secret": f"visible to {SERVICE_NAME} administrators only"}


@app.get("/config.json")
async def public_config() -> dict[str, str | None]:
    """Public values the page needs. Never a secret: the service secret and session key stay in this process."""
    return {
        "authUrl": config.auth_url,
        "serviceName": SERVICE_NAME,
        "sessionUrl": "/handoff/session" if sessions else None,
        "sessionLogoutUrl": "/handoff/logout" if sessions else None,
    }


@app.get("/")
@app.get("/handoff")  # the identity service returns the browser here with the token in the #fragment (sign-in)
async def page() -> FileResponse:
    # Not `no-referrer`: under that policy browsers send `Origin: null` on the hand-off form POST, and the destination
    # (rightly) refuses a ticket that does not come from the source service's origin.
    return FileResponse(
        HERE / "index.html", headers={"Cache-Control": "no-store", "Referrer-Policy": "strict-origin-when-cross-origin"}
    )


if SDK_DIST.is_dir():
    app.mount("/sdk", StaticFiles(directory=SDK_DIST), name="sdk")
