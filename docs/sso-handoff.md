# SSO hand-off: moving between Vetfab services without signing in again

Phase 2 of the identity platform. A person signed in to one Vetfab service (say the LMS) opens another (the IDE)
and lands there signed in, in either direction, without typing credentials. Each service still starts and governs its
own session. Normal authentication stays with the Phase 1 adapter ([adapter.md](adapter.md)); this is only the
coordination of the move between services.

| Piece | Where |
|---|---|
| Ticket issuing and redemption, service registry | identity service: `identity/handoff.py`, `identity/services.py`, `identity/web/handoff_routes.py`, migration `0004` |
| Destination side (redeem, own session, CSRF) | `sdk/python`: `HandoffRedeemer`, `SessionCookie`, `handoff_router`, `IdentityGuard(sessions=…)` |
| Source side (list services, start a hand-off) | `sdk/js`: `HandoffClient` (`createHandoffClient`), React `VetfabServiceSwitcher` |
| Two-service demo | `sdk/example` |

## 1. What the existing contract can and cannot do

Established from the code (`tokens.py`, `sessions.py`, `web/routes.py`), not assumed:

| Question | Answer | Consequence |
|---|---|---|
| Is the access token single-use? | **No.** `jti` is random but never recorded; it verifies any number of times for 15 minutes | Cannot be a one-time ticket |
| Bound to a recipient? | **No.** `aud=vetfab` is the same for every product; any product that holds a token can present it to any other product's backend | Cannot be destination-bound |
| Bound to a session? | **No.** It carries only `sub`; signing out does not stop it before `exp` | Survives logout |
| Where does it travel? | In the URL fragment of `<app>/handoff#token=…`, readable by page scripts | A reusable bearer credential in the browser |
| Who may get one? | Any allowlisted app origin, silently, with the refresh cookie (`GET /auth/login`) | Fine for sign-in; not a handoff authorisation |
| What is a "session"? | A rotating refresh-token family on the identity host; revoked on logout, reuse, suspension | Revocable: a ticket can be tied to it |

So an ordinary access token is **not** a secure handoff ticket, and this design does not treat it as one. Sign-in
(Phase 1) is unchanged and keeps working exactly as before. The handoff is a new, explicit operation on the identity
service.

## 2. Architecture and trust boundaries

```
 Source service page (LMS)        Identity service                  Destination backend (IDE)
 ─────────────────────────        ────────────────                  ─────────────────────────
 1. GET  /auth/services  ───────▶ registry, filtered for this person
    (refresh cookie, CORS: registered origins only)
 2. POST /auth/handoff {target, return_to}  ───▶ checks: session alive, Origin = registered source service,
    (refresh cookie, JSON)                        target registered+enabled+visible; issues a ticket
                          ◀─── {ticket, redeem_url (from the registry), expires_in}
 3. form POST ticket=…  ─────────────────────────────────────────────▶ POST /handoff/redeem   (browser navigation)
    (body, not URL)                                                     4. POST /auth/handoff/redeem  ◀── service secret
                                                  consumes the ticket atomically, checks it is for THIS service,
                                                  not expired, session not revoked, account active ──▶ {user_id,
                                                  source_origin, return_path}
                                                                        5. Origin header == source_origin ?
                                                                        6. its own load_user: provisioned here?
                                                                        7. Set-Cookie: its own session; 303 → return_path
 8. the destination page loads signed in (GET /handoff/session → cookie session)
```

Trust boundaries: the **browser** is untrusted (it carries the ticket but cannot read or alter its meaning); the
**identity service** is the authority on who the person is and which services exist; each **destination backend** is
the authority on whether that person may use it, and the only thing that ever sees a redeemed identity. The
**destination's session cookie** is its own: signed with a key only it holds, scoped to its own host.

Why this is separate from application authentication: the adapter answers "who is making this request" on every API
call, using a token the browser holds. The handoff answers "this person, already signed in over there, wants to be
signed in here". They have different credentials (access token vs one-time ticket), different lifetimes (15 minutes
vs 60 seconds) and different recipients, and mixing them would let a leaked access token act as a handoff.

## 3. The ticket

32 random bytes (256 bits, base64url), stored only as SHA-256 in `identity.handoff_tickets`. Bound at issue to the
person, the central session (refresh-token family), the source service, **one** destination service and a return path.
Lifetime `IDENTITY_HANDOFF_TICKET_SECONDS` (default 60, range 10 to 300).

| Property | How |
|---|---|
| Single use, atomic | `UPDATE … SET consumed_at = now() WHERE ticket_hash = … AND consumed_at IS NULL RETURNING …`: of any number of racing redemptions exactly one gets the row (tested with 12 at once) |
| Destination-bound | Redeemable only by the service it was issued for, authenticated with that service's secret. Presented by another service, it is refused **and consumed**, so a stolen ticket cannot be retried by anyone |
| User- and session-bound | Redemption also requires the central session not revoked or expired and the account still active, so signing out, password change, or suspension kills outstanding tickets |
| Short-lived | Expires in seconds; expired tickets are refused and purged |
| Not in logs | Hashed at rest; audit rows carry service ids and a refusal reason, never a ticket; the SDK never logs it |
| Not in a URL | The ticket travels in a form POST body and the 303 that follows carries none, so it never reaches history, Referer, analytics, or page scripts. The redeem URL itself is taken from the registry |
| Bounded | A session may hold at most 20 unredeemed tickets (429 beyond) |

Every refusal reason (unknown, reused, expired, wrong service, session ended, inactive) gives the caller the same
`400 invalid_ticket`; the reason is in the audit log (`handoff_rejected`).

### Login CSRF

An attacker could sign in as themselves, obtain a ticket and send a victim's browser to the destination with it,
signing the victim in as the attacker. Defence: a destination accepts a ticket only when the browser's `Origin`
header is the origin of the ticket's **source service**. A cross-site form POST always carries `Origin`; an attacker's
own page cannot forge one for the LMS. Consequence for source pages: **do not send `Referrer-Policy: no-referrer` (or
`same-origin`) on pages that host the switcher**: browsers then send `Origin: null` and the destination refuses the
ticket. `strict-origin-when-cross-origin` (the default) is correct.

## 4. Identity-server changes (what must be deployed)

* Migration `0004_handoff_tickets` (new table with RLS, three new audit actions). Run `alembic upgrade head` as for any release.
* New settings: `IDENTITY_SERVICES` (the registry, JSON) and `IDENTITY_HANDOFF_TICKET_SECONDS`. Both default to off/60;
  with no registry, the three new routes answer 403/401 and nothing else changes.
* New routes (all under `/auth`): `GET /services`, `POST /handoff`, `POST /handoff/redeem`.
* `identity-admin service-secret` generates a redemption secret and its hash.
* Deploy: `SERVICES_JSON` and `HANDOFF_TICKET_SECONDS` in `deploy/.env` (see `env.template`).
* **No change to the token contract** ([CONTRACT.md](../CONTRACT.md)), the sign-in routes, or the LMS/IDE verifiers.

## 5. Service registry

> **Since Phase 3 the registry lives in the database and is managed in the developer portal** ([developer-portal.md](developer-portal.md)).
> `IDENTITY_SERVICES` below is now only a **seed**: services missing from the database are inserted at start-up and an existing
> row is never overwritten. Everything in this section about fields and rules still applies, and is enforced by the same
> validation for both paths. A destination whose service has been disabled is told so (`403 service_disabled`).

`IDENTITY_SERVICES` (JSON; validated when the service starts, so a mistake stops the deploy naming the entry):

```json
{"services": [
  {"id": "lms", "display_name": "Vetfab LMS", "base_url": "https://lms.example", "environment": "production",
   "secret_sha256": "<hex>"},
  {"id": "ide", "display_name": "Vetfab IDE", "base_url": "https://ide.example", "roles": ["admin"],
   "callback_path": "/handoff/redeem", "enabled": true, "secret_sha256": "<hex>"}
]}
```

| Field | Meaning |
|---|---|
| `id` | Stable identifier (`a-z0-9-`, 2 to 32 chars). What the SDK sends as the target |
| `base_url` | The service's origin. Must also be in `IDENTITY_APP_ORIGINS` (use `EXTRA_APP_ORIGINS`), so the sign-in allowlist and the registry cannot drift; https required on a deployed service |
| `callback_path` | Where the destination receives tickets; default `/handoff/redeem`. The redeem URL is `base_url + callback_path`, never taken from a request |
| `environment` | `local`, `staging` or `production`: a label shown in the switcher. `local` is refused on a deployed identity service |
| `roles` | Optional list drawn from `public.users.role` (`admin`, `beta_user`). If present, only those accounts see the service or can start a hand-off to it |
| `enabled` | `false` hides the service and refuses tickets for it |
| `secret_sha256` | SHA-256 of the service's redemption secret (below) |

**Visibility is not authorisation.** `roles` hides a service in the menu and stops the identity service issuing a
ticket, but the destination's own `load_user` and role checks are what grant access. An origin on the allowlist is
not a registry entry, and a registry entry is not access.

Separate environments: each identity deployment has its own registry. A staging identity service lists staging
services; the production one lists production (and, if wanted, the staging **service** as a destination with
`"environment": "staging"`, which is how "hand off to an authorised staging environment" works). Production
refuses `local` entries and plain-http URLs.

### Secrets

```bash
identity-admin service-secret
# VETFAB_SERVICE_SECRET=<secret>        <- give to the service (server-side only, never in a frontend bundle)
# "secret_sha256": "<hash>"             <- goes in the registry
```

The identity service holds only the hash; the secret has 256 bits of entropy. Rotating: generate a new pair, deploy the
new hash and the service's new secret together (a short window of refused redemptions is the cost; users retry).

## 6. Destination integration (backend)

```python
from vetfab_identity_adapter import AdapterConfig, HandoffConfig, HandoffRedeemer, IdentityAdapter, SessionCookie
from vetfab_identity_adapter.fastapi import IdentityGuard, handoff_router

adapter_config = AdapterConfig.from_env()
handoff_config = HandoffConfig.from_env(adapter_config, os.environ)
sessions = SessionCookie(handoff_config)
guard = IdentityGuard(IdentityAdapter(adapter_config), load_user, sessions=sessions, app_origin=handoff_config.app_url)
app.include_router(
    handoff_router(
        HandoffRedeemer(adapter_config, handoff_config), sessions, load_user, app_origin=handoff_config.app_url
    )
)
```

Environment: `VETFAB_SERVICE_ID`, `VETFAB_SERVICE_SECRET`, `VETFAB_SESSION_SECRET` (32+ characters, unique per service),
`VETFAB_APP_URL`, optional `VETFAB_SESSION_SECONDS` (default 900, max 3600). Every problem is reported at start-up.

* `POST /handoff/redeem` receives the form, redeems server to server, checks `Origin`, asks **your** `load_user` whether
  this person has an account here (None: 403 page, no cookie), then starts your session and 303s to the return path.
* The session cookie is `__Host-vf_session` (`vf_session` over plain http for localhost): HttpOnly, Secure, SameSite=Lax,
  host-only, signed with HMAC-SHA256 over `{sub, service, iat, exp}` and your own key. It names the service, so another
  service's cookie, or the same key under a different service id, is rejected. It carries no role: your `load_user`
  reads status and roles on every request.
* `IdentityGuard` accepts the cookie **only when there is no `Authorization` header** (an invalid bearer is never
  rescued by a cookie) and requires `Origin == app_origin` on POST/PUT/PATCH/DELETE (CSRF).
* `GET /handoff/session` tells the page whether it holds a session; `POST /handoff/logout` ends this service's session.
* Failures: 400 invalid/expired/used ticket, 403 wrong source page or no account here, 503 identity unreachable or this
  service's credentials refused (an operator problem, logged without secrets). No failure leaves a cookie behind.

`redeemHandoff(request)` in the proposed API is `HandoffRedeemer.redeem(ticket)`: redemption is server-side only, by design.

## 7. Source integration (frontend)

```tsx
const client = createIdentityClient({ authUrl, sessionUrl: "/handoff/session", sessionLogoutUrl: "/handoff/logout" });
const handoff = createHandoffClient(client);

<VetfabServiceSwitcher handoff={handoff} currentService="lms" returnTo="/workspace" />
```

`HandoffClient`: `listAvailableServices()`, `getServiceUrl(id, returnTo?)` (plain link, **no** sign-in), `createHandoff(id,
{ returnTo })`, `getSnapshot()` / `subscribe()` with states `idle`, `loading`, `ready`, `starting`, `redirecting`, `error`
and error codes `unknown_service`, `service_unavailable`, `session_expired`, `too_many_tickets`, `network`,
`invalid_response`, `source_not_registered`.

What the browser does check: the target must be in the list the identity service returned; the ticket must look like
one; the redemption address must be on **the same origin as that service's registry `base_url`**, otherwise nothing is
posted. What it deliberately does not do: validate the handoff. A second click while one is in progress returns the
first call's promise. `validateHandoffState(state)` from the proposal does not exist: there is no client-held state,
because the one-time ticket is validated by the identity service and the destination's backend, and a check in the
browser would be no boundary.

`VetfabServiceSwitcher`: lists the other services this person may open (production-less ones are labelled), shows a
busy state and "Signing you in…", maps errors to messages with a dismiss button, ignores repeated activation, and is a
menu button with `aria-haspopup`, `aria-expanded`, `role=menu` and arrow/Home/End/Escape/Tab keys. It is not an
authorisation boundary.

With `sessionUrl` set, the page recognises the cookie session a handoff started (`snapshot.mode === "session"`),
sends the cookie only to its own origin, re-checks when it expires or an API call answers 401, and `logout()` ends the
local session before the central one. Without it nothing changes from Phase 1.

## 8. Authorisation and isolation

* Every service starts **its own** session after its **own** `load_user`. A handoff never copies a token or cookie
  between services; no cookie is sent across domains.
* A person who is an administrator in the LMS is whatever the IDE's records say in the IDE (tested: admin in one, member
  in the other, 403 on the admin endpoint). A person the destination has never provisioned gets no session.
* Workspace permissions and every application check stay inside the destination.
* **`aud=vetfab` implications.** Because every product accepts the one audience, an access token minted for a sign-in
  at one product is also acceptable to another product's backend. The handoff does not use access tokens, so it does not
  widen that, but it does not fix it either: per-service audiences would need the identity service to mint per `redirect`
  origin and every verifier to check its own audience, a coordinated contract change (CLAUDE.md). Recommended for a
  later release; not done here.

## 9. Logout and session expiry

| Action | Effect |
|---|---|
| `client.logout()` on a service | Ends **that service's** cookie session (if any), then POSTs to the identity service, which revokes the central session. Outstanding tickets die; no new handoff or silent sign-in works. |
| Other services' sessions | **Not revoked.** A destination's own session cookie is outside the identity service's reach and lasts until it expires (`VETFAB_SESSION_SECONDS`, default 15 minutes, max 1 hour). Logout is therefore **global for sign-in and handoff, local for already-established destination sessions**. Do not describe it as global sign-out. |
| Local logout only (`POST /handoff/logout`) | Clears one service's cookie; the central session and the other services are untouched |
| Account suspended | Central sessions are revoked immediately; each service's `load_user` re-reads status on every request, so access ends at once there |
| Failed / expired / replayed ticket | No cookie is ever set; the person is shown a short message and the central session is unaffected |

To shorten the window, lower `VETFAB_SESSION_SECONDS` or have `load_user` consult a service-specific revocation list.

## 10. Local demo (two independent services)

Needs the identity service's Postgres (`docker compose -f dev/docker-compose.yml up -d`, `alembic upgrade head`).

```bash
# one secret per service; keep the printed secrets, and put the hashes in the registry below
identity-admin service-secret     # run twice: one for "lms", one for "ide"

# 1. identity service (:8200) with both demo services registered
export IDENTITY_ENVIRONMENT=development IDENTITY_ISSUER=http://localhost:8200/auth IDENTITY_AUDIENCE=vetfab \
       IDENTITY_APP_ORIGINS=http://localhost:8300,http://localhost:8301 IDENTITY_KEYS_DIR=./.dev-keys \
       IDENTITY_DATABASE_URL=postgresql://identity:identity-local-only@127.0.0.1:54331/identity
export IDENTITY_SERVICES='{"services":[
 {"id":"lms","display_name":"Demo LMS","base_url":"http://localhost:8300","secret_sha256":"<lms hash>"},
 {"id":"ide","display_name":"Demo IDE","base_url":"http://localhost:8301","secret_sha256":"<ide hash>"}]}'
uv run uvicorn --factory identity.web.app:create_app --port 8200

# 2. build the browser SDK once
(cd sdk/js && npm ci && npm run build)

# 3. the two services (separate terminals); each has its own secret, session key, name and users
export VETFAB_AUTH_URL=http://localhost:8200 VETFAB_ENVIRONMENT=development PYTHONPATH=sdk/python/src
VETFAB_SERVICE_ID=lms VETFAB_SERVICE_SECRET=<lms secret> VETFAB_SESSION_SECRET=<32+ chars> \
  VETFAB_APP_URL=http://localhost:8300 DEMO_SERVICE_NAME="Demo LMS" DEMO_ADMIN_IDS=<your user id> \
  uv run uvicorn --app-dir sdk/example main:app --port 8300
VETFAB_SERVICE_ID=ide VETFAB_SERVICE_SECRET=<ide secret> VETFAB_SESSION_SECRET=<another 32+ chars> \
  VETFAB_APP_URL=http://localhost:8301 DEMO_SERVICE_NAME="Demo IDE" \
  uv run uvicorn --app-dir sdk/example main:app --port 8301
```

Open <http://localhost:8300>, sign in, press "Open Demo IDE": the IDE page loads signed in with mode `session`, and
`GET /api/admin` answers 200 on the LMS (you are its administrator) and 403 on the IDE (you are not). Add
`DEMO_MEMBER_IDS=<someone else's id>` to the IDE to see a valid identity refused with no session.

On Windows, psycopg's async mode needs the selector event loop for the identity service (works as is on Linux/macOS/CI).

## 11. Adding a future service (staging included)

1. Choose its origin per environment and add it to the identity deployment's `EXTRA_APP_ORIGINS`.
2. `identity-admin service-secret`; add an entry to `SERVICES_JSON` with the hash (set `"environment": "staging"` for staging, `roles` to restrict visibility). Redeploy the identity service (the registry is validated at start-up).
3. In the service's backend: `VETFAB_SERVICE_ID`, `VETFAB_SERVICE_SECRET`, `VETFAB_SESSION_SECRET` (unique), `VETFAB_APP_URL`, and the §6 wiring with its own `load_user`.
4. In its frontend: `createIdentityClient({ authUrl, sessionUrl, sessionLogoutUrl })`, `createHandoffClient`, and `<VetfabServiceSwitcher … />`.
5. No change to any other service: they learn of it from `GET /auth/services`.

## 12. Integrating the real LMS and IDE

Their repositories were not available here, so **neither is integrated**; this is the contract to follow, keeping
their user models, roles and workspace checks as they are.

* **LMS** (`packages/authz`, `apps/web`): register `lms`; add the §6 router at its `callback_path` in the API (or the
  web app's server, whichever terminates browser requests; the web app's `/bff` layer fits); `load_user` = the existing
  "find the user, read status and roles from `public.users`/`lms` tables" lookup, returning None for unknown or
  inactive accounts. Keep bearer auth for the web app's API calls; the cookie session is for people arriving by handoff.
  Add the switcher to the account menu in place of the "Open IDE" link.
* **IDE** (`backend/app/security`, frontend): register `ide`; same router in the backend, `load_user` = its existing
  user lookup including approval status and username onboarding (a user it has never seen goes to onboarding, per
  CONTRACT.md, instead of a 403 page, if preferred). Its workspace permission checks are untouched and still apply.
* Both: set `VETFAB_SESSION_SECRET` to different values; make sure no source page sets `Referrer-Policy: no-referrer`;
  keep services on `https` and, for the refresh cookie, on the same site as the identity host.

## 13. Threat model and limits

| Threat | Mitigation |
|---|---|
| Replay of a captured ticket | Single use, 60 s, atomic consume, bound to destination |
| Ticket stolen in the browser | Useless without the destination's secret; a different service's attempt burns it |
| Ticket used by another service | Refused and consumed |
| Forged or guessed ticket | 256-bit, hashed at rest, uniform `invalid_ticket` |
| Open redirect | Destination is the registry's; return path is a screened same-origin path, re-screened at the destination |
| Login CSRF via an attacker's ticket | `Origin` must equal the source service's origin |
| CSRF on cookie-authenticated requests | `Origin == app_origin` required on state-changing requests; SameSite=Lax |
| Cross-service leakage | Ticket in a form body; no token or cookie crosses services; Referrer-Policy no-referrer on the redeem response |
| Rogue service listing / poisoned list | The SDK drops malformed entries and refuses a redeem address off the service's origin |
| Stolen service secret | Lets an attacker redeem tickets issued to that service only; rotate the pair. Secrets are server-side only |
| Leaked tickets/secrets in logs | Never logged by the identity service or adapters; verified by tests |

Limits: an XSS on a **registered source service** can start a handoff as the signed-in person (it can already call that
service's API); a destination's session outlives central logout by up to its TTL (§9); the refresh cookie needs the
services on the same site as the identity host; the `Origin` check needs a browser (curl can set it, but cannot obtain
a ticket for someone else's session).

## 14. Troubleshooting

| Symptom | Cause |
|---|---|
| Switcher is disabled or empty | No services visible: not registered, `enabled: false`, `roles` excludes this person, or this is the only service |
| `source_not_registered` | This page's origin is not a registry `base_url` (port, scheme or `www` differ) |
| `session_expired` | The central session ended: sign in again |
| Destination page "sign-in did not come from a Vetfab service" | The source page sent `Origin: null` (a `no-referrer` policy), or a different origin than the registry's |
| Destination 503 "not reachable" | Identity service down, or the destination's id/secret does not match the registry (check its log; secrets are never printed) |
| Destination "no access" | `load_user` returned None: the person is not provisioned there |
| Identity service will not start: `IDENTITY_SERVICES: …` | The message names the service and field (origin not in `IDENTITY_APP_ORIGINS`, http on a deployed service, bad hash, …) |
| `429 too_many_tickets` | Over 20 unredeemed tickets on one session |

## 15. Tests

```bash
uv run pytest -q                       # identity service, adapter and cross-service tests (Postgres: docker compose -f dev/docker-compose.yml up -d)
(cd sdk/js && npm test)                # browser SDK and React component
```

`tests/test_handoff.py` (issuing, binding, single use, races, expiry, revocation, destinations, paths, secrecy),
`tests/test_services.py` (registry), `tests/test_handoff_cross_service.py` (LMS↔IDE↔staging, login-CSRF, isolation,
logout), `sdk/python/tests/test_handoff_adapter.py` (redeemer, session cookie, configuration), `sdk/js/tests/handoff.test.ts`,
`session.test.ts`, `switcher.test.tsx`.
