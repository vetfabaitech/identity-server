# The developer portal: registering and managing Vetfab services

Phase 3. An authorised person registers a service in a web page, receives its credentials and a tailored setup guide,
and an administrator activates it. No file on the identity server is edited and nothing restarts. It builds on the
[adapter](adapter.md) and the [SSO hand-off](sso-handoff.md) and adds no second identity system.

| Piece | Where |
|---|---|
| The page (single-page app, no build step) | `identity/web/static/developer/` (`portal.js`, `portal.css`), served at `/developer/services` |
| The API (all permission checks live here) | `identity/web/admin_routes.py` under `/auth/admin/*` |
| Persistent registry | `identity/registry_store.py`, `identity.services` and `identity.developer_grants` (migration `0005`) |
| Cache of sign-in origins, seed from the environment | `identity/registry_cache.py` |
| Service model and validation shared by the API and the seed | `identity/services.py` |

## 1. Architecture

```
 administrator / developer's browser                    identity service (any number of instances)              PostgreSQL
 ───────────────────────────────────                    ───────────────────────────────────────                 ──────────
 GET /developer/services  (static HTML + JS, no data) ─▶ portal_routes.py
 GET /auth/admin/me       (refresh cookie) ───────────▶ admin_routes._begin: who is this? admin? developer grant? ─▶ users, grants
 GET/POST /auth/admin/services… ──────────────────────▶ role + ownership + CSRF + rate limit + validation + audit ─▶ identity.services (one atomic
                                                                                                                      statement per change)
 services' handoff / list / redeem requests ──────────▶ handoff_routes.py reads identity.services IN THE REQUEST ─▶ (never from process memory)
 sign-in / CORS origin checks ────────────────────────▶ allowlist = IDENTITY_APP_ORIGINS + active services' origins (cache ≤ 5 s)
```

* **Authentication is the identity service's own.** There is no portal login. The portal page sends a signed-out visitor
  through `/auth/login`; the refresh cookie that sign-in sets (it is scoped to `/auth`, which is why the API lives at
  `/auth/admin` and not `/admin`) is the credential, and **every API request re-derives who the caller is from it**:
  account status and `users.role` are read each time, never cached. A suspended or demoted person loses access on their
  next request.
* **The frontend is not the security boundary.** The page hides buttons using the `permissions` the server returns for
  each service; the server re-checks everything. Removing the script changes nothing about what is allowed.
* **Why a vanilla-JS page and not React.** The identity service's frontend is server-rendered HTML, one stylesheet and one
  script, with no build step or Node in its image. The portal follows that: ES modules served as static files under
  `script-src 'self'`, built from text nodes only (never `innerHTML`). It is tested in jsdom with the React SDK's tooling.

### Sign-in for the portal

Sign-in returns the browser to an allowed *return origin* (CONTRACT.md: `<origin>/handoff`). For the portal that origin is
the identity host itself, so it must be one of the allowed origins: add `https://auth.<your domain>` to `EXTRA_APP_ORIGINS`.
`/handoff` on the identity host is a static page that drops the token from the address bar **unread** (the portal uses the
session cookie, not the token) and opens `/developer/services`. Caddy routes `/developer*` and `/handoff` to the service
(`deploy/Caddyfile`).

## 2. Who can do what

| | Administrator (`users.role = admin`, approved) | Developer (an administrator's grant) | Anyone else |
|---|---|---|---|
| Open the portal API | yes | yes | `403 not_authorised` |
| Register a service | any environment | only in a granted environment (`local`, `staging`), **never production** | no |
| See services | all | only those they own; others answer `404`, not `403` (no probing of identifiers) | no |
| Edit name, description, team, visibility, return paths, session length | yes | own | no |
| Edit address, redemption path, environment | any time (an active service needs its id typed) | own, **only while pending** | no |
| **Activate** (`enable`) | yes (production: id typed) | **no** | no |
| Disable | yes (production: id typed) | own | no |
| Rotate / revoke a secret | yes (id typed) | own | no |
| Grant or revoke developers | yes | no | no |

* Owner, status, role and credentials are **never read from a request body**: unknown fields are refused with `400 unknown_field`.
  There is no endpoint that changes anyone's `role`; a developer cannot grant themselves anything.
* **Why only an administrator activates.** An active service's address joins the list of origins that sign-in redirects tokens
  to and that CORS trusts. If a developer could activate their own, they could register a look-alike address and harvest the
  access tokens of anyone who followed a sign-in link. So everything a developer registers starts `pending`, and **nothing is
  activated automatically**, production or not.
* Developers register in `local`/`staging` only; production services are registered by an administrator and also start `pending`.

## 3. Registration and approval workflow

1. **Register** (`#/new`): name, identifier, environment, base URL, redemption path, visibility, optional return-path
   prefixes, session length. The page validates what it can, then shows a **review** screen with the server's checks.
2. The server stores the service as `pending` with the caller as **owner**, generates a secret (256 bits), stores only its
   SHA-256 and returns the secret **once**. The owner sees the integration guide.
3. The owner integrates and tests locally (the guide's steps B to D); a `pending` service can neither send nor receive a
   handoff and is not trusted with a sign-in.
4. **An administrator reviews and activates** (typing the id for production). Activation re-runs validation. Within seconds
   every instance trusts its origin and the switcher offers it to people who may see it.
5. **Production readiness is a person's decision.** The guide's step E lists what is done (registered, activated, https) and what
   only a human can confirm (secret installed, unique session key, tests, browser check); the API never reports a service as
   production-ready (`production_ready: false`).

### Validation (`POST /auth/admin/services/validate`, and on every create, edit and activation)

Unique id; origin form (scheme `http(s)`, host, optional port; **no path, query, fragment or embedded credentials**);
`https` for production and on any deployed identity service; production not on localhost or a private address; `local`
refused on a deployed identity service; redemption path is a plain path (no `..`, no `//`); visibility roles are real
roles; session length 60 to 3600; the address is not the identity host and not another service's; return-path prefixes are
plain paths. **No request is ever made to the address**: validation inspects text only, so the API cannot be pointed at
internal hosts (SSRF). A passing check means "the configuration is acceptable", not "the application works".

## 4. The registry: source of truth

**PostgreSQL (`identity.services`) is the source of truth.** `IDENTITY_SERVICES` (`SERVICES_JSON` in `deploy/.env`) is only a **seed**:

* At start-up (and the first request) any seeded service **missing from the database is inserted** (`source = bootstrap`,
  audited `service_bootstrapped`). A seeded service **already in the database is never overwritten**.
* If a seed entry later differs (another URL, secret or status), the database wins and a warning is logged naming the service.
  Change it in the portal; then remove or leave the seed entry (it is ignored).
* So environment and database cannot overwrite one another unpredictably. Removing a service from the seed does not remove it.
* Existing LMS/IDE/staging configuration keeps working through the transition: the first start after migrating inserts them
  as active with their existing secret hashes; nothing the portal does touches a service it was not asked about (tested).

Consistency across instances (several containers sharing the database):

| What | How it stays consistent |
|---|---|
| Issuing, redeeming and listing hand-offs | Read from the database **inside each request**: a disable, rotation or address change applies to the next call on every instance |
| Each change | One atomic SQL statement; uniqueness (id, address) is enforced by the database, not by a check-then-insert race |
| The sign-in / CORS origin allowlist (`settings.app_origins`) | Rebuilt from the database at most every `IDENTITY_REGISTRY_REFRESH_SECONDS` (default 5) and immediately on the instance that made the change. Worst case: another instance trusts a **disabled** service's origin for up to that many seconds, or does not yet trust a **newly activated** one |

## 5. Credentials

* `secrets.token_urlsafe(32)`: 256 bits. Stored only as SHA-256 (`secret_sha256`, database-checked as 64 hex characters, so a
  plaintext secret cannot be inserted). **Shown once** in the response that creates it (and again only as a new one on
  rotation); no endpoint returns an existing secret; it is never logged, put in a URL, stored in the browser or written into
  a generated file (tests scan logs, audit rows and API responses).
* **Rotation** (`POST …/rotate-secret`, the service id must be typed): the new secret is current at once and the previous one
  keeps working for `IDENTITY_SECRET_ROTATION_GRACE_SECONDS` (default 3600) so the service can be redeployed without dropping
  handoffs. Tick **revoke immediately** to give the old one no grace (handoffs to that service fail until it has the new one).
  `…/revoke-previous-secret` ends the grace early. The decision is read from the database on each redemption.
* Rate limits: portal mutations per administrator per window (`IDENTITY_ADMIN_RATE_LIMIT`, default 60); secret operations get a sixth.
* "Recent authentication" is **not** enforced: a refresh session renews silently, so it cannot prove a recent password entry.
  The compensating controls are the typed confirmation, CSRF protection, rate limits and the audit log. If a recent-sign-in
  requirement is wanted it needs a re-authentication step in the identity service.

## 6. Disabling and decommissioning

`POST …/disable` (`status = disabled`):

* New handoffs **to and from** the service are refused at once; **tickets already issued** involving it are spent
  (`tickets_spent` in the answer) and a redemption of one issued earlier is refused (the destination is told
  `403 service_disabled`, shown as a refused sign-in).
* Its origin leaves the sign-in allowlist within the refresh interval (immediately on the instance that made the change).
* **Nothing else is deleted.** The row, owner, history and audit remain; user accounts and the service's own data are untouched.
  The service role has **no `DELETE` grant** on `identity.services`, so even a bug cannot remove one. Re-enabling is an
  administrator action.
* The service's own already-issued cookie sessions last until they expire (≤ `VETFAB_SESSION_SECONDS`): see [sso-handoff.md](sso-handoff.md) §9.

Decommissioning = disable, rotate/revoke the secret, remove its DNS and deployment. The registration stays as a record.

## 7. Generated integration configuration (`GET …/integration-config`)

Built from the adapter's real configuration keys; it contains **no secret of any kind**.

| Variable | Source |
|---|---|
| `VETFAB_AUTH_URL` (and `VETFAB_AUTH_ISSUER` / `VETFAB_AUTH_AUDIENCE` if the identity service differs from the defaults) | **from the portal** |
| `VETFAB_ENVIRONMENT` (`local`→`development`, `staging`, `production`) | from the portal |
| `VETFAB_SERVICE_ID`, `VETFAB_APP_URL`, `VETFAB_SESSION_SECONDS`, `VETFAB_CLIENT_ID` (optional) | from the portal |
| `VETFAB_SERVICE_SECRET` | **one-time secret**: shown when registered or rotated; the guide fills it into the copyable template only while it is still in the page's memory |
| `VETFAB_SESSION_SECRET` | **you generate it** (`openssl rand -base64 48`): unique per service, never shared, never produced or stored by the portal |

The wizard: **A** summary and setup actions; **B** variables with their origin, and a copyable `.env` template; **C**
installation and wiring (`pip install "./sdk/python[fastapi]"`, `cd sdk/js && npm ci && npm run build`, the
`handoff_router`/`IdentityGuard` and `createHandoffClient`/`VetfabServiceSwitcher` code with the service's own redemption
path; both packages are private and not on an index yet, so the commands are repository-relative); **D** local test commands
(configuration loads, origin refusal, handoff both ways, your `load_user` refusing a stranger); **E** production readiness.

## 8. Audit

Every administrative action is recorded in `identity.audit` with `actor_id`, IP and user agent, and **never a secret or
hash**: `service_created`, `service_secret_issued`, `service_updated` (field names only), `service_status_changed`
(previous and new status, tickets spent), `service_secret_rotated`, `service_secret_revoked`, `service_bootstrapped`,
`developer_granted`, `developer_revoked`, and `admin_denied` (refused state-changing attempts by signed-in people,
rate-limited so a stranger cannot flood the log). Owners and administrators read a service's history in the portal
(`GET …/activity`).

## 9. Migration, rollback and deployment

* **Migration `0005_service_registry`** creates `identity.services` and `identity.developer_grants` (RLS, `identity_app` only) and
  extends the audit action list. Apply it as every release: `alembic upgrade head` with the owner URL (`deploy/deploy.sh` does).
  **Production migrations are an operator's decision; nothing here applies one.** Back up first.
* **Supabase SQL editor instead of alembic.** `deploy/supabase-identity.sql` is the whole schema (migrations 0001-0005, generated
  with `alembic upgrade head --sql`) for an existing IDE project: it checks the IDE's migrations are applied, lets the IDE's
  `users` table hold accounts without a GitHub/Google link or username, copies existing links, and creates the `identity`
  schema. Run it once, on a project with **no** `identity` schema; it refuses to run over an existing one. If the project already has one
  (the earlier LMS-era identity service created it), run `deploy/supabase-identity-upgrade.sql`: it reads `identity.alembic_version`
  and applies only the missing steps up to 0005 (tested from every start 0001-0005; a no-op at 0005). `deploy/supabase-identity-rollback.sql` undoes only 0004-0005. Regenerate both
  after adding a migration. Tested against a database built from the IDE's own `users` and beta-access migrations.
* **Rollback** `alembic downgrade 0004` drops the managed registry (**including every service registered in the portal**) and
  its audit rows; seeded services return at the next start from `SERVICES_JSON`. Copy `identity.services` out first.
* **Transition**: deploy the new image with `SERVICES_JSON` unchanged; the first start seeds the database from it. Services
  keep working with the same secrets. Afterwards manage them in the portal.
* **Deployment**: no new server or container. Settings: `REGISTRY_REFRESH_SECONDS`, `SECRET_ROTATION_GRACE_SECONDS`,
  `ADMIN_RATE_LIMIT` (see `deploy/env.template`). `deploy/Caddyfile` adds `/developer*` and `/handoff`. HTTPS is Caddy's, as before.
  Add `PUBLIC_ORIGIN` to `EXTRA_APP_ORIGINS` for the portal's sign-in, and make at least one administrator (`ADMIN_EMAILS`, as today).
* Development and production are separate by configuration: a deployed identity service refuses `local` services and plain
  http; a development one accepts `http://localhost`.

## 10. Try it locally

```bash
docker compose -f dev/docker-compose.yml up -d
export IDENTITY_ENVIRONMENT=development IDENTITY_ISSUER=http://localhost:8200/auth IDENTITY_AUDIENCE=vetfab \
       IDENTITY_APP_ORIGINS=http://localhost:8200 IDENTITY_KEYS_DIR=./.dev-keys \
       IDENTITY_DATABASE_URL=postgresql://identity:identity-local-only@127.0.0.1:54331/identity
uv run alembic upgrade head
uv run identity-admin create-user --email you@dev.vetfab.local --name You --status approved --password-stdin
# make yourself an administrator in the dev database:
#   UPDATE public.users SET role = 'admin' WHERE email = 'you@dev.vetfab.local';
uv run uvicorn --factory identity.web.app:create_app --port 8200
```

Open <http://localhost:8200/developer/services>, press **Sign in**, and use the pages. (On Windows psycopg needs the selector
event loop for the identity service; see [adapter.md](adapter.md).)

## 11. Example: a hypothetical "reports" service, without touching the LMS or IDE

1. An administrator grants a developer access: **Developers → email → Staging → Save**.
2. The developer opens the portal, **Register a service**: name *Reports*, id `reports`, environment *Staging*, base URL
   `https://reports.staging.example`, return paths `/dashboards`. Review shows every check; **Register service**.
3. The one-time panel shows the secret. They copy it into the service's secret store, generate `VETFAB_SESSION_SECRET`, and
   follow the guide: set the variables (B), install the adapter and add the `IdentityGuard` and `handoff_router` code with
   their own `load_user` (C), add `<VetfabServiceSwitcher>` to the page, and run the local checks (D).
4. An administrator opens the service, reads the checks, and **Activates** it. Within seconds the LMS and IDE switchers list
   *Reports* for people allowed to see it (no change to either application), and the handoff works in both directions.
5. Production later: an administrator registers `reports` in production (it starts pending), repeats the steps, and signs off
   the readiness list. To retire it: **Disable**.

## 12. Troubleshooting

| Symptom | Cause |
|---|---|
| Portal says "Sign in" after signing in | The identity host is not in `IDENTITY_APP_ORIGINS` / `EXTRA_APP_ORIGINS`, so the sign-in landed on another origin |
| `403 not_authorised` | The account is neither an approved administrator nor a developer; ask an administrator to grant access |
| `404 not_found` for a service | It does not exist or is owned by someone else (the two look the same on purpose) |
| `403 not_authorised` after working before | Your developer grant was revoked (you keep ownership of what you registered, but cannot use the portal) |
| `422 validation_failed` | The `checks` list says which rule failed (address form, https, conflict, ...) |
| `403 trusted_fields_locked` | A developer tried to move an approved service; an administrator must |
| `400 confirmation_required` | Type the service id (production, rotation, moving an active service) |
| `403 csrf` | The call did not come from the portal page on the identity host (or a proxy removed `Origin`) |
| `429 too_many_requests` | Rate limit; wait out the window |
| Service just activated but handoff gives `source_not_registered` / CORS 403 | Another instance has not refreshed yet; wait `REGISTRY_REFRESH_SECONDS` |
| Identity service will not start after upgrading | Migration `0005` not applied, or `SERVICES_JSON` is invalid (the message names the field) |
| Destination shows "sign-in refused" right after a rotation | The service still has the old secret and revocation was immediate; deploy the new one |

## 13. Known limitations

* **Not browser-tested.** The portal is tested in jsdom against the real module and, end to end, over HTTP against real
  servers, but no real-browser session (layout, focus rings, screen reader) was run. Do that before relying on it.
* Activation is a single administrator's decision (no second approver), and there is no ownership transfer: an owner who
  leaves must be handled by an administrator editing the database or registering again.
* A service has exactly one trusted browser origin (`base_url`); a separate frontend origin needs its own registration or a
  protocol change. `session_seconds` is advice written into the generated config: the identity service cannot enforce a
  service's own session length.
* Recent authentication is not required (see §5). Audit rows are not rotated or exported.
* The shared audience `aud=vetfab` is unchanged (see [sso-handoff.md](sso-handoff.md) §8).
* The LMS and IDE repositories were not available; neither is integrated here, and nothing in them was changed.
