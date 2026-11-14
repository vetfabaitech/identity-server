# Vetfab identity

One sign-in for every Vetfab product. Today that is the LMS (`test.vetfab.ai`) and the HDL IDE (`demo.vetfab.ai`):
a person signs in once, with GitHub, Google or email, and moves between them without signing in again.

This is its own product with its own deployment (`deploy/`). The products are clients: they send people here to
sign in, receive a short-lived access token, and check it against the public keys this service publishes. What a
token looks like is fixed in [CONTRACT.md](CONTRACT.md); read it before changing tokens, keys or routes.

Every route is under `/auth`. A sign-in ends with a 303 to `<product origin>/handoff#token=…&redirect=…&state=…`.
Tokens carry only the user id: each product re-reads status from its own copy of the user, which it keeps current with
the signed [user feed](#user-feed), and roles and organisations stay in each product.

Adding a product (backend + browser adapter, demo, localhost guide): [docs/adapter.md](docs/adapter.md). Moving a
signed-in person between products without a second sign-in (one-time tickets, service registry, shared switcher):
[docs/sso-handoff.md](docs/sso-handoff.md).

| Route | Purpose |
|---|---|
| `GET /auth/services` | The services this person may open (registry, filtered by role). Credentialed CORS for registered origins |
| `POST /auth/handoff` | A signed-in browser on a registered service gets a one-time ticket for another registered service |
| `POST /auth/handoff/redeem` | The destination's backend trades a ticket for the person's identity (HTTP Basic: service id and secret) |
| `GET /auth/service/user-events`, `GET /auth/service/users/{id}`, `GET /auth/service/users` | The signed user feed: a product's backend keeps its own copy of email, name and status (HTTP Basic: service id and secret; [User feed](#user-feed)) |

Registering and managing services (a web page for administrators and delegated developers, persistent in the database, one-time
secrets, validation, audit): [docs/developer-portal.md](docs/developer-portal.md), at `/developer/services` (API under `/auth/admin`).

Settings: `IDENTITY_SERVICES` (JSON; now only a **seed** for the database registry), `IDENTITY_HANDOFF_TICKET_SECONDS` (default 60),
`IDENTITY_REGISTRY_REFRESH_SECONDS` (5), `IDENTITY_SECRET_ROTATION_GRACE_SECONDS` (3600), `IDENTITY_ADMIN_RATE_LIMIT` (60). `identity-admin
service-secret` makes a redemption secret and its registry hash.

Deployment guide for all three services: [docs/operations/deploying.md](docs/operations/deploying.md). History: built
in the LMS repo (`apps/identity`, design in its `docs/superpowers/specs/2026-10-15-*` and
`2026-10-18-shared-identity-ide-lms-design.md`), moved here with its history on 26 Oct 2026.

| Route | Purpose |
|---|---|
| `GET /auth/login?redirect&state` | Silent sign-in from the refresh cookie, or the sign-in form |
| `POST /auth/login` | Email and password (argon2id), rate-limited per email and per address |
| `POST /auth/logout?redirect` | Revokes the session. Reached from the LMS's sign-out through a 307, or posted by a sibling product (the IDE) same-site; `redirect` may be a path or an absolute URL on an `APP_ORIGINS` origin |
| `GET/POST /auth/test-accounts`, `POST /auth/test-accounts/signin` | Test-accounts mode (off by default, refused in production) |
| `POST /auth/session/token` | A new access token from the refresh cookie, for allowlisted origins only (CORS with credentials); rotates the cookie |
| `GET /auth/oauth/{provider}/start`, `GET …/callback` | GitHub and Google sign-in (providers with an id and secret set) |
| `GET /auth/.well-known/jwks.json` | Public keys; every product's verifier fetches them |
| `GET /auth/health` | Liveness |

Sessions: the refresh token lives in an HttpOnly cookie on `Path=/auth`, is stored only as its SHA-256, rotates on every use and is revoked on sign-out. A token rotated in the last 30 seconds still works once (two tabs renewing together); older reuse revokes the session.

## Settings (`IDENTITY_` prefix)

| Variable | Notes |
|---|---|
| `ENVIRONMENT` | Required: `development`, `test`, `staging`, `production` |
| `DATABASE_URL` | The service login: NOINHERIT, member of `identity_app` only. Migrations use the owner URL in the same variable |
| `ISSUER`, `AUDIENCE` | Stamped on tokens; every product's issuer/audience settings must match exactly (CONTRACT.md). https outside development |
| `APP_ORIGINS` | Comma-separated origins whose `/handoff` may receive a token; the first is the default for path-only redirects. https outside development |
| `KEYS_DIR` | One `<kid>.pem` per key; the newest signs, all are published |
| `ACCESS_TOKEN_SECONDS` | 900 (at most 900) |
| `REFRESH_TOKEN_DAYS`, `REFRESH_GRACE_SECONDS` | 30 days, 30 seconds |
| `RATE_LIMIT_ATTEMPTS`, `RATE_LIMIT_ACCOUNT_ATTEMPTS`, `RATE_LIMIT_ADDRESS_ATTEMPTS`, `RATE_LIMIT_WINDOW_SECONDS` | Failed sign-ins allowed per 600 seconds: 10 per account and client address (one person), 50 per account from anywhere, 500 per client address across accounts (a college behind one public address; see the load test report) |
| `MAX_CONCURRENT_VERIFIES`, `VERIFY_QUEUE_SECONDS` | 2 password checks at once per process (64 MiB each), and a 3-second wait for one before sign-in answers 503 busy with `Retry-After: 2` |
| `DB_WAIT_SECONDS` | 30: how long a request waits for a pooled database connection before answering 503 busy with `Retry-After: 2` (reached only by a storm of renewals; sign-ins are bounded before they touch the pool) |
| `TEST_ACCOUNTS` | `true` enables the picker; refused in production |
| `TEST_ACCOUNTS_PASSPHRASE` | At least 12 characters; gates the picker |
| `TEST_ACCOUNTS_EMAILS` | Comma-separated accounts the picker offers, in order |
| `TEST_ACCOUNTS_PASSWORD` | What `identity-admin seed-test-accounts` sets on them |
| `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | GitHub OAuth app; GitHub sign-in is offered only when both are set |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | Google OAuth client (type "Web application"); same rule |
| `ADMIN_EMAILS` | Comma-separated; these accounts become approved administrators on GitHub or Google sign-in |
| `ALLOW_LOCALHOST_DEV_ORIGINS` | `false` (default). `true` lets an administrator activate a `local` service at exactly `http://localhost:<port>` or `http://127.0.0.1:<port>`, so a developer can run a service on their machine against this deployed identity (sign-in redirect only: no CORS, no silent renewal, no hand-off). Refused in production. See [developer-portal.md](docs/developer-portal.md) §14 |
| `USER_FEED_SERVICES` | Empty (default: the user feed is off). Comma-separated registry service ids whose backends may read the [user feed](#user-feed); each must also be active |
| `USER_FEED_RATE_LIMIT` | 1200: feed requests per service per 600 seconds before 429 with `Retry-After` |
| `USER_EVENTS_RETENTION_DAYS` | 30 (at least 7): how long user events are kept before they are purged |
| `ACCOUNT_STATUS_SERVICES` | Empty (default: off). Comma-separated registry service ids whose backends may [ask for an account to be approved, rejected or suspended](#account-status-changes-by-a-product); each must also be active. Separate from `USER_FEED_SERVICES`: reading users never implies changing them |
| `ACCOUNT_STATUS_RATE_LIMIT` | 120: status-change requests per service per 600 seconds before 429 with `Retry-After` |

### OAuth callbacks to register

Each provider redirects back to `<ISSUER>/oauth/<provider>/callback`. Register, per provider:

- `https://test.vetfab.ai/auth/oauth/github/callback` and `http://localhost:8200/auth/oauth/github/callback`
- `https://test.vetfab.ai/auth/oauth/google/callback` and `http://localhost:8200/auth/oauth/google/callback`

An account is found by its provider link, else by an email the provider has verified (linked on first use), else
created `pending`. A provider email that is not verified neither links nor creates an account (spec 2026-10-18 SI-5).

## Run and test

```bash
docker compose -f dev/docker-compose.yml up -d      # Postgres on 127.0.0.1:54331
uv sync
uv run pytest -q                                    # DB tests create and drop identity_test_* databases
uv run pyright && uvx ruff check . && uvx ruff format --check .
IDENTITY_DATABASE_URL=postgresql://identity:identity-local-only@127.0.0.1:54331/identity uv run alembic upgrade head
```

The service runs with `uv run uvicorn --factory identity.web.app:create_app --port 8200 --proxy-headers`. In development a missing signing key is generated on start; elsewhere run `identity-admin ensure-key` first.

## `identity-admin`

```bash
identity-admin ensure-key                      # generate a key if none exists (deploy job)
identity-admin rotate-key                      # add a newer key; restart; delete the old file after 15 minutes
identity-admin create-user --email E --name N [--status approved] [--password-stdin]
identity-admin set-password EMAIL [--password-stdin]        # also signs the account out everywhere
identity-admin set-status EMAIL suspended                   # suspended/rejected also sign it out
identity-admin token EMAIL                     # 15-minute token for scripts (content import); audited
identity-admin seed-test-accounts              # test password on the listed test accounts (not in production)
identity-admin revoke-sessions EMAIL
identity-admin purge-user-events               # drop user events past USER_EVENTS_RETENTION_DAYS now (the feed also does it hourly)
```

## Database

Migration `0001` creates `public.users` only when it is absent (the LMS dev stub and the IDE's table are kept), adds `password_hash`, `email_verified_at` and `last_login_at`, and creates `identity.refresh_tokens`, `identity.signin_attempts` and the append-only `identity.audit`. Every table has RLS with a policy for `identity_app` only. The service login is created by `deploy/deploy.sh` (`deploy/provision-role.sql`): NOINHERIT, member of `identity_app` only.

Migration `0003` copies existing GitHub/Google links from the IDE's `users.oauth_provider` / `oauth_id` columns when
they exist. On the shared database, run the IDE repo's `backend/supabase_migration_shared_identity.sql` **before**
this service's migrations: it makes the IDE columns this service does not fill (username, oauth_provider, oauth_id)
nullable.

Migration `0006` is the [user feed](#user-feed)'s change capture: `identity.user_versions` (every existing user at
version 1), `identity.user_events`, and three triggers on `public.users` that record every new or deleted account and
every real change to `email`, `display_name` or `status`, whoever writes (this service, the IDE as `service_role`, the
Supabase dashboard). It takes a short write lock on `public.users` while it runs. Without a direct database connection,
apply it in the Supabase SQL editor with `deploy/supabase-identity-upgrade.sql` (it applies only the missing steps;
`deploy/supabase-identity.sql` is for a project with no `identity` schema yet); undo it with
`deploy/supabase-identity-rollback-0006.sql`. Products that read the feed must reconcile after an undo and reapply.
After changing any migration, regenerate these files (their headers say how; a test fails when they drift).

## User feed

Products keep their own copy of a few user fields instead of reading `public.users`: the contract is in
[CONTRACT.md](CONTRACT.md#user-feed). Change capture is the trigger of migration 0006, never application code, so the
IDE's direct writes are included.

To let a product read it:

1. Register it in the developer portal (`/developer/services`) and have an administrator activate it; its backend
   keeps the service secret, as for hand-off redemption.
2. Add its id to `USER_FEED_SERVICES` in `deploy/.env` (`USER_FEED_SERVICES=lms`) and re-run `deploy/deploy.sh`.
3. Its backend polls `GET /auth/service/user-events?after=<cursor>` every few seconds, looks up a user it has never
   seen with `GET /auth/service/users/{id}`, and reconciles from `GET /auth/service/users` nightly and on a gap.

What the product must verify on every document (CONTRACT.md has the details): `alg` RS256, `typ` exactly
`user-feed+jwt`, a `kid` from this service's JWKS and a valid signature, `iss` the identity issuer, `aud` its own service
id, `exp` not passed, `kind` the route's, and on a page `after` and `limit` equal to what it asked for (a document is
valid for 300 seconds; the echo stops a replay as another request's answer). It applies a snapshot only when its `version` is higher than the one it holds,
moves its cursor only to `next`, and reconciles when `after + 1 < oldest`. A feed document is never an access token:
the access-token verifiers refuse it, and the feed verifier must refuse an access token.

Disabling the service in the portal stops its feed on its next request; removing it from `USER_FEED_SERVICES` does once
the service is re-deployed.

## Account status changes by a product

Account status is this service's. An operator changes it with `identity-admin set-status EMAIL approved|rejected|suspended`
on this host; a product's administrators can be given the same three actions from the product's own screen (the LMS's
Admin › Accounts page) without a shell here. The product never writes `public.users`: its backend calls
`POST /auth/service/users/{id}/status` with the administrator's user id, and the new status reaches every product
through the user feed. Contract: [CONTRACT.md](CONTRACT.md#account-status).

It is off until you allow a service:

1. The service is registered and active in the developer portal (it already is if it reads the feed).
2. Add its id to `ACCOUNT_STATUS_SERVICES` in `deploy/.env` (`ACCOUNT_STATUS_SERVICES=lms`) and re-run `deploy/deploy.sh`.
   This is a separate decision from `USER_FEED_SERVICES`: it lets that product's administrators approve, reject and
   suspend every non-administrator account, for all products.

What the route guarantees whatever the product sends: only `approved`, `rejected` or `suspended`; unknown fields are
refused; an administrator's account (`role = admin` or in `ADMIN_EMAILS`) is never changed; the acting person must be an
approved account and not the account itself; `rejected` and `suspended` sign the account out exactly as the command does;
a repeat is harmless; and every change is in `identity.audit` with the calling service and the acting person:

```sql
SELECT at, user_id, actor_id, metadata FROM identity.audit
 WHERE action IN ('status_change', 'admin_denied') AND metadata->>'via' = 'service' ORDER BY id DESC LIMIT 20;
```

To switch it off again, remove the id from `ACCOUNT_STATUS_SERVICES` and re-deploy (or disable the service in the
portal, which also stops its feed and hand-offs, at once).

## Deploy

Its own host, e.g. `auth.vetfab.ai`: Ubuntu with Docker and the compose plugin (1 vCPU / 1 GB is plenty), ports
80/443 open, DNS pointing at it.

```bash
git clone <this repo> identity && cd identity
cp deploy/env.template deploy/.env && $EDITOR deploy/.env     # every value is explained in the file
deploy/deploy.sh                                               # build, migrate, DB login, signing key, start, check
```

`deploy/deploy.sh --local` runs the same stack on `https://localhost:9443` (Caddy's internal CA) for a rehearsal.
Re-run `deploy/deploy.sh` after every `git pull`; it is idempotent. Back up the `vetfab-identity_identity-keys`
volume: losing it signs everyone out, leaking it lets anyone forge sign-ins.

Admin commands on the server:
`docker compose -f deploy/compose.yml --env-file deploy/.env run --rm identity-admin <command>`.

### Capacity

Measured on 26–27 Oct 2026 ([docs/operations/load-test-2026-10-26.md](docs/operations/load-test-2026-10-26.md)):
on 2 vCPU the service sustains about 5 password sign-ins a second and over 200 token renewals a second; 1,000 people
pressing "Sign in" in the same second all get in within 2½ minutes, the page retrying on its own in between. Sign-in
is bounded by argon2id (two checks at once, about 100 MiB each with their threads, 50 MiB base: 512 MiB in
`deploy/`); everything past the bound is answered 503 with `Retry-After`, never an error. Rerun the tests with
`load/` (its README).

### Connecting a product

1. Add its origin to `LMS_ORIGIN`/`IDE_ORIGIN` in `deploy/.env` (they become `IDENTITY_APP_ORIGINS`; the LMS first,
   because a sign-in with a plain path lands there) and re-deploy.
2. In the product: issuer `https://<this host>/auth`, audience `vetfab`, keys from
   `https://<this host>/auth/.well-known/jwks.json`, sign-in at `/auth/login?redirect=<absolute URL>&state=<nonce>`,
   renewal `POST /auth/session/token` with credentials, sign-out as a form `POST /auth/logout?redirect=<URL>`.
3. All products and this host must be on the same site (`*.vetfab.ai`) and on https: renewal relies on the
   refresh cookie being sent across the products' hosts.
