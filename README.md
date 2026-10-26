# Vetfab identity

One sign-in for every Vetfab product. Today that is the LMS (`test.vetfab.ai`) and the HDL IDE (`demo.vetfab.ai`):
a person signs in once, with GitHub, Google or email, and moves between them without signing in again.

This is its own product with its own deployment (`deploy/`). The products are clients: they send people here to
sign in, receive a short-lived access token, and check it against the public keys this service publishes. What a
token looks like is fixed in [CONTRACT.md](CONTRACT.md); read it before changing tokens, keys or routes.

Every route is under `/auth`. A sign-in ends with a 303 to `<product origin>/handoff#token=…&redirect=…&state=…`.
Tokens carry only the user id: status, roles and organisations stay in each product, which re-reads them from the
shared `users` table.

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
| `RATE_LIMIT_ATTEMPTS`, `RATE_LIMIT_WINDOW_SECONDS` | 10 failures per 600 seconds |
| `MAX_CONCURRENT_VERIFIES`, `VERIFY_QUEUE_SECONDS` | 2 password checks at once per process (64 MiB each), and a 3-second wait for one before sign-in answers 503 busy with `Retry-After: 2` |
| `DB_WAIT_SECONDS` | 30: how long a request waits for a pooled database connection before answering 503 busy with `Retry-After: 2` (reached only by a storm of renewals; sign-ins are bounded before they touch the pool) |
| `TEST_ACCOUNTS` | `true` enables the picker; refused in production |
| `TEST_ACCOUNTS_PASSPHRASE` | At least 12 characters; gates the picker |
| `TEST_ACCOUNTS_EMAILS` | Comma-separated accounts the picker offers, in order |
| `TEST_ACCOUNTS_PASSWORD` | What `identity-admin seed-test-accounts` sets on them |
| `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | GitHub OAuth app; GitHub sign-in is offered only when both are set |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | Google OAuth client (type "Web application"); same rule |
| `ADMIN_EMAILS` | Comma-separated; these accounts become approved administrators on GitHub or Google sign-in |

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
```

## Database

Migration `0001` creates `public.users` only when it is absent (the LMS dev stub and the IDE's table are kept), adds `password_hash`, `email_verified_at` and `last_login_at`, and creates `identity.refresh_tokens`, `identity.signin_attempts` and the append-only `identity.audit`. Every table has RLS with a policy for `identity_app` only. The service login is created by `deploy/deploy.sh` (`deploy/provision-role.sql`): NOINHERIT, member of `identity_app` only.

Migration `0003` copies existing GitHub/Google links from the IDE's `users.oauth_provider` / `oauth_id` columns when
they exist. On the shared database, run the IDE repo's `backend/supabase_migration_shared_identity.sql` **before**
this service's migrations: it makes the IDE columns this service does not fill (username, oauth_provider, oauth_id)
nullable.

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

Measured on 26 Oct 2026 ([docs/operations/load-test-2026-10-26.md](docs/operations/load-test-2026-10-26.md)): on
2 vCPU the service sustains about 5 password sign-ins a second and over 200 token renewals a second; 1,000 people
pressing "Sign in" in the same second all get in within 2½ minutes, seeing "busy, try again" in between. Sign-in is
bounded by argon2id (two checks at once, 64 MiB each); everything past the bound is answered 503 with `Retry-After`,
never an error. Rerun the tests with `load/` (its README).

### Connecting a product

1. Add its origin to `LMS_ORIGIN`/`IDE_ORIGIN` in `deploy/.env` (they become `IDENTITY_APP_ORIGINS`; the LMS first,
   because a sign-in with a plain path lands there) and re-deploy.
2. In the product: issuer `https://<this host>/auth`, audience `vetfab`, keys from
   `https://<this host>/auth/.well-known/jwks.json`, sign-in at `/auth/login?redirect=<absolute URL>&state=<nonce>`,
   renewal `POST /auth/session/token` with credentials, sign-out as a form `POST /auth/logout?redirect=<URL>`.
3. All products and this host must be on the same site (`*.vetfab.ai`) and on https: renewal relies on the
   refresh cookie being sent across the products' hosts.
