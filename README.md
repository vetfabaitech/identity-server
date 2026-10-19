# Vetfab identity service (`apps/identity`)

Signs people in and issues the access tokens the LMS API accepts: RS256, `typ: at+jwt`, 15 minutes, keys published as a JWKS (plan §28, D-11 revised, audit H8). Design: [test deployment and identity spec](../../docs/superpowers/specs/2026-10-15-test-deployment-and-identity-design.md).

The service is mounted under `/auth` on the same origin as the web app. A sign-in ends with a 303 to `<app origin>/handoff#token=…&redirect=…&state=…`, the hand-off the web app already implements. Roles are never in the token: the LMS reads them from `lms.role_grants` on every request.

| Route | Purpose |
|---|---|
| `GET /auth/login?redirect&state` | Silent sign-in from the refresh cookie, or the sign-in form |
| `POST /auth/login` | Email and password (argon2id), rate-limited per email and per address |
| `POST /auth/logout?redirect` | Revokes the session. Reached from the LMS's sign-out through a 307, or posted by a sibling product (the IDE) same-site; `redirect` may be a path or an absolute URL on an `APP_ORIGINS` origin |
| `GET/POST /auth/test-accounts`, `POST /auth/test-accounts/signin` | Test-accounts mode (off by default, refused in production) |
| `POST /auth/session/token` | A new access token from the refresh cookie, for allowlisted origins only (CORS with credentials); rotates the cookie |
| `GET /auth/oauth/{provider}/start`, `GET …/callback` | GitHub and Google sign-in (providers with an id and secret set) |
| `GET /auth/.well-known/jwks.json` | Public keys (`LMS_JWKS_URL` points here) |
| `GET /auth/health` | Liveness |

Sessions: the refresh token lives in an HttpOnly cookie on `Path=/auth`, is stored only as its SHA-256, rotates on every use and is revoked on sign-out. A token rotated in the last 30 seconds still works once (two tabs renewing together); older reuse revokes the session.

## Settings (`IDENTITY_` prefix)

| Variable | Notes |
|---|---|
| `ENVIRONMENT` | Required: `development`, `test`, `staging`, `production` |
| `DATABASE_URL` | The service login: NOINHERIT, member of `identity_app` only. Migrations use the owner URL in the same variable |
| `ISSUER`, `AUDIENCE` | Stamped on tokens; the API's `LMS_TOKEN_ISSUER` and `LMS_TOKEN_AUDIENCE` must match. https outside development |
| `APP_ORIGINS` | Comma-separated origins whose `/handoff` may receive a token; the first is the default for path-only redirects. https outside development |
| `KEYS_DIR` | One `<kid>.pem` per key; the newest signs, all are published |
| `ACCESS_TOKEN_SECONDS` | 900 (at most 900) |
| `REFRESH_TOKEN_DAYS`, `REFRESH_GRACE_SECONDS` | 30 days, 30 seconds |
| `RATE_LIMIT_ATTEMPTS`, `RATE_LIMIT_WINDOW_SECONDS` | 10 failures per 600 seconds |
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
docker compose -f infra/local/docker-compose.yml up -d     # from the repo root
cd apps/identity && uv sync
uv run pytest -q                                           # DB tests create and drop identity_test_* databases
IDENTITY_DATABASE_URL=postgresql://lms:lms-local-only@127.0.0.1:54329/lms uv run alembic upgrade head
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

Migration `0001` creates `public.users` only when it is absent (the LMS dev stub and the IDE's table are kept), adds `password_hash`, `email_verified_at` and `last_login_at`, and creates `identity.refresh_tokens`, `identity.signin_attempts` and the append-only `identity.audit`. Every table has RLS with a policy for `identity_app` only. The service login must be provisioned once per environment ([database roles runbook](../../docs/operations/runbooks/database-roles.md)).
