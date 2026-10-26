# Deploying identity, LMS and IDE as three services

For whoever deploys the shared sign-in. It covers the identity service on its own host (`deploy/` in this repo). Written 26 Oct 2026 in the LMS repo,
moved here with the service. Background on why there is one sign-in for both products:
`shared-sign-in-handover.md` (same folder).

## 1. The picture

```
                    auth.vetfab.ai  (identity service, this repo)
                    - sign-in pages, GitHub/Google/email
                    - issues 15-minute tokens, publishes public keys (JWKS)
                    - refresh cookie, sign-out for everyone
                       ▲              ▲
        sign in /      │              │   sign in / renew / sign out
        sign out       │              │   public keys
                       │              │
   test.vetfab.ai  (LMS)           demo.vetfab.ai  (IDE)
   apps/web + apps/api             frontend + backend + runner
                       │              │
                       └──── one Postgres (Supabase) ────┘
                    public.users (shared) · identity.* · lms.* · IDE tables
```

Three things connect the services, and nothing else does:

1. **Redirects in the browser.** Each product sends a signed-out visitor to the identity service, which sends them
   back to `<product>/handoff#token=…`. The products never call each other.
2. **Public keys.** Each product's backend downloads the identity service's public keys once every few minutes and
   checks every token with them. Only the identity service holds the private key.
3. **The shared `users` table.** A token carries only the user's id. Each product looks the id up in the same
   `public.users` table for email, name, approval status and role.

## 2. Rules that must hold, or sign-in breaks

- **All three hostnames under `vetfab.ai`.** The IDE renews its token with a background request to the identity
  host that carries the refresh cookie. Browsers only send that cookie between hosts of the same site. A product on
  another domain (say `vetfab-ide.com`) would sign out every 15 minutes.
- **HTTPS everywhere.** The identity service refuses http addresses outside development, and the cookies are
  `Secure`.
- **One issuer string, written identically in four places.** `https://auth.vetfab.ai/auth`: the identity
  service's own setting, the LMS API, the IDE backend, and (as an origin) the IDE frontend. Tokens whose issuer
  does not match exactly are refused.
- **One audience: `vetfab`**, in the identity service, the LMS API and the IDE backend.
- **The LMS listed first in `IDENTITY_APP_ORIGINS`.** The first origin is where a sign-in with no explicit
  destination lands, and the LMS sends plain paths.
- **One database for identity, the LMS and the IDE's users table.** If the identity service and a product read
  different `users` tables, a valid token names an account the product cannot find (401).
- **Signing keys are precious.** They live in a Docker volume (`/keys`). Losing them signs everyone out; leaking them
  lets anyone forge sign-ins. Back the volume up; never put keys in git or in an image.

## 3. Wiring, per service

### Identity (this repo, its own host)

| Setting | Value |
|---|---|
| `IDENTITY_ENVIRONMENT` | `staging` (test accounts allowed) or `production` (test accounts refused) |
| `IDENTITY_DATABASE_URL` | the `lms_identity` login on the shared Postgres (not the owner login) |
| `IDENTITY_ISSUER` | `https://auth.vetfab.ai/auth` |
| `IDENTITY_AUDIENCE` | `vetfab` |
| `IDENTITY_APP_ORIGINS` | `https://test.vetfab.ai,https://demo.vetfab.ai` (LMS first) |
| `IDENTITY_GITHUB_CLIENT_ID` / `_SECRET` | the Vetfab GitHub OAuth app |
| `IDENTITY_GOOGLE_CLIENT_ID` / `_SECRET` | optional |
| `IDENTITY_ADMIN_EMAILS` | people who become approved administrators on first GitHub/Google sign-in |
| `IDENTITY_TEST_ACCOUNTS*` | only on a test deployment |
| volume | `/keys`, backed up; `identity-admin ensure-key` creates the first key |

Reverse proxy: serve the service at `https://auth.vetfab.ai` and pass `/auth/*` to it (port 8200). The routes
always live under `/auth`, so the issuer, the key URL and the callback URLs all contain `/auth`.

OAuth apps: register `https://auth.vetfab.ai/auth/oauth/github/callback` on the GitHub OAuth app (and the
`google` equivalent on the Google client). Keep the old `test.vetfab.ai` callback until the switch is done.

Database order on a fresh database: the IDE's SQL files (including `supabase_migration_shared_identity.sql`) → the
identity service's migrations → the LMS API's migrations → `infra/test/provision-roles.sql`.
Rehearse the order on a throwaway database before touching the shared one.

### LMS (`apps/web` + `apps/api`, `test.vetfab.ai`)

| Service | Setting | Value |
|---|---|---|
| API | `LMS_JWKS_URL` | `https://auth.vetfab.ai/auth/.well-known/jwks.json` |
| API | `LMS_TOKEN_ISSUER` | `https://auth.vetfab.ai/auth` |
| API | `LMS_TOKEN_AUDIENCE` | `vetfab` |
| web | `LOGIN_URL` | `https://auth.vetfab.ai/auth/login` |
| web | `LOGOUT_URL` | `https://auth.vetfab.ai/auth/logout` |
| web | `APP_ORIGIN` | `https://test.vetfab.ai` |
| web | `IDE_URL` | `https://demo.vetfab.ai` (the "Open IDE" link) |

The LMS reverse proxy no longer needs a `/auth/*` route once the switch is done.

### IDE (`frontend` + `backend` + runner, `demo.vetfab.ai`)

| Service | Setting | Value |
|---|---|---|
| backend | `IDENTITY_JWKS_URL` | `https://auth.vetfab.ai/auth/.well-known/jwks.json` |
| backend | `IDENTITY_ISSUER` | `https://auth.vetfab.ai/auth` |
| backend | `IDENTITY_AUDIENCE` | `vetfab` |
| backend | `TICKET_SECRET` | 32+ random characters (`openssl rand -base64 48`) |
| backend | `SUPABASE_URL` / `SUPABASE_SERVICE_ROLE_KEY` | the same Supabase project as the identity database |
| backend | `CORS_ORIGINS` | `https://demo.vetfab.ai` |
| backend | `IDE_PUBLIC_URL` | `https://demo.vetfab.ai` (link in approval emails) |
| backend | `JWT_SECRET` | empty (only for the retired log-in app's tokens) |
| frontend (build time) | `NEXT_PUBLIC_IDENTITY_URL` | `https://auth.vetfab.ai` |
| frontend (build time) | `NEXT_PUBLIC_LMS_URL` | `https://test.vetfab.ai` |

`NEXT_PUBLIC_*` values are baked in when the frontend is built: changing them means rebuilding, not restarting.

## 4. Deploying the identity host

Everything needed is in this repo under `deploy/` (compose file, Caddy config, settings template, the database-login
script and `deploy.sh`). Rehearsed end to end on a laptop on 26 Oct 2026 against an empty database: migrations,
service login, signing key, HTTPS, key URL, sign-in page, GitHub callback address, and sign-out from both products
across hosts.

On a new server (Ubuntu with Docker and the compose plugin; 1 vCPU / 1 GB is plenty):

```bash
git clone https://github.com/arnavsao-vetfab/Identity-Auth.git identity && cd identity
cp deploy/env.template deploy/.env
$EDITOR deploy/.env                    # every value is explained in the file
deploy/deploy.sh                       # build, migrate, create the DB login, create the key, start, health-check
```

Then:

1. Firewall: open 80 and 443 to everyone, 22 to your own address only.
2. DNS: point `auth.vetfab.ai` at the server before running `deploy.sh` (Caddy needs it for the certificate).
3. Back up the `vetfab-identity_identity-keys` Docker volume.
4. Admin commands: `docker compose -f deploy/compose.yml --env-file deploy/.env run --rm identity-admin <command>`
   (`create-user`, `set-status`, `set-password`, `revoke-sessions`, `rotate-key`, `token`, `seed-test-accounts`).
5. Updates: `git pull && deploy/deploy.sh` (idempotent).

The database is the one dependency outside this host: the service connects to the shared Postgres through
`OWNER_DATABASE_URL` (migrations and the service login, once) and `IDENTITY_DATABASE_URL` (the service). The LMS
and the IDE must use the same database, or a valid token names an account they cannot find. If the LMS keeps its
own Postgres on its test box, that Postgres must be reachable from this host (a firewall rule for this host's
address on port 5432, and `listen_addresses`), and the IDE's users would not be the same accounts; see the
handover (§4.1) for the one-database plan.

Migration order on a fresh database: the IDE's SQL files (including `supabase_migration_shared_identity.sql`)
→ this service's migrations (`deploy.sh` runs them) → the LMS API's migrations (its `infra/test/deploy.sh`, which
refuses to run until `public.users` exists). The LMS test box's seeding needs a token from this host:
`identity-admin token author@dev.vetfab.local`, passed as `LMS_IMPORT_TOKEN`.

## 5. Order of the switch

1. Database: rehearse the migration order on a throwaway database, then run the IDE's
   `supabase_migration_shared_identity.sql` on Supabase (handover §4.1). The identity migrations run from `deploy.sh`.
2. Identity: DNS for `auth.vetfab.ai`, then `deploy/deploy.sh`. Register
   `https://auth.vetfab.ai/auth/oauth/github/callback` on the GitHub OAuth app (and the Google one). Check
   `https://auth.vetfab.ai/auth/.well-known/jwks.json` returns a key.
3. LMS: on the test box, set `IDENTITY_ORIGIN=https://auth.vetfab.ai` in `infra/test/.env` (the LMS repo's compose
   derives the §3 settings from it), redeploy with `infra/test/deploy.sh`. Sign in on the LMS to check.
4. IDE: set the backend settings, build the frontend with the new values, deploy, repoint DNS for `demo.vetfab.ai`.
5. Remove the old `/auth/*` route from the LMS host and the old callback URLs from the OAuth apps.

Everyone is signed out once at step 3, because the old refresh cookies belong to `test.vetfab.ai`. That is expected.

## 6. Checks after each change

| Check | Expect |
|---|---|
| Open the LMS signed out | redirected to `auth.vetfab.ai/auth/login`, back to the LMS after sign-in |
| LMS account menu → Open IDE | the IDE opens signed in, no second sign-in page |
| Leave the IDE open 15+ minutes | keeps working (token renewed in the background) |
| Sign out in the IDE, then use the LMS | the LMS asks for sign-in within a minute |
| Sign out in the LMS | lands on the LMS's signed-out page |
| New GitHub account | IDE shows "waiting for access"; after approval in the IDE admin console, asks for a username |

## 7. When something fails

| Symptom | Usual cause |
|---|---|
| Every request 401 right after sign-in | issuer or audience differs between identity and the product, or the product cannot reach the key URL |
| "Your account was not found" in the IDE | the identity service and the IDE use different `users` tables |
| IDE signs out every 15 minutes | hosts not on the same site, or `IDENTITY_APP_ORIGINS` missing the IDE (renewal refused) |
| Sign-in lands on the LMS instead of the IDE | `IDENTITY_APP_ORIGINS` missing or misspelling the IDE origin (no trailing slash, exact scheme) |
| GitHub says "redirect_uri mismatch" | the callback URL on the GitHub app does not match the identity host |
| "This request did not come from the Vetfab sign-in page" on sign-out | the product's origin is not in `IDENTITY_APP_ORIGINS` (exact scheme and host, no trailing slash) |
| IDE backend refuses to start | `ENVIRONMENT=production` with a missing setting; it prints the full list |
