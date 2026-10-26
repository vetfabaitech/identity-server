# Shared sign-in for the LMS and the IDE: handover for deployment

> Historical record, kept as written on 19 Oct 2026 in the LMS repo. Paths such as `apps/identity` and
> `infra/test` refer to the LMS repo's layout at that time; the identity service now lives in this repo and deploys
> from `deploy/` (see `deploying.md`).

Written 19 Oct 2026 for whoever takes the deployment forward. Everything described here is built, tested and pushed;
nothing is deployed yet. Read §1 first: it explains why this is not "point the IDE's login at the LMS".

Code: this repo (github.com/arnavsao-vetfab/Identity-Auth; until 26 Oct 2026 `apps/identity` in the LMS repo), LMS repo `main` (github.com/arnavsao-vetfab/LMS) and IDE repo branch `feat/shared-identity`
(github.com/vetfabaitech/vetfab). Design: the LMS repo's `docs/superpowers/specs/2026-10-18-shared-identity-ide-lms-design.md`.
Step list: the LMS repo's `docs/superpowers/plans/2026-10-19-shared-identity-cutover.md`. Deployment: `deploying.md` (same folder).

## 1. What is being built, and why it is not a small change

The goal: a person signs in once and moves between the LMS (`test.vetfab.ai`) and the HDL IDE (`demo.vetfab.ai`)
without signing in again, using GitHub, Google or email. Each product keeps its own servers, database tables and
features. Only sign-in is shared.

"Just connect the IDE's login to the LMS" does not work, because the two products had two incompatible sign-in
systems and two separate user tables:

| | IDE before this work | LMS |
|---|---|---|
| Sign-in service | its own `log-in` app: GitHub works, Google half-wired, email a stub | `apps/identity`: email/password only, no GitHub/Google |
| Session token | HS256, signed with a shared secret, lives 24 hours, no renewal | RS256 with public keys, lives 15 minutes, refresh cookie |
| What the token carries | user id, email, name, status, role | user id only; everything else is re-read from the database |
| Where users live | Supabase Postgres, table `public.users` with IDE columns (username, theme…) | its own Postgres on the test box, table `public.users` with LMS columns |
| Who may use it | approval queue, admin console inside the IDE | roles granted per organisation |

A token from one system means nothing to the other, and a user id from one table does not exist in the other. So
"connecting" them means choosing one sign-in service and one user table, and making the other product a client of
it. The LMS's identity service was the better foundation (public-key tokens, short lifetime, refresh, rate limits,
audit), so that is what was kept, and the IDE's GitHub/Google code was moved into it. The IDE's old `log-in` app is
retired.

What changed, in plain terms:

1. **Identity service (LMS repo, `apps/identity`)** now signs people in with GitHub and Google as well as email,
   can hand the signed-in user back to either product, renews tokens for pages in the background, and signs the
   user out of both products at once.
2. **IDE backend** no longer trusts its old 24-hour tokens as the main path. It checks the identity service's tokens
   against the service's published public keys and reads the user's status and role from the shared user table
   every minute. The account and admin screens' APIs that lived in the old `log-in` app now live in the IDE backend.
3. **IDE frontend** sends visitors to the identity service to sign in, keeps the 15-minute token fresh, and hosts
   the "waiting for approval" and "choose your username" screens itself.
4. **LMS web app** gets an "Open IDE" entry in the account menu.
5. **One user table.** The identity service and the LMS will use the IDE's existing Supabase Postgres as their
   database, so one account id is valid everywhere. The IDE's user table gets three columns relaxed so the identity
   service can create accounts in it; existing GitHub/Google users are linked automatically.

Verified locally end to end in a real browser: sign in on the LMS, click "Open IDE", land in the IDE already signed
in, token renewed in the background, sign out from the IDE ends the LMS session too. Test counts at the time of
writing: identity 236, IDE backend 429 (sign-in related), IDE frontend 1,039, LMS web 1,183.

## 2. Target layout

| Host | Runs | Status |
|---|---|---|
| `test.vetfab.ai` | LMS web, LMS API, **identity service** (`/auth/*`), judge runner, Caddy | deployed on AWS (EC2 m7i-flex.large, ap-southeast-2) from `infra/test` |
| `demo.vetfab.ai` | IDE frontend, IDE backend, IDE container runner | **not deployed anywhere yet**; the name currently points at 153.92.1.72, which is not the AWS account |
| Supabase project `hxyxnuzjezbabywlrbez` | the one Postgres: IDE tables + `identity` schema + LMS `lms` schema | exists; migrations not yet run |

Sign-in flows: a visitor to either product is sent to `https://test.vetfab.ai/auth/login?redirect=<where they
were>&state=<nonce>`. The identity service signs them in (or, if they already are, hands straight back without a
page) to `<product>/handoff#token=…`. Both products read the token from that fragment. Tokens last 15 minutes and
pages renew them from the identity service's refresh cookie; sign-out posts to the identity service, which revokes
that cookie.

This is a development setup: both hosts hold no real user data, test-accounts mode stays on. The spec's §SI-10
describes the later production split (identity on its own hostname, test accounts off, keys backed up).

## 3. What the person deploying needs to have or do

Things only someone with company access can do:

| # | Item | Needed for |
|---|---|---|
| 1 | **DNS** for `vetfab.ai`: repoint `demo.vetfab.ai` to the new IDE server once it exists | the IDE host |
| 2 | **AWS account** used for the LMS (`vetfab` CLI profile): create the IDE server, open its firewall, update the test box | both hosts |
| 3 | **Supabase project** `hxyxnuzjezbabywlrbez`: the Postgres connection string. In the dashboard: Connect → "Session pooler" URI (port 5432, **not** the transaction pooler on 6543) with the database password filled in. Reset the password under Project Settings → Database if unknown; nothing running uses it | migrations, identity + LMS database |
| 4 | **GitHub OAuth app** (client id starts `Ov23li0`; the IDE's `log-in/backend/.env` has id and secret): add callback URLs `https://test.vetfab.ai/auth/oauth/github/callback` and `http://localhost:8200/auth/oauth/github/callback`. OAuth apps accept up to 10 | GitHub sign-in |
| 5 | **Google OAuth client** (optional, Web application type) with the same two URLs using `google` in place of `github` | Google sign-in |
| 6 | **IDE backend secrets** the IDE already runs with locally: Supabase API keys, S3 bucket + keys, OpenRouter key, GitHub OAuth id/secret for "Connect GitHub". They are in the IDE repo's untracked `.env` on Arnav's Mac; copy, don't recreate | the IDE host |

Note on secrets: the Supabase anon and service-role keys were pasted into a chat on 19 Oct. Rotate the service role
key (Project Settings → API) at some point and update the IDE's `.env`.

## 4. Deployment steps

Each step has its detail in the cutover plan. In order:

### 4.1 Database, on the Supabase project (do first, it is the one irreversible-ish step)

Rehearse on a Supabase **branch** or a scratch database first. The LMS repo has
`scripts/rehearse-shared-identity-db.sh <path to IDE repo> [admin postgres URL]`, which replays everything below on
a throwaway database and checks the result; it passes locally against a replica built from the IDE's own SQL files.

1. Check no two accounts differ only by email case:
   `select lower(email), count(*) from public.users group by 1 having count(*) > 1;` (must return nothing).
2. Run the IDE's `backend/supabase_migration_shared_identity.sql` (three columns become nullable; no data change).
3. From the LMS repo, with the owner connection string:
   `cd apps/identity && IDENTITY_DATABASE_URL=<url> uv run alembic upgrade head` (creates the `identity` schema,
   the `identity_app` role, links existing GitHub/Google users), then
   `cd apps/api && LMS_DATABASE_URL=<url with postgresql+asyncpg://> uv run alembic upgrade head`.
4. Run `infra/test/provision-roles.sql` to create the three service logins (`lms_identity`, `lms_api`, `lms_judge`)
   with passwords of your choosing. If Supabase's plan refuses `CREATE ROLE`, stop: the plan's fallback (SI-2 option
   C, linking by email) needs a decision.

### 4.2 Test box (`test.vetfab.ai`)

1. `git pull` on the box, then edit `infra/test/.env`:
   - `IDENTITY_DATABASE_URL`, `LMS_DATABASE_URL`, runner URL → the Supabase project with the logins from 4.1.
   - `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, optionally `GOOGLE_CLIENT_ID`/`SECRET`.
   - `ADMIN_EMAILS=arnav.sao@vetfab.ai,arnavsao1924@gmail.com` (these become approved administrators on first
     GitHub/Google sign-in; add yourself).
   - `IDE_ORIGIN=https://demo.vetfab.ai` (allows hand-offs to the IDE and the "Open IDE" link).
2. `infra/test/deploy.sh`, then `infra/test/seed.sh` (LMS content and test accounts now land in Supabase).
3. Check `https://test.vetfab.ai/auth/.well-known/jwks.json` returns a key and the sign-in page shows
   "Continue with GitHub".

### 4.3 IDE host (`demo.vetfab.ai`), new server

The IDE has never been deployed. Its repo's `deploy/README.md` and `deploy/compose.app.yml` / `compose.runner.yml`
describe the layout: a backend container plus a "runner" that holds the Docker socket and starts the per-user
simulation containers. Needs more memory than the LMS box (Verilator compiles; 8 GB minimum, 16 GB comfortable),
Docker, and three images built on the box (`deploy/README.md` lists the three `docker build` lines; build the
toolchain image with `--build-arg MAKE_JOBS=2` on small machines). The frontend is a Next.js app (`frontend/`,
`npm run build && npm start`) behind the same reverse proxy, with `/api/` and `/ws/` routed to the backend.

Backend `.env` (start from `backend/.env.example`; copy the real secrets from the local `.env`), the sign-in part:

```
ENVIRONMENT=production
REQUIRE_AUTH=true
IDENTITY_JWKS_URL=https://test.vetfab.ai/auth/.well-known/jwks.json
IDENTITY_ISSUER=https://test.vetfab.ai/auth
IDENTITY_AUDIENCE=vetfab
TICKET_SECRET=<openssl rand -base64 48>
IDE_PUBLIC_URL=https://demo.vetfab.ai
CORS_ORIGINS=https://demo.vetfab.ai
JWT_SECRET=                      # leave empty: the old log-in app is not deployed
```

Frontend build-time environment:

```
NEXT_PUBLIC_API_URL=            # empty: same origin through the proxy
NEXT_PUBLIC_WS_URL=             # empty: same origin
NEXT_PUBLIC_IDENTITY_URL=https://test.vetfab.ai
NEXT_PUBLIC_LMS_URL=https://test.vetfab.ai
```

With `ENVIRONMENT=production` the backend refuses to start until every production setting is right and prints the
list (`SECURITY.md` has the table). Then repoint DNS.

### 4.4 Verify

1. Open `https://test.vetfab.ai`, sign in with GitHub, open the account menu, click "Open IDE": the IDE must load
   signed in with no second sign-in page.
2. In the IDE, wait 15 minutes (or set the stored token's expiry in the past in devtools) and keep working: the
   token renews silently.
3. Sign out from the IDE; the LMS must ask for sign-in again within a minute.
4. Sign in with a brand-new GitHub account: it must land on the IDE's "waiting for access" page; approve it in the
   IDE's admin console (`/admin`); it must then be asked to choose a username.

The headless-browser script that automates steps 1 to 3 against localhost is in Arnav's scratch area; it takes the
three base URLs as constants and can be pointed at the real hosts.

### 4.5 One release later

Delete `log-in/backend` and `log-in/frontend` from the IDE repo, drop `users.oauth_provider`/`oauth_id` once nothing
reads them, and work through the deferred items listed at the end of each plan's ledger (all small).

## 5. Things to know

- **Approvals.** New accounts start `pending` in both products. Only the IDE's admin console (and the
  `identity-admin set-status` command on the test box) can approve; the LMS has no approve button yet.
- **Account deletion is disabled** in the IDE admin console: the row is shared with the LMS. Suspend or reject.
- **Status changes take up to a minute** to reach a running IDE session; the LMS checks on every request.
- **One GitHub OAuth app serves two things:** sign-in (callback on the identity host) and the IDE's "Connect GitHub"
  source-control feature (callback `https://demo.vetfab.ai/github/callback`). Both callbacks go on the same app.
- **Test accounts** (`/auth/test-accounts` with the passphrase) can now open the IDE too, since the table is shared.
  Fine for development; off at go-live.
- **Who to ask:** Arnav Sao (arnav.sao@vetfab.ai) built and reviewed this with an AI assistant; the decision record is
  the spec (decisions `SI-1`…`SI-10`) and the four plans under `docs/superpowers/plans/2026-10-19-*`.
