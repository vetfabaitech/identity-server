# The Vetfab identity adapter

A reusable way for any Vetfab service to sign people in with this identity service, instead of every product writing
its own login, hand-off, renewal and token checks. It implements the contract in [CONTRACT.md](../CONTRACT.md) and
nothing else; it does not add a login protocol.

| Package | Where | For |
|---|---|---|
| `vetfab-identity-adapter` (Python, import `vetfab_identity_adapter`) | [sdk/python](../sdk/python) | backends: verify tokens, protect endpoints (FastAPI integration included) |
| `@vetfab/identity-adapter` (TypeScript) | [sdk/js](../sdk/js) | browsers: sign in, hand-off, renewal, sign-out; React bindings at `@vetfab/identity-adapter/react` |
| Demo service | [sdk/example](../sdk/example) | a complete hypothetical service using both, runnable on localhost |

## What this service is, and is not (read first)

The brief for the adapter assumed an OpenID Connect provider. This service is not one. Verified against the code:

| OIDC / OAuth 2.0 capability | This service | Consequence for the adapter |
|---|---|---|
| Discovery (`/.well-known/openid-configuration`) | **No.** Endpoints are fixed in CONTRACT.md | Endpoints derive from one setting, `VETFAB_AUTH_URL`; none are guessed per request |
| Authorization Code flow + PKCE | **No.** A sign-in ends with `303 <app>/handoff#token=…&state=…` carrying the access token in the URL fragment | The adapter implements that hand-off. PKCE does not apply: no code is exchanged, and the fragment is never sent to a server |
| `state` | **Yes**, echoed untouched | Generated per sign-in, kept per tab, compared in constant time, **consumed once**, expires in 10 minutes |
| `nonce`, ID token, `userinfo` | **No** | Not implementable. `sub` is the only identity claim; profile, status and roles come from each product's own data (CONTRACT.md) |
| Per-client registration, client ids/secrets | **No.** One audience (`vetfab`) for the platform; a product is "registered" by its origin in `IDENTITY_APP_ORIGINS` | `VETFAB_CLIENT_ID` is a label only. The service holds no secrets and the adapter needs none. See "Known gaps" |
| Signed access tokens, JWKS, rotation | **Yes** (RS256 `at+jwt`, 15 min, `kid`) | Fully verified: algorithm, `typ`, issuer, audience, expiry, lifetime, required claims, rotation, outage rules |
| Refresh / silent renewal | Yes: HttpOnly refresh cookie on the identity host, `POST /auth/session/token` | The browser client renews from it; the backend never sees it |
| RP-initiated logout, `post_logout_redirect_uri` | A form `POST /auth/logout?redirect=<URL>` on an allowlisted origin | `client.logout()` posts it; the service revokes the session for every product |

If standards-compliant OIDC (code + PKCE, ID tokens, discovery) is wanted, it is a change to this service and a
breaking change to the contract (CLAUDE.md: update the contract, this repo's verifier and every product together).
It is deliberately **not** done here.

## Architecture

```
 browser (Vetfab service)              identity service                   service backend
 ────────────────────────              ────────────────                   ───────────────
 client.login()  ──── GET /auth/login?redirect=<app URL>&state=<random> ──▶
                 ◀──── 303 <app>/handoff#token=…&state=… ────  (after sign-in, or silently if already signed in)
 client.handleCallback(): state matches the one this tab made? token for this app? drop the fragment
 token kept in memory only
 client.fetch('/api/…') ──── Authorization: Bearer <token> ──────────────────────────────▶ IdentityGuard
                                                                       verifies signature (JWKS), iss, aud, exp, typ
                                                                       → VerifiedIdentity(user_id)
                                                                       → your load_user(identity) → your roles
 renew (before expiry) ─▶ POST /auth/session/token  (refresh cookie, CORS for allowlisted origins)
 client.logout() ──────▶ POST /auth/logout?redirect=…   (ends the shared session)
```

Authentication is the adapter's job; **authorisation is yours**. A valid identity carries only a user id. It does not
make anyone an administrator or give them any workspace: `load_user` finds *your* record and your checks decide.

Why bearer tokens and no server-side session cookie? The products already work this way (token in memory, renewed from
the refresh cookie). A backend that only reads `Authorization` has no cookie-based authentication of its own, so there
is no CSRF surface to defend and nothing long-lived in browser storage. (The identity service's own cookie flows keep
their origin checks.)

## Install

```bash
# backend (from this repo, or your package index once published)
pip install "./sdk/python[fastapi]"

# frontend
cd sdk/js && npm ci && npm run build      # then depend on it: "@vetfab/identity-adapter": "file:../identity/sdk/js"
```

The package is `private` until Vetfab decides where to publish it.

## Configuration

Backend (`AdapterConfig.from_env()`; fails at start-up and lists every problem):

| Variable | Required | Meaning |
|---|---|---|
| `VETFAB_AUTH_URL` | yes | The identity service's origin, e.g. `http://localhost:8200`. No path |
| `VETFAB_ENVIRONMENT` | yes | `development`, `test`, `staging` or `production`. `staging`/`production` refuse plain http |
| `VETFAB_AUTH_ISSUER` | no | Default `<VETFAB_AUTH_URL>/auth`; must equal the service's `IDENTITY_ISSUER` |
| `VETFAB_AUTH_AUDIENCE` | no | Default `vetfab`; must equal `IDENTITY_AUDIENCE` |
| `VETFAB_AUTH_JWKS_URL` | no | Default `<VETFAB_AUTH_URL>/auth/.well-known/jwks.json` |
| `VETFAB_CLIENT_ID` | no | A name for this service in logs. Not a credential and not sent anywhere |

Frontend (`createIdentityClient({...})`, values come from your app's own build/runtime config):

| Option | Default | Meaning |
|---|---|---|
| `authUrl` | required | Same origin as `VETFAB_AUTH_URL`. http only for localhost |
| `appUrl` | page origin | This app's origin; **must be in the service's `IDENTITY_APP_ORIGINS`** |
| `apiOrigins` | `[]` | Extra origins `client.fetch` may attach the token to (your API host). The token is never sent anywhere else |
| `callbackPath` | `/handoff` | Fixed by the contract; the route must exist in your app |
| `issuer`, `audience` | derived / `vetfab` | Only if the service was configured differently |
| `onSessionExpired` | none | Called when a renewal is refused (signed out elsewhere, revoked) |

There are no secrets in this integration: the browser holds a short-lived token, the backend holds public keys.
Nothing environment-specific is hardcoded; localhost, staging and production differ only in these values.

## Public API

### Python

```python
from vetfab_identity_adapter import AdapterConfig, IdentityAdapter, VerifiedIdentity
from vetfab_identity_adapter.fastapi import IdentityGuard

adapter = IdentityAdapter.from_env()  # one per process: caches signing keys
guard = IdentityGuard(adapter, load_user)  # load_user(identity) -> your user | None

Depends(guard.identity)  # VerifiedIdentity; no database access
Depends(guard.user)  # your user object; 403 account_not_provisioned if None
Depends(guard.require(lambda u: u.is_admin, "admin_required"))  # your authorisation rule; 403 with that code
```

Outcomes: `401` (no/invalid/expired token; `WWW-Authenticate: Bearer`), `403` (authenticated, not allowed), `503`
`identity_unavailable` (signing keys unreachable *and* cached ones older than an hour; `Retry-After: 5`). Bodies carry a
short `code` only. Without FastAPI use `await adapter.verify(token)` and `bearer_token(header)` directly; it raises
`InvalidTokenError` / `SigningKeysUnavailableError`.

Verification (same rules as the LMS): RS256 only, `typ: at+jwt`, issuer and audience exact, `exp`/`iat`/`sub`/`iss`/`aud`
required, lifetime at most 15 minutes, `sub` a UUID, 30 s leeway, keys cached 5 minutes, one refetch per 30 s for an unknown
`kid`, no trust in cached keys an hour after the last good fetch. Tokens are never logged or echoed.

### TypeScript

```ts
import { createIdentityClient } from "@vetfab/identity-adapter";
const client = createIdentityClient({ authUrl });          // throws IdentityConfigError listing every problem

await client.init();            // silent sign-in from the refresh cookie (skipped on the hand-off page)
client.login({ returnTo });     // redirect to sign-in; returnTo is a same-origin path, anything else becomes "/"
await client.handleCallback();  // on /handoff: validates state + token, returns { returnTo }; idempotent
client.getSnapshot();           // { status: loading|authenticated|unauthenticated|error, claims, error }
await client.fetch("/api/x");   // fetch with the bearer token; renews once on 401; own origins only
await client.getAccessToken();  // current token, renewed if about to expire
client.logout({ returnTo });    // POST to the service; ends the session for every product
```

React (`@vetfab/identity-adapter/react`):

```tsx
<VetfabAuthProvider client={client} loadProfile={(c) => c.fetch("/api/me").then((r) => r.json())}>
  <Routes>
    <Route path="/handoff" element={<AuthCallback onSuccess={(to) => navigate(to, { replace: true })}
                                                  onError={(e) => <SignInFailed code={e.code} />} />} />
    <Route path="/*" element={<RequireAuth loading={<Loading />}><App /></RequireAuth>} />
  </Routes>
</VetfabAuthProvider>

const auth = useVetfabAuth();   // { loading, isAuthenticated, userId, claims, profile, error, login, logout, fetch, getAccessToken }
```

Error codes (`IdentityError.code`): `callback_missing`, `callback_state`, `callback_token`, `storage_unavailable`,
`login_loop`, `origin_not_allowed`, `service_busy`, `network`, `renew_failed`, `not_authenticated`, `token_destination`.

The browser reads the token's claims for the interface only (who is signed in, when to renew) after checking that issuer
and audience are this app's. It does **not** verify signatures and makes no access decision: every backend endpoint
verifies the token itself, so a forged token in the browser opens nothing.

## Protecting routes and endpoints

* Frontend: wrap routes in `RequireAuth`. It redirects once per mount and shows an error (never a redirect) for a
  sign-in loop or blocked storage. This is presentation only.
* Backend: every endpoint that matters depends on `guard.user` or `guard.require(...)`, whatever the frontend shows.

## Register a new service

> Since Phase 3 the steps below that touch the identity service's configuration are done in the developer portal
> ([developer-portal.md](developer-portal.md)): register the service, receive its secret and a tailored setup guide, and have an
> administrator activate it. No file on the identity server is edited.

1. Choose its origin for each environment (`https://newservice.vetfab.ai`, `http://localhost:3000` for development).
   Production origins must be https and on the same site (`*.vetfab.ai`) as the identity host: the refresh cookie is
   `SameSite=Lax` on the identity host, so a product on another site cannot renew silently.
2. Add the origin to the identity service: set `EXTRA_APP_ORIGINS=https://newservice.vetfab.ai` (comma-separated for
   several) in `deploy/.env` and run `deploy/deploy.sh`. This becomes `IDENTITY_APP_ORIGINS`; for a local identity
   service set `IDENTITY_APP_ORIGINS` directly. A sign-in or renewal from an unlisted origin is refused (`403`
   `origin_not_allowed`). The first origin in the list is the default for path-only redirects: leave it alone.
3. In the service's backend: `VETFAB_AUTH_URL`, `VETFAB_ENVIRONMENT`; add `IdentityGuard`.
4. In its frontend: `createIdentityClient({ authUrl })`, a route at `/handoff` rendering `AuthCallback`, `RequireAuth` around
   the app.
5. Handle a person you have never seen (`load_user` returns `None` → 403, or creates your own record): accounts made by the
   identity service carry no product data (CONTRACT.md).

A minimal complete service is [sdk/example](../sdk/example): [main.py](../sdk/example/main.py) (about 40 lines of code) and
[index.html](../sdk/example/index.html).

## Try it on localhost

Nothing needs a real domain. In this repo:

```bash
docker compose -f dev/docker-compose.yml up -d
uv sync && uv run alembic upgrade head      # with IDENTITY_DATABASE_URL set as in README "Run and test"

# 1. the identity service, allowing the demo's origin to receive sign-ins
IDENTITY_ENVIRONMENT=development IDENTITY_ISSUER=http://localhost:8200/auth IDENTITY_AUDIENCE=vetfab \
IDENTITY_APP_ORIGINS=http://localhost:8300 IDENTITY_KEYS_DIR=./.dev-keys \
IDENTITY_DATABASE_URL=postgresql://identity:identity-local-only@127.0.0.1:54331/identity \
  uv run uvicorn --factory identity.web.app:create_app --port 8200
uv run identity-admin create-user --email you@dev.vetfab.local --name You --status approved --password-stdin

# 2. build the browser SDK, 3. run the demo service
(cd sdk/js && npm ci && npm run build)
VETFAB_AUTH_URL=http://localhost:8200 VETFAB_ENVIRONMENT=development PYTHONPATH=sdk/python/src \
  uv run uvicorn --app-dir sdk/example main:app --port 8300
```

Open <http://localhost:8300>, sign in, then use the buttons. `/api/me` works; `/api/admin` answers 403 until you start
the demo with `DEMO_ADMIN_IDS=<your id>`. Both ports are on `localhost`, which browsers treat as the same site, so the
refresh cookie works over plain http in development (it is `Secure` only when the app origin is https).

On Windows, psycopg's async mode needs the selector event loop; the service works as is on Linux/macOS and in CI.

## Staging and production

Same code, different values. For a staging deployment of a product, add *its* staging origin to `EXTRA_APP_ORIGINS` of the
staging identity service and point its `VETFAB_AUTH_URL` at that service: a staging product must not be added to the
production service's origin list, and the staging identity service should not list production origins. `staging` and
`production` refuse plain-http URLs in both packages. The identity service's own settings (`IDENTITY_ENVIRONMENT`,
test accounts off in production) are unchanged.

## Logout and session expiry

* Access token: 15 minutes, in memory. The client renews about 60 s before expiry from the refresh cookie (30 days, rotating).
* Renewal refused (`401`: signed out elsewhere, revoked, suspended, expired): status becomes `unauthenticated` and
  `onSessionExpired` fires; `RequireAuth` then starts a new sign-in.
* Service busy (`503`): retried twice honouring `Retry-After`, then `service_busy` without signing the person out. Service
  unreachable: the current token keeps working until it expires.
* `logout()` forgets the token and POSTs to `/auth/logout`, which revokes the refresh session for every Vetfab product, then
  returns to your path. Other tabs notice at their next renewal (cross-tab sign-out is not implemented).
* Backend: nothing to clean up; there is no server session. A token already issued stays valid until it expires (at most
  15 minutes); suspending a user takes effect at their next renewal, and immediately for anything your `load_user`
  re-checks (CONTRACT.md: read status from the database, cache at most a minute).

## Troubleshooting

| Symptom | Cause |
|---|---|
| After sign-in you land on another product's `/` or `callback_state` | Your origin is not in `IDENTITY_APP_ORIGINS`, or `appUrl` differs from it (port, `www`, scheme) |
| `origin_not_allowed` | Same: the renewal endpoint refused the page's origin |
| `login_loop` | Sign-in returns three times in 30 s without completing: the origin or `/handoff` route is wrong |
| `callback_state` on the hand-off page | Opened in a different tab/browser than the one that started sign-in, took over 10 minutes, or the page processed it twice outside the SDK |
| `callback_token` | Token issuer/audience differ from the client's `issuer`/`audience` |
| Backend `401 invalid_token` for fresh tokens | `VETFAB_AUTH_ISSUER`/`AUDIENCE` differ from the service's, or the clock is off by more than 30 s |
| Backend `503 identity_unavailable` | The JWKS URL cannot be reached from the backend (and the cached keys are over an hour old) |
| Renewal always `401` in development | Different sites (not `localhost`↔`localhost`), or http↔https mixed |
| `ConfigError` at start-up | The message names each variable to fix |

## Rotating secrets and keys

* There are no client secrets to rotate in this integration.
* Signing keys rotate on the identity service (`identity-admin rotate-key`, restart, delete the old file after 15
  minutes). Adapters need no change or restart: they refetch on an unknown `kid` (at most every 30 s) and refresh every
  5 minutes, and the old key stays published until its file is deleted.

## Known gaps and Phase 2

Not implemented, and why:

* OIDC discovery, code + PKCE, ID token, nonce: the service does not offer them (table above).
* Per-service client ids and audiences: every product shares the audience `vetfab`, so a token minted for one product's
  sign-in is accepted by another product's backend. Separating them (an `aud` per product, minted per `redirect` origin)
  is a contract change.
* Cross-tab sign-out, server-managed sessions, and a JWKS-verifying browser client: not needed by the current design.
* Integrating the existing LMS and IDE: their repositories are separate and were not available here. They already
  implement this contract with their own copies; migrating each to this adapter is a change in those repositories
  (replace `packages/authz` token verification with `IdentityGuard`; replace the web apps' hand-off page and renewal with
  `AuthCallback`/`client`), keeping their role and permission checks as `load_user`/`require`.

Phase 2 (SSO hand-off between services and the shared switcher) is built: see [sso-handoff.md](sso-handoff.md). It is a
separate mechanism on purpose. Access tokens still never move between services; a one-time, destination-bound ticket
does, and each service starts its own session. Two changes to this guide's package: `IdentityClient.logout()` is now
`async` (it ends a cookie session first when one exists), and `AuthSnapshot` has a `mode` field.
