# The identity contract

What every product may rely on. Changing anything here is a breaking change for the LMS and the IDE: update this file,
then their verifiers and tests, in the same release. Each product keeps its own verifier (the LMS:
`packages/authz/src/vetfab_authz/tokens.py`; the IDE: `backend/app/security/jwks.py`); this repo's
`tests/contract/verifier.py` is a copy of the LMS one, so the tests here fail when a minted token stops matching.

## Access token

A JWT, signed RS256 with a key published in the JWKS.

| Part | Value |
|---|---|
| header `alg` | `RS256` (nothing else is ever accepted, so a public key can never be used as an HMAC secret) |
| header `typ` | `at+jwt` |
| header `kid` | id of the signing key in the JWKS |
| `sub` | the user's id: a UUID, the `public.users.id` of the shared users table |
| `iss` | `<origin>/auth`, e.g. `https://auth.vetfab.ai/auth`; must match each product's setting exactly |
| `aud` | `vetfab` (one audience for the whole platform) |
| `iat`, `exp` | seconds; `exp - iat` is at most 900 (15 minutes) |
| `jti` | random, unique per token |

Nothing else is in the token, and products must not trust anything but `sub`: email, name, status and roles are read
from the database on every request (or from a cache of at most a minute).

## Keys

`GET <origin>/auth/.well-known/jwks.json`, `Cache-Control: public, max-age=300`. RSA keys with `kid`, `use: sig`,
`alg: RS256`; the `kid` is the first 16 hex characters of the SHA-256 of the public key's DER encoding. Every key in
the service's key directory is published; the newest signs. Rotation: add a key (`identity-admin rotate-key`),
restart, delete the old key after 15 minutes. Products should cache keys for about 5 minutes, refetch at most every
30 seconds for an unknown `kid`, and stop trusting cached keys an hour after the last successful fetch.

## Browser flows

| Flow | Request | Result |
|---|---|---|
| Sign in | `GET /auth/login?redirect=<absolute product URL or path>&state=<nonce>` | sign-in page, or straight back when already signed in |
| Hand-off | (redirect) | `303 <product origin>/handoff#token=<access token>&redirect=<path>&state=<nonce>` |
| Renew | `POST /auth/session/token`, `credentials: include`, from an allowlisted origin | `200 {"access_token", "expires_in"}`, or `401 {"error"}`; CORS only for allowlisted origins |
| Sign out | form `POST /auth/logout?redirect=<absolute product URL or path>` | revokes the refresh session for every product, `303` to the redirect |

`redirect` must be on an origin in `IDENTITY_APP_ORIGINS`, else the user lands on the first one's `/`. `state` is the
product's own one-time nonce, echoed back untouched; products must refuse a hand-off whose `state` they did not issue.
The refresh cookie is `HttpOnly; Secure; SameSite=Lax; Path=/auth` on this host, so every product must be on the same
site (`*.vetfab.ai`) and on https.

## Shared database

This service owns, in the shared Postgres:

- `public.users`: creates rows with `email` (unique, case-insensitive), `display_name`, `status` (`pending` |
  `approved` | `rejected` | `suspended`) and `role` (`admin` | `beta_user`); maintains `password_hash`,
  `email_verified_at`, `last_login_at`. Products may add their own columns (the IDE's `username`, preferences) but
  must leave these semantics alone; `status` and `role` may also be changed by a product's admin console.
- `identity.*`: refresh sessions, OAuth links, rate limits, audit. Products never read it.

Accounts created here have no product-specific data: a product must handle a user it has never seen (the IDE sends
them to onboarding).
