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

Nothing else is in the token, and products must not trust anything but `sub`: email, name and status are read on every
request from the product's own copy, which the [user feed](#user-feed) keeps current within seconds (the IDE, which
still shares this service's database, reads the table itself); roles and organisations are each product's own.

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

This service owns, in its Postgres:

- `public.users`: creates rows with `email` (unique, case-insensitive), `display_name`, `status` (`pending` |
  `approved` | `rejected` | `suspended`) and `role` (`admin` | `beta_user`); maintains `password_hash`,
  `email_verified_at`, `last_login_at`.
- `identity.*`: refresh sessions, OAuth links, rate limits, audit, the user feed's versions and events.

Products do not read either. A product that needs a person's email, name or status keeps its own copy, fed by the
[user feed](#user-feed), and reads that copy; it never connects to this database for it. The products' databases are
their own (the LMS's is separate) and this service never reads them.

The one exception, for now, is the IDE, which still runs on this database: it keeps its own columns on `public.users`
(`username`, profile, preferences), its admin console may change `status` and `role`, and it may read the table.
It must leave the semantics above alone. Its changes to `email`, `display_name` and `status` reach the feed like this
service's own, because the feed is captured by a trigger on the table, whoever writes. `role` is not in the feed.

Accounts created here have no product-specific data: a product must handle a user it has never seen (look it up with
`GET /auth/service/users/{id}` the first time an access token names it; the IDE sends them to onboarding).

## User feed

How a product keeps its copy of `email`, `display_name` and `status`: it **pulls** signed documents from this service.
There is no push and no webhook: the product polls the events every few seconds from its own cursor, looks a user up
by id the first time it sees one, and reconciles from the full list (nightly, and whenever it finds a gap). Nothing is
lost if it is down for a while, and duplicates or reordering are harmless thanks to per-user versions.

### Access

The caller is a product's **backend**, registered in the developer portal (`identity.services`). It authenticates
with HTTP Basic `<service id>:<service secret>`, the same credentials as `POST /auth/handoff/redeem`; after a secret
rotation the previous secret keeps working until its grace window ends. The service must be **active** and listed in
`IDENTITY_USER_FEED_SERVICES` (comma-separated service ids; empty switches the feed off). There is no CORS: browsers
cannot call these routes.

Every answer, success or error, carries `Cache-Control: no-store`. Errors are JSON:

| Status | Body | When |
|---|---|---|
| 401 | `{"detail": {"code": "invalid_client"}}`, header `WWW-Authenticate: Basic realm="vetfab-identity"` | credentials missing, malformed or wrong, or no such service |
| 403 | `{"detail": {"code": "user_feed_not_allowed"}}` | valid credentials, but the service is pending or disabled, or not in `IDENTITY_USER_FEED_SERVICES` |
| 422 | `{"detail": {"code": "invalid_request", "field": "after" \| "limit" \| "id"}}` | a parameter outside its bounds (checked only for an authenticated caller) |
| 429 | `{"detail": {"code": "too_many_requests"}}`, header `Retry-After: <seconds>` | more than 1200 requests by this service in its current 600-second window (`IDENTITY_USER_FEED_RATE_LIMIT`) |
| 503 | `{"detail": {"code": "busy"}}`, header `Retry-After: 2` | the database cannot take the request now |

Retry 429 and 503 after `Retry-After`, and 5xx with backoff.

### Documents

A success is `200`, `Content-Type: application/jwt`, and the body is a compact JWS, signed with the same key as the
access tokens (so it is in the JWKS above):

| Part | Value |
|---|---|
| header `alg` | `RS256` |
| header `typ` | `user-feed+jwt` |
| header `kid` | id of the signing key in the JWKS |
| `iss` | the identity issuer, the same value as in access tokens |
| `aud` | the calling service's id |
| `iat`, `exp` | seconds; `exp = iat + 300` |
| `jti` | random, unique per document |
| `kind` | `user-events`, `user` or `users`, plus that kind's claims below |
| `after`, `limit` | in `user-events` and `users` documents: the request they answer (see below) |

A consumer must check, and refuse the document otherwise: `alg` is `RS256` and nothing else; `typ` is exactly
`user-feed+jwt`; the `kid` is in the JWKS (the same key cache as for access tokens); the signature; `iss`; `aud` is
its own service id; `exp` (at most 30 seconds of leeway); `kind` is the one the route returns; and for a page, that
`after` and `limit` are exactly what it asked for (for one user, that `user.id` is the id it asked for, in canonical lowercase form). A document is
valid for 300 seconds, so these echoes are what stop one from being replayed as the answer to another request. The distinct `typ`
means a feed document is never an access token and an access token is never a feed document: the access-token
verifiers refuse anything that is not `at+jwt`, and a feed verifier must refuse anything that is not `user-feed+jwt`.
Documents can be several hundred kilobytes (a page of 1000 users), so an access token's 8 KiB length limit does not
apply to them.

### User snapshot

```json
{"id": "<uuid>", "version": 7, "deleted": false, "email": "ada@example.org", "display_name": "Ada", "status": "approved"}
{"id": "<uuid>", "version": 8, "deleted": true}
```

A deleted (or unknown) user carries no personal data. `status` is `pending`, `approved`, `rejected` or `suspended`.

`version` is per user and only grows: every user that existed when the feed was installed starts at 1, a new user
starts at 1, and it goes up by one with every committed change that really changes `email`, `display_name` or `status`
(an update writing the same value does not count), and once more when the user is deleted. Changes to anything else
(password, last sign-in, `role`, OAuth links, the IDE's profile columns) do not change it and produce no event. A
consumer stores the version with its copy and applies a snapshot only when its version is higher than the stored
one. An unknown id is `{"id", "version": 0, "deleted": true}`.

### 1. Events: `GET /auth/service/user-events?after=<int ≥ 0, default 0>&limit=<1..500, default 200>`

```json
{"kind": "user-events", "after": 40, "limit": 200,
 "events": [{"seq": 41, "type": "user.updated", "occurred_at": "2026-11-07T09:13:00.123456Z", "user": {"id": "…", "version": 3, "deleted": false, "email": "…", "display_name": "…", "status": "suspended"}}],
 "next": 41, "head": 57, "oldest": 12}
```

- `after`, `limit`: the request this page answers, after defaults (`0`, `200`).
- `events`: those with `seq > after`, ascending, at most `limit`. `type` is `user.created`, `user.updated` or
  `user.deleted`; `user` is the snapshot as of that event. `occurred_at` is RFC 3339 in UTC with microseconds (the
  start of the writing transaction; informative, order by `seq`).
- `next`: the last returned `seq`, or exactly `after` when none were returned (an empty page). Use it as the next
  `after`.
- `head`: the highest committed `seq` (0 when there has never been an event).
- `oldest`: the lowest `seq` still retained, or `head + 1` when none is.
- **Gap**: if `after + 1 < oldest`, events this consumer never read have been purged: reconcile from the list (3),
  then continue from the `head` of the reconcile's first page.
- **Ordering**: events become visible in `seq` order: a reader that sees an event sees every committed event with a
  lower `seq`, so a consumer that only moves its cursor to `next` never skips one. (Writers of these fields take
  `pg_advisory_xact_lock(5279438479318730070)` before they allocate a `seq` and hold it until they commit.) `seq` never
  goes backwards and is never reused, but it can skip values (a rolled-back write uses one up): a missing number is
  not a gap; only `oldest` says that.
- **Retention**: events are kept `IDENTITY_USER_EVENTS_RETENTION_DAYS` (default 30, at least 7), then purged oldest
  first; the newest event is never purged.
- If `head < after`, the feed was reinstalled (its versions and seq started again at 1): drop the stored versions and
  cursor, and reconcile.

### 2. One user: `GET /auth/service/users/{id}`

`{"kind": "user", "user": <snapshot>}`: the current snapshot. Unknown id: version 0, deleted. Deleted user: deleted,
with its last version. An `id` that is not a UUID is 422 (`field: "id"`).

### 3. Every live user: `GET /auth/service/users?after=<uuid, optional>&limit=<1..1000, default 500>`

`{"kind": "users", "after": "<uuid>" | null, "limit": <int>, "users": [<live snapshot>, …], "next": "<uuid>" | null,
"head": <int>}`: `after` and `limit` echo the request after defaults (`after` as a canonical lowercase UUID, or `null`
when absent; `limit` 500 by default), so send `after` in that form. `users` are live users with `id > after`, strictly
ascending by id (Postgres `uuid` order: the 16 bytes compared as unsigned, the same as comparing the lowercase strings);
`next` is the last id on the page, or `null` on the last page. `head` is the event head
read in the same database snapshot as the page, before it: every change up to `head` is reflected in the page, every
later change has a higher `seq`.

A reconcile: read pages from no `after` until `next` is `null`, keeping the **first** page's `head`; apply every listed
snapshot by the version rule; for each id you hold that no page listed, fetch it with (2) and apply that (it answers
deleted, with its version); then read events from `after = <first page's head>`. Nothing is missed in between.
