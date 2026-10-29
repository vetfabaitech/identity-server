# Vetfab identity service

This repository is the **identity service** (`github.com/arnavsao-vetfab/Identity-Auth`): one sign-in for every
Vetfab product (the LMS at `test.vetfab.ai`, the HDL IDE at `demo.vetfab.ai`), deployed on its own host at
`auth.vetfab.ai`. The products are separate repositories and separate deployments; they integrate with this service
only through the browser flows and the token contract in `CONTRACT.md`. Never assume a product's checkout is on the
same filesystem, and never import a product's code.

## Layout

- `identity/` is the FastAPI service: `web/` (routes, templates, cookies, origin checks), `oauth/` (GitHub, Google),
  `keys.py` (RSA key ring, JWKS), `tokens.py` (RS256 `at+jwt`), `sessions.py` (rotating refresh tokens), `store.py`,
  `cli.py` (`identity-admin`).
- `migrations/` is Alembic for the `identity` schema and the columns this service owns on `public.users`
  (version table `identity.alembic_version`). It creates `public.users` only when absent.
- `tests/` runs against a throwaway database per session; `tests/contract/verifier.py` is a verbatim copy of the LMS
  verifier, so a token that stops matching the contract fails here. `tests/fixtures/lms-users-stub.sql` mirrors the
  LMS's local users stub.
- `deploy/` is the production/staging deployment (Caddy + the service, external Postgres): `deploy.sh` is idempotent.
- `dev/docker-compose.yml` is the local Postgres (port 54331).
- `docs/operations/deploying.md` is the three-service deployment guide; `CONTRACT.md` is the contract.
- The service registry is in PostgreSQL (`registry_store.py`, `identity.services`, migration 0005) and managed by the developer
  portal (`web/admin_routes.py` = every permission check, `web/static/developer/` = the page, `registry_cache.py`).
  `IDENTITY_SERVICES` only seeds it and never overwrites a row. A service's origin joins the sign-in allowlist only while
  **active**, and only an administrator activates: never let a developer path add a trusted origin. No `DELETE` on services,
  ever (disable). Secrets are stored as hashes and shown once; never log, return or audit one. Docs: `docs/developer-portal.md`.
- `services.py` (the service model and validation), `handoff.py` (one-time tickets: atomic single use, bound to
  user, session and destination) and `web/handoff_routes.py` are the SSO hand-off (`docs/sso-handoff.md`). Tickets are
  never access tokens and never in a URL or a log; keep it that way. A *seeded* registry `base_url` must also be in `APP_ORIGINS`; a managed one joins the allowlist when activated.
- `sdk/` is the client adapter for products: `python/` (token verification, FastAPI guard, hand-off destination),
  `js/` (browser client, hand-off client, React incl. `VetfabServiceSwitcher`), `example/` (a demo service, run twice for
  the hand-off). They implement `CONTRACT.md` plus the hand-off routes; guides in `docs/adapter.md`, `docs/sso-handoff.md`. Python tests run with the
  root `pytest`; JS: `cd sdk/js && npm ci && npm test`.
- `load/` is the k6 load test (seeder, scenarios, timeline); results and sizing in `docs/operations/load-test-2026-10-26.md`.

## Commands

```bash
docker compose -f dev/docker-compose.yml up -d          # Postgres :54331
uv sync
uvx ruff@0.16.8 check . && uvx ruff@0.16.8 format --check .
uv run pyright
uv run pytest -q                                        # DB tests skip without Postgres; IDENTITY_REQUIRE_DB=1 in CI
uv run uvicorn --factory identity.web.app:create_app --port 8200   # needs IDENTITY_* env (README "Settings")
docker build -t vetfab-identity .
ENV_FILE=/path/to/identity.env deploy/deploy.sh --local            # https://localhost:9443 rehearsal
```

## Rules

- Security-critical: tokens, keys, cookies, origin checks, rate limits and RLS are never weakened to make a test pass.
- Changing anything in `CONTRACT.md` is a breaking change for the LMS and the IDE: update the contract, this repo's
  copy of the verifier, and each product's verifier in the same release.
- `public.users` is shared with the products. Migrations must keep their rows and columns; migration order on a
  fresh database is IDE SQL → this service → LMS API.
- Small Conventional Commits on a linear `main`; push after each green unit and check the `ci` workflow.
- No secrets in git: `deploy/.env` and signing keys stay on the host.
