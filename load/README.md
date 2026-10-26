# Identity load tests

How to measure what the identity service can take, on a laptop, against the same deployment the server runs
(`deploy/`: Caddy with TLS in front of one identity container, 256 MiB). Results of the first run are in
[docs/operations/load-test-2026-10-26.md](../docs/operations/load-test-2026-10-26.md).

| File | Role |
|---|---|
| `seed.py` | 1000 approved accounts `load-NNNN@load.vetfab.local` with one password, and a live refresh session each (JSON) |
| `k6/identity.js` | The scenarios, chosen with `SCENARIO` (below) |
| `watch.sh` | Samples the container's CPU, memory, restarts and OOM kills every 2 s |
| `timeline.py` | Turns k6's CSV output into a per-interval table of attempts by status and their latency |

## Set up (once)

```bash
docker compose -f dev/docker-compose.yml up -d                       # Postgres on 54331
docker exec vetfab-identity-dev-postgres-1 psql -U identity -d identity -c "CREATE DATABASE identity_load"
# A settings file outside the repo, for example /tmp/identity-load.env:
#   SITE_ADDRESS=localhost  SITE_TLS=tls internal  PUBLIC_ORIGIN=https://localhost:9443
#   LMS_ORIGIN=https://localhost:8443  IDE_ORIGIN=https://localhost:3443  IDENTITY_ENVIRONMENT=staging
#   OWNER_DATABASE_URL=postgresql://identity:identity-local-only@host.docker.internal:54331/identity_load
#   IDENTITY_DB_USER=lms_identity  IDENTITY_DB_PASSWORD=<random>
#   IDENTITY_DATABASE_URL=postgresql://lms_identity:<same>@host.docker.internal:54331/identity_load
ENV_FILE=/tmp/identity-load.env deploy/deploy.sh --local             # https://localhost:9443
export LOAD_PASSWORD=<any 10+ characters>
LOAD_DATABASE_URL=postgresql://identity:identity-local-only@127.0.0.1:54331/identity_load \
  uv run python load/seed.py --users 1000 --sessions-out /tmp/sessions.json
```

Pin the container to the CPUs of the server you are sizing, for example `docker update --cpus 1
vetfab-identity-identity-1`. Without a limit the container shares the laptop's cores with k6 and everything else,
and results swing from run to run.

Re-run `seed.py` before every `renew` or `storm` run: renewals rotate the seeded refresh tokens, and replaying a
rotated token after the 30-second grace revokes the session (reuse detection), which k6 would report as failures.
Clear `identity.signin_attempts` after a `nat` run, or later sign-ins from this laptop stay refused for 10 minutes.

## Run

```bash
k6 run -e SCENARIO=signin -e RATE=2 -e DURATION=2m -e LOAD_PASSWORD=$LOAD_PASSWORD load/k6/identity.js
k6 run -e SCENARIO=burst -e VUS=1000 -e MAX_TRIES=15 -e LOAD_PASSWORD=$LOAD_PASSWORD load/k6/identity.js
k6 run -e SCENARIO=renew -e SESSIONS=/tmp/sessions.json load/k6/identity.js
k6 run -e SCENARIO=storm -e VUS=1000 -e SESSIONS=/tmp/sessions.json load/k6/identity.js
k6 run -e SCENARIO=mixed -e RATE=3.33 -e DURATION=5m -e RENEW_RATE=1.2 -e LOAD_PASSWORD=$LOAD_PASSWORD \
  -e SESSIONS=/tmp/sessions.json load/k6/identity.js
k6 run -e SCENARIO=nat -e RATE=2 -e DURATION=3m -e TYPO_RATE=0.05 -e LOAD_PASSWORD=$LOAD_PASSWORD load/k6/identity.js
```

Add `--out csv=run.csv.gz` and run `python3 load/timeline.py run.csv.gz` for the timeline; run `load/watch.sh
out.csv &` beside k6 for the container's side.

| Scenario | What a person does |
|---|---|
| `signin` | Opens the sign-in page and submits it, `RATE` people a second (fractions allowed) for `DURATION`, each a different account. On "busy" (503) they press again after `Retry-After`, up to `MAX_TRIES` times (15 is about 75 s of patience) |
| `burst` | `VUS` people press "Sign in" at the same moment, same retry rule |
| `renew` | Signed-in pages renewing their 15-minute token in the background, ramping through `STAGES` (`rate:duration,...`) |
| `storm` | `VUS` renewals at the same moment (every open tab waking up together) |
| `mixed` | A class starting: sign-ins at `RATE` while the seeded users renew at `RENEW_RATE` and product backends fetch the keys |
| `nat` | `signin` with every person behind one address (a college network), `TYPO_RATE` of them mistyping first; counts correct passwords refused with 429 |

`signed_in` counts every person who started, including those still waiting when the arrival window closes
(`gracefulStop`), so a rate below 100 % means people who gave up, not requests that were cut off.
