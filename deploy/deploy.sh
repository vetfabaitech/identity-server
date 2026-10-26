#!/usr/bin/env bash
# Deploys the identity service on its own host (README.md, "Deploy"): build the image, migrate,
# provision the service login, make sure a signing key exists, start, check health. Idempotent: run after every
# `git pull`.
#
#   deploy/deploy.sh            # on the server, with deploy/.env filled in from env.template
#   deploy/deploy.sh --local    # on a laptop: https://localhost:9443 with Caddy's internal CA
#
# ENV_FILE overrides where the settings are read from (default deploy/.env).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
mode="${1:-server}"
env_file="${ENV_FILE:-$here/.env}"
[[ -f "$env_file" ]] || { echo "No settings file at $env_file. Copy deploy/env.template and fill it in." >&2; exit 1; }

# Every value compose requires (`${NAME:?}`) must be set.
while read -r name; do
  grep -qE "^$name=.+" "$env_file" || { echo "$name is not set in $env_file." >&2; exit 1; }
done < <(grep -oE '\$\{[A-Z_]+:\?' "$here/compose.yml" | sed -E 's/^\$\{//; s/:\?$//' | sort -u)

if [[ "$mode" == "--local" ]]; then
  export HTTP_PORT="${HTTP_PORT:-9080}" HTTPS_PORT="${HTTPS_PORT:-9443}"
fi
compose() { docker compose -f "$here/compose.yml" --env-file "$env_file" "$@"; }

echo "==> Image"
compose build --quiet identity
echo "==> Migrations (schema owner)"
compose run --rm migrate
echo "==> Service login"
compose run --rm provision
echo "==> Signing key"
compose run --rm identity-admin ensure-key
echo "==> Services"
compose up -d --remove-orphans
echo "==> Health"
origin="$(grep -E '^PUBLIC_ORIGIN=' "$env_file" | cut -d= -f2-)"
curl_opts=(--silent --show-error --fail --output /dev/null --write-out '%{http_code} %{url}\n')
[[ "$mode" == "--local" ]] && curl_opts+=(--insecure)
# The first deploy for a hostname waits for Let's Encrypt (usually under a minute).
for path in /auth/health /auth/.well-known/jwks.json /auth/login; do
  ok=""
  for _ in $(seq 1 24); do
    curl "${curl_opts[@]}" "$origin$path" 2>/dev/null && { ok=1; break; }
    sleep 5
  done
  [[ -n "$ok" ]] || { echo "Health check failed: $origin$path" >&2; compose logs --tail 50 identity >&2; exit 1; }
done
echo "Deployed: $origin  (JWKS: $origin/auth/.well-known/jwks.json)"
