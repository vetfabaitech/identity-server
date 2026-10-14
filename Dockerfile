# Identity service. Build from the repository root:
#   docker build -f apps/identity/Dockerfile -t vetfab-identity .
# The same image runs the identity migrations and `identity-admin` (ensure-key, token, seed-test-accounts).
FROM ghcr.io/astral-sh/uv:0.9.18 AS uv

FROM python:3.12-slim-bookworm
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /repo

# packages/authz is a dev-only source (the tests verify tokens with it); the lock still names its path.
COPY packages/authz packages/authz
COPY apps/identity/pyproject.toml apps/identity/uv.lock apps/identity/
RUN uv sync --frozen --no-dev --no-install-project --directory apps/identity
COPY apps/identity apps/identity
RUN uv sync --frozen --no-dev --directory apps/identity \
 && useradd --uid 10002 --no-create-home --shell /usr/sbin/nologin identity \
 && mkdir -p /keys && chown 10002:10002 /keys && chmod 700 /keys

USER 10002
WORKDIR /repo/apps/identity
ENV PATH=/repo/apps/identity/.venv/bin:$PATH IDENTITY_KEYS_DIR=/keys
VOLUME ["/keys"]
EXPOSE 8200
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8200/auth/health', timeout=3)"]
# Only Caddy reaches the service; the client address for rate limits comes from its X-Forwarded-For.
CMD ["uvicorn", "--factory", "identity.web.app:create_app", "--host", "0.0.0.0", "--port", "8200", "--proxy-headers", "--forwarded-allow-ips", "*"]
