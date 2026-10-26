# Vetfab identity service. Build from the repository root:
#   docker build -t vetfab-identity .
# The same image runs the migrations (`alembic upgrade head`) and `identity-admin` (ensure-key, create-user, ...).
FROM ghcr.io/astral-sh/uv:0.9.18 AS uv

FROM python:3.12-slim-bookworm
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY alembic.ini README.md ./
COPY identity identity
COPY migrations migrations
RUN uv sync --frozen --no-dev \
 && useradd --uid 10002 --no-create-home --shell /usr/sbin/nologin identity \
 && mkdir -p /keys && chown 10002:10002 /keys && chmod 700 /keys

USER 10002
ENV PATH=/app/.venv/bin:$PATH IDENTITY_KEYS_DIR=/keys
VOLUME ["/keys"]
EXPOSE 8200
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8200/auth/health', timeout=3)"]
# Only the reverse proxy reaches the service; the client address for rate limits comes from its X-Forwarded-For.
CMD ["uvicorn", "--factory", "identity.web.app:create_app", "--host", "0.0.0.0", "--port", "8200", "--proxy-headers", "--forwarded-allow-ips", "*"]
