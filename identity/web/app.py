"""Identity service entry point: `uvicorn --factory identity.web.app:create_app`.

Settings are validated when the app is created. At startup the service refuses (outside development and test) a
privileged database login, and refuses to serve without a signing key; in development a missing key is generated.
"""

import asyncio
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from psycopg_pool import AsyncConnectionPool, PoolTimeout

from identity.config import Settings, get_settings
from identity.db import login_problems, open_pool
from identity.keys import KeyRing, NoSigningKeyError, generate_key
from identity.web.oauth_routes import router as oauth_router
from identity.web.routes import busy_response, router
from identity.web.security import BodyLimit, security_headers

log = logging.getLogger("identity")
HERE = Path(__file__).resolve().parent


def load_keys(settings: Settings) -> KeyRing:
    try:
        return KeyRing.load(settings.keys_dir)
    except NoSigningKeyError:
        if settings.environment != "development":
            raise
        log.warning("no signing key in %s; generating a development key", settings.keys_dir)
        generate_key(settings.keys_dir)
        return KeyRing.load(settings.keys_dir)


def create_app(
    settings: Settings | None = None, *, pool: AsyncConnectionPool | None = None, keys: KeyRing | None = None
) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        owned = app.state.pool is None
        if owned:
            app.state.pool = await open_pool(settings.database_url, wait_seconds=settings.db_wait_seconds)
        try:
            async with app.state.pool.connection() as conn:
                problems = await login_problems(conn)
            if problems and settings.deployed:
                raise RuntimeError("Unsafe database login for the identity service: " + "; ".join(problems))
            for problem in problems:
                log.warning("database login is not production-safe: %s", problem)
            if app.state.keys is None:
                app.state.keys = load_keys(settings)
            yield
        finally:
            if owned:
                await app.state.pool.close()

    app = FastAPI(title="Vetfab identity", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.pool = pool
    app.state.keys = keys
    app.state.templates = Jinja2Templates(directory=HERE / "templates")
    # Bounds concurrent password checks (perf design §10); see routes.login().
    app.state.verify_slots = asyncio.Semaphore(settings.max_concurrent_verifies)
    headers = security_headers(settings)

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        response = await call_next(request)
        for key, value in headers.items():
            response.headers.setdefault(key, value)
        return response

    app.add_middleware(BodyLimit)

    async def pool_timeout(request: Request, exc: Exception) -> Response:
        log.warning("no database connection within the pool timeout: %s %s", request.method, request.url.path)
        return busy_response(request)

    app.add_exception_handler(PoolTimeout, pool_timeout)
    app.include_router(router)
    app.include_router(oauth_router)
    app.mount("/auth/static", StaticFiles(directory=HERE / "static"), name="static")
    return app
