"""This instance's copy of the managed registry, and the sign-in origin allowlist built from it.

Several identity-service instances share one database, so none of them may treat its memory as the truth. What is
cached here is only what cannot afford a query per check: the **origins** that may receive sign-ins and CORS (used by
`redirects.py`, `security.py`, the CSP). Everything that decides a hand-off (issuing, redeeming, listing) reads the
database in the request itself.

The allowlist is `IDENTITY_APP_ORIGINS` plus the `base_url` of every **active** managed service, rebuilt at most every
`IDENTITY_REGISTRY_REFRESH_SECONDS` and straight after a change made on this instance. A service that is pending or
disabled contributes nothing, so it can never be sent a token. The first refresh also seeds the database from
`IDENTITY_SERVICES` (registry_store.bootstrap).

On a deployed service an **active** `local` service joins the allowlist too, but only while
`IDENTITY_ALLOW_LOCALHOST_DEV_ORIGINS` is on and its origin is still exactly a loopback `http://localhost:<port>`
(checked again here, whatever the row says). Turning the setting off drops them all at the next refresh.
"""

import asyncio
import logging
import time
from typing import Any

from psycopg_pool import AsyncConnectionPool

from identity import registry_store
from identity.config import Settings
from identity.services import Registry, is_localhost_dev_origin

log = logging.getLogger("identity")


class RegistryCache:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._env_origins = settings.app_origin_list  # IDENTITY_APP_ORIGINS, before anything is added
        self._seed = settings.registry
        self._ttl = settings.registry_refresh_seconds
        self._refreshed_at: float | None = None
        self._seeded = False
        self._lock = asyncio.Lock()
        self.registry = Registry()
        self.local_dev_services: dict[str, str] = {}  # trusted localhost development origin -> service id

    def _apply(self, registry: Registry) -> None:
        origins = list(self._env_origins)
        origins += [s.base_url for s in registry.services if s.enabled and s.base_url not in origins]
        local = {
            s.base_url: s.id
            for s in registry.services
            if self._settings.deployed
            and self._settings.allow_localhost_dev_origins
            and s.status == "active"
            and s.environment == "local"
            and is_localhost_dev_origin(s.base_url)
        }
        origins += [origin for origin in local if origin not in origins]
        self.local_dev_services = local
        # Pydantic does not re-validate on assignment; the values are already normalised origins.
        self._settings.app_origins = ",".join(origins)
        self.registry = registry
        self._refreshed_at = time.monotonic()

    async def refresh(self, pool: AsyncConnectionPool[Any]) -> None:
        async with self._lock, pool.connection() as conn:
            if not self._seeded:
                result = await registry_store.bootstrap(conn, self._seed)
                for service_id in result.inserted:
                    from identity import store  # local: store imports nothing from here

                    await store.audit(conn, "service_bootstrapped", metadata={"service": service_id})
                self._seeded = True
            self._apply(await registry_store.load_registry(conn, deployed=self._settings.deployed))

    async def refresh_if_stale(self, pool: AsyncConnectionPool[Any]) -> None:
        """Called at the start of every request. A failure keeps the previous copy and is retried after the interval."""
        now = time.monotonic()
        if self._refreshed_at is not None and now - self._refreshed_at < self._ttl:
            return
        try:
            await self.refresh(pool)
        except Exception:
            log.exception("could not refresh the service registry; keeping the previous copy")
            self._refreshed_at = time.monotonic()
