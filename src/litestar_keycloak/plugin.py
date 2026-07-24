"""Litestar plugin entry point that wires all Keycloak components together.

``KeycloakPlugin`` implements ``InitPluginProtocol``.  On application init
it registers the auth backend, installs exception handlers, binds DI
providers, and — when opted in — mounts the OIDC route group.  Keycloak
endpoint URLs are derived from ``server_url`` and ``realm`` (see
``KeycloakConfig``), not fetched from the OIDC discovery document.  This is
the only object consumers need to import to integrate Keycloak into a
Litestar application.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, cast

from litestar.middleware import DefineMiddleware
from litestar.plugins import InitPluginProtocol

from litestar_keycloak.auth import create_auth_middleware
from litestar_keycloak.dependencies import build_dependencies
from litestar_keycloak.exceptions import JWKSFetchError, exception_handlers
from litestar_keycloak.http_client import KeycloakHttpClient
from litestar_keycloak.routes import build_auth_controller
from litestar_keycloak.token import JWKSCache, TokenVerifier

if TYPE_CHECKING:
    from litestar.config.app import AppConfig

    from litestar_keycloak.config import KeycloakConfig

logger = logging.getLogger(__name__)


class KeycloakPlugin(InitPluginProtocol):
    """Litestar plugin that integrates Keycloak authentication.

    Usage::

        from litestar import Litestar
        from litestar_keycloak import KeycloakPlugin, KeycloakConfig

        app = Litestar(
            route_handlers=[...],
            plugins=[KeycloakPlugin(
                KeycloakConfig(
                    server_url="https://keycloak.example.com",
                    realm="my-realm",
                    client_id="my-app",
                )
            )],
        )
    """

    __slots__ = ("_config", "_http", "_jwks_cache", "_verifier")

    def __init__(self, config: KeycloakConfig) -> None:
        self._config = config
        self._http = KeycloakHttpClient(config.http_timeout)
        self._jwks_cache = JWKSCache(
            jwks_url=config.jwks_url,
            ttl=config.jwks_cache_ttl,
            http=self._http,
        )
        self._verifier = TokenVerifier(config, self._jwks_cache)

    def on_app_init(self, app_config: AppConfig) -> AppConfig:
        """Hook called by Litestar during application startup.

        Registers:
        - Authentication middleware (bearer token extraction + validation)
        - Exception handlers (``KeycloakError`` hierarchy -> HTTP responses)
        - DI providers (``current_user``, ``token_payload``, ``raw_token``)
        - OIDC routes (when ``include_routes`` is ``True``)
        - Lifespan handlers to warm the JWKS cache on startup (best-effort) and
          close the shared HTTP client on shutdown
        """
        # -- auth middleware -----------------------------------------------
        # Appended (not inserted at 0) so it runs *after* any app-level session
        # middleware — required for callback_response_mode="redirect", where the
        # token is read from the session the session middleware populates.
        middleware_cls = create_auth_middleware(self._config, self._verifier)
        app_config.middleware.append(
            DefineMiddleware(
                middleware_cls,
                exclude=self._config.exclude_auth_patterns,
                exclude_from_auth_key=self._config.exclude_opt_key,
            )
        )

        # -- exception handlers --------------------------------------------
        app_config.exception_handlers = cast(
            "Any",
            {
                **exception_handlers,
                **app_config.exception_handlers,
            },
        )

        # -- DI providers --------------------------------------------------
        app_config.dependencies = {
            **build_dependencies(),
            **app_config.dependencies,
        }

        # -- OIDC routes ---------------------------------------------------
        if self._config.include_routes:
            controller = build_auth_controller(self._config, self._http)
            app_config.route_handlers.append(controller)

        # -- lifespan: warm JWKS on startup, close HTTP client on shutdown --
        app_config.on_startup.append(self._on_startup)
        app_config.on_shutdown.append(self._on_shutdown)

        return app_config

    async def _on_startup(self) -> None:
        """Warm the JWKS cache so the first request doesn't pay fetch latency.

        Best-effort: if Keycloak is unreachable at boot the warm-up is skipped
        rather than aborting application startup — the cache refetches lazily on
        the first request (which returns 502 until Keycloak is reachable).
        """
        try:
            await self._jwks_cache.warm()
        except JWKSFetchError as exc:
            logger.warning(
                "JWKS warm-up skipped (Keycloak unreachable at startup): %s. "
                "Keys will be fetched on the first request.",
                exc,
            )

    async def _on_shutdown(self) -> None:
        """Close the shared HTTP client so its connections are released."""
        await self._http.close()
