"""Litestar plugin entry point that wires all Keycloak components together.

``KeycloakPlugin`` implements ``InitPluginProtocol``.  On application init
it fetches OIDC discovery metadata, registers the auth backend, installs
exception handlers, binds DI providers, and — when opted in — mounts the
OIDC route group.  This is the only object consumers need to import to
integrate Keycloak into a Litestar application.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from litestar.plugins import InitPluginProtocol

from litestar_keycloak.auth import create_auth_middleware
from litestar_keycloak.dependencies import build_dependencies
from litestar_keycloak.exceptions import exception_handlers
from litestar_keycloak.routes import build_auth_controller
from litestar_keycloak.token import JWKSCache, TokenVerifier

if TYPE_CHECKING:
    from litestar.config.app import AppConfig

    from litestar_keycloak.config import KeycloakConfig


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

    __slots__ = ("_config", "_jwks_cache", "_verifier")

    def __init__(self, config: KeycloakConfig) -> None:
        self._config = config
        self._jwks_cache = JWKSCache(
            jwks_url=config.jwks_url,
            ttl=config.jwks_cache_ttl,
            http_timeout=config.http_timeout,
        )
        self._verifier = TokenVerifier(config, self._jwks_cache)

    def on_app_init(self, app_config: AppConfig) -> AppConfig:
        """Hook called by Litestar during application startup.

        Registers:
        - Authentication middleware (bearer token extraction + validation)
        - Exception handlers (``KeycloakError`` hierarchy -> HTTP responses)
        - DI providers (``current_user``, ``token_payload``, ``raw_token``)
        - OIDC routes (when ``include_routes`` is ``True``)
        - Lifespan handler to warm the JWKS cache on startup
        """
        # -- auth middleware -----------------------------------------------
        middleware_cls = create_auth_middleware(self._config, self._verifier)
        app_config.middleware.insert(0, middleware_cls)

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
            controller = build_auth_controller(self._config)
            app_config.route_handlers.append(controller)

        # -- JWKS warm-up on startup ---------------------------------------
        app_config.on_startup.append(self._on_startup)

        return app_config

    async def _on_startup(self) -> None:
        """Warm the JWKS cache so the first request doesn't pay fetch latency."""
        await self._jwks_cache.warm()
