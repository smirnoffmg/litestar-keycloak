"""Tests for KeycloakPlugin registration (middleware, deps, handlers, startup)."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from litestar.config.app import AppConfig
from litestar.di import Provide

from litestar_keycloak import KeycloakConfig, KeycloakPlugin
from litestar_keycloak.exceptions import (
    AuthenticationError,
    AuthorizationError,
    JWKSFetchError,
    KeycloakBackendError,
)


@pytest.fixture
def keycloak_config():
    """Minimal config for plugin (no real HTTP)."""
    return KeycloakConfig(
        server_url="http://localhost:8080",
        realm="test-realm",
        client_id="test-app",
    )


def test_plugin_registers_middleware(keycloak_config):
    """on_app_init adds the auth middleware."""
    app_config = AppConfig()
    assert app_config.middleware == []
    plugin = KeycloakPlugin(keycloak_config)
    plugin.on_app_init(app_config)
    assert len(app_config.middleware) == 1
    assert app_config.middleware[0] is not None


def test_middleware_appended_after_existing(keycloak_config):
    """Auth middleware is appended so it runs after app-level (session) middleware."""
    other_middleware = MagicMock()
    app_config = AppConfig()
    app_config.middleware = [other_middleware]
    plugin = KeycloakPlugin(keycloak_config)
    plugin.on_app_init(app_config)
    assert len(app_config.middleware) == 2
    # existing middleware stays first (outer); auth is appended last (inner)
    assert app_config.middleware[0] is other_middleware
    assert app_config.middleware[1] is not other_middleware


def test_plugin_registers_exception_handlers(keycloak_config):
    """on_app_init registers Keycloak exception handlers."""
    app_config = AppConfig()
    plugin = KeycloakPlugin(keycloak_config)
    plugin.on_app_init(app_config)
    assert AuthenticationError in app_config.exception_handlers
    assert AuthorizationError in app_config.exception_handlers
    assert KeycloakBackendError in app_config.exception_handlers


def test_plugin_registers_dependencies(keycloak_config):
    """on_app_init registers current_user, token_payload, raw_token."""
    app_config = AppConfig()
    plugin = KeycloakPlugin(keycloak_config)
    plugin.on_app_init(app_config)
    assert "current_user" in app_config.dependencies
    assert "token_payload" in app_config.dependencies
    assert "raw_token" in app_config.dependencies


def test_plugin_adds_startup_callback(keycloak_config):
    """on_app_init appends JWKS warm-up to on_startup."""
    app_config = AppConfig()
    assert app_config.on_startup == []
    plugin = KeycloakPlugin(keycloak_config)
    plugin.on_app_init(app_config)
    assert len(app_config.on_startup) == 1


def test_plugin_with_include_routes_adds_route_handlers(keycloak_config):
    """When include_routes=True, plugin appends auth controller."""
    config_with_routes = KeycloakConfig(
        server_url="http://localhost:8080",
        realm="test-realm",
        client_id="test-app",
        include_routes=True,
        redirect_uri="http://localhost:8000/auth/callback",
    )
    app_config = AppConfig()
    assert app_config.route_handlers == []
    plugin = KeycloakPlugin(config_with_routes)
    plugin.on_app_init(app_config)
    assert len(app_config.route_handlers) == 1
    # Controller has path = config.auth_prefix
    assert getattr(app_config.route_handlers[0], "path", None) == "/auth"


def test_plugin_without_include_routes_adds_no_routes(keycloak_config):
    """When include_routes=False, route_handlers unchanged."""
    app_config = AppConfig()
    plugin = KeycloakPlugin(keycloak_config)
    plugin.on_app_init(app_config)
    assert app_config.route_handlers == []


def test_user_exception_handler_overrides_plugin_default(keycloak_config):
    """User exception handler for AuthenticationError is preserved (merge order)."""
    user_handler = MagicMock()
    app_config = AppConfig()
    app_config.exception_handlers = {AuthenticationError: user_handler}
    plugin = KeycloakPlugin(keycloak_config)
    plugin.on_app_init(app_config)
    assert app_config.exception_handlers[AuthenticationError] is user_handler


async def _dummy_user_provider():
    return None


def test_user_dependency_overrides_plugin_default(keycloak_config):
    """User-provided dependency for current_user is preserved (merge order)."""
    user_provide = Provide(_dummy_user_provider)
    app_config = AppConfig()
    app_config.dependencies = {"current_user": user_provide}
    plugin = KeycloakPlugin(keycloak_config)
    plugin.on_app_init(app_config)
    assert app_config.dependencies["current_user"] is user_provide


async def test_on_startup_calls_jwks_warm(keycloak_config):
    """The on_startup callback calls _jwks_cache.warm()."""
    app_config = AppConfig()
    plugin = KeycloakPlugin(keycloak_config)
    plugin.on_app_init(app_config)
    assert len(app_config.on_startup) == 1
    warm_mock = AsyncMock()
    plugin._jwks_cache.warm = warm_mock
    await app_config.on_startup[0]()
    warm_mock.assert_called_once()


async def test_on_startup_survives_keycloak_unavailable(keycloak_config):
    """A JWKS fetch failure at startup is swallowed so the app can still boot."""
    plugin = KeycloakPlugin(keycloak_config)
    app_config = AppConfig()
    plugin.on_app_init(app_config)
    plugin._jwks_cache.warm = AsyncMock(side_effect=JWKSFetchError("Keycloak down"))
    # Must not raise — the cache refetches lazily on the first request.
    await app_config.on_startup[0]()
    plugin._jwks_cache.warm.assert_awaited_once()


def test_plugin_adds_shutdown_callback(keycloak_config):
    """on_app_init appends an HTTP-client close to on_shutdown."""
    app_config = AppConfig()
    assert app_config.on_shutdown == []
    plugin = KeycloakPlugin(keycloak_config)
    plugin.on_app_init(app_config)
    assert len(app_config.on_shutdown) == 1


async def test_on_shutdown_closes_http_client(keycloak_config):
    """The on_shutdown callback closes the shared HTTP client."""
    app_config = AppConfig()
    plugin = KeycloakPlugin(keycloak_config)
    plugin.on_app_init(app_config)
    close_mock = AsyncMock()
    plugin._http.close = close_mock
    await app_config.on_shutdown[0]()
    close_mock.assert_called_once()
