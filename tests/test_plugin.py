"""Tests for KeycloakPlugin registration (middleware, deps, handlers, startup)."""

import pytest
from litestar.config.app import AppConfig

from litestar_keycloak import KeycloakConfig, KeycloakPlugin
from litestar_keycloak.exceptions import (
    AuthenticationError,
    AuthorizationError,
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
    """on_app_init adds auth middleware at position 0."""
    app_config = AppConfig()
    assert app_config.middleware == []
    plugin = KeycloakPlugin(keycloak_config)
    plugin.on_app_init(app_config)
    assert len(app_config.middleware) == 1
    # Middleware is a class (factory), not an instance
    assert app_config.middleware[0] is not None


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
