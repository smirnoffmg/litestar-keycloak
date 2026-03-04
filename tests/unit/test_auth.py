"""Unit tests for auth middleware (token extraction, excluded paths)."""

import time
from unittest.mock import AsyncMock

import pytest

from litestar_keycloak.auth import (
    RAW_TOKEN_STATE_KEY,
    TOKEN_STATE_KEY,
    create_auth_middleware,
)
from litestar_keycloak.config import KeycloakConfig, TokenLocation
from litestar_keycloak.exceptions import MissingTokenError
from litestar_keycloak.models import KeycloakUser, TokenPayload


def _mock_app():
    """Dummy app for AbstractAuthenticationMiddleware.__init__(app)."""
    return object()


def _connection(
    scope_path: str = "/api/me",
    headers: dict | None = None,
    cookies: dict | None = None,
):
    """Minimal ASGIConnection double for auth middleware."""

    class State(dict):
        pass

    scope = {"path": scope_path}
    h = headers or {}
    c = cookies or {}
    conn = type(
        "Connection",
        (),
        {
            "scope": scope,
            "headers": type(
                "Headers", (), {"get": lambda self, k, d="": h.get(k.lower(), d)}
            )(),
            "cookies": type("Cookies", (), {"get": lambda self, k: c.get(k)})(),
            "state": State(),
        },
    )()
    return conn


def _token_payload() -> TokenPayload:
    now = int(time.time())
    return TokenPayload(
        sub="user-1",
        iss="http://localhost:8080/realms/test",
        aud="test-app",
        exp=now + 3600,
        iat=now,
        realm_access={"roles": ["user"]},
    )


# --- excluded_paths ---


async def test_excluded_path_returns_none_user_without_calling_verifier():
    """Excluded path: middleware returns no user and does not verify."""
    config = KeycloakConfig(
        server_url="http://localhost:8080",
        realm="test-realm",
        client_id="test-app",
        excluded_paths=frozenset({"/health", "/public"}),
    )
    verifier = AsyncMock()
    middleware_cls = create_auth_middleware(config, verifier)
    middleware = middleware_cls(_mock_app())
    conn = _connection(scope_path="/health")
    result = await middleware.authenticate_request(conn)
    assert result.user is None
    assert result.auth is None
    verifier.verify.assert_not_called()


# --- header extraction ---


async def test_valid_bearer_header_calls_verifier_and_returns_user():
    """Bearer token leads to verification and user set on state."""
    config = KeycloakConfig(
        server_url="http://localhost:8080",
        realm="test-realm",
        client_id="test-app",
    )
    payload = _token_payload()
    verifier = AsyncMock()
    verifier.verify = AsyncMock(return_value=payload)
    middleware_cls = create_auth_middleware(config, verifier)
    middleware = middleware_cls(_mock_app())
    conn = _connection(headers={"authorization": "Bearer my.jwt.token"})
    result = await middleware.authenticate_request(conn)
    assert result.user is not None
    assert isinstance(result.user, KeycloakUser)
    assert result.user.sub == "user-1"
    assert result.auth == payload
    assert conn.state[TOKEN_STATE_KEY] == payload
    assert conn.state[RAW_TOKEN_STATE_KEY] == "my.jwt.token"
    verifier.verify.assert_called_once_with("my.jwt.token")


async def test_missing_authorization_header_raises():
    """No Authorization header raises MissingTokenError."""
    config = KeycloakConfig(
        server_url="http://localhost:8080",
        realm="test-realm",
        client_id="test-app",
    )
    verifier = AsyncMock()
    middleware_cls = create_auth_middleware(config, verifier)
    middleware = middleware_cls(_mock_app())
    conn = _connection(headers={})
    with pytest.raises(MissingTokenError) as exc_info:
        await middleware.authenticate_request(conn)
    assert "header" in str(exc_info.value).lower()
    verifier.verify.assert_not_called()


async def test_malformed_bearer_header_raises():
    """Malformed Authorization (not 'Bearer <token>') raises MissingTokenError."""
    config = KeycloakConfig(
        server_url="http://localhost:8080",
        realm="test-realm",
        client_id="test-app",
    )
    verifier = AsyncMock()
    middleware_cls = create_auth_middleware(config, verifier)
    middleware = middleware_cls(_mock_app())
    conn = _connection(headers={"authorization": "Basic xyz"})
    with pytest.raises(MissingTokenError):
        await middleware.authenticate_request(conn)
    conn2 = _connection(headers={"authorization": "Bearer"})  # no token
    with pytest.raises(MissingTokenError):
        await middleware.authenticate_request(conn2)
    verifier.verify.assert_not_called()


# --- cookie extraction ---


async def test_cookie_location_extracts_token_and_calls_verifier():
    """When token_location is COOKIE, token is read from cookie."""
    config = KeycloakConfig(
        server_url="http://localhost:8080",
        realm="test-realm",
        client_id="test-app",
        token_location=TokenLocation.COOKIE,
        cookie_name="access_token",
    )
    payload = _token_payload()
    verifier = AsyncMock()
    verifier.verify = AsyncMock(return_value=payload)
    middleware_cls = create_auth_middleware(config, verifier)
    middleware = middleware_cls(_mock_app())
    conn = _connection(cookies={"access_token": "cookie.jwt.value"})
    result = await middleware.authenticate_request(conn)
    assert result.user is not None
    assert result.user.sub == "user-1"
    verifier.verify.assert_called_once_with("cookie.jwt.value")


async def test_cookie_location_missing_cookie_raises():
    """When token_location is COOKIE and cookie missing, raises MissingTokenError."""
    config = KeycloakConfig(
        server_url="http://localhost:8080",
        realm="test-realm",
        client_id="test-app",
        token_location=TokenLocation.COOKIE,
        cookie_name="access_token",
    )
    verifier = AsyncMock()
    middleware_cls = create_auth_middleware(config, verifier)
    middleware = middleware_cls(_mock_app())
    conn = _connection(cookies={})
    with pytest.raises(MissingTokenError) as exc_info:
        await middleware.authenticate_request(conn)
    assert "cookie" in str(exc_info.value).lower() or "access_token" in str(
        exc_info.value
    )
    verifier.verify.assert_not_called()
