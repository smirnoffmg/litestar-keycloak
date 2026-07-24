"""Unit tests for auth middleware (token extraction, excluded paths)."""

import time
from unittest.mock import AsyncMock, patch

import pytest
from litestar import Litestar, get
from litestar.testing import TestClient

from litestar_keycloak import KeycloakPlugin
from litestar_keycloak.auth import (
    RAW_TOKEN_STATE_KEY,
    TOKEN_STATE_KEY,
    create_auth_middleware,
)
from litestar_keycloak.config import KeycloakConfig, TokenLocation
from litestar_keycloak.exceptions import InvalidIssuerError, MissingTokenError
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


# --- authentication exclusion (framework-level, via the plugin) ---


@pytest.fixture(autouse=True)
def _no_jwks_warm():
    """Stub the startup JWKS warm-up so app-level tests need no live Keycloak."""
    with patch("litestar_keycloak.plugin.JWKSCache.warm", new_callable=AsyncMock):
        yield


@get("/health")
async def _health() -> dict:
    return {"ok": True}


@get("/health-secret")
async def _health_secret() -> dict:
    return {"secret": True}


@get("/public/data")
async def _public_data() -> dict:
    return {"public": True}


@get("/open", exclude_from_auth=True)
async def _open() -> dict:
    return {"open": True}


@get("/me")
async def _me() -> dict:
    return {"me": True}


def _plugin_app(**config_kwargs) -> Litestar:
    config = KeycloakConfig(
        server_url="http://localhost:8080",
        realm="test-realm",
        client_id="test-app",
        **config_kwargs,
    )
    return Litestar(
        route_handlers=[_health, _health_secret, _public_data, _open, _me],
        plugins=[KeycloakPlugin(config)],
    )


def test_exact_excluded_path_bypasses_auth():
    """A path in excluded_paths is reachable without a token."""
    app = _plugin_app(excluded_paths=frozenset({"/health"}))
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/me").status_code == 401


def test_excluded_path_is_anchored_not_prefix():
    """excluded_paths matches exactly: /health does not exclude /health-secret."""
    app = _plugin_app(excluded_paths=frozenset({"/health"}))
    with TestClient(app) as client:
        assert client.get("/health-secret").status_code == 401


def test_exclude_pattern_covers_a_subtree():
    """A regex in exclude_patterns bypasses auth for a whole path prefix."""
    app = _plugin_app(exclude_patterns=("^/public/",))
    with TestClient(app) as client:
        assert client.get("/public/data").status_code == 200
        assert client.get("/me").status_code == 401


def test_per_handler_exclude_from_auth_opt_out():
    """A handler marked exclude_from_auth=True bypasses auth with no config."""
    app = _plugin_app()
    with TestClient(app) as client:
        assert client.get("/open").status_code == 200
        assert client.get("/me").status_code == 401


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


# --- bearer case and whitespace ---


async def test_bearer_case_insensitive():
    """Authorization header accepts Bearer in any case (Bearer, BEARER, bearer)."""
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
    for auth_value in (
        "Bearer my.jwt.token",
        "BEARER my.jwt.token",
        "bearer my.jwt.token",
    ):
        conn = _connection(headers={"authorization": auth_value})
        result = await middleware.authenticate_request(conn)
        assert result.user is not None
        assert result.user.sub == "user-1"
    verifier.verify.assert_called_with("my.jwt.token")
    assert verifier.verify.call_count == 3


async def test_extra_whitespace_in_authorization_header():
    """Extra whitespace between Bearer and token is normalized; token extracted."""
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
    conn = _connection(headers={"authorization": "Bearer   my.jwt.token"})
    result = await middleware.authenticate_request(conn)
    assert result.user is not None
    verifier.verify.assert_called_once_with("my.jwt.token")


async def test_session_fallback_used_when_header_absent():
    """No Authorization header but a token in the session -> session token is used."""
    config = KeycloakConfig(
        server_url="http://localhost:8080",
        realm="test-realm",
        client_id="test-app",
    )
    payload = _token_payload()
    verifier = AsyncMock()
    verifier.verify = AsyncMock(return_value=payload)
    middleware = create_auth_middleware(config, verifier)(_mock_app())
    conn = _connection(headers={})
    conn.scope["session"] = {"keycloak_access_token": "sess-tok"}
    result = await middleware.authenticate_request(conn)
    assert result.user is not None
    verifier.verify.assert_called_once_with("sess-tok")


async def test_no_header_and_no_session_raises():
    """No header and no session token still raises MissingTokenError."""
    config = KeycloakConfig(
        server_url="http://localhost:8080",
        realm="test-realm",
        client_id="test-app",
    )
    verifier = AsyncMock()
    middleware = create_auth_middleware(config, verifier)(_mock_app())
    conn = _connection(headers={})  # scope has no "session" key
    with pytest.raises(MissingTokenError):
        await middleware.authenticate_request(conn)
    verifier.verify.assert_not_called()


async def test_verifier_exception_propagates_unchanged():
    """Verifier exception (e.g. InvalidIssuerError) propagates from auth."""
    config = KeycloakConfig(
        server_url="http://localhost:8080",
        realm="test-realm",
        client_id="test-app",
    )
    verifier = AsyncMock()
    verifier.verify = AsyncMock(
        side_effect=InvalidIssuerError(expected="https://kc/r", got="https://wrong/r")
    )
    middleware_cls = create_auth_middleware(config, verifier)
    middleware = middleware_cls(_mock_app())
    conn = _connection(headers={"authorization": "Bearer my.jwt.token"})
    with pytest.raises(InvalidIssuerError) as exc_info:
        await middleware.authenticate_request(conn)
    assert exc_info.value.expected == "https://kc/r"
    assert exc_info.value.got == "https://wrong/r"
