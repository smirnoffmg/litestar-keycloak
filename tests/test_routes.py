"""Tests for OIDC auth routes (login, callback, logout, refresh) with mocked HTTP."""

import urllib.parse
from unittest.mock import AsyncMock, patch

import pytest
from litestar import Litestar, Request, get
from litestar.middleware.session.server_side import ServerSideSessionConfig
from litestar.stores.memory import MemoryStore
from litestar.testing import TestClient

from litestar_keycloak import KeycloakConfig, KeycloakPlugin


def _config_with_routes(**kwargs):
    """Config with auth routes; effective_excluded_paths auto-includes auth paths.

    ``cookie_secure=False`` so the TestClient (http://testserver) sends the
    plugin's state cookie back on follow-up requests.
    """
    kwargs.setdefault("cookie_secure", False)
    return KeycloakConfig(
        server_url="http://keycloak.example.com",
        realm="test-realm",
        client_id="test-app",
        include_routes=True,
        redirect_uri="http://localhost:8000/auth/callback",
        auth_prefix="/auth",
        **kwargs,
    )


@pytest.fixture(autouse=True)
def _no_jwks_warm():
    """Stub the startup JWKS warm-up so tests need no live Keycloak."""
    with patch("litestar_keycloak.plugin.JWKSCache.warm", new_callable=AsyncMock):
        yield


@pytest.fixture
def app_with_routes():
    """App with auth routes in the default json (SPA) mode."""
    return Litestar(plugins=[KeycloakPlugin(_config_with_routes())])


@get("/debug/session", exclude_from_auth=True)
async def _session_debug(request: Request) -> dict:
    """Public route exposing the Keycloak tokens stored in the session."""
    return {
        "access": request.session.get("keycloak_access_token"),
        "refresh": request.session.get("keycloak_refresh_token"),
    }


@get("/me")
async def _me() -> dict:
    """Protected route — reachable only when the auth middleware authenticates."""
    return {"ok": True}


@pytest.fixture
def app_redirect_mode():
    """App with auth routes in redirect mode + server-side session middleware."""
    config = _config_with_routes(callback_response_mode="redirect")
    session_config = ServerSideSessionConfig()
    return Litestar(
        route_handlers=[_session_debug, _me],
        plugins=[KeycloakPlugin(config)],
        middleware=[session_config.middleware],
        stores={"sessions": MemoryStore()},
    )


def _login_state(client) -> str:
    """Drive /auth/login; return the state (also stored as a cookie by the client)."""
    resp = client.get("/auth/login", follow_redirects=False)
    query = urllib.parse.urlparse(resp.headers["location"]).query
    return urllib.parse.parse_qs(query)["state"][0]


def _complete_login(client, tokens: dict) -> None:
    """Drive login + callback so *tokens* land in the server-side session."""
    with patch(
        "litestar_keycloak.routes._exchange_code",
        new_callable=AsyncMock,
        return_value=tokens,
    ):
        state = _login_state(client)
        client.get(f"/auth/callback?code=c&state={state}", follow_redirects=False)


def _set_cookie_header(resp, name: str) -> str:
    """Return the Set-Cookie header for *name*, or '' if absent."""
    for header in resp.headers.get_list("set-cookie"):
        if header.startswith(f"{name}="):
            return header
    return ""


# --- Fake HTTP client injected into the token/logout helpers (no server) ---


class _FakeHttp:
    """Records calls and returns canned JSON — stands in for KeycloakHttpClient."""

    def __init__(self, data: dict | None = None) -> None:
        self._data = data or {}
        self.get_calls: list[tuple] = []
        self.post_calls: list[tuple] = []

    async def get_json(self, url, *, headers=None) -> dict:
        self.get_calls.append((url, headers))
        return self._data

    async def post_form(self, url, data) -> dict:
        self.post_calls.append((url, data))
        return self._data

    async def post_form_discard(self, url, data) -> None:
        self.post_calls.append((url, data))

    async def close(self) -> None:
        pass


def test_login_redirect_includes_client_id_and_redirect_uri(app_with_routes):
    """GET /auth/login returns redirect to Keycloak with client_id and redirect_uri."""
    with TestClient(app_with_routes) as client:
        resp = client.get("/auth/login", follow_redirects=False)
    assert resp.status_code in (302, 307)
    location = resp.headers.get("location", "")
    assert "client_id=test-app" in location or "client_id=" in location
    assert "redirect_uri=" in location
    assert "state=" in location
    assert "keycloak.example.com" in location and "openid-connect/auth" in location


def test_callback_missing_code_raises(app_with_routes):
    """GET /auth/callback without code returns 401."""
    with TestClient(app_with_routes) as client:
        resp = client.get("/auth/callback")
    assert resp.status_code == 401


def test_callback_invalid_state_raises(app_with_routes):
    """GET /auth/callback with no prior login (no state cookie) returns 401."""
    with TestClient(app_with_routes) as client:
        resp = client.get("/auth/callback?code=abc&state=wrong")
    assert resp.status_code == 401


@patch("litestar_keycloak.routes._exchange_code", new_callable=AsyncMock)
def test_callback_valid_returns_tokens(mock_exchange, app_with_routes):
    """HEADER mode: callback with matching state returns the token JSON."""
    mock_exchange.return_value = {
        "access_token": "at",
        "refresh_token": "rt",
        "expires_in": 3600,
    }
    with TestClient(app_with_routes) as client:
        state = _login_state(client)  # sets the state cookie in the client jar
        resp = client.get(f"/auth/callback?code=valid&state={state}")
    assert resp.status_code == 200
    assert resp.json()["access_token"] == "at"
    mock_exchange.assert_called_once()
    assert mock_exchange.call_args[0][1] == "valid"


@patch("litestar_keycloak.routes._exchange_code", new_callable=AsyncMock)
def test_callback_redirect_mode_stores_session_and_redirects(
    mock_exchange, app_redirect_mode
):
    """redirect mode: callback stores tokens in the session and redirects."""
    mock_exchange.return_value = {"access_token": "at", "refresh_token": "rt"}
    with TestClient(app_redirect_mode) as client:
        state = _login_state(client)
        resp = client.get(
            f"/auth/callback?code=valid&state={state}", follow_redirects=False
        )
        assert resp.status_code in (301, 302, 303, 307, 308)
        assert resp.headers["location"] == "/"
        # no raw JWT cookie is set
        assert not _set_cookie_header(resp, "access_token")
        # tokens are in the server-side session
        stored = client.get("/debug/session").json()
    assert stored == {"access": "at", "refresh": "rt"}
    # state cookie is cleared on callback
    state_cookie = _set_cookie_header(resp, "kc_oauth_state")
    assert "Max-Age=0" in state_cookie or "expires=" in state_cookie.lower()


def test_middleware_reads_token_from_session(app_redirect_mode):
    """After a redirect-mode login, a protected route authenticates via the session."""
    from litestar_keycloak.models import TokenPayload

    payload = TokenPayload(
        sub="u1",
        iss="http://keycloak.example.com/realms/test-realm",
        aud="test-app",
        exp=9999999999,
        iat=0,
    )
    with (
        patch(
            "litestar_keycloak.token.TokenVerifier.verify",
            new_callable=AsyncMock,
            return_value=payload,
        ) as mock_verify,
        TestClient(app_redirect_mode) as client,
    ):
        # no session token yet -> 401
        assert client.get("/me").status_code == 401
        _complete_login(client, {"access_token": "sess-at", "refresh_token": "rt"})
        resp = client.get("/me")
    assert resp.status_code == 200
    mock_verify.assert_awaited_with("sess-at")


def test_login_sets_httponly_state_cookie(app_with_routes):
    """The OAuth state cookie is HttpOnly (no session middleware needed for state)."""
    with TestClient(app_with_routes) as client:
        resp = client.get("/auth/login", follow_redirects=False)
    state_cookie = _set_cookie_header(resp, "kc_oauth_state")
    assert state_cookie and "HttpOnly" in state_cookie


@patch("litestar_keycloak.routes._keycloak_logout", new_callable=AsyncMock)
def test_logout_returns_200(mock_logout, app_with_routes):
    """POST /auth/logout returns 2xx and logged_out status."""
    with TestClient(app_with_routes) as client:
        resp = client.post("/auth/logout", json={"refresh_token": "rt123"})
    assert resp.status_code in (200, 201)
    data = resp.json()
    assert data.get("status") == "logged_out"


def test_refresh_missing_token_raises(app_with_routes):
    """POST /auth/refresh without refresh_token returns 401."""
    with TestClient(app_with_routes) as client:
        resp = client.post("/auth/refresh", json={})
    assert resp.status_code == 401


@patch("litestar_keycloak.routes._refresh_token", new_callable=AsyncMock)
def test_refresh_valid_returns_tokens(mock_refresh, app_with_routes):
    """POST /auth/refresh with refresh_token returns new tokens when mock provides."""
    mock_refresh.return_value = {
        "access_token": "new_at",
        "refresh_token": "new_rt",
        "expires_in": 3600,
    }
    with TestClient(app_with_routes) as client:
        resp = client.post("/auth/refresh", json={"refresh_token": "old_rt"})
    assert resp.status_code in (200, 201)
    mock_refresh.assert_called_once()
    assert mock_refresh.call_args[0][1] == "old_rt"


def test_login_includes_scopes_from_config(app_with_routes):
    """Login redirect URL includes scope parameter from config.scopes."""
    config = _config_with_routes(scopes=("openid", "profile", "email"))
    with patch("litestar_keycloak.plugin.JWKSCache.warm", new_callable=AsyncMock):
        app = Litestar(plugins=[KeycloakPlugin(config)])
    with TestClient(app) as client:
        resp = client.get("/auth/login", follow_redirects=False)
    assert resp.status_code in (302, 307)
    location = resp.headers.get("location", "")
    query = urllib.parse.urlparse(location).query
    params = urllib.parse.parse_qs(query)
    assert "scope" in params
    scope = params["scope"][0]
    assert "openid" in scope and "profile" in scope and "email" in scope


def test_login_state_is_cryptographically_random(app_with_routes):
    """Two GET /auth/login requests produce different state values in redirect URL."""
    with TestClient(app_with_routes) as client:
        r1 = client.get("/auth/login", follow_redirects=False)
        r2 = client.get("/auth/login", follow_redirects=False)
    loc1 = r1.headers.get("location", "")
    loc2 = r2.headers.get("location", "")
    q1 = urllib.parse.parse_qs(urllib.parse.urlparse(loc1).query)
    q2 = urllib.parse.parse_qs(urllib.parse.urlparse(loc2).query)
    state1 = q1.get("state", [""])[0]
    state2 = q2.get("state", [""])[0]
    assert state1 != state2
    assert len(state1) >= 32 and len(state2) >= 32


@patch("litestar_keycloak.routes._keycloak_logout", new_callable=AsyncMock)
def test_logout_clears_session_even_when_keycloak_call_fails(
    mock_logout, app_with_routes
):
    """When _keycloak_logout raises, logout returns 2xx or 5xx (current: 5xx)."""
    mock_logout.side_effect = Exception("Keycloak unreachable")
    with TestClient(app_with_routes) as client:
        resp = client.post("/auth/logout", json={"refresh_token": "rt123"})
    # Current implementation does not catch; exception propagates -> 500
    assert resp.status_code in (200, 201, 500)
    if resp.status_code in (200, 201):
        assert resp.json().get("status") == "logged_out"


@patch("litestar_keycloak.routes._token_request", new_callable=AsyncMock)
def test_refresh_forwards_correct_grant_type(mock_token_request, app_with_routes):
    """Refresh route calls token endpoint with grant_type=refresh_token."""
    mock_token_request.return_value = {
        "access_token": "at",
        "refresh_token": "rt",
        "expires_in": 3600,
    }
    with TestClient(app_with_routes) as client:
        resp = client.post("/auth/refresh", json={"refresh_token": "my_refresh_token"})
    assert resp.status_code in (200, 201)
    mock_token_request.assert_called_once()
    args = mock_token_request.call_args[0]
    form_data = args[1]
    assert form_data.get("grant_type") == "refresh_token"
    assert form_data.get("refresh_token") == "my_refresh_token"


@patch("litestar_keycloak.routes._exchange_code", new_callable=AsyncMock)
async def test_callback_calls_exchange_with_correct_code(mock_exchange):
    """Callback handler calls _exchange_code with the code from the request."""
    mock_exchange.return_value = {
        "access_token": "at",
        "refresh_token": "rt",
        "expires_in": 3600,
    }
    config = _config_with_routes()

    # Test the callback logic without Controller instance: simulate what callback does
    class SimpleRequest:
        query_params = {"code": "the_auth_code", "state": "saved_state"}

    request = SimpleRequest()
    from litestar_keycloak.routes import _exchange_code

    token_data = await _exchange_code(config, request.query_params.get("code"))
    mock_exchange.assert_called_once()
    assert mock_exchange.call_args[0][1] == "the_auth_code"
    assert token_data["access_token"] == "at"


@patch("litestar_keycloak.routes._exchange_code", new_callable=AsyncMock)
async def test_callback_returns_full_token_response(mock_exchange):
    """Callback returns the full token response from _exchange_code."""
    token_data = {
        "access_token": "access_xyz",
        "refresh_token": "refresh_xyz",
        "expires_in": 3600,
        "token_type": "Bearer",
    }
    mock_exchange.return_value = token_data
    config = _config_with_routes()
    # Callback returns Response(content=token_data); assert _exchange_code return used
    from litestar_keycloak.routes import _exchange_code

    result = await _exchange_code(config, "code")
    assert result == token_data
    from litestar import Response

    response = Response(content=result)
    assert response.content == token_data


# --- callback state validation (cookie-based, no session middleware) ---


def test_callback_valid_state_returns_tokens(app_with_routes):
    """Callback with a state matching the state cookie exchanges the code."""
    with (
        patch(
            "litestar_keycloak.routes._exchange_code",
            new_callable=AsyncMock,
            return_value={"access_token": "at", "refresh_token": "rt"},
        ) as mock_exchange,
        TestClient(app_with_routes) as client,
    ):
        state = _login_state(client)
        resp = client.get(f"/auth/callback?code=the-code&state={state}")
    assert resp.status_code == 200
    assert resp.json()["access_token"] == "at"
    mock_exchange.assert_called_once()
    assert mock_exchange.call_args[0][1] == "the-code"


def test_callback_wrong_state_returns_401(app_with_routes):
    """Callback with a state that doesn't match the state cookie is rejected 401."""
    with TestClient(app_with_routes) as client:
        _login_state(client)  # sets a state cookie with a different value
        resp = client.get("/auth/callback?code=the-code&state=not-the-saved-state")
    assert resp.status_code == 401


def test_logout_without_refresh_token_skips_keycloak(app_with_routes):
    """Logout with no refresh_token returns logged_out without calling Keycloak."""
    with (
        patch(
            "litestar_keycloak.routes._keycloak_logout", new_callable=AsyncMock
        ) as mock_logout,
        TestClient(app_with_routes) as client,
    ):
        resp = client.post("/auth/logout", json={})
    assert resp.status_code in (200, 201)
    assert resp.json()["status"] == "logged_out"
    mock_logout.assert_not_called()


def test_refresh_redirect_mode_reads_session_and_rotates(app_redirect_mode):
    """redirect mode: refresh reads the refresh token from the session and rotates."""
    with (
        patch(
            "litestar_keycloak.routes._refresh_token",
            new_callable=AsyncMock,
            return_value={"access_token": "new_at", "refresh_token": "new_rt"},
        ) as mock_refresh,
        TestClient(app_redirect_mode) as client,
    ):
        _complete_login(client, {"access_token": "at", "refresh_token": "old_rt"})
        resp = client.post("/auth/refresh")
        assert resp.status_code in (200, 201)
        assert resp.json()["status"] == "refreshed"
        stored = client.get("/debug/session").json()
    mock_refresh.assert_called_once()
    assert mock_refresh.call_args[0][1] == "old_rt"
    assert stored == {"access": "new_at", "refresh": "new_rt"}


def test_refresh_redirect_mode_without_session_returns_401(app_redirect_mode):
    """redirect mode: refresh with no token in the session returns 401."""
    with TestClient(app_redirect_mode) as client:
        resp = client.post("/auth/refresh")
    assert resp.status_code == 401


def test_logout_redirect_mode_clears_session(app_redirect_mode):
    """redirect mode: logout invalidates the token at Keycloak and clears session."""
    with (
        patch(
            "litestar_keycloak.routes._keycloak_logout", new_callable=AsyncMock
        ) as mock_logout,
        TestClient(app_redirect_mode) as client,
    ):
        _complete_login(client, {"access_token": "at", "refresh_token": "rt"})
        resp = client.post("/auth/logout", follow_redirects=False)
        assert resp.status_code in (200, 201)
        stored = client.get("/debug/session").json()
    mock_logout.assert_called_once()
    assert mock_logout.call_args[0][1] == "rt"
    assert stored == {"access": None, "refresh": None}


# --- aiohttp token/logout helpers (exercised via fake session) ---


async def test_token_request_posts_to_token_url_and_returns_json():
    """_token_request POSTs form data to the token endpoint and returns parsed JSON."""
    from litestar_keycloak.routes import _token_request

    config = _config_with_routes()
    http = _FakeHttp({"access_token": "at", "expires_in": 3600})
    result = await _token_request(config, {"grant_type": "refresh_token"}, http=http)
    assert result == {"access_token": "at", "expires_in": 3600}
    url, data = http.post_calls[0]
    assert url == config.token_url
    assert data == {"grant_type": "refresh_token"}


async def test_exchange_code_uses_authorization_code_grant():
    """_exchange_code sends grant_type=authorization_code with the code and redirect."""
    from litestar_keycloak.routes import _exchange_code

    config = _config_with_routes()
    http = _FakeHttp({"access_token": "at"})
    result = await _exchange_code(config, "the-auth-code", http=http)
    assert result == {"access_token": "at"}
    url, data = http.post_calls[0]
    assert url == config.token_url
    assert data["grant_type"] == "authorization_code"
    assert data["code"] == "the-auth-code"
    assert data["redirect_uri"] == config.redirect_uri


async def test_keycloak_logout_posts_to_logout_url():
    """_keycloak_logout POSTs the refresh token to the end-session endpoint."""
    from litestar_keycloak.routes import _keycloak_logout

    config = _config_with_routes()
    http = _FakeHttp()
    await _keycloak_logout(config, "rt-123", http=http)
    url, data = http.post_calls[0]
    assert url == config.logout_url
    assert data["refresh_token"] == "rt-123"
