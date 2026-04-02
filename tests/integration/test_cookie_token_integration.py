import urllib.parse
import urllib.request

import pytest
from litestar import Litestar, Request, get, post
from litestar.middleware.session.server_side import ServerSideSessionConfig
from litestar.stores.memory import MemoryStore
from litestar.testing import TestClient

from litestar_keycloak import (
    KeycloakConfig,
    KeycloakPlugin,
    KeycloakUser,
    TokenLocation,
)
from litestar_keycloak.routes import REFRESH_TOKEN_SESSION_KEY


def _refresh_tokens_for_keycloak(
    keycloak_config: KeycloakConfig, refresh_token: str
) -> dict:
    """Call Keycloak token endpoint with refresh_token grant."""
    import json

    data = urllib.parse.urlencode(
        {
            "grant_type": "refresh_token",
            "client_id": keycloak_config.client_id,
            "client_secret": keycloak_config.client_secret or "",
            "refresh_token": refresh_token,
        }
    ).encode()
    req = urllib.request.Request(
        f"{keycloak_config.server_url}/realms/{keycloak_config.realm}/protocol/openid-connect/token",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def _cookie_mode_app(keycloak_config: KeycloakConfig):
    """Build a Litestar app that authenticates via access_token cookie."""

    @get("/me")
    async def me(current_user: KeycloakUser) -> dict:
        return {"sub": current_user.sub, "roles": list(current_user.realm_roles)}

    @post("/auth/set-refresh")
    async def set_refresh(request: Request) -> dict[str, str]:
        body = await request.json()
        refresh_token = body.get("refresh_token", "")
        assert isinstance(refresh_token, str) and refresh_token

        # In cookie mode, refresh uses refresh token stored in server-side session.
        request.set_session({REFRESH_TOKEN_SESSION_KEY: refresh_token})
        return {"status": "ok"}

    cookie_config = KeycloakConfig(
        server_url=keycloak_config.server_url,
        realm=keycloak_config.realm,
        client_id=keycloak_config.client_id,
        client_secret=keycloak_config.client_secret,
        token_location=TokenLocation.COOKIE,
        cookie_secure=False,
        include_routes=True,
        redirect_uri=f"{keycloak_config.server_url}/auth/callback",
        excluded_paths=frozenset({"/auth/set-refresh"}),
    )

    session_config = ServerSideSessionConfig(store="sessions")
    return (
        Litestar(
            route_handlers=[me, set_refresh],
            plugins=[KeycloakPlugin(cookie_config)],
            middleware=[session_config.middleware],
            stores={"sessions": MemoryStore()},
        ),
        cookie_config,
    )


@pytest.mark.integration
@pytest.mark.timeout(120)
def test_cookie_mode_valid_access_token_returns_200(
    keycloak_config, user_token_response
):
    """Cookie mode: access token from cookie authenticates protected routes."""
    app, config = _cookie_mode_app(keycloak_config)

    with TestClient(app) as client:
        client.cookies.set(config.cookie_name, user_token_response["access_token"])
        resp = client.get("/me")
    assert resp.status_code == 200
    assert "user" in resp.json()["roles"]


@pytest.mark.integration
@pytest.mark.timeout(120)
def test_cookie_mode_refresh_uses_session_and_updates_cookie(
    keycloak_config, user_token_response
):
    """Cookie mode: refresh reads session refresh token only (body ignored)."""
    app, config = _cookie_mode_app(keycloak_config)
    initial_refresh = user_token_response["refresh_token"]
    initial_access = user_token_response["access_token"]

    with TestClient(app) as client:
        # Prime the server-side session with the refresh token.
        resp = client.post(
            "/auth/set-refresh",
            json={"refresh_token": initial_refresh},
        )
        assert resp.status_code in (200, 201)

        # First refresh: request body refresh token is wrong but should be ignored.
        resp1 = client.post("/auth/refresh", json={"refresh_token": "wrong"})
        assert resp1.status_code in (200, 201)
        assert resp1.json() == {"status": "refreshed"}
        access1 = client.cookies.get(config.cookie_name)
        assert isinstance(access1, str) and access1
        assert access1 != initial_access

        # Second refresh: should still work with rotated refresh token stored in
        # session.
        resp2 = client.post("/auth/refresh", json={"refresh_token": "wrong2"})
        assert resp2.status_code in (200, 201)
        assert resp2.json() == {"status": "refreshed"}
        access2 = client.cookies.get(config.cookie_name)
        assert isinstance(access2, str) and access2
        assert access2 != access1


@pytest.mark.integration
@pytest.mark.timeout(120)
def test_cookie_mode_logout_deletes_access_cookie_and_clears_session(
    keycloak_config, user_token_response
):
    """Cookie mode: logout deletes access token cookie and subsequent refresh fails."""
    app, config = _cookie_mode_app(keycloak_config)
    refresh_token = user_token_response["refresh_token"]

    with TestClient(app) as client:
        # Prime session and set cookie via the refresh endpoint so cookie
        # attributes match what the plugin uses.
        resp = client.post(
            "/auth/set-refresh",
            json={"refresh_token": refresh_token},
        )
        assert resp.status_code in (200, 201)

        refresh_resp = client.post("/auth/refresh", json={"refresh_token": "wrong"})
        assert refresh_resp.status_code in (200, 201)
        assert refresh_resp.json() == {"status": "refreshed"}
        assert client.cookies.get(config.cookie_name) is not None

        # Logout: request body refresh_token should be ignored in cookie mode.
        logout_resp = client.post("/auth/logout", json={"refresh_token": "wrong"})
        assert logout_resp.status_code in (200, 201)
        assert logout_resp.json() == {"status": "logged_out"}
        assert client.cookies.get(config.cookie_name) is None

        # Session should be cleared, so refresh should be unauthorized.
        refresh_resp2 = client.post("/auth/refresh", json={"refresh_token": "whatever"})
        assert refresh_resp2.status_code == 401
