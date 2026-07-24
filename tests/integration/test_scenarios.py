"""Integration tests for the three usage scenarios against real Keycloak:

- service-to-service (client_credentials, Bearer token)
- SPA (json callback -> Bearer header)
- classic server-rendered web (redirect callback -> server-side session)
"""

import dataclasses
import re
import urllib.parse

import httpx
import pytest
from litestar import Litestar, get
from litestar.middleware.session.server_side import ServerSideSessionConfig
from litestar.stores.memory import MemoryStore
from litestar.testing import TestClient

from litestar_keycloak import CurrentTokenPayload, CurrentUser, KeycloakPlugin

#: Registered redirect URI for ``test-app`` in the imported realm.
REDIRECT_URI = "http://localhost:8000/auth/callback"


def _routes_config(keycloak_config, **overrides):
    """A copy of the base config with the OIDC routes enabled for TestClient (http)."""
    return dataclasses.replace(
        keycloak_config,
        include_routes=True,
        redirect_uri=REDIRECT_URI,
        cookie_secure=False,  # the TestClient runs over http://testserver
        **overrides,
    )


def _obtain_service_token(base_url: str) -> str:
    """client_credentials grant for the ``test-service`` service account."""
    resp = httpx.post(
        f"{base_url}/realms/test-realm/protocol/openid-connect/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "test-service",
            "client_secret": "service-secret",
        },
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def _browser_login(authorize_url: str, username: str, password: str) -> str:
    """Drive Keycloak's HTML login form; return the callback redirect (with code)."""
    with httpx.Client(follow_redirects=False, timeout=30) as client:
        page = client.get(authorize_url)
        page.raise_for_status()
        match = re.search(
            r'action="(?P<url>[^"]*login-actions/authenticate[^"]*)"', page.text
        )
        assert match, "Keycloak login form not found on the authorization page"
        action = match.group("url").replace("&amp;", "&")
        # Keycloak sets its session cookies as SameSite=None; Secure, which httpx
        # will not resend over plain http — forward them explicitly.
        cookie_header = "; ".join(f"{k}={v}" for k, v in client.cookies.items())
        resp = client.post(
            action,
            data={"username": username, "password": password},
            headers={"Cookie": cookie_header},
        )
        assert resp.status_code in (302, 303), f"login POST -> {resp.status_code}"
        return resp.headers["location"]


def _query_param(url: str, name: str) -> str:
    return urllib.parse.parse_qs(urllib.parse.urlparse(url).query)[name][0]


# --- Scenario 1: service-to-service (machine-to-machine) --------------------


@pytest.mark.integration
@pytest.mark.timeout(120)
def test_service_to_service_token_accepted(keycloak_config, keycloak_container):
    """A client_credentials token is accepted when its client is an optional aud."""
    token = _obtain_service_token(keycloak_container.get_url())
    config = dataclasses.replace(
        keycloak_config, optional_audiences=frozenset({"test-service"})
    )

    @get("/internal")
    async def internal(token_payload: CurrentTokenPayload) -> dict:
        return {"azp": token_payload.azp}

    app = Litestar(route_handlers=[internal], plugins=[KeycloakPlugin(config)])
    with TestClient(app) as client:
        resp = client.get("/internal", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["azp"] == "test-service"


# --- Scenario 2: SPA (json callback + Bearer header) ------------------------


@pytest.mark.integration
@pytest.mark.timeout(120)
def test_spa_json_callback_then_bearer(keycloak_config, keycloak_container):
    """json mode: callback returns tokens, then the access token works as Bearer."""
    config = _routes_config(keycloak_config, callback_response_mode="json")

    @get("/me")
    async def me(current_user: CurrentUser) -> dict:
        return {"sub": current_user.sub, "roles": list(current_user.realm_roles)}

    app = Litestar(route_handlers=[me], plugins=[KeycloakPlugin(config)])
    with TestClient(app) as client:
        login = client.get("/auth/login", follow_redirects=False)
        authorize_url = login.headers["location"]
        state = _query_param(authorize_url, "state")
        callback_url = _browser_login(authorize_url, "testuser", "testpass")
        code = _query_param(callback_url, "code")

        callback = client.get(f"/auth/callback?code={code}&state={state}")
        assert callback.status_code == 200
        access_token = callback.json()["access_token"]

        me_resp = client.get("/me", headers={"Authorization": f"Bearer {access_token}"})
    assert me_resp.status_code == 200
    assert "user" in me_resp.json()["roles"]


# --- Scenario 3: classic server-rendered web (redirect + session) -----------


@pytest.mark.integration
@pytest.mark.timeout(120)
def test_classic_web_session_flow(keycloak_config, keycloak_container):
    """redirect mode: login stores tokens in the session; the session authenticates."""
    config = _routes_config(keycloak_config, callback_response_mode="redirect")
    session_config = ServerSideSessionConfig()

    @get("/me")
    async def me(current_user: CurrentUser) -> dict:
        return {"sub": current_user.sub}

    app = Litestar(
        route_handlers=[me],
        plugins=[KeycloakPlugin(config)],
        middleware=[session_config.middleware],
        stores={"sessions": MemoryStore()},
    )
    with TestClient(app) as client:
        # unauthenticated: no session token yet
        assert client.get("/me").status_code == 401

        login = client.get("/auth/login", follow_redirects=False)
        authorize_url = login.headers["location"]
        state = _query_param(authorize_url, "state")
        callback_url = _browser_login(authorize_url, "testuser", "testpass")
        code = _query_param(callback_url, "code")

        callback = client.get(
            f"/auth/callback?code={code}&state={state}", follow_redirects=False
        )
        assert callback.status_code in (302, 303, 307, 308)

        # protected route now works via the session cookie — no Bearer header
        me_resp = client.get("/me")
        assert me_resp.status_code == 200
        assert me_resp.json()["sub"]

        # refresh rotates the session tokens; the route still authenticates
        assert client.post("/auth/refresh").status_code in (200, 201)
        assert client.get("/me").status_code == 200

        # logout clears the session tokens; the route is rejected again
        client.post("/auth/logout")
        assert client.get("/me").status_code == 401
