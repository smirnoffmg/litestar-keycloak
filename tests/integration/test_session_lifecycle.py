"""Integration tests for the session lifecycle against real Keycloak.

- auto-refresh: a server-rendered login outlives its short access token;
- back-channel logout: Keycloak's own logout token, captured on the way to a
  stand-in endpoint, ends the session in the app.
"""

import threading
import time
import urllib.parse
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest
from litestar import Litestar, Request, get
from litestar.middleware.session.server_side import ServerSideSessionConfig
from litestar.stores.memory import MemoryStore
from litestar.testing import TestClient

from litestar_keycloak import CurrentUser, KeycloakConfig, KeycloakPlugin

pytestmark = pytest.mark.integration

REDIRECT_URI = "http://localhost:8000/auth/callback"


@get("/me")
async def me(current_user: CurrentUser) -> dict:
    return {"username": current_user.preferred_username}


@get("/debug/access-token", exclude_from_auth=True)
async def access_token(request: Request) -> dict:
    return {"access": request.session.get("keycloak_access_token")}


def _config(keycloak_container, client_id: str, **overrides) -> KeycloakConfig:
    return KeycloakConfig(
        server_url=keycloak_container.get_url(),
        realm="test-realm",
        client_id=client_id,
        client_secret=f"{client_id}-secret",
        include_routes=True,
        redirect_uri=REDIRECT_URI,
        cookie_secure=False,  # the TestClient runs over http://testserver
        **overrides,
    )


def _session_app(config: KeycloakConfig) -> Litestar:
    return Litestar(
        route_handlers=[me, access_token],
        plugins=[KeycloakPlugin(config)],
        middleware=[ServerSideSessionConfig().middleware],
        stores={"sessions": MemoryStore()},
    )


def test_session_outlives_its_access_token(
    keycloak_container, admin_api, browser_login
):
    """With session_auto_refresh, an expired session token is renewed in place."""
    resp = admin_api.post(
        "/clients",
        json={
            "clientId": "test-refresh",
            "secret": "test-refresh-secret",
            "standardFlowEnabled": True,
            "redirectUris": [REDIRECT_URI],
            "attributes": {"access.token.lifespan": "2"},
        },
    )
    assert resp.status_code in (201, 409), resp.text
    config = _config(
        keycloak_container,
        "test-refresh",
        callback_response_mode="redirect",
        session_auto_refresh=True,
    )
    with TestClient(_session_app(config)) as client:
        authorize_url = client.get("/auth/login", follow_redirects=False).headers[
            "location"
        ]
        callback = browser_login(authorize_url, "testuser", "testpass")
        query = urllib.parse.urlparse(callback).query
        client.get(f"/auth/callback?{query}", follow_redirects=False)
        first_token = client.get("/debug/access-token").json()["access"]
        assert client.get("/me").status_code == 200

        time.sleep(3)  # past the 2-second access-token lifespan

        assert client.get("/me").json() == {"username": "testuser"}
        assert client.get("/debug/access-token").json()["access"] != first_token


@pytest.fixture
def logout_token_sink() -> Iterator[tuple[str, list[str]]]:
    """A host HTTP endpoint that records the logout tokens Keycloak posts to it."""
    received: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers["Content-Length"])).decode()
            received.extend(urllib.parse.parse_qs(body).get("logout_token", []))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *_args: object) -> None:
            pass

    server = HTTPServer(("0.0.0.0", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://host.docker.internal:{server.server_address[1]}/backchannel"
    yield url, received
    server.shutdown()


def test_backchannel_logout_ends_the_session_in_the_app(
    keycloak_container, admin_api, probe_user, logout_token_sink
):
    """Keycloak's real logout token is accepted and refuses the session's tokens."""
    sink_url, received = logout_token_sink
    resp = admin_api.post(
        "/clients",
        json={
            "clientId": "test-backchannel",
            "secret": "test-backchannel-secret",
            "directAccessGrantsEnabled": True,
            "attributes": {
                "backchannel.logout.url": sink_url,
                "backchannel.logout.session.required": "true",
            },
        },
    )
    assert resp.status_code in (201, 409), resp.text
    username = admin_api.get(f"/users/{probe_user}").json()["username"]
    token = httpx.post(
        f"{keycloak_container.get_url()}/realms/test-realm/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "test-backchannel",
            "client_secret": "test-backchannel-secret",
            "username": username,
            "password": "pw",
        },
        timeout=30,
    ).json()["access_token"]

    config = _config(keycloak_container, "test-backchannel", backchannel_logout=True)
    bearer = {"Authorization": f"Bearer {token}"}
    with TestClient(_session_app(config)) as client:
        assert client.get("/me", headers=bearer).status_code == 200

        admin_api.post(f"/users/{probe_user}/logout").raise_for_status()
        deadline = time.monotonic() + 10
        while not received and time.monotonic() < deadline:
            time.sleep(0.1)
        assert received, "Keycloak did not send a logout token"

        resp = client.post(
            "/auth/backchannel-logout", data={"logout_token": received[0]}
        )
        assert resp.status_code == 200, resp.text
        assert client.get("/me", headers=bearer).status_code == 401


def test_session_binding_refuses_a_stolen_session_id(
    keycloak_container, admin_api, browser_login
):
    """A real login's session id, replayed without the binding cookie, is a 401."""
    resp = admin_api.post(
        "/clients",
        json={
            "clientId": "test-binding",
            "secret": "test-binding-secret",
            "standardFlowEnabled": True,
            "redirectUris": [REDIRECT_URI],
        },
    )
    assert resp.status_code in (201, 409), resp.text
    config = _config(
        keycloak_container,
        "test-binding",
        callback_response_mode="redirect",
        session_binding=True,
    )
    # One client: two TestClients would run the plugin's HTTP client on two
    # event loops.  The attacker is the same session id minus the binding cookie.
    with TestClient(_session_app(config)) as client:
        client.cookies.set("session", "planted-session-id", domain="testserver.local")
        authorize_url = client.get("/auth/login", follow_redirects=False).headers[
            "location"
        ]
        callback = browser_login(authorize_url, "testuser", "testpass")
        query = urllib.parse.urlparse(callback).query
        client.get(f"/auth/callback?{query}", follow_redirects=False)
        assert client.cookies.get("session") == "planted-session-id"
        assert client.get("/me").json() == {"username": "testuser"}

        client.cookies.delete("kc_session_binding")
        assert client.get("/me").status_code == 401
