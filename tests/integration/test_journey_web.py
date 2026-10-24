"""Journey B2 (JOURNEYS.md): a user of a server-rendered app, in redirect mode.

The session holds the tokens; the access token lives 2 seconds, so auto-refresh
and step-up by login age are part of the walk.
"""

import time
import urllib.parse

import pytest
from litestar import Litestar, get
from litestar.middleware.session.server_side import ServerSideSessionConfig
from litestar.stores.memory import MemoryStore
from litestar.testing import TestClient

from litestar_keycloak import (
    CurrentUser,
    KeycloakConfig,
    KeycloakPlugin,
    require_recent_auth,
)

pytestmark = pytest.mark.integration

REDIRECT_URI = "http://localhost:8000/auth/callback"
RECENT = 3  # seconds a login counts as recent for /transfer


@get("/me")
async def me(current_user: CurrentUser) -> dict:
    return {"username": current_user.preferred_username}


@get("/transfer", guards=[require_recent_auth(RECENT)])
async def transfer() -> dict:
    return {"ok": True}


def _query(url: str) -> dict[str, str]:
    return {
        k: v[0]
        for k, v in urllib.parse.parse_qs(urllib.parse.urlparse(url).query).items()
    }


def _web_app(keycloak_container, admin_api) -> Litestar:
    resp = admin_api.post(
        "/clients",
        json={
            "clientId": "journey-web",
            "secret": "journey-web-secret",
            "standardFlowEnabled": True,
            "redirectUris": [REDIRECT_URI],
            # basic carries sub and auth_time, which require_recent_auth reads.
            "defaultClientScopes": ["basic", "profile", "roles"],
            "attributes": {"access.token.lifespan": "2"},
        },
    )
    assert resp.status_code in (201, 409), resp.text
    config = KeycloakConfig(
        server_url=keycloak_container.get_url(),
        realm="test-realm",
        client_id="journey-web",
        client_secret="journey-web-secret",
        include_routes=True,
        redirect_uri=REDIRECT_URI,
        cookie_secure=False,  # the TestClient runs over http://testserver
        callback_response_mode="redirect",
        session_auto_refresh=True,
        session_binding=True,
    )
    return Litestar(
        route_handlers=[me, transfer],
        plugins=[KeycloakPlugin(config)],
        middleware=[ServerSideSessionConfig().middleware],
        stores={"sessions": MemoryStore()},
    )


def _sign_in(client, browser_login, username: str, password: str, query: str = ""):
    authorize_url = client.get(f"/auth/login{query}", follow_redirects=False).headers[
        "location"
    ]
    callback = browser_login(authorize_url, username, password)
    resp = client.get(
        f"/auth/callback?{urllib.parse.urlparse(callback).query}",
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303), resp.text
    return authorize_url, resp


def test_web_user_journey(keycloak_container, admin_api, browser_login):
    with TestClient(_web_app(keycloak_container, admin_api)) as client:
        # 1. Opens a page without a session.
        assert client.get("/me").status_code == 401

        # 2. Signs in; the session authenticates, bound to its cookie.
        _, callback = _sign_in(client, browser_login, "testuser", "testpass")
        assert "kc_session_binding=" in callback.headers.get("set-cookie", "")
        assert client.get("/me").json() == {"username": "testuser"}

        # 3. Keeps working past the access token's lifetime.
        time.sleep(RECENT + 1)
        assert client.get("/me").status_code == 200

        # 4. A page that needs a recent login asks for one.
        stale = client.get("/transfer")
        assert stale.status_code == 401
        assert f'max_age="{RECENT}"' in stale.headers["www-authenticate"]

        # 5. Signs in again through /auth/login?max_age=0; the page opens.
        authorize_url, _ = _sign_in(
            client, browser_login, "testuser", "testpass", query="?max_age=0"
        )
        assert _query(authorize_url)["max_age"] == "0"
        assert client.get("/transfer").json() == {"ok": True}

        # 6. Signs out.
        client.post("/auth/logout")
        assert client.get("/me").status_code == 401


def test_session_ended_in_keycloak_is_refused_not_crashed(
    keycloak_container, admin_api, browser_login, probe_user
):
    """Alt path: an admin ends the Keycloak session; the next refresh is refused."""
    username = admin_api.get(f"/users/{probe_user}").json()["username"]
    with TestClient(_web_app(keycloak_container, admin_api)) as client:
        _sign_in(client, browser_login, username, "pw")
        assert client.get("/me").status_code == 200

        admin_api.post(f"/users/{probe_user}/logout").raise_for_status()
        time.sleep(3)  # past the access token's lifetime: auto-refresh runs

        refused = client.get("/me")
        assert refused.status_code == 401
        assert "WWW-Authenticate" in refused.headers, refused.text
