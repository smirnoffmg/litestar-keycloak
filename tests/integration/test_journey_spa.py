"""Journey J1 (JOURNEYS.md): a SPA user signs in, outlives the access token, signs out.

json mode: the browser app holds the tokens and sends the access token as
Bearer.  One client with a 2-second access token, so expiry is part of the walk.
"""

import time
import urllib.parse

import pytest
from litestar import Litestar, get
from litestar.testing import TestClient

from litestar_keycloak import CurrentUser, KeycloakConfig, KeycloakPlugin

pytestmark = pytest.mark.integration

REDIRECT_URI = "http://localhost:8000/auth/callback"


@get("/me")
async def me(current_user: CurrentUser) -> dict:
    return {"username": current_user.preferred_username}


def _query(url: str) -> dict[str, str]:
    return {
        k: v[0]
        for k, v in urllib.parse.parse_qs(urllib.parse.urlparse(url).query).items()
    }


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _spa_config(keycloak_container, admin_api) -> KeycloakConfig:
    """A confidential client with a 2-second access token, PKCE and ID token checks."""
    resp = admin_api.post(
        "/clients",
        json={
            "clientId": "journey-spa",
            "secret": "journey-spa-secret",
            "standardFlowEnabled": True,
            "redirectUris": [REDIRECT_URI],
            "attributes": {"access.token.lifespan": "2"},
        },
    )
    assert resp.status_code in (201, 409), resp.text
    return KeycloakConfig(
        server_url=keycloak_container.get_url(),
        realm="test-realm",
        client_id="journey-spa",
        client_secret="journey-spa-secret",
        include_routes=True,
        redirect_uri=REDIRECT_URI,
        cookie_secure=False,  # the TestClient runs over http://testserver
        use_pkce=True,
        validate_id_token=True,
    )


def test_spa_user_journey(keycloak_container, admin_api, browser_login):
    config = _spa_config(keycloak_container, admin_api)
    with TestClient(
        Litestar(route_handlers=[me], plugins=[KeycloakPlugin(config)])
    ) as client:
        # 1. Arrives without a token: told to authenticate.
        anonymous = client.get("/me")
        assert anonymous.status_code == 401
        assert anonymous.headers["www-authenticate"] == "Bearer"

        # 2. Signs in at Keycloak; the callback hands the SPA its tokens.
        authorize_url = client.get("/auth/login", follow_redirects=False).headers[
            "location"
        ]
        params = _query(browser_login(authorize_url, "testuser", "testpass"))
        callback = client.get(
            f"/auth/callback?code={params['code']}&state={params['state']}"
        )
        assert callback.status_code == 200, callback.text
        assert callback.headers["cache-control"] == "no-store"
        tokens = callback.json()

        # 3. Calls the API with the access token.
        assert client.get("/me", headers=_bearer(tokens["access_token"])).json() == {
            "username": "testuser"
        }

        # 4. The access token expires: 401 that says so.
        time.sleep(3)
        expired = client.get("/me", headers=_bearer(tokens["access_token"]))
        assert expired.status_code == 401
        assert (
            'error_description="Token expired"' in expired.headers["www-authenticate"]
        )

        # 5. Refreshes through the app and carries on.
        refreshed = client.post(
            "/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
        )
        assert refreshed.status_code == 201, refreshed.text
        renewed = refreshed.json()
        assert (
            client.get("/me", headers=_bearer(renewed["access_token"])).status_code
            == 200
        )

        # 6. Signs out; the Keycloak session ends with it.
        logout = client.post(
            "/auth/logout", json={"refresh_token": renewed["refresh_token"]}
        )
        assert logout.json() == {"status": "logged_out"}

        # 7. The refresh token is dead: 401, not 500.
        dead = client.post(
            "/auth/refresh", json={"refresh_token": renewed["refresh_token"]}
        )
        assert dead.status_code == 401


def test_replayed_authorization_code_ends_the_users_session(
    keycloak_container, admin_api, browser_login
):
    """Alt path: Keycloak treats a reused code as theft and ends that login too."""
    config = _spa_config(keycloak_container, admin_api)
    with TestClient(
        Litestar(route_handlers=[me], plugins=[KeycloakPlugin(config)])
    ) as client:
        authorize_url = client.get("/auth/login", follow_redirects=False).headers[
            "location"
        ]
        params = _query(browser_login(authorize_url, "testuser", "testpass"))
        tokens = client.get(
            f"/auth/callback?code={params['code']}&state={params['state']}"
        ).json()

        # The attacker replays the code with a login transaction of their own.
        replay_state = _query(
            client.get("/auth/login", follow_redirects=False).headers["location"]
        )["state"]
        replay = client.get(
            f"/auth/callback?code={params['code']}&state={replay_state}"
        )
        assert replay.status_code == 401

        # The victim's refresh token died with it: 401, not 500.
        refreshed = client.post(
            "/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
        )
        assert refreshed.status_code == 401
