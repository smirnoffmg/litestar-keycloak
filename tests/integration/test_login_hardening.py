"""Integration tests for the hardened login: PKCE, nonce + ID token, public clients.

Each test registers a client that *requires* PKCE (S256), so Keycloak itself
proves the plugin sends a correct challenge and verifier.
"""

import urllib.parse

import pytest
from litestar import Litestar, get
from litestar.testing import TestClient

from litestar_keycloak import CurrentUser, KeycloakConfig, KeycloakPlugin

pytestmark = pytest.mark.integration

REDIRECT_URI = "http://localhost:8000/auth/callback"


@pytest.fixture
def pkce_public_client(admin_api) -> str:
    """A public client (no secret) for which Keycloak enforces PKCE S256."""
    resp = admin_api.post(
        "/clients",
        json={
            "clientId": "test-pkce-public",
            "publicClient": True,
            "standardFlowEnabled": True,
            "redirectUris": [REDIRECT_URI],
            "defaultClientScopes": ["basic", "acr", "profile", "roles"],
            "attributes": {"pkce.code.challenge.method": "S256"},
        },
    )
    assert resp.status_code in (201, 409), resp.text
    return "test-pkce-public"


@get("/me")
async def me(current_user: CurrentUser) -> dict:
    return {"username": current_user.preferred_username}


def _config(keycloak_container, client_id: str, **overrides) -> KeycloakConfig:
    return KeycloakConfig(
        server_url=keycloak_container.get_url(),
        realm="test-realm",
        client_id=client_id,
        include_routes=True,
        redirect_uri=REDIRECT_URI,
        cookie_secure=False,  # the TestClient runs over http://testserver
        **overrides,
    )


def _query(url: str) -> dict[str, str]:
    return {
        k: v[0]
        for k, v in urllib.parse.parse_qs(urllib.parse.urlparse(url).query).items()
    }


def test_public_client_logs_in_with_pkce_and_verified_id_token(
    keycloak_container, pkce_public_client, browser_login
):
    """Login, code exchange without a secret, ID token check, then Bearer use."""
    config = _config(
        keycloak_container, pkce_public_client, use_pkce=True, validate_id_token=True
    )
    app = Litestar(route_handlers=[me], plugins=[KeycloakPlugin(config)])
    with TestClient(app) as client:
        authorize_url = client.get("/auth/login", follow_redirects=False).headers[
            "location"
        ]
        assert "nonce" in _query(authorize_url)
        callback = browser_login(authorize_url, "testuser", "testpass")
        params = _query(callback)
        resp = client.get(
            f"/auth/callback?code={params['code']}&state={params['state']}"
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["id_token"]
        access_token = resp.json()["access_token"]
        me_resp = client.get("/me", headers={"Authorization": f"Bearer {access_token}"})
    assert me_resp.json() == {"username": "testuser"}


def test_login_without_pkce_surfaces_keycloaks_error(
    keycloak_container, pkce_public_client
):
    """Keycloak refuses the authorize request; the callback reports why."""
    import httpx

    config = _config(keycloak_container, pkce_public_client)
    app = Litestar(plugins=[KeycloakPlugin(config)])
    with TestClient(app) as client:
        authorize_url = client.get("/auth/login", follow_redirects=False).headers[
            "location"
        ]
        refused = httpx.get(authorize_url, follow_redirects=False, timeout=30)
        assert refused.status_code in (302, 303)
        params = _query(refused.headers["location"])
        assert params["error"] == "invalid_request"
        resp = client.get(
            f"/auth/callback?error={params['error']}&state={params['state']}"
        )
    assert resp.status_code == 401
    assert "invalid_request" in resp.json()["detail"]
