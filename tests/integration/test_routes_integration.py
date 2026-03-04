"""Integration tests: OIDC routes (refresh, logout) with real Keycloak."""

import urllib.parse
import urllib.request

import pytest
from litestar import Litestar, get
from litestar.testing import TestClient

from litestar_keycloak import KeycloakPlugin, KeycloakUser


def _refresh_tokens(keycloak_config, refresh_token: str) -> dict:
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


@pytest.mark.integration
@pytest.mark.timeout(120)
def test_refresh_with_real_refresh_token(keycloak_config, user_token_response):
    """Refresh token grant returns new access and refresh tokens."""
    refresh_token = user_token_response.get("refresh_token")
    assert refresh_token
    result = _refresh_tokens(keycloak_config, refresh_token)
    assert "access_token" in result
    assert "refresh_token" in result
    assert result["access_token"] != user_token_response["access_token"]


@pytest.mark.integration
@pytest.mark.timeout(120)
def test_valid_user_token_after_refresh(keycloak_config, user_token_response):
    """New access token from refresh works on protected route."""
    result = _refresh_tokens(keycloak_config, user_token_response["refresh_token"])
    new_access = result["access_token"]

    @get("/me")
    async def me(current_user: KeycloakUser) -> dict:
        return {"sub": current_user.sub, "roles": list(current_user.realm_roles)}

    app = Litestar(
        route_handlers=[me],
        plugins=[KeycloakPlugin(keycloak_config)],
    )
    with TestClient(app) as client:
        resp = client.get("/me", headers={"Authorization": f"Bearer {new_access}"})
    assert resp.status_code == 200
    assert "sub" in resp.json()
