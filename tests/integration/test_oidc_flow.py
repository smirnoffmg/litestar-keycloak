# tests/integration/test_oidc_flow.py
import jwt
import pytest
from litestar.testing import TestClient


@pytest.fixture
def app(keycloak_config):
    from litestar import Litestar, get

    from litestar_keycloak import CurrentUser, KeycloakPlugin

    @get("/me")
    async def me(current_user: CurrentUser) -> dict:
        return {"sub": current_user.sub, "roles": list(current_user.realm_roles)}

    return Litestar(
        route_handlers=[me],
        plugins=[KeycloakPlugin(keycloak_config)],
    )


@pytest.mark.integration
def test_valid_token_returns_user(app, user_token):
    with TestClient(app) as client:
        resp = client.get("/me", headers={"Authorization": f"Bearer {user_token}"})
        assert resp.status_code == 200
        claims = jwt.decode(user_token, options={"verify_signature": False})
        # test-app lacks the basic scope, so Keycloak omits sub and the plugin
        # falls back to preferred_username.
        assert resp.json()["sub"] == claims.get("sub", claims["preferred_username"])
        assert "user" in resp.json()["roles"]


@pytest.mark.integration
def test_no_token_returns_401(app):
    with TestClient(app) as client:
        resp = client.get("/me")
        assert resp.status_code == 401


@pytest.mark.integration
def test_admin_has_admin_role(app, admin_token):
    with TestClient(app) as client:
        resp = client.get("/me", headers={"Authorization": f"Bearer {admin_token}"})
        assert "admin" in resp.json()["roles"]
