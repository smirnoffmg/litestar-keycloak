# tests/integration/test_oidc_flow.py
import pytest
from litestar.testing import TestClient


@pytest.fixture
def app(keycloak_config):
    from litestar import Litestar, get

    from litestar_keycloak import KeycloakPlugin, KeycloakUser

    @get("/me")
    async def me(current_user: KeycloakUser) -> dict:
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
        assert "testuser" in resp.json()["sub"] or resp.json()["roles"] == ["user"]


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
