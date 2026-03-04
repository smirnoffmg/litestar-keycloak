"""Integration tests: guards (require_roles) with real Keycloak tokens."""

import pytest
from litestar import Litestar, get
from litestar.testing import TestClient

from litestar_keycloak import KeycloakPlugin, KeycloakUser
from litestar_keycloak.guards import require_roles


def _app(keycloak_config):
    @get("/me")
    async def me(current_user: KeycloakUser) -> dict:
        return {"sub": current_user.sub, "roles": list(current_user.realm_roles)}

    @get("/admin", guards=[require_roles("admin")])
    async def admin(current_user: KeycloakUser) -> dict:
        return {"sub": current_user.sub, "roles": list(current_user.realm_roles)}

    return Litestar(
        route_handlers=[me, admin],
        plugins=[KeycloakPlugin(keycloak_config)],
    )


@pytest.mark.integration
@pytest.mark.timeout(120)
def test_admin_guard_allows_admin_token(keycloak_config, admin_token):
    """Admin-only route returns 200 when token has admin role."""
    with TestClient(_app(keycloak_config)) as client:
        resp = client.get("/admin", headers={"Authorization": f"Bearer {admin_token}"})
    assert resp.status_code == 200
    assert "admin" in resp.json()["roles"]


@pytest.mark.integration
@pytest.mark.timeout(120)
def test_admin_guard_rejects_user_token_with_403(keycloak_config, user_token):
    """Admin-only route returns 403 when token has only user role."""
    with TestClient(_app(keycloak_config)) as client:
        resp = client.get("/admin", headers={"Authorization": f"Bearer {user_token}"})
    assert resp.status_code == 403
