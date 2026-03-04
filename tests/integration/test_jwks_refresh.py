"""Integration tests for JWKS and token validation against a real Keycloak container.

Run with: pytest -m integration tests/integration/
"""

import pytest
from litestar import Litestar, get
from litestar.testing import TestClient

from litestar_keycloak import KeycloakPlugin, KeycloakUser


@pytest.mark.integration
@pytest.mark.timeout(120)
def test_protected_route_with_valid_token(keycloak_config, user_token):
    """App with KeycloakPlugin validates token via JWKS and returns user."""

    @get("/me")
    async def me(current_user: KeycloakUser) -> dict:
        return {"sub": current_user.sub, "roles": list(current_user.realm_roles)}

    app = Litestar(
        route_handlers=[me],
        plugins=[KeycloakPlugin(keycloak_config)],
    )
    with TestClient(app) as client:
        resp = client.get("/me", headers={"Authorization": f"Bearer {user_token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert "sub" in data
    assert "roles" in data
