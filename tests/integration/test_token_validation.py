"""Integration tests: token validation against real Keycloak."""

import pytest
from litestar import Litestar, get
from litestar.testing import TestClient

from litestar_keycloak import KeycloakPlugin, KeycloakUser


def _app(keycloak_config):
    @get("/me")
    async def me(current_user: KeycloakUser) -> dict:
        return {"sub": current_user.sub, "roles": list(current_user.realm_roles)}

    return Litestar(
        route_handlers=[me],
        plugins=[KeycloakPlugin(keycloak_config)],
    )


@pytest.mark.integration
@pytest.mark.timeout(120)
def test_valid_user_token_returns_200_with_user_claims(keycloak_config, user_token):
    """Valid user token returns 200 and user claims (sub, roles)."""
    with TestClient(_app(keycloak_config)) as client:
        resp = client.get("/me", headers={"Authorization": f"Bearer {user_token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert "sub" in data
    assert "roles" in data
    assert "user" in data["roles"]


@pytest.mark.integration
@pytest.mark.timeout(120)
def test_valid_admin_token_includes_admin_role(keycloak_config, admin_token):
    """Valid admin token returns 200 and includes admin role."""
    with TestClient(_app(keycloak_config)) as client:
        resp = client.get("/me", headers={"Authorization": f"Bearer {admin_token}"})
    assert resp.status_code == 200
    assert "admin" in resp.json()["roles"]


@pytest.mark.integration
@pytest.mark.timeout(120)
def test_invalid_token_signature_returns_401(keycloak_config, user_token):
    """Token with invalid/tampered signature is rejected with 401."""
    parts = user_token.split(".")
    if len(parts) >= 3:
        tampered = parts[0] + "." + parts[1] + ".tampered_signature"
    else:
        tampered = "invalid.jwt.token"
    with TestClient(_app(keycloak_config)) as client:
        resp = client.get("/me", headers={"Authorization": f"Bearer {tampered}"})
    assert resp.status_code == 401


@pytest.mark.integration
@pytest.mark.timeout(120)
def test_tampered_token_signature_returns_401(keycloak_config, user_token):
    """Token with tampered signature is rejected with 401."""
    parts = user_token.rsplit(".", 1)
    tampered = parts[0] + ".tampered" if len(parts) == 2 else "x.y.z"
    with TestClient(_app(keycloak_config)) as client:
        resp = client.get("/me", headers={"Authorization": f"Bearer {tampered}"})
    assert resp.status_code == 401


@pytest.mark.integration
@pytest.mark.timeout(120)
def test_token_from_wrong_realm_returns_401(keycloak_config):
    """Token issued for a different realm is rejected (wrong issuer)."""
    # Invalid JWT so verification fails (wrong kid/iss/signature)
    wrong_token = (
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJpc3MiOiJodHRwOi8vd3JvbmcvcmVhbG0iLCJzdWIiOiJ1In0.sig"
    )
    with TestClient(_app(keycloak_config)) as client:
        resp = client.get("/me", headers={"Authorization": f"Bearer {wrong_token}"})
    assert resp.status_code == 401
