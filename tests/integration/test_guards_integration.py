"""Integration tests: guards (require_roles) with real Keycloak tokens."""

import pytest
from litestar import Litestar, get
from litestar.testing import TestClient

from litestar_keycloak import CurrentUser, KeycloakPlugin
from litestar_keycloak.guards import require_roles, require_scopes


def _app(keycloak_config):
    @get("/me")
    async def me(current_user: CurrentUser) -> dict:
        return {"sub": current_user.sub, "roles": list(current_user.realm_roles)}

    @get("/admin", guards=[require_roles("admin")])
    async def admin(current_user: CurrentUser) -> dict:
        return {"sub": current_user.sub, "roles": list(current_user.realm_roles)}

    @get("/profile-scoped", guards=[require_scopes("profile")])
    async def profile_scoped(current_user: CurrentUser) -> dict:
        return {"sub": current_user.sub, "scopes": sorted(current_user.scopes)}

    @get("/reports", guards=[require_scopes("reports")])
    async def reports(current_user: CurrentUser) -> dict:
        return {"sub": current_user.sub}

    return Litestar(
        route_handlers=[me, admin, profile_scoped, reports],
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


@pytest.mark.integration
@pytest.mark.timeout(120)
def test_scope_guard_validates_real_token_scopes(keycloak_config, user_token):
    """require_scopes matches the real space-delimited scope claim Keycloak issues.

    ``profile`` is a default client scope on test-app so every token carries it;
    ``reports`` is never granted, so the same token must be refused there.
    """
    auth = {"Authorization": f"Bearer {user_token}"}
    with TestClient(_app(keycloak_config)) as client:
        granted = client.get("/profile-scoped", headers=auth)
        denied = client.get("/reports", headers=auth)

    assert granted.status_code == 200
    assert "profile" in granted.json()["scopes"]
    assert denied.status_code == 403
