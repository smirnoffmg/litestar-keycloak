"""Tests for the public testing helpers (create_test_token, MockKeycloakPlugin).

These are documented in docs/guides/testing.md for downstream users; nothing else
in this suite exercises them, so regressions here are invisible without this file.
"""

from litestar import Litestar, get
from litestar.testing import TestClient

from litestar_keycloak import CurrentUser
from tests.conftest import MockKeycloakPlugin, create_test_token


@get("/me")
async def _me(current_user: CurrentUser) -> dict:
    return {"sub": current_user.sub, "roles": sorted(current_user.realm_roles)}


def _app(**kwargs) -> Litestar:
    return Litestar(route_handlers=[_me], plugins=[MockKeycloakPlugin(**kwargs)])


def test_mock_plugin_app_starts_and_shuts_down_cleanly():
    """Leaving the TestClient context must not raise.

    Regression: the mock plugin did not set _http, so the inherited _on_shutdown
    raised AttributeError on app shutdown for anyone following the docs.
    """
    with TestClient(_app()) as client:
        resp = client.get(
            "/me",
            headers={"Authorization": f"Bearer {create_test_token()}"},
        )
    assert resp.status_code == 200


def test_create_test_token_is_accepted_by_mock_plugin():
    """A token from create_test_token validates against MockKeycloakPlugin."""
    token = create_test_token(sub="user-42", realm_roles=["admin", "user"])
    with TestClient(_app()) as client:
        resp = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json() == {"sub": "user-42", "roles": ["admin", "user"]}


def test_expired_token_from_helper_is_rejected():
    """A negative exp_offset produces a token the plugin rejects with 401."""
    token = create_test_token(exp_offset=-3600)
    with TestClient(_app()) as client:
        resp = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401
