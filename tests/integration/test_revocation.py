"""Integration tests for revocation through token introspection.

Each test signs in a user of its own, so ending its session or disabling it
leaves the shared realm untouched for the other tests.
"""

import dataclasses
import uuid

import httpx
import pytest
from litestar import Litestar, get
from litestar.testing import TestClient

from litestar_keycloak import CurrentUser, KeycloakPlugin

pytestmark = pytest.mark.integration


@get("/me")
async def me(current_user: CurrentUser) -> dict:
    return {"username": current_user.preferred_username}


@pytest.fixture
def probe_user(admin_api) -> str:
    """A throwaway user; returns its ID."""
    username = f"probe-{uuid.uuid4().hex[:8]}"
    resp = admin_api.post(
        "/users",
        json={
            "username": username,
            "enabled": True,
            "firstName": "Probe",
            "lastName": "User",
            "email": f"{username}@test.local",
            "emailVerified": True,
            "credentials": [{"type": "password", "value": "pw", "temporary": False}],
        },
    )
    assert resp.status_code == 201, resp.text
    [user] = admin_api.get(
        "/users", params={"username": username, "exact": "true"}
    ).json()
    return user["id"]


def _token_for(keycloak_container, admin_api, user_id: str) -> str:
    username = admin_api.get(f"/users/{user_id}").json()["username"]
    resp = httpx.post(
        f"{keycloak_container.get_url()}/realms/test-realm/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "test-app",
            "client_secret": "test-secret",
            "username": username,
            "password": "pw",
        },
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def _status(config, token: str) -> int:
    app = Litestar(route_handlers=[me], plugins=[KeycloakPlugin(config)])
    with TestClient(app) as client:
        return client.get(
            "/me", headers={"Authorization": f"Bearer {token}"}
        ).status_code


def _end_session(admin_api, user_id: str) -> None:
    admin_api.post(f"/users/{user_id}/logout").raise_for_status()


def _disable(admin_api, user_id: str) -> None:
    user = admin_api.get(f"/users/{user_id}").json()
    admin_api.put(
        f"/users/{user_id}", json={**user, "enabled": False}
    ).raise_for_status()


@pytest.mark.parametrize("revoke", [_end_session, _disable], ids=["logout", "disable"])
def test_introspection_rejects_a_revoked_token_at_once(
    keycloak_container, keycloak_config, admin_api, probe_user, revoke
):
    """After logout or disabling, the still-unexpired JWT is refused (И78, И83)."""
    token = _token_for(keycloak_container, admin_api, probe_user)
    introspecting = dataclasses.replace(keycloak_config, token_introspection=True)
    assert _status(introspecting, token) == 200

    revoke(admin_api, probe_user)

    assert _status(introspecting, token) == 401
    # Without introspection the signature alone still admits it — the gap closed.
    assert _status(keycloak_config, token) == 200


def test_introspection_accepts_service_account_tokens(
    keycloak_container, keycloak_config
):
    """A client_credentials token issued to another client introspects as active."""
    resp = httpx.post(
        f"{keycloak_container.get_url()}/realms/test-realm/protocol/openid-connect/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "test-service",
            "client_secret": "service-secret",
        },
        timeout=30,
    )
    resp.raise_for_status()
    config = dataclasses.replace(
        keycloak_config,
        token_introspection=True,
        optional_audiences=frozenset({"test-service"}),
    )
    assert _status(config, resp.json()["access_token"]) == 200


def test_wrong_client_secret_is_a_502_not_a_401(keycloak_config, user_token):
    """Keycloak refusing *our* credentials is a server fault, not the caller's."""
    config = dataclasses.replace(
        keycloak_config, token_introspection=True, client_secret="wrong"
    )
    assert _status(config, user_token) == 502
