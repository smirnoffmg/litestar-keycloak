"""Integration tests for realms that sign access tokens with EC or Ed25519 keys.

The imported realm only has RSA keys, so each test adds a key provider and a
client whose access tokens use that algorithm through the Admin REST API.
"""

import dataclasses

import httpx
import jwt
import pytest
from litestar import Litestar, get
from litestar.testing import TestClient

from litestar_keycloak import CurrentUser, KeycloakPlugin

pytestmark = pytest.mark.integration


def _admin_headers(base_url: str, container) -> dict[str, str]:
    resp = httpx.post(
        f"{base_url}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": container.username,
            "password": container.password,
        },
        timeout=30,
    )
    resp.raise_for_status()
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _add_signing_client(
    base_url: str, container, *, provider: dict, client_id: str, alg: str
) -> None:
    """Add a key provider and a client whose access tokens are signed with *alg*."""
    admin = f"{base_url}/admin/realms/test-realm"
    headers = _admin_headers(base_url, container)
    realm_id = httpx.get(admin, headers=headers, timeout=30).json()["id"]
    resp = httpx.post(
        f"{admin}/components",
        headers=headers,
        json={**provider, "parentId": realm_id},
        timeout=30,
    )
    assert resp.status_code in (201, 409), resp.text
    resp = httpx.post(
        f"{admin}/clients",
        headers=headers,
        json={
            "clientId": client_id,
            "secret": f"{client_id}-secret",
            "publicClient": False,
            "directAccessGrantsEnabled": True,
            "attributes": {"access.token.signed.response.alg": alg},
        },
        timeout=30,
    )
    assert resp.status_code in (201, 409), resp.text


@get("/me")
async def me(current_user: CurrentUser) -> dict:
    return {"sub": current_user.sub}


@pytest.mark.parametrize(
    ("alg", "provider"),
    [
        (
            "ES256",
            {
                "name": "ecdsa-it",
                "providerId": "ecdsa-generated",
                "providerType": "org.keycloak.keys.KeyProvider",
                "config": {"priority": ["100"], "ecdsaEllipticCurveKey": ["P-256"]},
            },
        ),
        (
            "EdDSA",
            {
                "name": "eddsa-it",
                "providerId": "eddsa-generated",
                "providerType": "org.keycloak.keys.KeyProvider",
                "config": {"priority": ["100"], "eddsaEllipticCurveKey": ["Ed25519"]},
            },
        ),
    ],
)
def test_non_rsa_signed_token_is_accepted(
    keycloak_container, keycloak_config, alg, provider
):
    """A token signed by a real EC/Ed25519 key provider authenticates."""
    base_url = keycloak_container.get_url()
    client_id = f"test-{alg.lower()}"
    _add_signing_client(
        base_url, keycloak_container, provider=provider, client_id=client_id, alg=alg
    )
    resp = httpx.post(
        f"{base_url}/realms/test-realm/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": client_id,
            "client_secret": f"{client_id}-secret",
            "username": "testuser",
            "password": "testpass",
        },
        timeout=30,
    )
    resp.raise_for_status()
    token = resp.json()["access_token"]
    assert jwt.get_unverified_header(token)["alg"] == alg

    config = dataclasses.replace(
        keycloak_config,
        client_id=client_id,
        client_secret=None,
        algorithms=(alg,),
    )
    app = Litestar(route_handlers=[me], plugins=[KeycloakPlugin(config)])
    with TestClient(app) as client:
        resp = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200, resp.text
