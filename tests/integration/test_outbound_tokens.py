"""Integration tests for outbound service tokens.

client_credentials runs against the suite's Keycloak 26.0 container.  Standard
token exchange (RFC 8693) exists only from Keycloak 26.2, so that test starts a
26.4 container of its own.
"""

import dataclasses
from pathlib import Path

import httpx
import jwt
import pytest
from litestar import Litestar, get
from litestar.testing import TestClient

from litestar_keycloak import (
    CurrentRawToken,
    CurrentUser,
    KeycloakConfig,
    KeycloakPlugin,
    ServiceTokens,
)

pytestmark = pytest.mark.integration

EXCHANGE_IMAGE = "quay.io/keycloak/keycloak:26.4"
REALM_EXPORT = Path(__file__).parent.parent / "fixtures" / "realm-export.json"


def test_client_token_is_a_cached_service_account_token(
    keycloak_container, keycloak_config
):
    """The token is issued to this client's service account and reused."""

    @get("/outbound", exclude_from_auth=True)
    async def outbound(service_tokens: ServiceTokens) -> dict:
        first = await service_tokens.client_token()
        second = await service_tokens.client_token()
        return {"token": first, "reused": first == second}

    config = dataclasses.replace(
        keycloak_config, client_id="test-service", client_secret="service-secret"
    )
    app = Litestar(route_handlers=[outbound], plugins=[KeycloakPlugin(config)])
    with TestClient(app) as client:
        body = client.get("/outbound").json()
    claims = jwt.decode(body["token"], options={"verify_signature": False})
    assert body["reused"] is True
    assert claims["azp"] == "test-service"
    assert claims["client_id"] == "test-service"


@pytest.fixture(scope="module")
def keycloak_26_4():
    from testcontainers.core.wait_strategies import HttpWaitStrategy
    from testcontainers.keycloak import KeycloakContainer

    kc = KeycloakContainer(EXCHANGE_IMAGE).with_realm_import_file(str(REALM_EXPORT))
    kc.start()
    HttpWaitStrategy(
        8080, "/realms/test-realm/.well-known/openid-configuration"
    ).for_status_code(200).with_startup_timeout(180).wait_until_ready(kc)
    yield kc
    kc.stop()


def _audience_mapper(target: str) -> dict:
    return {
        "name": f"audience-{target}",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-mapper",
        "config": {"included.client.audience": target, "access.token.claim": "true"},
    }


@pytest.mark.timeout(300)
def test_exchange_turns_the_callers_token_into_one_for_another_service(keycloak_26_4):
    """frontend token -> this API -> exchanged token for billing, same user."""
    base_url = keycloak_26_4.get_url()
    admin_token = httpx.post(
        f"{base_url}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": keycloak_26_4.username,
            "password": keycloak_26_4.password,
        },
        timeout=30,
    ).json()["access_token"]
    with httpx.Client(
        base_url=f"{base_url}/admin/realms/test-realm",
        headers={"Authorization": f"Bearer {admin_token}"},
        timeout=30,
    ) as admin:
        for client in (
            {"clientId": "billing", "secret": "billing-secret"},
            {
                "clientId": "orders-api",
                "secret": "orders-secret",
                "attributes": {"standard.token.exchange.enabled": "true"},
                "protocolMappers": [_audience_mapper("billing")],
            },
            {
                "clientId": "frontend",
                "secret": "frontend-secret",
                "directAccessGrantsEnabled": True,
                "protocolMappers": [_audience_mapper("orders-api")],
            },
        ):
            resp = admin.post("/clients", json=client)
            assert resp.status_code in (201, 409), resp.text
    user_token = httpx.post(
        f"{base_url}/realms/test-realm/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "frontend",
            "client_secret": "frontend-secret",
            "username": "testuser",
            "password": "testpass",
        },
        timeout=30,
    ).json()["access_token"]

    @get("/orders")
    async def orders(
        current_user: CurrentUser,
        raw_token: CurrentRawToken,
        service_tokens: ServiceTokens,
    ) -> dict:
        billing_token = await service_tokens.exchange(raw_token, audience="billing")
        return {"user": current_user.sub, "billing_token": billing_token}

    @get("/orders/unrelated")
    async def unrelated(
        raw_token: CurrentRawToken, service_tokens: ServiceTokens
    ) -> dict:
        await service_tokens.exchange(raw_token, audience="test-app")
        return {}

    config = KeycloakConfig(
        server_url=base_url,
        realm="test-realm",
        client_id="orders-api",
        client_secret="orders-secret",
        strict_audience=True,
    )
    app = Litestar(route_handlers=[orders, unrelated], plugins=[KeycloakPlugin(config)])
    bearer = {"Authorization": f"Bearer {user_token}"}
    with TestClient(app) as client:
        body = client.get("/orders", headers=bearer).json()
        refused = client.get("/orders/unrelated", headers=bearer)

    exchanged = jwt.decode(body["billing_token"], options={"verify_signature": False})
    assert exchanged["aud"] == "billing"
    assert exchanged["azp"] == "orders-api"
    assert exchanged["sub"] == body["user"]
    assert refused.status_code == 502
    assert "not available" not in refused.text
