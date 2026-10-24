"""Journeys B4 and B5 (JOURNEYS.md): services calling services with client_credentials.

``inventory-api`` is a receiving service with its own plugin and
``strict_audience``; its ``stock-read`` client role guards ``/stock``.
``warehouse-worker`` holds that role and an Audience mapper for
``inventory-api``; ``nosy-worker`` has the mapper but not the role.  Tokens are
obtained by each caller's own plugin (``service_tokens.client_token()``), and
``inventory-api`` checks them: B5 is the caller's side of B4.
"""

import time

import httpx
import pytest
from litestar import Litestar, get
from litestar.testing import TestClient

from litestar_keycloak import (
    CurrentUser,
    KeycloakConfig,
    KeycloakPlugin,
    ServiceTokens,
    require_client_roles,
)

pytestmark = pytest.mark.integration

RECEIVER = "inventory-api"
ROLE = "stock-read"


def _client_uuid(admin_api, client_id: str) -> str:
    [client] = admin_api.get("/clients", params={"clientId": client_id}).json()
    return client["id"]


def _create_client(admin_api, representation: dict) -> str:
    resp = admin_api.post("/clients", json=representation)
    assert resp.status_code in (201, 409), resp.text
    return _client_uuid(admin_api, representation["clientId"])


def _service_client(client_id: str, **attributes: str) -> dict:
    return {
        "clientId": client_id,
        "secret": f"{client_id}-secret",
        "serviceAccountsEnabled": True,
        "standardFlowEnabled": False,
        "attributes": attributes,
        "protocolMappers": [
            {
                "name": f"audience-{RECEIVER}",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "config": {
                    "included.client.audience": RECEIVER,
                    "access.token.claim": "true",
                },
            }
        ],
    }


@pytest.fixture(scope="module")
def services(keycloak_container):
    """Register the receiver, two callers, and grant the role to one of them."""
    base_url = keycloak_container.get_url()
    token = httpx.post(
        f"{base_url}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": keycloak_container.username,
            "password": keycloak_container.password,
        },
        timeout=30,
    ).json()["access_token"]
    with httpx.Client(
        base_url=f"{base_url}/admin/realms/test-realm",
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
    ) as admin_api:
        receiver = _create_client(
            admin_api,
            {
                "clientId": RECEIVER,
                "secret": f"{RECEIVER}-secret",
                "standardFlowEnabled": False,
            },
        )
        admin_api.post(f"/clients/{receiver}/roles", json={"name": ROLE})
        role = admin_api.get(f"/clients/{receiver}/roles/{ROLE}").json()
        # A 2-second token, so renewal happens within the test.
        worker = _create_client(
            admin_api,
            _service_client("warehouse-worker", **{"access.token.lifespan": "2"}),
        )
        _create_client(admin_api, _service_client("nosy-worker"))
        account = admin_api.get(f"/clients/{worker}/service-account-user").json()
        resp = admin_api.post(
            f"/users/{account['id']}/role-mappings/clients/{receiver}", json=[role]
        )
        assert resp.status_code == 204, resp.text
    return base_url


@get("/stock", guards=[require_client_roles(RECEIVER, ROLE)])
async def stock(current_user: CurrentUser) -> dict:
    return {"caller": current_user.azp, "service": current_user.is_service_account}


@get("/token", exclude_from_auth=True)
async def outbound_token(service_tokens: ServiceTokens) -> dict:
    return {"token": await service_tokens.client_token()}


def _config(base_url: str, client_id: str, **overrides) -> KeycloakConfig:
    overrides.setdefault("client_secret", f"{client_id}-secret")
    return KeycloakConfig(
        server_url=base_url, realm="test-realm", client_id=client_id, **overrides
    )


def _app(config: KeycloakConfig, *handlers) -> TestClient:
    return TestClient(
        Litestar(route_handlers=list(handlers), plugins=[KeycloakPlugin(config)])
    )


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_service_calls_another_service_as_itself(services):
    """B5 then B4.2: the worker's plugin gets, caches and renews a token that the
    receiving service accepts."""
    with (
        _app(_config(services, "warehouse-worker"), outbound_token) as caller,
        _app(_config(services, RECEIVER, strict_audience=True), stock) as receiver,
    ):
        # B5.1–2. Gets a token; the receiver accepts it as this service.
        first = caller.get("/token").json()["token"]
        accepted = receiver.get("/stock", headers=_bearer(first))
        assert accepted.status_code == 200, accepted.text
        assert accepted.json() == {"caller": "warehouse-worker", "service": True}

        # B5.3. Calls again: the cached token.
        assert caller.get("/token").json()["token"] == first

        # B5.4. After half the 2-second lifetime: a renewed token, also accepted.
        time.sleep(1.5)
        renewed = caller.get("/token").json()["token"]
        assert renewed != first
        assert receiver.get("/stock", headers=_bearer(renewed)).status_code == 200


def test_receiving_service_refuses_callers_without_role_or_audience(
    services, keycloak_container
):
    """B4.3–4: authenticated but unauthorised is 403; not addressed to it is 401."""
    with (
        _app(_config(services, "nosy-worker"), outbound_token) as nosy,
        _app(_config(services, RECEIVER, strict_audience=True), stock) as receiver,
    ):
        no_role = nosy.get("/token").json()["token"]
        forbidden = receiver.get("/stock", headers=_bearer(no_role))
        assert forbidden.status_code == 403
        assert (
            forbidden.headers["www-authenticate"] == 'Bearer error="insufficient_scope"'
        )

        # test-service has no Audience mapper for inventory-api.
        foreign = httpx.post(
            f"{services}/realms/test-realm/protocol/openid-connect/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "test-service",
                "client_secret": "service-secret",
            },
            timeout=30,
        ).json()["access_token"]
        not_addressed = receiver.get("/stock", headers=_bearer(foreign))
        assert not_addressed.status_code == 401
        assert 'error="invalid_token"' in not_addressed.headers["www-authenticate"]


def test_wrong_client_secret_is_a_generic_502(services):
    """B5.5: Keycloak refusing this service's own credentials is a server fault."""
    config = _config(services, "warehouse-worker", client_secret="wrong")
    with _app(config, outbound_token) as caller:
        refused = caller.get("/token")
    assert refused.status_code == 502
    assert refused.json() == {"error": "Keycloak request failed"}
