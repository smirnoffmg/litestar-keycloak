"""Integration tests for identity claims and the guards built on them.

Groups, service-account detection and step-up (acr / auth_time) depend on what
real Keycloak puts in its tokens, so each test sets up the client it needs
through the Admin REST API and authenticates with a token Keycloak issued.
"""

import dataclasses
import time
import urllib.parse

import httpx
import pytest
from litestar import Litestar, get
from litestar.testing import TestClient

from litestar_keycloak import (
    CurrentUser,
    KeycloakPlugin,
    require_acr,
    require_groups,
    require_recent_auth,
)

pytestmark = pytest.mark.integration

REDIRECT_URI = "http://localhost:8000/auth/callback"


def _token_url(base_url: str) -> str:
    return f"{base_url}/realms/test-realm/protocol/openid-connect/token"


def _create_client(admin_api, representation: dict) -> None:
    resp = admin_api.post("/clients", json=representation)
    assert resp.status_code in (201, 409), resp.text


def _password_grant(base_url: str, client_id: str) -> str:
    resp = httpx.post(
        _token_url(base_url),
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
    return resp.json()["access_token"]


def _app(config, *handlers) -> TestClient:
    return TestClient(
        Litestar(route_handlers=list(handlers), plugins=[KeycloakPlugin(config)])
    )


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@get("/whoami")
async def whoami(current_user: CurrentUser) -> dict:
    return {
        "groups": sorted(current_user.groups),
        "is_service_account": current_user.is_service_account,
        "acr": current_user.acr,
        "auth_time": current_user.auth_time,
        "sid": current_user.sid,
    }


def test_group_membership_mapper_feeds_require_groups(
    keycloak_container, keycloak_config, admin_api
):
    """Groups from Keycloak's Group Membership mapper reach the user and the guard."""
    base_url = keycloak_container.get_url()
    resp = admin_api.post("/groups", json={"name": "staff"})
    assert resp.status_code in (201, 409), resp.text
    [group] = [g for g in admin_api.get("/groups").json() if g["name"] == "staff"]
    [user] = admin_api.get(
        "/users", params={"username": "testuser", "exact": "true"}
    ).json()
    admin_api.put(f"/users/{user['id']}/groups/{group['id']}").raise_for_status()
    _create_client(
        admin_api,
        {
            "clientId": "test-groups",
            "secret": "test-groups-secret",
            "publicClient": False,
            "directAccessGrantsEnabled": True,
            "protocolMappers": [
                {
                    "name": "groups",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-group-membership-mapper",
                    "config": {
                        "claim.name": "groups",
                        "full.path": "false",
                        "access.token.claim": "true",
                    },
                }
            ],
        },
    )
    token = _password_grant(base_url, "test-groups")

    @get("/staff", guards=[require_groups("staff")])
    async def staff() -> dict:
        return {}

    @get("/audit", guards=[require_groups("audit")])
    async def audit() -> dict:
        return {}

    config = dataclasses.replace(
        keycloak_config,
        client_secret=None,
        client_id="test-groups",
    )
    with _app(config, whoami, staff, audit) as client:
        assert client.get("/whoami", headers=_bearer(token)).json()["groups"] == [
            "staff"
        ]
        assert client.get("/staff", headers=_bearer(token)).status_code == 200
        assert client.get("/audit", headers=_bearer(token)).status_code == 403


def test_service_account_token_is_flagged(
    keycloak_container, keycloak_config, user_token
):
    """A client_credentials token is a service account; a user token is not."""
    resp = httpx.post(
        _token_url(keycloak_container.get_url()),
        data={
            "grant_type": "client_credentials",
            "client_id": "test-service",
            "client_secret": "service-secret",
        },
        timeout=30,
    )
    resp.raise_for_status()
    service_token = resp.json()["access_token"]
    config = dataclasses.replace(
        keycloak_config,
        client_secret=None,
        client_id="test-app",
        optional_audiences=frozenset({"test-service"}),
    )
    with _app(config, whoami) as client:
        service = client.get("/whoami", headers=_bearer(service_token)).json()
        user = client.get("/whoami", headers=_bearer(user_token)).json()
    assert service["is_service_account"] is True
    assert user["is_service_account"] is False


def test_step_up_guards_on_a_browser_login(
    keycloak_container, keycloak_config, admin_api, browser_login
):
    """A real browser login carries acr and auth_time; the guards act on them."""
    base_url = keycloak_container.get_url()
    _create_client(
        admin_api,
        {
            "clientId": "test-stepup",
            "secret": "test-stepup-secret",
            "publicClient": False,
            "standardFlowEnabled": True,
            "redirectUris": [REDIRECT_URI],
            # basic carries sub and auth_time, acr the authentication level.
            "defaultClientScopes": ["basic", "acr", "profile", "roles"],
        },
    )
    authorize = f"{base_url}/realms/test-realm/protocol/openid-connect/auth?" + (
        urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": "test-stepup",
                "redirect_uri": REDIRECT_URI,
                "scope": "openid",
                "state": "s",
            }
        )
    )
    callback = browser_login(authorize, "testuser", "testpass")
    code = urllib.parse.parse_qs(urllib.parse.urlparse(callback).query)["code"][0]
    resp = httpx.post(
        _token_url(base_url),
        data={
            "grant_type": "authorization_code",
            "client_id": "test-stepup",
            "client_secret": "test-stepup-secret",
            "redirect_uri": REDIRECT_URI,
            "code": code,
        },
        timeout=30,
    )
    resp.raise_for_status()
    token = resp.json()["access_token"]

    @get("/recent", guards=[require_recent_auth(3600)])
    async def recent() -> dict:
        return {}

    @get("/strong", guards=[require_acr("2")])
    async def strong() -> dict:
        return {}

    config = dataclasses.replace(
        keycloak_config,
        client_secret=None,
        client_id="test-stepup",
    )
    with _app(config, whoami, recent, strong) as client:
        me = client.get("/whoami", headers=_bearer(token)).json()
        recent_resp = client.get("/recent", headers=_bearer(token))
        strong_resp = client.get("/strong", headers=_bearer(token))
    assert me["acr"] == "1"
    assert me["sid"]
    assert abs(me["auth_time"] - time.time()) < 300
    assert recent_resp.status_code == 200
    assert strong_resp.status_code == 401
    assert (
        'error="insufficient_user_authentication"'
        in strong_resp.headers["www-authenticate"]
    )
    assert 'acr_values="2"' in strong_resp.headers["www-authenticate"]
