"""Integration test fixtures: Keycloak container, config, tokens.

Uses testcontainers recommended API:
- KeycloakContainer.with_realm_import_file() for realm import
- HttpWaitStrategy for waiting on realm OIDC discovery

To see debug output when running integration tests:
    pytest -m integration -o log_cli=true -o log_cli_level=INFO
For more detail (e.g. wait polling):
    pytest -m integration -o log_cli=true -o log_cli_level=DEBUG
"""

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

import pytest

from litestar_keycloak.config import KeycloakConfig

logger = logging.getLogger(__name__)

REALM_EXPORT = Path(__file__).parent.parent / "fixtures" / "realm-export.json"

# Timeout for realm OIDC discovery after container start (realm import can be slow)
OIDC_READINESS_TIMEOUT = 120


@pytest.fixture(scope="session")
def keycloak_container():
    from testcontainers.core.wait_strategies import HttpWaitStrategy
    from testcontainers.keycloak import KeycloakContainer

    logger.info(
        "Starting Keycloak container (image: quay.io/keycloak/keycloak:26.0)..."
    )
    kc = (
        KeycloakContainer("quay.io/keycloak/keycloak:26.0")
        .with_realm_import_file(str(REALM_EXPORT))
        # Lets Keycloak call back into the test process (back-channel logout);
        # Docker Desktop has this name already, Linux needs the mapping.
        .with_kwargs(extra_hosts={"host.docker.internal": "host-gateway"})
    )
    kc.start()
    base_url = kc.get_url()
    logger.info("Container up at %s, waiting for realm OIDC discovery...", base_url)
    oidc_path = "/realms/test-realm/.well-known/openid-configuration"
    oidc_strategy = (
        HttpWaitStrategy(8080, oidc_path)
        .for_status_code(200)
        .with_startup_timeout(OIDC_READINESS_TIMEOUT)
    )
    oidc_strategy.wait_until_ready(kc)
    logger.info("Keycloak ready, realm test-realm available")
    yield kc
    logger.info("Stopping Keycloak container...")
    kc.stop()


@pytest.fixture(scope="session")
def keycloak_config(keycloak_container) -> KeycloakConfig:
    url = keycloak_container.get_url()  # http://localhost:<random_port>
    return KeycloakConfig(
        server_url=url,
        realm="test-realm",
        client_id="test-app",
        client_secret="test-secret",
    )


def obtain_token(
    base_url: str,
    username: str,
    password: str,
    *,
    client_id: str = "test-app",
    client_secret: str = "test-secret",
    scope: str | None = None,
) -> dict[str, Any]:
    """Direct grant (resource owner password) — only for tests."""
    form = {
        "grant_type": "password",
        "client_id": client_id,
        "client_secret": client_secret,
        "username": username,
        "password": password,
    }
    # Omitted entirely rather than sent empty: Keycloak treats an empty scope as
    # a request for no scopes, dropping even the default ones.
    if scope is not None:
        form["scope"] = scope
    data = urllib.parse.urlencode(form).encode()

    req = urllib.request.Request(
        f"{base_url}/realms/test-realm/protocol/openid-connect/token",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.fp.read().decode() if e.fp else ""
        raise RuntimeError(f"Token request failed {e.code}: {body}") from e


@pytest.fixture
def user_token(keycloak_container) -> str:
    logger.debug("Obtaining token for testuser...")
    result = obtain_token(keycloak_container.get_url(), "testuser", "testpass")
    logger.debug("Got user token (expires_in=%s)", result.get("expires_in"))
    return result["access_token"]


@pytest.fixture
def admin_token(keycloak_container) -> str:
    logger.debug("Obtaining token for testadmin...")
    result = obtain_token(keycloak_container.get_url(), "testadmin", "testpass")
    logger.debug("Got admin token (expires_in=%s)", result.get("expires_in"))
    return result["access_token"]


@pytest.fixture
def shortlived_token(keycloak_container) -> str:
    """Access token from the ``test-shortlived`` client (access.token.lifespan=1)."""
    result = obtain_token(
        keycloak_container.get_url(),
        "testuser",
        "testpass",
        client_id="test-shortlived",
        client_secret="shortlived-secret",
    )
    return result["access_token"]


@pytest.fixture
def user_token_response(keycloak_container) -> dict[str, Any]:
    """Full token response (access_token, refresh_token, etc.) for testuser."""
    return obtain_token(keycloak_container.get_url(), "testuser", "testpass")


@pytest.fixture
def admin_api(keycloak_container):
    """httpx client for the test-realm Admin REST API, as the bootstrap admin."""
    import httpx

    base_url = keycloak_container.get_url()
    resp = httpx.post(
        f"{base_url}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": keycloak_container.username,
            "password": keycloak_container.password,
        },
        timeout=30,
    )
    resp.raise_for_status()
    with httpx.Client(
        base_url=f"{base_url}/admin/realms/test-realm",
        headers={"Authorization": f"Bearer {resp.json()['access_token']}"},
        timeout=30,
    ) as client:
        yield client


@pytest.fixture
def browser_login():
    """Drive Keycloak's HTML login form; return the callback redirect (with code)."""
    import re

    import httpx

    def _login(authorize_url: str, username: str, password: str) -> str:
        with httpx.Client(follow_redirects=False, timeout=30) as client:
            page = client.get(authorize_url)
            page.raise_for_status()
            match = re.search(
                r'action="(?P<url>[^"]*login-actions/authenticate[^"]*)"', page.text
            )
            assert match, "Keycloak login form not found on the authorization page"
            action = match.group("url").replace("&amp;", "&")
            # Keycloak sets its session cookies as SameSite=None; Secure, which
            # httpx will not resend over plain http — forward them explicitly.
            cookie_header = "; ".join(f"{k}={v}" for k, v in client.cookies.items())
            resp = client.post(
                action,
                data={"username": username, "password": password},
                headers={"Cookie": cookie_header},
            )
            assert resp.status_code in (302, 303), f"login POST -> {resp.status_code}"
            return resp.headers["location"]

    return _login


@pytest.fixture
def probe_user(admin_api) -> str:
    """A throwaway user (password ``pw``) that a test may log out or disable."""
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
