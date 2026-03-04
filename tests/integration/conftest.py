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
    kc = KeycloakContainer("quay.io/keycloak/keycloak:26.0").with_realm_import_file(
        str(REALM_EXPORT)
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


def obtain_token(base_url: str, username: str, password: str) -> dict[str, Any]:
    """Direct grant (resource owner password) — only for tests."""
    data = urllib.parse.urlencode(
        {
            "grant_type": "password",
            "client_id": "test-app",
            "client_secret": "test-secret",
            "username": username,
            "password": password,
        }
    ).encode()

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
def user_token_response(keycloak_container) -> dict[str, Any]:
    """Full token response (access_token, refresh_token, etc.) for testuser."""
    return obtain_token(keycloak_container.get_url(), "testuser", "testpass")
