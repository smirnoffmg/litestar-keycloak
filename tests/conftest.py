"""Shared test fixtures and helpers (create_test_token, MockKeycloakPlugin)."""

from __future__ import annotations

import base64
import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import PyJWK

from litestar_keycloak.config import KeycloakConfig
from litestar_keycloak.exceptions import JWKSFetchError
from litestar_keycloak.plugin import KeycloakPlugin
from litestar_keycloak.token import TokenVerifier

# Fixed key pair for testing — same key for create_test_token and MockKeycloakPlugin.
_TEST_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_TEST_PUBLIC_KEY = _TEST_PRIVATE_KEY.public_key()

DEFAULT_ISSUER = "http://localhost:8080/realms/test-realm"
DEFAULT_AUDIENCE = "test-app"
DEFAULT_KID = "test-kid"


def _int_to_base64url(i: int) -> str:
    by = i.to_bytes((i.bit_length() + 7) // 8 or 1, "big")
    return base64.urlsafe_b64encode(by).rstrip(b"=").decode("ascii")


def _public_key_to_jwk(
    public_key: rsa.RSAPublicKey, kid: str = DEFAULT_KID
) -> dict[str, Any]:
    numbers = public_key.public_numbers()
    return {
        "kty": "RSA",
        "kid": kid,
        "n": _int_to_base64url(numbers.n),
        "e": _int_to_base64url(numbers.e),
    }


_TEST_JWK = PyJWK(_public_key_to_jwk(_TEST_PUBLIC_KEY))


class _InMemoryJWKSCache:
    """Returns the fixed test key for DEFAULT_KID. No HTTP."""

    async def get_key(self, kid: str) -> PyJWK:
        if kid != DEFAULT_KID:
            raise JWKSFetchError(f"Key {kid!r} not found in JWKS after refresh")
        return _TEST_JWK

    async def warm(self) -> None:
        pass


def create_test_token(
    sub: str = "test-user-id",
    realm_roles: list[str] | None = None,
    exp_offset: int = 3600,
    iss: str = DEFAULT_ISSUER,
    aud: str = DEFAULT_AUDIENCE,
    headers: dict[str, str] | None = None,
    **extra_claims: Any,
) -> str:
    """Build a JWT signed with the test key for use with MockKeycloakPlugin."""
    now = int(time.time())
    payload = {
        "sub": sub,
        "iss": iss,
        "aud": aud,
        "iat": now,
        "exp": now + exp_offset,
        "realm_access": {"roles": realm_roles or ["user"]},
        **extra_claims,
    }
    h = dict(headers) if headers is not None else {}
    if "kid" not in h:
        h["kid"] = DEFAULT_KID
    return jwt.encode(
        payload,
        _TEST_PRIVATE_KEY,
        algorithm="RS256",
        headers=h,
    )


def MockKeycloakPlugin(
    server_url: str = "http://localhost:8080",
    realm: str = "test-realm",
    client_id: str = "test-app",
    **kwargs: Any,
) -> KeycloakPlugin:
    """Plugin that validates tokens with the test key (no Keycloak server)."""
    config = KeycloakConfig(
        server_url=server_url,
        realm=realm,
        client_id=client_id,
        **kwargs,
    )
    cache = _InMemoryJWKSCache()
    verifier = TokenVerifier(config, cache)  # type: ignore[arg-type]

    class _MockPlugin(KeycloakPlugin):
        def __init__(self) -> None:
            self._config = config
            self._jwks_cache = cache
            self._verifier = verifier

    return _MockPlugin()


# Fixtures that expose the helpers for tests that request them by name.
@pytest.fixture
def create_test_token_factory():
    """Fixture that returns the create_test_token callable."""
    return create_test_token


@pytest.fixture
def mock_keycloak_plugin_factory():
    """Fixture that returns the MockKeycloakPlugin callable."""
    return MockKeycloakPlugin
