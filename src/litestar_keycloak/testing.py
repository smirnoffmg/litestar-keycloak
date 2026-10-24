"""Helpers for testing apps that use the plugin, without a Keycloak server.

``create_test_token`` signs a JWT with a key generated when this module is first
imported; ``MockKeycloakPlugin`` is a ``KeycloakPlugin`` that verifies tokens
with that key instead of fetching the realm's JWKS::

    from litestar_keycloak.testing import MockKeycloakPlugin, create_test_token

    app = Litestar(route_handlers=[me], plugins=[MockKeycloakPlugin()])
    with TestClient(app) as client:
        token = create_test_token(sub="user-1", realm_roles=["admin"])
        client.get("/me", headers={"Authorization": f"Bearer {token}"})

The key exists only in this process, so these tokens are accepted by nothing
but ``MockKeycloakPlugin``.  Not for production code.
"""

from __future__ import annotations

import time
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import PyJWK
from jwt.algorithms import RSAAlgorithm

from litestar_keycloak.config import KeycloakConfig
from litestar_keycloak.exceptions import UnknownSigningKeyError
from litestar_keycloak.http_client import KeycloakHttpClient
from litestar_keycloak.plugin import KeycloakPlugin
from litestar_keycloak.token import TokenVerifier

__all__ = [
    "DEFAULT_AUDIENCE",
    "DEFAULT_ISSUER",
    "DEFAULT_KID",
    "MockKeycloakPlugin",
    "create_test_token",
]

#: Claims ``create_test_token`` sets by default; they match the defaults of
#: ``MockKeycloakPlugin`` (``http://localhost:8080``, realm ``test-realm``,
#: client ``test-app``).
DEFAULT_ISSUER = "http://localhost:8080/realms/test-realm"
DEFAULT_AUDIENCE = "test-app"
DEFAULT_KID = "test-kid"

_TEST_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_TEST_JWK = PyJWK(
    {
        **RSAAlgorithm.to_jwk(_TEST_PRIVATE_KEY.public_key(), as_dict=True),
        "kid": DEFAULT_KID,
    }
)


class _InMemoryJWKSCache:
    """Holds only the test key; never makes an HTTP call."""

    async def get_key(self, kid: str) -> PyJWK:
        if kid != DEFAULT_KID:
            raise UnknownSigningKeyError(f"Key {kid!r} not found in JWKS after refresh")
        return _TEST_JWK

    async def warm(self) -> None:
        pass


def create_test_token(
    sub: str = "test-user-id",
    realm_roles: list[str] | None = None,
    exp_offset: int = 3600,
    iss: str = DEFAULT_ISSUER,
    aud: str = DEFAULT_AUDIENCE,
    typ: str | None = "Bearer",
    headers: dict[str, str] | None = None,
    **extra_claims: Any,
) -> str:
    """A JWT signed with the test key, shaped like a Keycloak access token.

    *exp_offset* is seconds from now (negative for an expired token);
    *extra_claims* are added as is (e.g. ``groups=[...]``,
    ``resource_access={...}``).  ``typ=None`` leaves the ``typ`` claim out.
    """
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
    if typ is not None:
        payload["typ"] = typ
    return jwt.encode(
        payload,
        _TEST_PRIVATE_KEY,
        algorithm="RS256",
        headers={"kid": DEFAULT_KID, **(headers or {})},
    )


def MockKeycloakPlugin(  # noqa: N802 - reads as the plugin class it stands in for
    server_url: str = "http://localhost:8080",
    realm: str = "test-realm",
    client_id: str = "test-app",
    **kwargs: Any,
) -> KeycloakPlugin:
    """A ``KeycloakPlugin`` that accepts ``create_test_token`` tokens.

    *kwargs* are any other ``KeycloakConfig`` fields.  Everything but key
    retrieval is the real plugin: guards, dependencies, routes and error
    responses behave as in production.
    """
    config = KeycloakConfig(
        server_url=server_url, realm=realm, client_id=client_id, **kwargs
    )
    cache = _InMemoryJWKSCache()
    verifier = TokenVerifier(config, cache)  # type: ignore[arg-type]

    class _MockPlugin(KeycloakPlugin):
        def __init__(self) -> None:
            self._config = config
            self._jwks_cache = cache  # type: ignore[assignment]
            self._verifier = verifier
            # Unused by the in-memory cache, but _on_shutdown closes it;
            # close() is a no-op when no session was ever opened.
            self._http = KeycloakHttpClient(config.http_timeout)

    return _MockPlugin()
