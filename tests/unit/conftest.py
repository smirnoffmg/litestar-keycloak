import base64
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import PyJWK

from litestar_keycloak.config import KeycloakConfig
from litestar_keycloak.exceptions import JWKSFetchError
from litestar_keycloak.token import JWKSCache, TokenVerifier


def _int_to_base64url(i: int) -> str:
    """Encode a non-negative integer as base64url (RFC 7518)."""
    by = i.to_bytes((i.bit_length() + 7) // 8 or 1, "big")
    return base64.urlsafe_b64encode(by).rstrip(b"=").decode("ascii")


def _rsa_public_key_to_jwk(public_key: rsa.RSAPublicKey, kid: str = "test-kid") -> dict:
    """Build a JWK dict from a cryptography RSA public key."""
    numbers = public_key.public_numbers()
    return {
        "kty": "RSA",
        "kid": kid,
        "n": _int_to_base64url(numbers.n),
        "e": _int_to_base64url(numbers.e),
    }


@pytest.fixture(scope="session")
def rsa_keypair():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key()
    return private, public


@pytest.fixture(scope="session")
def test_jwk(rsa_keypair) -> PyJWK:
    """PyJWK for the test RSA key — matches tokens from make_token."""
    _, public_key = rsa_keypair
    return PyJWK(_rsa_public_key_to_jwk(public_key))


class MockJWKSCache:
    """In-memory JWKS that returns the test key for 'test-kid'. No HTTP."""

    def __init__(self, jwk: PyJWK, kid: str = "test-kid") -> None:
        self._jwk = jwk
        self._kid = kid

    async def get_key(self, kid: str) -> PyJWK:
        if kid != self._kid:
            raise JWKSFetchError(f"Key {kid!r} not found in JWKS after refresh")
        return self._jwk

    async def warm(self) -> None:
        pass


@pytest.fixture
def mock_jwks_cache(test_jwk) -> JWKSCache:
    """JWKSCache double that returns test_jwk for 'test-kid'. Used by TokenVerifier."""
    return MockJWKSCache(test_jwk)  # type: ignore[return-value]


@pytest.fixture
def keycloak_config() -> KeycloakConfig:
    """Config matching make_token issuer/audience (no real HTTP)."""
    return KeycloakConfig(
        server_url="http://localhost:8080",
        realm="test-realm",
        client_id="test-app",
    )


@pytest.fixture
def token_verifier(keycloak_config, mock_jwks_cache) -> TokenVerifier:
    return TokenVerifier(keycloak_config, mock_jwks_cache)


@pytest.fixture
def make_token(rsa_keypair):
    """Factory to mint JWTs with arbitrary claims — no Keycloak needed."""
    private_key, _ = rsa_keypair

    def _make(
        sub: str = "test-user-id",
        realm_roles: list[str] | None = None,
        exp_offset: int = 3600,
        headers: dict | None = None,
        **extra_claims,
    ) -> str:
        now = int(time.time())
        payload = {
            "sub": sub,
            "iss": "http://localhost:8080/realms/test-realm",
            "aud": "test-app",
            "iat": now,
            "exp": now + exp_offset,
            "realm_access": {"roles": realm_roles or ["user"]},
            **extra_claims,
        }
        h = headers if headers is not None else {"kid": "test-kid"}
        return jwt.encode(payload, private_key, algorithm="RS256", headers=h)

    return _make
