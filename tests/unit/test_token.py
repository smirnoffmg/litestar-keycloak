"""Unit tests for TokenVerifier and token validation."""

import dataclasses
import time

import jwt
import pytest

from litestar_keycloak.exceptions import (
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidTokenTypeError,
    JWKSFetchError,
    TokenDecodeError,
    TokenExpiredError,
)
from litestar_keycloak.models import TokenPayload
from litestar_keycloak.token import TokenVerifier


async def test_verify_valid_token_returns_token_payload(token_verifier, make_token):
    """Valid token returns TokenPayload with correct sub and realm_roles."""
    token = make_token(sub="user-123", realm_roles=["admin", "user"])
    payload = await token_verifier.verify(token)
    assert isinstance(payload, TokenPayload)
    assert payload.sub == "user-123"
    assert payload.realm_roles == frozenset({"admin", "user"})
    assert payload.iss == "http://localhost:8080/realms/test-realm"
    assert payload.aud == "test-app"


async def test_verify_expired_token_raises(token_verifier, make_token):
    """Expired token raises TokenExpiredError."""
    token = make_token(exp_offset=-3600)
    with pytest.raises(TokenExpiredError):
        await token_verifier.verify(token)


async def test_verify_wrong_issuer_raises(token_verifier, make_token):
    """Token with wrong iss raises InvalidIssuerError."""
    token = make_token(iss="http://wrong-issuer/realms/other")
    with pytest.raises(InvalidIssuerError) as exc_info:
        await token_verifier.verify(token)
    assert (
        "wrong-issuer" in str(exc_info.value)
        or exc_info.value.got == "http://wrong-issuer/realms/other"
    )


async def test_verify_accepts_frontend_issuer_via_expected_issuer(
    keycloak_config, mock_jwks_cache, make_token
):
    """A token whose iss is Keycloak's frontend URL passes when expected_issuer set."""
    frontend_iss = "https://sso.public.example.com/realms/test-realm"
    token = make_token(iss=frontend_iss)

    # Default config expects the server_url-derived issuer -> mismatch.
    default_verifier = TokenVerifier(keycloak_config, mock_jwks_cache)
    with pytest.raises(InvalidIssuerError):
        await default_verifier.verify(token)

    # With expected_issuer set to the frontend value, validation succeeds.
    config = dataclasses.replace(keycloak_config, expected_issuer=frontend_iss)
    payload = await TokenVerifier(config, mock_jwks_cache).verify(token)
    assert payload.iss == frontend_iss


async def test_verify_wrong_audience_raises(token_verifier, make_token):
    """Token with wrong aud raises InvalidAudienceError."""
    token = make_token(aud="wrong-client")
    with pytest.raises(InvalidAudienceError) as exc_info:
        await token_verifier.verify(token)
    assert (
        "wrong-client" in str(exc_info.value) or exc_info.value.expected == "test-app"
    )


async def test_verify_missing_kid_raises(token_verifier, make_token):
    """Token with no kid in header raises TokenDecodeError."""
    token = make_token(headers={})  # no kid
    with pytest.raises(TokenDecodeError) as exc_info:
        await token_verifier.verify(token)
    assert "kid" in str(exc_info.value).lower()


async def test_verify_malformed_jwt_raises(token_verifier):
    """Malformed JWT string raises TokenDecodeError."""
    with pytest.raises(TokenDecodeError):
        await token_verifier.verify("not.a.jwt")
    with pytest.raises(TokenDecodeError):
        await token_verifier.verify("")


async def test_verify_unknown_kid_raises_jwks_fetch_error(
    keycloak_config, make_token, test_jwk
):
    """Token with kid not in cache raises JWKSFetchError."""
    from litestar_keycloak.token import TokenVerifier

    class CacheOnlyOtherKid:
        async def get_key(self, kid: str):
            if kid != "other-kid":
                raise JWKSFetchError(f"Key {kid!r} not found")
            return test_jwk

        async def warm(self):
            pass

    verifier = TokenVerifier(keycloak_config, CacheOnlyOtherKid())  # type: ignore[arg-type]
    token = make_token(headers={"kid": "unknown-kid"})
    with pytest.raises(JWKSFetchError) as exc_info:
        await verifier.verify(token)
    assert "unknown-kid" in str(exc_info.value)


async def test_verify_audience_list_with_expected_in_list(token_verifier, make_token):
    """Token with aud as list containing expected client passes."""
    token = make_token(aud=["other", "test-app", "third"])
    payload = await token_verifier.verify(token)
    assert payload.sub == "test-user-id"


async def test_verify_extra_claims_land_in_extra(token_verifier, make_token):
    """Extra claims end up in TokenPayload.extra."""
    token = make_token(custom_claim="value", another=42)
    payload = await token_verifier.verify(token)
    assert payload.extra.get("custom_claim") == "value"
    assert payload.extra.get("another") == 42


# --- token type (typ) validation ---


async def test_verify_bearer_token_accepted(token_verifier, make_token):
    """Access token with typ='Bearer' is accepted."""
    token = make_token(sub="user-1", typ="Bearer")
    payload = await token_verifier.verify(token)
    assert payload.sub == "user-1"
    assert payload.typ == "Bearer"


async def test_verify_id_token_rejected(token_verifier, make_token):
    """ID token (typ='ID') is rejected even though aud matches client_id."""
    token = make_token(typ="ID")
    with pytest.raises(InvalidTokenTypeError) as exc_info:
        await token_verifier.verify(token)
    assert exc_info.value.expected == "Bearer"
    assert exc_info.value.got == "ID"


async def test_verify_refresh_token_rejected(token_verifier, make_token):
    """Refresh token (typ='Refresh') is rejected as an access token."""
    token = make_token(typ="Refresh")
    with pytest.raises(InvalidTokenTypeError):
        await token_verifier.verify(token)


async def test_verify_missing_typ_rejected_by_default(token_verifier, make_token):
    """Token without a typ claim is rejected under the default 'Bearer'."""
    token = make_token(typ=None)
    with pytest.raises(InvalidTokenTypeError):
        await token_verifier.verify(token)


async def test_verify_typ_check_disabled_allows_id_token(
    keycloak_config, mock_jwks_cache, make_token
):
    """Setting expected_token_type=None disables the check (ID token passes)."""
    config = dataclasses.replace(keycloak_config, expected_token_type=None)
    verifier = TokenVerifier(config, mock_jwks_cache)
    token = make_token(sub="user-2", typ="ID")
    payload = await verifier.verify(token)
    assert payload.sub == "user-2"


# -- regression: the InvalidTokenError family must map to 401, not escape as 500 --


async def test_verify_nbf_in_future_raises_token_decode_error(
    token_verifier, make_token
):
    """A not-yet-valid token is a client error, not an unhandled 500.

    ImmatureSignatureError sits beside DecodeError under InvalidTokenError, so
    catching only DecodeError let it escape the verifier uncaught.
    """
    token = make_token(nbf=int(time.time()) + 3600)
    with pytest.raises(TokenDecodeError):
        await token_verifier.verify(token)


async def test_verify_wrong_algorithm_raises_token_decode_error(
    token_verifier, make_token
):
    """A token signed with an algorithm outside `algorithms` is rejected as 401.

    This is the shape of an alg-confusion probe: PyJWT refuses it because the
    verifier pins RS256, but it used to surface as InvalidAlgorithmError -> 500.
    """
    now = int(time.time())
    token = jwt.encode(
        {
            "sub": "user-1",
            "iss": "http://localhost:8080/realms/test-realm",
            "aud": "test-app",
            "iat": now,
            "exp": now + 3600,
            "typ": "Bearer",
        },
        "a" * 32,  # >=32 bytes: PyJWT warns on short HMAC keys
        algorithm="HS256",
        headers={"kid": "test-kid"},
    )
    with pytest.raises(TokenDecodeError):
        await token_verifier.verify(token)


async def test_verify_invalid_signature_raises_token_decode_error(
    token_verifier, make_token
):
    """A token whose signature does not match the key is rejected."""
    token = make_token()
    head, payload, sig = token.split(".")
    tampered = f"{head}.{payload}.{sig[:-4]}AAAA"
    with pytest.raises(TokenDecodeError):
        await token_verifier.verify(tampered)


async def test_verify_empty_aud_falls_back_to_azp(
    keycloak_config, mock_jwks_cache, make_token
):
    """A token with no aud is accepted when azp names an accepted audience."""
    verifier = TokenVerifier(keycloak_config, mock_jwks_cache)
    token = make_token(aud="", azp="test-app")
    payload = await verifier.verify(token)
    assert payload.azp == "test-app"


# -- audience modes --


async def test_verify_lenient_accepts_foreign_aud_with_our_azp(
    token_verifier, make_token
):
    """Default (lenient) mode accepts aud="account" when azp is accepted."""
    token = make_token(aud="account", azp="test-app")
    payload = await token_verifier.verify(token)
    assert payload.azp == "test-app"


@pytest.fixture
def strict_verifier(keycloak_config, mock_jwks_cache) -> TokenVerifier:
    config = dataclasses.replace(
        keycloak_config,
        strict_audience=True,
        optional_audiences=frozenset({"other-service"}),
    )
    return TokenVerifier(config, mock_jwks_cache)


async def test_verify_strict_accepts_matching_aud(strict_verifier, make_token):
    """Strict mode accepts a token whose aud is the configured audience."""
    payload = await strict_verifier.verify(make_token(aud="test-app"))
    assert payload.aud == "test-app"


async def test_verify_strict_accepts_aud_list_with_optional_audience(
    strict_verifier, make_token
):
    """Strict mode accepts an aud list containing an optional audience."""
    token = make_token(aud=["account", "other-service"])
    payload = await strict_verifier.verify(token)
    assert payload.sub == "test-user-id"


async def test_verify_strict_rejects_foreign_aud_with_our_azp(
    strict_verifier, make_token
):
    """Strict mode ignores azp: a foreign aud is rejected."""
    token = make_token(aud="other-api", azp="test-app")
    with pytest.raises(InvalidAudienceError):
        await strict_verifier.verify(token)


@pytest.mark.parametrize("aud", ["", []])
async def test_verify_strict_rejects_empty_aud(strict_verifier, make_token, aud):
    """Strict mode rejects an empty aud even when azp is accepted."""
    token = make_token(aud=aud, azp="test-app")
    with pytest.raises(InvalidAudienceError):
        await strict_verifier.verify(token)


async def test_verify_strict_rejects_missing_aud(strict_verifier, rsa_keypair):
    """Strict mode rejects a token with no aud claim even when azp is accepted."""
    private_key, _ = rsa_keypair
    now = int(time.time())
    token = jwt.encode(
        {
            "sub": "user-1",
            "iss": "http://localhost:8080/realms/test-realm",
            "azp": "test-app",
            "iat": now,
            "exp": now + 3600,
            "typ": "Bearer",
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "test-kid"},
    )
    with pytest.raises(InvalidAudienceError):
        await strict_verifier.verify(token)
