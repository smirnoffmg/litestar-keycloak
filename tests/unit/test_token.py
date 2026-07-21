"""Unit tests for TokenVerifier and token validation."""

import dataclasses

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
