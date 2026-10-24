"""Unit tests for TokenVerifier and token validation."""

import dataclasses
import time
from unittest.mock import AsyncMock

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from jwt import PyJWK
from jwt.algorithms import ECAlgorithm, OKPAlgorithm

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


class _KeyByKid:
    """JWKS double serving several keys by kid."""

    def __init__(self, keys: dict[str, PyJWK]) -> None:
        self._keys = keys

    async def get_key(self, kid: str) -> PyJWK:
        if kid not in self._keys:
            raise JWKSFetchError(f"Key {kid!r} not found in JWKS after refresh")
        return self._keys[kid]


def _claims(**overrides) -> dict:
    now = int(time.time())
    return {
        "sub": "user-1",
        "iss": "http://localhost:8080/realms/test-realm",
        "aud": "test-app",
        "iat": now,
        "exp": now + 3600,
        "typ": "Bearer",
        **overrides,
    }


@pytest.fixture(scope="module")
def ec_keypair():
    private = ec.generate_private_key(ec.SECP256R1())
    jwk_dict = ECAlgorithm.to_jwk(private.public_key(), as_dict=True)
    return private, PyJWK({**jwk_dict, "kid": "ec-kid", "alg": "ES256"})


@pytest.fixture(scope="module")
def ed25519_keypair():
    private = ed25519.Ed25519PrivateKey.generate()
    jwk_dict = OKPAlgorithm.to_jwk(private.public_key(), as_dict=True)
    return private, PyJWK({**jwk_dict, "kid": "ed-kid", "alg": "EdDSA"})


def _multi_alg_verifier(keycloak_config, test_jwk, ec_keypair, ed25519_keypair):
    config = dataclasses.replace(
        keycloak_config, algorithms=("RS256", "ES256", "EdDSA")
    )
    cache = _KeyByKid(
        {"test-kid": test_jwk, "ec-kid": ec_keypair[1], "ed-kid": ed25519_keypair[1]}
    )
    return TokenVerifier(config, cache)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("keypair", "alg", "kid"),
    [("ec_keypair", "ES256", "ec-kid"), ("ed25519_keypair", "EdDSA", "ed-kid")],
)
async def test_verify_accepts_non_rsa_signing_keys(
    request, keycloak_config, test_jwk, ec_keypair, ed25519_keypair, keypair, alg, kid
):
    """Realms signing with an EC or Ed25519 key are supported."""
    verifier = _multi_alg_verifier(
        keycloak_config, test_jwk, ec_keypair, ed25519_keypair
    )
    private, _ = request.getfixturevalue(keypair)
    token = jwt.encode(_claims(), private, algorithm=alg, headers={"kid": kid})
    payload = await verifier.verify(token)
    assert payload.sub == "user-1"


async def test_verify_rejects_alg_from_another_key_family(
    keycloak_config, test_jwk, ec_keypair, ed25519_keypair, rsa_keypair
):
    """An RS256 token pointing at an EC kid is a 401, not a server error."""
    verifier = _multi_alg_verifier(
        keycloak_config, test_jwk, ec_keypair, ed25519_keypair
    )
    rsa_private, _ = rsa_keypair
    token = jwt.encode(
        _claims(), rsa_private, algorithm="RS256", headers={"kid": "ec-kid"}
    )
    with pytest.raises(TokenDecodeError, match="ES256|EC"):
        await verifier.verify(token)


async def test_verify_rejects_ec_alg_for_another_curve(keycloak_config):
    """ES256 on a P-384 kid is a 401; PyJWT's curve check would raise a 500."""
    signer = ec.generate_private_key(ec.SECP256R1())
    p384 = ec.generate_private_key(ec.SECP384R1()).public_key()
    jwk = PyJWK({**ECAlgorithm.to_jwk(p384, as_dict=True), "kid": "p384"})
    config = dataclasses.replace(keycloak_config, algorithms=("ES256", "ES384"))
    verifier = TokenVerifier(config, _KeyByKid({"p384": jwk}))  # type: ignore[arg-type]
    token = jwt.encode(_claims(), signer, algorithm="ES256", headers={"kid": "p384"})
    with pytest.raises(TokenDecodeError, match="P-384|secp384r1"):
        await verifier.verify(token)


@pytest.mark.parametrize("claim", ["exp", "iat"])
async def test_verify_requires_exp_and_iat(token_verifier, rsa_keypair, claim):
    """A token without exp or iat is a 401, not a TypeError from TokenPayload."""
    private_key, _ = rsa_keypair
    claims = {k: v for k, v in _claims().items() if k != claim}
    token = jwt.encode(
        claims, private_key, algorithm="RS256", headers={"kid": "test-kid"}
    )
    with pytest.raises(TokenDecodeError, match=claim):
        await token_verifier.verify(token)


async def test_verify_rejects_recently_expired_token_without_leeway(
    token_verifier, make_token
):
    """Default leeway is 0: a token expired seconds ago is rejected."""
    token = make_token(exp_offset=-5)
    with pytest.raises(TokenExpiredError):
        await token_verifier.verify(token)


async def test_verify_leeway_tolerates_clock_skew(
    keycloak_config, mock_jwks_cache, make_token
):
    """With leeway, a slightly expired token and a future iat both pass."""
    config = dataclasses.replace(keycloak_config, leeway=30)
    verifier = TokenVerifier(config, mock_jwks_cache)
    await verifier.verify(make_token(exp_offset=-5))
    await verifier.verify(make_token(iat=int(time.time()) + 10))


async def test_verify_introspects_after_local_validation(
    keycloak_config, mock_jwks_cache, make_token
):
    """Only a token that passes local checks costs an introspection call."""
    introspector = AsyncMock()
    verifier = TokenVerifier(keycloak_config, mock_jwks_cache, introspector)
    token = make_token()
    await verifier.verify(token)
    introspector.ensure_active.assert_awaited_once_with(token)

    introspector.reset_mock()
    with pytest.raises(TokenExpiredError):
        await verifier.verify(make_token(exp_offset=-60))
    introspector.ensure_active.assert_not_awaited()


# --- ID token (OIDC Core 3.1.3.7) ---


def _id_token(rsa_keypair, **overrides) -> str:
    private_key, _ = rsa_keypair
    claims = _claims(typ="ID", azp="test-app", nonce="n-1")
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(
        claims, private_key, algorithm="RS256", headers={"kid": "test-kid"}
    )


async def test_verify_id_token_returns_claims(token_verifier, rsa_keypair):
    claims = await token_verifier.verify_id_token(_id_token(rsa_keypair), nonce="n-1")
    assert claims["sub"] == "user-1"


@pytest.mark.parametrize(
    ("overrides", "error"),
    [
        ({"nonce": "other"}, TokenDecodeError),
        ({"nonce": None}, TokenDecodeError),
        ({"typ": "Bearer"}, InvalidTokenTypeError),
        ({"iss": "https://evil/realms/test-realm"}, InvalidIssuerError),
        ({"aud": "other-app", "azp": "other-app"}, InvalidAudienceError),
        ({"aud": ["test-app", "other-app"], "azp": "other-app"}, InvalidAudienceError),
        ({"exp": int(time.time()) - 60}, TokenExpiredError),
        ({"exp": None}, TokenDecodeError),
    ],
    ids=["nonce", "no-nonce", "typ", "iss", "aud", "azp", "exp", "no-exp"],
)
async def test_verify_id_token_rejects(token_verifier, rsa_keypair, overrides, error):
    """A replayed, foreign or stale ID token must not complete a login."""
    with pytest.raises(error):
        await token_verifier.verify_id_token(
            _id_token(rsa_keypair, **overrides), nonce="n-1"
        )


async def test_verify_id_token_checks_client_id_not_optional_audiences(
    keycloak_config, mock_jwks_cache, rsa_keypair
):
    """An ID token is for this client only; extra API audiences do not count."""
    config = dataclasses.replace(
        keycloak_config, optional_audiences=frozenset({"other-app"})
    )
    verifier = TokenVerifier(config, mock_jwks_cache)
    token = _id_token(rsa_keypair, aud="other-app", azp="other-app")
    with pytest.raises(InvalidAudienceError):
        await verifier.verify_id_token(token, nonce="n-1")


async def test_verify_id_token_rejects_empty_expected_nonce(
    token_verifier, rsa_keypair
):
    """A lost nonce cookie must not let a nonce-less ID token through."""
    with pytest.raises(TokenDecodeError):
        await token_verifier.verify_id_token(
            _id_token(rsa_keypair, nonce=None), nonce=""
        )


async def test_verify_id_token_non_ascii_nonce_is_rejected_not_crashed(
    token_verifier, rsa_keypair
):
    with pytest.raises(TokenDecodeError):
        await token_verifier.verify_id_token(_id_token(rsa_keypair), nonce="я")


# --- back-channel logout token (OIDC Back-Channel Logout 1.0, 2.6) ---

_BACKCHANNEL_EVENT = "http://schemas.openid.net/event/backchannel-logout"


def _logout_token(rsa_keypair, typ_header="logout+jwt", **overrides) -> str:
    private_key, _ = rsa_keypair
    claims = _claims(typ="Logout", sid="s-1", events={_BACKCHANNEL_EVENT: {}})
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    headers = {"kid": "test-kid"}
    if typ_header is not None:
        headers["typ"] = typ_header
    return jwt.encode(claims, private_key, algorithm="RS256", headers=headers)


async def test_verify_logout_token_returns_claims(token_verifier, rsa_keypair):
    claims = await token_verifier.verify_logout_token(_logout_token(rsa_keypair))
    assert (claims["sid"], claims["sub"]) == ("s-1", "user-1")


async def test_verify_logout_token_accepts_sub_only(token_verifier, rsa_keypair):
    token = _logout_token(rsa_keypair, sid=None)
    assert (await token_verifier.verify_logout_token(token))["sub"] == "user-1"


@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        ({"events": None}, TokenDecodeError),
        ({"events": {"other": {}}}, TokenDecodeError),
        ({"nonce": "n"}, TokenDecodeError),
        ({"sid": None, "sub": None}, TokenDecodeError),
        ({"iat": None}, TokenDecodeError),
        ({"typ_header": "JWT"}, TokenDecodeError),
        ({"aud": "other-app"}, InvalidAudienceError),
        ({"iss": "https://evil/realms/test-realm"}, InvalidIssuerError),
    ],
    ids=[
        "no-events",
        "wrong-event",
        "nonce",
        "no-subject",
        "no-iat",
        "typ",
        "aud",
        "iss",
    ],
)
async def test_verify_logout_token_rejects(token_verifier, rsa_keypair, kwargs, error):
    """An access or ID token, or a token for another client, cannot log anyone out."""
    with pytest.raises(error):
        await token_verifier.verify_logout_token(_logout_token(rsa_keypair, **kwargs))


@pytest.mark.parametrize(
    "drop", [("sub",), ("sub", "preferred_username")], ids=["no-sub", "no-identity"]
)
async def test_require_sub_refuses_tokens_without_sub(
    keycloak_config, test_jwk, rsa_keypair, drop
):
    """Without basic scope, sub would fall back to a reassignable username."""
    private_key, _ = rsa_keypair
    claims = {
        k: v for k, v in _claims(preferred_username="alice").items() if k not in drop
    }
    token = jwt.encode(
        claims, private_key, algorithm="RS256", headers={"kid": "test-kid"}
    )
    lenient = TokenVerifier(keycloak_config, _KeyByKid({"test-kid": test_jwk}))  # type: ignore[arg-type]
    strict = TokenVerifier(
        dataclasses.replace(keycloak_config, require_sub=True),
        _KeyByKid({"test-kid": test_jwk}),  # type: ignore[arg-type]
    )
    assert (await lenient.verify(token)).sub == ("alice" if drop == ("sub",) else "")
    with pytest.raises(TokenDecodeError, match="sub"):
        await strict.verify(token)
