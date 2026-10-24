"""Unit tests for JWKSCache (TTL, refresh, concurrent access)."""

import asyncio
import base64
from unittest.mock import AsyncMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from jwt.algorithms import ECAlgorithm, OKPAlgorithm

from litestar_keycloak.exceptions import JWKSFetchError
from litestar_keycloak.http_client import KeycloakHttpClient
from litestar_keycloak.token import MIN_FORCED_REFRESH_INTERVAL, JWKSCache


def _int_to_base64url(i: int) -> str:
    by = i.to_bytes((i.bit_length() + 7) // 8 or 1, "big")
    return base64.urlsafe_b64encode(by).rstrip(b"=").decode("ascii")


def _make_jwk_dict(kid: str = "test-kid"):
    """Build a minimal RSA JWK dict for testing."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private.public_key().public_numbers()
    return {
        "kty": "RSA",
        "kid": kid,
        "n": _int_to_base64url(numbers.n),
        "e": _int_to_base64url(numbers.e),
    }


def _jwks_response(*kids: str) -> dict:
    """Build JWKS response with one or more keys."""
    return {"keys": [_make_jwk_dict(kid) for kid in kids]}


async def test_warm_populates_cache():
    """warm() calls _refresh and populates the cache."""
    cache = JWKSCache("http://example.com/jwks", ttl=3600, http=KeycloakHttpClient(10))
    jwks_data = _jwks_response("kid-1")
    with patch.object(
        cache, "_fetch_jwks", new_callable=AsyncMock, return_value=jwks_data
    ):
        await cache.warm()
    key = await cache.get_key("kid-1")
    assert key is not None
    assert key.key_id == "kid-1"


async def test_get_key_returns_cached_key_without_refetch():
    """After warm(), get_key returns from cache without calling _fetch_jwks again."""
    cache = JWKSCache("http://example.com/jwks", ttl=3600, http=KeycloakHttpClient(10))
    jwks_data = _jwks_response("kid-1")
    fetch_mock = AsyncMock(return_value=jwks_data)
    with patch.object(cache, "_fetch_jwks", fetch_mock):
        await cache.warm()
        k1 = await cache.get_key("kid-1")
        k2 = await cache.get_key("kid-1")
    assert k1 is k2
    assert fetch_mock.call_count == 1


async def test_get_key_refreshes_on_ttl_expiry():
    """When TTL has expired, get_key triggers a refresh."""
    cache = JWKSCache("http://example.com/jwks", ttl=1, http=KeycloakHttpClient(10))
    jwks_data = _jwks_response("kid-1")
    now = 100.0
    with (
        patch.object(
            cache, "_fetch_jwks", new_callable=AsyncMock, return_value=jwks_data
        ) as fetch_mock,
        patch("litestar_keycloak.token.time.monotonic", side_effect=lambda: now),
    ):
        await cache.get_key("kid-1")
        await cache.get_key("kid-1")
        assert fetch_mock.call_count == 1
        now += 2
        await cache.get_key("kid-1")
    assert fetch_mock.call_count == 2


async def test_get_key_refreshes_on_unknown_kid():
    """When kid is not in cache, get_key triggers refresh then looks up again."""
    cache = JWKSCache("http://example.com/jwks", ttl=3600, http=KeycloakHttpClient(10))
    jwks_with_kid2 = _jwks_response("kid-2")
    fetch_mock = AsyncMock(side_effect=[{"keys": []}, jwks_with_kid2])
    with patch.object(cache, "_fetch_jwks", fetch_mock):
        with pytest.raises(JWKSFetchError, match="kid-1"):
            await cache.get_key("kid-1")
        key = await cache.get_key("kid-2")
    assert key.key_id == "kid-2"
    assert fetch_mock.call_count == 2


async def test_get_key_raises_after_refresh_if_kid_still_missing():
    """If refresh returns JWKS without requested kid, get_key raises JWKSFetchError."""
    cache = JWKSCache("http://example.com/jwks", ttl=3600, http=KeycloakHttpClient(10))
    jwks_data = _jwks_response("other-kid")
    with (
        patch.object(
            cache, "_fetch_jwks", new_callable=AsyncMock, return_value=jwks_data
        ),
        pytest.raises(JWKSFetchError, match="missing-kid"),
    ):
        await cache.get_key("missing-kid")


async def test_concurrent_refreshes_only_fetch_once():
    """Concurrent get_key when cache empty results in single _fetch_jwks call."""
    cache = JWKSCache("http://example.com/jwks", ttl=3600, http=KeycloakHttpClient(10))
    jwks_data = _jwks_response("kid-1")

    async def slow_fetch():
        await asyncio.sleep(0)  # a bare AsyncMock never yields, so nothing races
        return jwks_data

    with patch.object(cache, "_fetch_jwks", side_effect=slow_fetch) as mock_fetch:
        results = await asyncio.gather(
            cache.get_key("kid-1"),
            cache.get_key("kid-1"),
            cache.get_key("kid-1"),
        )
    assert len(results) == 3
    assert all(r.key_id == "kid-1" for r in results)
    assert mock_fetch.call_count == 1


async def test_ttl_zero_always_refetches():
    """When ttl=0, each get_key triggers _refresh; warm + get_key = 2 fetches."""
    cache = JWKSCache("http://example.com/jwks", ttl=0, http=KeycloakHttpClient(10))
    jwks_data = _jwks_response("kid-1")
    with patch.object(
        cache, "_fetch_jwks", new_callable=AsyncMock, return_value=jwks_data
    ) as mock_fetch:
        await cache.warm()
        key = await cache.get_key("kid-1")
    assert key.key_id == "kid-1"
    assert mock_fetch.call_count == 2


async def test_fetch_failure_raises_jwks_fetch_error():
    """When _fetch_jwks raises, get_key raises JWKSFetchError."""
    cache = JWKSCache("http://example.com/jwks", ttl=3600, http=KeycloakHttpClient(10))
    with (
        patch.object(
            cache,
            "_fetch_jwks",
            new_callable=AsyncMock,
            side_effect=JWKSFetchError("Network error"),
        ),
        pytest.raises(JWKSFetchError, match="Network error"),
    ):
        await cache.get_key("kid-1")


async def test_malformed_jwks_response_skips_bad_keys():
    """Invalid or non-RSA keys in JWKS are skipped; valid keys are cached."""
    cache = JWKSCache("http://example.com/jwks", ttl=3600, http=KeycloakHttpClient(10))
    valid_jwk = _make_jwk_dict("valid-kid")
    jwks_data = {
        "keys": [
            {"kid": "no-kty", "e": "AQAB"},
            valid_jwk,
            {"kty": "EC", "kid": "ec-kid", "crv": "P-256", "x": "x", "y": "y"},
        ]
    }
    with patch.object(
        cache, "_fetch_jwks", new_callable=AsyncMock, return_value=jwks_data
    ):
        await cache.warm()
        key = await cache.get_key("valid-kid")
        assert key.key_id == "valid-kid"
        with pytest.raises(JWKSFetchError, match="ec-kid"):
            await cache.get_key("ec-kid")


async def test_jwks_key_without_kid_is_skipped():
    """A JWK with no 'kid' is skipped without disturbing valid keys."""
    cache = JWKSCache("http://example.com/jwks", ttl=3600, http=KeycloakHttpClient(10))
    no_kid = {k: v for k, v in _make_jwk_dict("tmp").items() if k != "kid"}
    valid_jwk = _make_jwk_dict("valid-kid")
    jwks_data = {"keys": [no_kid, valid_jwk]}
    with patch.object(
        cache, "_fetch_jwks", new_callable=AsyncMock, return_value=jwks_data
    ):
        await cache.warm()
    assert (await cache.get_key("valid-kid")).key_id == "valid-kid"


async def test_unparseable_rsa_jwk_is_skipped():
    """An RSA JWK that PyJWK cannot parse is skipped; valid keys still load."""
    cache = JWKSCache("http://example.com/jwks", ttl=3600, http=KeycloakHttpClient(10))
    bad_rsa = {"kty": "RSA", "kid": "bad-kid", "n": "!!!not-base64!!!", "e": "AQAB"}
    valid_jwk = _make_jwk_dict("valid-kid")
    jwks_data = {"keys": [bad_rsa, valid_jwk]}
    with patch.object(
        cache, "_fetch_jwks", new_callable=AsyncMock, return_value=jwks_data
    ):
        await cache.warm()
        assert (await cache.get_key("valid-kid")).key_id == "valid-kid"
        with pytest.raises(JWKSFetchError, match="bad-kid"):
            await cache.get_key("bad-kid")


async def test_fetch_jwks_network_error_wrapped_as_jwks_fetch_error():
    """_fetch_jwks wraps a real aiohttp connection error as JWKSFetchError."""
    # Port 1 is reserved and refuses connections -> aiohttp.ClientError.
    http = KeycloakHttpClient(2)
    cache = JWKSCache("http://127.0.0.1:1/jwks", ttl=3600, http=http)
    try:
        with pytest.raises(JWKSFetchError, match="Failed to fetch JWKS"):
            await cache._fetch_jwks()
    finally:
        await http.close()


async def test_enc_key_is_parsed_with_rs256():
    """A key marked use=enc still parses — same RSA material, forced to RS256."""
    key = _make_jwk_dict("enc-kid")
    key["use"] = "enc"
    cache = JWKSCache("http://example.com/jwks", ttl=3600, http=KeycloakHttpClient(10))
    with patch.object(
        cache, "_fetch_jwks", new_callable=AsyncMock, return_value={"keys": [key]}
    ):
        assert await cache.get_key("enc-kid") is not None


async def test_non_signing_alg_key_is_parsed_with_rs256():
    """A key advertising a non-signing alg is coerced to RS256 rather than dropped."""
    key = _make_jwk_dict("wrap-kid")
    key["alg"] = "RSA-OAEP"
    cache = JWKSCache("http://example.com/jwks", ttl=3600, http=KeycloakHttpClient(10))
    with patch.object(
        cache, "_fetch_jwks", new_callable=AsyncMock, return_value={"keys": [key]}
    ):
        assert await cache.get_key("wrap-kid") is not None


async def test_unknown_kid_refetches_even_when_cache_is_fresh():
    """Key rotation: a kid issued after warm-up is fetched before the TTL expires."""
    cache = JWKSCache("http://example.com/jwks", ttl=3600, http=KeycloakHttpClient(10))
    fetch_mock = AsyncMock(
        side_effect=[_jwks_response("old-kid"), _jwks_response("old-kid", "new-kid")]
    )
    with patch.object(cache, "_fetch_jwks", fetch_mock):
        await cache.warm()
        key = await cache.get_key("new-kid")
    assert key.key_id == "new-kid"
    assert fetch_mock.call_count == 2


async def test_concurrent_requests_for_rotated_kid_fetch_once():
    """Requests racing on a newly rotated kid share a single forced refresh."""
    cache = JWKSCache("http://example.com/jwks", ttl=3600, http=KeycloakHttpClient(10))
    fetch_mock = AsyncMock(
        side_effect=[_jwks_response("old-kid"), _jwks_response("old-kid", "new-kid")]
    )
    with patch.object(cache, "_fetch_jwks", fetch_mock):
        await cache.warm()
        results = await asyncio.gather(*(cache.get_key("new-kid") for _ in range(3)))
    assert all(r.key_id == "new-kid" for r in results)
    assert fetch_mock.call_count == 2


async def test_forced_refresh_is_throttled():
    """Made-up kids cannot turn every request into a JWKS fetch."""
    cache = JWKSCache("http://example.com/jwks", ttl=3600, http=KeycloakHttpClient(10))
    fetch_mock = AsyncMock(return_value=_jwks_response("kid-1"))
    with patch.object(cache, "_fetch_jwks", fetch_mock):
        await cache.warm()
        for kid in ("bogus-1", "bogus-2", "bogus-3"):
            with pytest.raises(JWKSFetchError, match=kid):
                await cache.get_key(kid)
    assert fetch_mock.call_count == 2


async def test_forced_refresh_allowed_again_after_throttle_interval():
    """Once the throttle interval passes, an unknown kid triggers a fetch again."""
    cache = JWKSCache("http://example.com/jwks", ttl=3600, http=KeycloakHttpClient(10))
    fetch_mock = AsyncMock(return_value=_jwks_response("kid-1"))
    now = 1000.0
    with (
        patch.object(cache, "_fetch_jwks", fetch_mock),
        patch("litestar_keycloak.token.time.monotonic", side_effect=lambda: now),
    ):
        await cache.warm()
        with pytest.raises(JWKSFetchError):
            await cache.get_key("bogus-1")
        now += MIN_FORCED_REFRESH_INTERVAL + 1
        with pytest.raises(JWKSFetchError):
            await cache.get_key("bogus-2")
    assert fetch_mock.call_count == 3


async def test_ttl_expiry_refresh_does_not_throttle_rotation():
    """Only fetches forced on a fresh cache count toward the throttle."""
    cache = JWKSCache("http://example.com/jwks", ttl=60, http=KeycloakHttpClient(10))
    fetch_mock = AsyncMock(
        side_effect=[
            _jwks_response("kid-1"),
            _jwks_response("kid-1"),
            _jwks_response("kid-1", "kid-2"),
        ]
    )
    now = 1000.0
    with (
        patch.object(cache, "_fetch_jwks", fetch_mock),
        patch("litestar_keycloak.token.time.monotonic", side_effect=lambda: now),
    ):
        await cache.warm()
        now += 61
        await cache.get_key("kid-1")
        key = await cache.get_key("kid-2")
    assert key.key_id == "kid-2"
    assert fetch_mock.call_count == 3


async def test_ec_and_okp_signing_keys_are_cached():
    """EC and Ed25519 signing keys load alongside RSA ones."""
    ec_jwk = ECAlgorithm.to_jwk(
        ec.generate_private_key(ec.SECP384R1()).public_key(), as_dict=True
    )
    ed_jwk = OKPAlgorithm.to_jwk(
        ed25519.Ed25519PrivateKey.generate().public_key(), as_dict=True
    )
    jwks = {
        "keys": [
            {**ec_jwk, "kid": "ec-kid", "alg": "ES384", "use": "sig"},
            {**ed_jwk, "kid": "ed-kid", "alg": "EdDSA", "use": "sig"},
        ]
    }
    cache = JWKSCache("http://example.com/jwks", ttl=3600, http=KeycloakHttpClient(10))
    with patch.object(cache, "_fetch_jwks", new_callable=AsyncMock, return_value=jwks):
        assert (await cache.get_key("ec-kid")).algorithm_name == "ES384"
        assert (await cache.get_key("ed-kid")).algorithm_name == "EdDSA"


async def test_ec_encryption_key_is_skipped():
    """An EC key published for encryption (ECDH-ES) is not a signing key."""
    ec_jwk = ECAlgorithm.to_jwk(
        ec.generate_private_key(ec.SECP256R1()).public_key(), as_dict=True
    )
    jwks = {"keys": [{**ec_jwk, "kid": "enc-kid", "alg": "ECDH-ES", "use": "enc"}]}
    cache = JWKSCache("http://example.com/jwks", ttl=3600, http=KeycloakHttpClient(10))
    with (
        patch.object(cache, "_fetch_jwks", new_callable=AsyncMock, return_value=jwks),
        pytest.raises(JWKSFetchError, match="enc-kid"),
    ):
        await cache.get_key("enc-kid")
