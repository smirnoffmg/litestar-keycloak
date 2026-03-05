"""Unit tests for JWKSCache (TTL, refresh, concurrent access)."""

import asyncio
import base64
from unittest.mock import AsyncMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from litestar_keycloak.exceptions import JWKSFetchError
from litestar_keycloak.token import JWKSCache


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
    cache = JWKSCache("http://example.com/jwks", ttl=3600, http_timeout=10)
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
    cache = JWKSCache("http://example.com/jwks", ttl=3600, http_timeout=10)
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
    cache = JWKSCache("http://example.com/jwks", ttl=1, http_timeout=10)
    jwks_data = _jwks_response("kid-1")
    # Patch time.monotonic so _is_expired is controlled.
    with (
        patch.object(
            cache, "_fetch_jwks", new_callable=AsyncMock, return_value=jwks_data
        ) as fetch_mock,
        patch(
            "litestar_keycloak.token.time.monotonic",
            side_effect=[100, 101, 102, 103, 104, 105, 106, 107],
        ),
    ):
        await cache.get_key("kid-1")
        await cache.get_key("kid-1")
    assert fetch_mock.call_count == 2


async def test_get_key_refreshes_on_unknown_kid():
    """When kid is not in cache, get_key triggers refresh then looks up again."""
    cache = JWKSCache("http://example.com/jwks", ttl=3600, http_timeout=10)
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
    cache = JWKSCache("http://example.com/jwks", ttl=3600, http_timeout=10)
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
    cache = JWKSCache("http://example.com/jwks", ttl=3600, http_timeout=10)
    jwks_data = _jwks_response("kid-1")
    with patch.object(
        cache, "_fetch_jwks", new_callable=AsyncMock, return_value=jwks_data
    ) as mock_fetch:
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
    cache = JWKSCache("http://example.com/jwks", ttl=0, http_timeout=10)
    jwks_data = _jwks_response("kid-1")
    with patch.object(
        cache, "_fetch_jwks", new_callable=AsyncMock, return_value=jwks_data
    ) as mock_fetch:
        await cache.warm()
        with pytest.raises(JWKSFetchError, match="kid-1"):
            await cache.get_key("kid-1")
    assert mock_fetch.call_count == 2


async def test_fetch_failure_raises_jwks_fetch_error():
    """When _fetch_jwks raises, get_key raises JWKSFetchError."""
    cache = JWKSCache("http://example.com/jwks", ttl=3600, http_timeout=10)
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
    cache = JWKSCache("http://example.com/jwks", ttl=3600, http_timeout=10)
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
