"""Unit tests for TokenIntrospector (RFC 7662 call, positive cache, failures)."""

from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from litestar_keycloak import introspection
from litestar_keycloak.config import KeycloakConfig
from litestar_keycloak.exceptions import IntrospectionError, TokenInactiveError
from litestar_keycloak.http_client import KeycloakHttpClient
from litestar_keycloak.introspection import TokenIntrospector


def _config(**overrides) -> KeycloakConfig:
    return KeycloakConfig(
        server_url="http://kc",
        realm="r",
        client_id="api",
        client_secret="s3cret",
        token_introspection=True,
        **overrides,
    )


def _introspector(response, **config_overrides):
    http = KeycloakHttpClient(10)
    post = (
        AsyncMock(side_effect=response)
        if isinstance(response, (list, BaseException))
        else AsyncMock(return_value=response)
    )
    http.post_form = post  # type: ignore[method-assign]
    return TokenIntrospector(_config(**config_overrides), http), post


async def test_active_token_passes_and_posts_client_credentials():
    """The token is introspected with the client's own credentials."""
    introspector, post = _introspector({"active": True})
    await introspector.ensure_active("tok")
    post.assert_awaited_once_with(
        "http://kc/realms/r/protocol/openid-connect/token/introspect",
        {"token": "tok", "client_id": "api", "client_secret": "s3cret"},
    )


@pytest.mark.parametrize("body", [{"active": False}, {}, {"active": "true"}])
async def test_anything_but_active_true_is_rejected(body):
    """Revoked, logged-out or disabled users' tokens come back inactive."""
    introspector, _ = _introspector(body)
    with pytest.raises(TokenInactiveError):
        await introspector.ensure_active("tok")


@pytest.mark.parametrize(
    "error",
    [
        aiohttp.ClientResponseError(MagicMock(), (), status=401),
        aiohttp.ClientConnectionError("refused"),
        TimeoutError(),
    ],
)
async def test_introspection_failure_fails_closed(error):
    """If Keycloak cannot answer, the request is refused, not let through."""
    introspector, _ = _introspector(error)
    with pytest.raises(IntrospectionError):
        await introspector.ensure_active("tok")


async def test_without_cache_every_request_is_introspected():
    introspector, post = _introspector({"active": True})
    await introspector.ensure_active("tok")
    await introspector.ensure_active("tok")
    assert post.await_count == 2


async def test_cache_reuses_an_active_result_until_ttl():
    introspector, post = _introspector(
        [{"active": True}, {"active": False}], introspection_cache_ttl=30
    )
    now = 1000.0
    with patch(
        "litestar_keycloak.introspection.time.monotonic", side_effect=lambda: now
    ):
        await introspector.ensure_active("tok")
        now += 29
        await introspector.ensure_active("tok")
        assert post.await_count == 1
        now += 2
        with pytest.raises(TokenInactiveError):
            await introspector.ensure_active("tok")
    assert post.await_count == 2


async def test_inactive_result_is_not_cached():
    introspector, post = _introspector(
        [{"active": False}, {"active": False}], introspection_cache_ttl=30
    )
    for _ in range(2):
        with pytest.raises(TokenInactiveError):
            await introspector.ensure_active("tok")
    assert post.await_count == 2


async def test_cache_size_is_bounded(monkeypatch):
    """Expired entries go first, then the oldest; memory stays capped."""
    monkeypatch.setattr(introspection, "MAX_CACHED_TOKENS", 3)
    introspector, post = _introspector({"active": True}, introspection_cache_ttl=30)
    now = 1000.0
    with patch(
        "litestar_keycloak.introspection.time.monotonic", side_effect=lambda: now
    ):
        await introspector.ensure_active("a")
        now += 31  # "a" expired
        for tok in ("b", "c", "d", "e"):
            await introspector.ensure_active(tok)
        assert introspector.cached_count == 3
        post.reset_mock()
        await introspector.ensure_active("e")  # newest survives
        assert post.await_count == 0
        await introspector.ensure_active("b")  # oldest was evicted
        assert post.await_count == 1
