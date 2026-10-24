"""Unit tests for ServiceTokenClient (client_credentials cache, token exchange)."""

import asyncio
from unittest.mock import AsyncMock, patch

import aiohttp
import pytest

from litestar_keycloak.config import KeycloakConfig
from litestar_keycloak.exceptions import ServiceTokenError
from litestar_keycloak.http_client import KeycloakHttpClient
from litestar_keycloak.service_tokens import ServiceTokenClient

TOKEN_URL = "http://kc/realms/r/protocol/openid-connect/token"
CREDENTIALS = {"client_id": "svc", "client_secret": "s3cret"}


def _client(*responses, client_secret: str | None = "s3cret"):
    http = KeycloakHttpClient(10)
    post = AsyncMock(side_effect=list(responses))
    http.post_form_status = post  # type: ignore[method-assign]
    config = KeycloakConfig(
        server_url="http://kc", realm="r", client_id="svc", client_secret=client_secret
    )
    return ServiceTokenClient(config, http), post


def _granted(token: str, expires_in: int = 300):
    return (200, {"access_token": token, "expires_in": expires_in})


# -- client_credentials -----------------------------------------------------------


async def test_client_token_runs_client_credentials_grant():
    tokens, post = _client(_granted("t1"))
    assert await tokens.client_token() == "t1"
    post.assert_awaited_once_with(
        TOKEN_URL, {"grant_type": "client_credentials", **CREDENTIALS}
    )


async def test_client_token_passes_scope():
    tokens, post = _client(_granted("t1"))
    await tokens.client_token(scope="reports:read")
    assert post.await_args.args[1]["scope"] == "reports:read"


async def test_client_token_is_cached_until_shortly_before_expiry():
    tokens, post = _client(_granted("t1", 300), _granted("t2", 300))
    now = 1000.0
    with patch(
        "litestar_keycloak.service_tokens.time.monotonic", side_effect=lambda: now
    ):
        assert await tokens.client_token() == "t1"
        now += 260
        assert await tokens.client_token() == "t1"
        now += 15  # within the 30 s renewal margin
        assert await tokens.client_token() == "t2"
    assert post.await_count == 2


async def test_short_lived_token_is_renewed_at_half_its_life():
    """A 20 s token cannot keep a 30 s margin; renew at half its lifetime."""
    tokens, post = _client(_granted("t1", 20), _granted("t2", 20))
    now = 1000.0
    with patch(
        "litestar_keycloak.service_tokens.time.monotonic", side_effect=lambda: now
    ):
        await tokens.client_token()
        now += 9
        assert await tokens.client_token() == "t1"
        now += 2
        assert await tokens.client_token() == "t2"


async def test_each_scope_has_its_own_cached_token():
    tokens, post = _client(_granted("a"), _granted("b"))
    assert await tokens.client_token(scope="x") == "a"
    assert await tokens.client_token(scope="y") == "b"
    assert await tokens.client_token(scope="x") == "a"
    assert post.await_count == 2


async def test_concurrent_callers_share_one_grant():
    tokens, post = _client()

    async def slow_grant(*_args):
        await asyncio.sleep(0)  # let the other callers reach the lock
        return _granted("t1")

    post.side_effect = slow_grant
    results = await asyncio.gather(*(tokens.client_token() for _ in range(5)))
    assert results == ["t1"] * 5
    assert post.await_count == 1


# -- token exchange (RFC 8693) ------------------------------------------------------


async def test_exchange_posts_rfc8693_request():
    tokens, post = _client(_granted("exchanged"))
    assert await tokens.exchange("user-token", audience="billing") == "exchanged"
    post.assert_awaited_once_with(
        TOKEN_URL,
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            **CREDENTIALS,
            "subject_token": "user-token",
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": "billing",
        },
    )


async def test_exchange_passes_scope():
    tokens, post = _client(_granted("x"))
    await tokens.exchange("u", audience="billing", scope="invoices:read")
    assert post.await_args.args[1]["scope"] == "invoices:read"


async def test_exchange_is_not_cached():
    """Each exchange is for a particular caller's token; nothing is reused."""
    tokens, post = _client(_granted("a"), _granted("b"))
    await tokens.exchange("u", audience="billing")
    await tokens.exchange("u", audience="billing")
    assert post.await_count == 2


# -- failures -----------------------------------------------------------------------


async def test_refusal_carries_keycloak_error_but_not_in_message():
    """The description goes to attributes and logs, not the 502 body."""
    refusal = (
        400,
        {
            "error": "invalid_request",
            "error_description": "Requested audience not available: x",
        },
    )
    tokens, _ = _client(refusal)
    with pytest.raises(ServiceTokenError) as exc_info:
        await tokens.exchange("u", audience="x")
    err = exc_info.value
    assert (err.status, err.error) == (400, "invalid_request")
    assert err.error_description == "Requested audience not available: x"
    assert "audience not available" not in str(err)


@pytest.mark.parametrize(
    "error", [aiohttp.ClientConnectionError("refused"), TimeoutError()]
)
async def test_network_failure_is_a_service_token_error(error):
    tokens, _ = _client(error)
    with pytest.raises(ServiceTokenError):
        await tokens.client_token()


async def test_success_without_access_token_is_an_error():
    tokens, _ = _client((200, {"error": "weird"}))
    with pytest.raises(ServiceTokenError):
        await tokens.client_token()


async def test_public_client_cannot_get_service_tokens():
    tokens, post = _client(client_secret=None)
    with pytest.raises(ValueError, match="client_secret"):
        await tokens.client_token()
    with pytest.raises(ValueError, match="client_secret"):
        await tokens.exchange("u", audience="x")
    post.assert_not_awaited()
