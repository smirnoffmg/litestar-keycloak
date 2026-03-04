"""Unit tests for dependency providers (current_user, token_payload, raw_token)."""

from unittest.mock import MagicMock

import pytest

from litestar_keycloak.dependencies import (
    RAW_TOKEN_STATE_KEY,
    TOKEN_STATE_KEY,
    build_dependencies,
)
from litestar_keycloak.models import KeycloakUser, TokenPayload


def _mock_request(
    *,
    user: KeycloakUser | None = None,
    token_payload: TokenPayload | None = None,
    raw_token: str = "",
):
    """Build a minimal request-like object with user and state."""
    request = MagicMock()
    request.user = user
    request.state = {}
    if token_payload is not None:
        request.state[TOKEN_STATE_KEY] = token_payload
    if raw_token:
        request.state[RAW_TOKEN_STATE_KEY] = raw_token
    return request


@pytest.fixture
def sample_user():
    """KeycloakUser for provider tests."""
    return KeycloakUser(
        sub="user-123",
        preferred_username="jdoe",
        realm_roles=frozenset({"user"}),
    )


@pytest.fixture
def sample_payload():
    """TokenPayload for provider tests."""
    return TokenPayload(
        sub="user-123",
        iss="https://kc/realms/r",
        aud="my-client",
        exp=999,
        iat=0,
    )


async def test_provide_current_user_returns_connection_user(sample_user):
    """_provide_current_user returns request.user (KeycloakUser)."""
    from litestar_keycloak.dependencies import _provide_current_user

    request = _mock_request(user=sample_user)
    result = await _provide_current_user(request)
    assert result is sample_user
    assert result.sub == "user-123"


async def test_provide_token_payload_returns_state_value(sample_payload):
    """_provide_token_payload returns request.state[TOKEN_STATE_KEY] (TokenPayload)."""
    from litestar_keycloak.dependencies import _provide_token_payload

    request = _mock_request(token_payload=sample_payload)
    result = await _provide_token_payload(request)
    assert result is sample_payload
    assert result.sub == "user-123"


async def test_provide_raw_token_returns_state_value():
    """_provide_raw_token returns request.state[RAW_TOKEN_STATE_KEY]."""
    from litestar_keycloak.dependencies import _provide_raw_token

    raw = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIn0.sig"
    request = _mock_request(raw_token=raw)
    result = await _provide_raw_token(request)
    assert result == raw


def test_build_dependencies_returns_expected_keys():
    """build_dependencies returns dict with current_user, token_payload, raw_token."""
    deps = build_dependencies()
    assert "current_user" in deps
    assert "token_payload" in deps
    assert "raw_token" in deps
    assert len(deps) == 3
