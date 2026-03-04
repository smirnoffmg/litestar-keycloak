"""Unit tests for require_roles, require_client_roles, require_scopes guards."""

from typing import Any

import pytest

from litestar_keycloak.exceptions import InsufficientRoleError, InsufficientScopeError
from litestar_keycloak.guards import (
    MatchStrategy,
    require_client_roles,
    require_roles,
    require_scopes,
)
from litestar_keycloak.models import KeycloakUser


def _connection(user: Any) -> Any:
    """Minimal connection double with .user for guards."""
    return type("Connection", (), {"user": user})()


def _handler() -> Any:
    """Dummy route handler (guards don't use it)."""
    return None


# --- require_roles ---


def test_require_roles_single_role_satisfied():
    """User with required realm role passes."""
    user = KeycloakUser(sub="u1", realm_roles=frozenset({"admin"}))
    guard = require_roles("admin")
    guard(_connection(user), _handler())  # no raise


def test_require_roles_single_role_missing_raises():
    """User without required realm role raises InsufficientRoleError."""
    user = KeycloakUser(sub="u1", realm_roles=frozenset())
    guard = require_roles("admin")
    with pytest.raises(InsufficientRoleError) as exc_info:
        guard(_connection(user), _handler())
    assert exc_info.value.required == frozenset({"admin"})
    assert exc_info.value.actual == frozenset()


def test_require_roles_all_strategy_both_required():
    """MatchStrategy.ALL: user must have every role."""
    user = KeycloakUser(sub="u1", realm_roles=frozenset({"admin", "user"}))
    guard = require_roles("admin", "user", strategy=MatchStrategy.ALL)
    guard(_connection(user), _handler())  # no raise


def test_require_roles_all_strategy_missing_one_raises():
    """MatchStrategy.ALL: missing one role raises."""
    user = KeycloakUser(sub="u1", realm_roles=frozenset({"admin"}))
    guard = require_roles("admin", "user", strategy=MatchStrategy.ALL)
    with pytest.raises(InsufficientRoleError):
        guard(_connection(user), _handler())


def test_require_roles_any_strategy_one_sufficient():
    """MatchStrategy.ANY: one of the roles is enough."""
    user = KeycloakUser(sub="u1", realm_roles=frozenset({"user"}))
    guard = require_roles("admin", "user", strategy=MatchStrategy.ANY)
    guard(_connection(user), _handler())  # no raise


def test_require_roles_any_strategy_none_raises():
    """MatchStrategy.ANY: no required role raises."""
    user = KeycloakUser(sub="u1", realm_roles=frozenset())
    guard = require_roles("admin", "manager", strategy=MatchStrategy.ANY)
    with pytest.raises(InsufficientRoleError):
        guard(_connection(user), _handler())


def test_require_roles_user_not_keycloak_user_raises():
    """connection.user not KeycloakUser raises InsufficientRoleError."""
    guard = require_roles("admin")
    with pytest.raises(InsufficientRoleError):
        guard(_connection(None), _handler())
    with pytest.raises(InsufficientRoleError):
        guard(_connection("not-a-user"), _handler())


def test_require_roles_with_superset_of_roles_passes():
    """User with superset of required roles passes (e.g. admin+user, require admin)."""
    user = KeycloakUser(sub="u1", realm_roles=frozenset({"admin", "user"}))
    guard = require_roles("admin")
    guard(_connection(user), _handler())  # no raise


def test_empty_roles_argument_passes_any_user():
    """require_roles() with no arguments passes for any user (required is empty)."""
    user = KeycloakUser(sub="u1", realm_roles=frozenset())
    guard = require_roles()
    guard(_connection(user), _handler())  # no raise
    user_with_roles = KeycloakUser(sub="u2", realm_roles=frozenset({"admin"}))
    guard(_connection(user_with_roles), _handler())  # no raise


# --- require_client_roles ---


def test_require_client_roles_satisfied():
    """User with required client role passes."""
    user = KeycloakUser(
        sub="u1",
        client_roles={"my-client": frozenset({"read"})},
    )
    guard = require_client_roles("my-client", "read")
    guard(_connection(user), _handler())  # no raise


def test_require_client_roles_wrong_client_raises():
    """User has role for other client only raises."""
    user = KeycloakUser(
        sub="u1",
        client_roles={"other-client": frozenset({"read"})},
    )
    guard = require_client_roles("my-client", "read")
    with pytest.raises(InsufficientRoleError) as exc_info:
        guard(_connection(user), _handler())
    assert exc_info.value.required == frozenset({"read"})
    assert exc_info.value.actual == frozenset()


def test_require_client_roles_any_strategy():
    """MatchStrategy.ANY with client roles."""
    user = KeycloakUser(
        sub="u1",
        client_roles={"svc": frozenset({"read"})},
    )
    guard = require_client_roles("svc", "read", "write", strategy=MatchStrategy.ANY)
    guard(_connection(user), _handler())  # no raise


def test_require_client_roles_all_strategy_missing_one_raises():
    """require_client_roles with ALL strategy: user missing one of two roles raises."""
    user = KeycloakUser(
        sub="u1",
        client_roles={"my-client": frozenset({"read"})},
    )
    guard = require_client_roles(
        "my-client", "read", "write", strategy=MatchStrategy.ALL
    )
    with pytest.raises(InsufficientRoleError) as exc_info:
        guard(_connection(user), _handler())
    assert exc_info.value.required == frozenset({"read", "write"})
    assert exc_info.value.actual == frozenset({"read"})


# --- require_scopes ---


def test_require_scopes_satisfied():
    """User with required scope passes."""
    user = KeycloakUser(sub="u1", scopes=frozenset({"openid", "profile"}))
    guard = require_scopes("openid")
    guard(_connection(user), _handler())  # no raise


def test_require_scopes_missing_raises():
    """Missing scope raises InsufficientScopeError."""
    user = KeycloakUser(sub="u1", scopes=frozenset({"openid"}))
    guard = require_scopes("reports:read")
    with pytest.raises(InsufficientScopeError) as exc_info:
        guard(_connection(user), _handler())
    assert exc_info.value.required == frozenset({"reports:read"})
    assert "reports:read" in str(exc_info.value)


def test_require_scopes_all_strategy():
    """MatchStrategy.ALL: every scope required."""
    user = KeycloakUser(sub="u1", scopes=frozenset({"openid", "profile", "email"}))
    guard = require_scopes("openid", "profile", strategy=MatchStrategy.ALL)
    guard(_connection(user), _handler())  # no raise


def test_require_scopes_any_strategy():
    """MatchStrategy.ANY: one scope is enough."""
    user = KeycloakUser(sub="u1", scopes=frozenset({"profile"}))
    guard = require_scopes("openid", "profile", strategy=MatchStrategy.ANY)
    guard(_connection(user), _handler())  # no raise
