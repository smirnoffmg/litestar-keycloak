"""Guard factories for role-based and scope-based access control.

Provides ``require_roles`` and ``require_scopes`` — factory functions
that return Litestar guard callables.  Guards inspect the ``KeycloakUser``
already placed on the connection by the auth backend and raise
``InsufficientRoleError`` or ``InsufficientScopeError`` when the required
claims are missing.  Supports both ALL (default) and ANY match semantics.
"""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING, Any

from litestar_keycloak.exceptions import InsufficientRoleError, InsufficientScopeError
from litestar_keycloak.models import KeycloakUser

if TYPE_CHECKING:
    from collections.abc import Callable

    from litestar.connection import ASGIConnection
    from litestar.handlers import BaseRouteHandler


class MatchStrategy(enum.Enum):
    """How multiple required values are evaluated."""

    ALL = "all"
    """User must hold **every** required role/scope (default)."""

    ANY = "any"
    """User must hold **at least one** of the required roles/scopes."""


def _resolve_user(connection: ASGIConnection[Any, Any, Any, Any]) -> KeycloakUser:
    user = connection.user
    if not isinstance(user, KeycloakUser):
        raise InsufficientRoleError(
            required=frozenset(),
            actual=frozenset(),
        )
    return user


def require_roles(
    *roles: str,
    strategy: MatchStrategy = MatchStrategy.ALL,
) -> Callable[..., None]:
    """Guard factory that enforces realm-level roles.

    Args:
        *roles: One or more role names the user must hold.
        strategy: ``ALL`` (default) requires every role;
                  ``ANY`` requires at least one.

    Example::

        @get("/admin", guards=[require_roles("admin")])
        async def admin_panel() -> dict: ...

        @get("/staff", guards=[require_roles(
            "admin", "manager", strategy=MatchStrategy.ANY)])
        async def staff_area() -> dict: ...
    """
    required = frozenset(roles)

    def guard(
        connection: ASGIConnection[Any, Any, Any, Any], _: BaseRouteHandler
    ) -> None:
        user = _resolve_user(connection)
        if strategy is MatchStrategy.ALL:
            satisfied = required <= user.realm_roles
        else:
            satisfied = bool(required & user.realm_roles)

        if not satisfied:
            raise InsufficientRoleError(required=required, actual=user.realm_roles)

    return guard


def require_client_roles(
    client_id: str,
    *roles: str,
    strategy: MatchStrategy = MatchStrategy.ALL,
) -> Callable[..., None]:
    """Guard factory that enforces client-level roles.

    Args:
        client_id: The Keycloak client whose roles are checked.
        *roles: One or more role names the user must hold for *client_id*.
        strategy: ``ALL`` (default) or ``ANY``.

    Example::

        @get("/billing", guards=[require_client_roles("billing-service", "read")])
        async def billing() -> dict: ...
    """
    required = frozenset(roles)

    def guard(
        connection: ASGIConnection[Any, Any, Any, Any], _: BaseRouteHandler
    ) -> None:
        user = _resolve_user(connection)
        actual = user.client_roles.get(client_id, frozenset())

        if strategy is MatchStrategy.ALL:
            satisfied = required <= actual
        else:
            satisfied = bool(required & actual)

        if not satisfied:
            raise InsufficientRoleError(required=required, actual=actual)

    return guard


def require_scopes(
    *scopes: str,
    strategy: MatchStrategy = MatchStrategy.ALL,
) -> Callable[..., None]:
    """Guard factory that enforces token scopes.

    Args:
        *scopes: One or more scope strings the token must carry.
        strategy: ``ALL`` (default) or ``ANY``.

    Example::

        @get("/reports", guards=[require_scopes("reports:read")])
        async def reports() -> dict: ...
    """
    required = frozenset(scopes)

    def guard(
        connection: ASGIConnection[Any, Any, Any, Any], _: BaseRouteHandler
    ) -> None:
        user = _resolve_user(connection)

        if strategy is MatchStrategy.ALL:
            satisfied = required <= user.scopes
        else:
            satisfied = bool(required & user.scopes)

        if not satisfied:
            raise InsufficientScopeError(required=required, actual=user.scopes)

    return guard
