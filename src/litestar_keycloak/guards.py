"""Guard factories for role-, group-, scope- and login-based access control.

Provides ``require_roles``, ``require_client_roles``, ``require_groups`` and
``require_scopes`` (ALL or ANY match semantics), the step-up guards
``require_acr`` and ``require_recent_auth``, and ``require_user`` for an
arbitrary predicate.  Each factory returns a Litestar guard callable that
inspects the ``KeycloakUser`` already placed on the connection by the auth
backend and raises a typed error from ``exceptions`` when the check fails.
"""

from __future__ import annotations

import enum
import time
from typing import TYPE_CHECKING, Any

from litestar_keycloak.exceptions import (
    AuthorizationError,
    InsufficientAuthenticationError,
    InsufficientGroupError,
    InsufficientRoleError,
    InsufficientScopeError,
    MissingTokenError,
)
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
    if user is None:
        # An optional_auth route let an anonymous request through; signing in
        # can satisfy the guard, so this is a 401 with a Bearer challenge.
        raise MissingTokenError("header")
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


def require_groups(
    *groups: str,
    strategy: MatchStrategy = MatchStrategy.ALL,
) -> Callable[..., None]:
    """Guard factory that enforces group membership.

    Names are compared exactly as they appear in the token: with the Group
    Membership mapper's "Full group path" on, write ``"/parent/child"``.

    Example::

        @get("/ops", guards=[require_groups("ops", "sre", strategy=MatchStrategy.ANY)])
        async def ops_panel() -> dict: ...
    """
    required = frozenset(groups)

    def guard(
        connection: ASGIConnection[Any, Any, Any, Any], _: BaseRouteHandler
    ) -> None:
        user = _resolve_user(connection)
        if strategy is MatchStrategy.ALL:
            satisfied = required <= user.groups
        else:
            satisfied = bool(required & user.groups)

        if not satisfied:
            raise InsufficientGroupError(required=required, actual=user.groups)

    return guard


def require_acr(*acr_values: str) -> Callable[..., None]:
    """Guard factory that requires one of *acr_values* as the login's ``acr``.

    On failure the client gets a 401 step-up challenge (RFC 9470) naming the
    acceptable values, so it can send the user back to Keycloak with
    ``acr_values`` to authenticate more strongly.

    Example::

        @post("/payments", guards=[require_acr("2")])
        async def pay() -> dict: ...
    """
    accepted = frozenset(acr_values)

    def guard(
        connection: ASGIConnection[Any, Any, Any, Any], _: BaseRouteHandler
    ) -> None:
        user = _resolve_user(connection)
        if user.acr not in accepted:
            raise InsufficientAuthenticationError(acr_values=acr_values)

    return guard


def require_recent_auth(max_age: int) -> Callable[..., None]:
    """Guard factory that requires a login at most *max_age* seconds old.

    Judged by the ``auth_time`` claim, which Keycloak adds only through the
    ``basic`` client scope and not for every grant (e.g. not for password
    grants); a token without it is rejected, since its login age is unknown.

    Example::

        @delete("/account", guards=[require_recent_auth(300)])
        async def close_account() -> None: ...
    """
    if max_age < 0:
        raise ValueError("max_age must be non-negative")

    def guard(
        connection: ASGIConnection[Any, Any, Any, Any], _: BaseRouteHandler
    ) -> None:
        user = _resolve_user(connection)
        if user.auth_time is None or time.time() - user.auth_time > max_age:
            raise InsufficientAuthenticationError(max_age=max_age)

    return guard


def require_user(
    predicate: Callable[[KeycloakUser], bool],
    *,
    detail: str = "Access denied",
) -> Callable[..., None]:
    """Guard factory for a check the other guards cannot express.

    *predicate* receives the ``KeycloakUser`` and returns whether access is
    allowed; on ``False`` the request gets a 403 with *detail*.

    Example::

        @get("/reports", guards=[require_user(
            lambda u: u.has_role("auditor") or u.has_group("finance"))])
        async def reports() -> dict: ...
    """

    def guard(
        connection: ASGIConnection[Any, Any, Any, Any], _: BaseRouteHandler
    ) -> None:
        user = _resolve_user(connection)
        if not predicate(user):
            raise AuthorizationError(detail)

    return guard
