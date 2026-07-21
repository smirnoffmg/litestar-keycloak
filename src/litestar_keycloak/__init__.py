"""Keycloak authentication plugin for Litestar."""

from litestar_keycloak.config import KeycloakConfig, TokenLocation
from litestar_keycloak.dependencies import (
    CurrentRawToken,
    CurrentTokenPayload,
    CurrentUser,
)
from litestar_keycloak.guards import (
    MatchStrategy,
    require_client_roles,
    require_roles,
    require_scopes,
)
from litestar_keycloak.models import KeycloakUser, TokenPayload
from litestar_keycloak.plugin import KeycloakPlugin

__all__ = [
    "CurrentRawToken",
    "CurrentTokenPayload",
    "CurrentUser",
    "KeycloakConfig",
    "KeycloakPlugin",
    "KeycloakUser",
    "MatchStrategy",
    "TokenLocation",
    "TokenPayload",
    "require_client_roles",
    "require_roles",
    "require_scopes",
]
