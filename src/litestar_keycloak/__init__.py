"""Keycloak authentication plugin for Litestar."""

from litestar_keycloak.config import KeycloakConfig, TokenLocation
from litestar_keycloak.dependencies import (
    CurrentRawToken,
    CurrentTokenPayload,
    CurrentUser,
    OptionalCurrentUser,
    OptionalRawToken,
    OptionalTokenPayload,
    ServiceTokens,
)
from litestar_keycloak.guards import (
    MatchStrategy,
    require_acr,
    require_client_roles,
    require_groups,
    require_recent_auth,
    require_roles,
    require_scopes,
    require_user,
)
from litestar_keycloak.models import KeycloakUser, TokenPayload
from litestar_keycloak.plugin import KeycloakPlugin
from litestar_keycloak.service_tokens import ServiceTokenClient

__all__ = [
    "CurrentRawToken",
    "CurrentTokenPayload",
    "CurrentUser",
    "KeycloakConfig",
    "KeycloakPlugin",
    "KeycloakUser",
    "MatchStrategy",
    "OptionalCurrentUser",
    "OptionalRawToken",
    "OptionalTokenPayload",
    "ServiceTokenClient",
    "ServiceTokens",
    "TokenLocation",
    "TokenPayload",
    "require_acr",
    "require_client_roles",
    "require_groups",
    "require_recent_auth",
    "require_roles",
    "require_scopes",
    "require_user",
]
