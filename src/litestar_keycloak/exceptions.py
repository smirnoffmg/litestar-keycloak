"""Typed exception hierarchy and Litestar exception handlers.

Every error the plugin can raise inherits from ``KeycloakError`` so
consumers can catch broadly or narrowly.  Leaf exceptions map to specific
failure modes — missing token, expired token, insufficient roles, JWKS
fetch failure, etc.  Companion ``exception_handlers`` dict is registered
by the plugin to translate these into proper HTTP 401/403 responses.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from litestar import MediaType, Response

if TYPE_CHECKING:
    from litestar.connection import Request


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------


class KeycloakError(Exception):
    """Root of the litestar-keycloak exception hierarchy."""


# ---------------------------------------------------------------------------
# Authentication errors -> HTTP 401
# ---------------------------------------------------------------------------


class AuthenticationError(KeycloakError):
    """Token is missing, malformed, or cannot be validated."""


class MissingTokenError(AuthenticationError):
    """No bearer token found in the configured location."""

    def __init__(self, location: str = "header") -> None:
        self.location = location
        super().__init__(f"No token found in {location}")


class TokenDecodeError(AuthenticationError):
    """Token is not a valid JWT or cannot be decoded."""


class TokenExpiredError(AuthenticationError):
    """Token ``exp`` claim is in the past."""


class InvalidIssuerError(AuthenticationError):
    """Token ``iss`` does not match the expected Keycloak realm URL."""

    def __init__(self, expected: str, got: str) -> None:
        self.expected = expected
        self.got = got
        super().__init__(f"Expected issuer {expected!r}, got {got!r}")


class InvalidAudienceError(AuthenticationError):
    """Token ``aud`` does not contain the configured client ID."""

    def __init__(self, expected: str, got: str | list[str]) -> None:
        self.expected = expected
        self.got = got
        super().__init__(f"Expected audience {expected!r}, got {got!r}")


# ---------------------------------------------------------------------------
# Authorization errors -> HTTP 403
# ---------------------------------------------------------------------------


class AuthorizationError(KeycloakError):
    """Token is valid but lacks required permissions."""


class InsufficientRoleError(AuthorizationError):
    """User does not hold one or more required realm/client roles."""

    def __init__(self, required: frozenset[str], actual: frozenset[str]) -> None:
        self.required = required
        self.actual = actual
        missing = required - actual
        super().__init__(f"Missing roles: {', '.join(sorted(missing))}")


class InsufficientScopeError(AuthorizationError):
    """Token does not carry one or more required scopes."""

    def __init__(self, required: frozenset[str], actual: frozenset[str]) -> None:
        self.required = required
        self.actual = actual
        missing = required - actual
        super().__init__(f"Missing scopes: {', '.join(sorted(missing))}")


# ---------------------------------------------------------------------------
# Infrastructure errors -> HTTP 502
# ---------------------------------------------------------------------------


class KeycloakBackendError(KeycloakError):
    """Communication with Keycloak failed (OIDC discovery, JWKS fetch, etc.)."""


class OIDCDiscoveryError(KeycloakBackendError):
    """Failed to fetch or parse the OpenID Connect discovery document."""


class JWKSFetchError(KeycloakBackendError):
    """Failed to retrieve the JSON Web Key Set from Keycloak."""


# ---------------------------------------------------------------------------
# Litestar exception handlers
# ---------------------------------------------------------------------------


def _error_response(status_code: int, detail: str) -> Response[dict[str, str]]:
    return Response(
        content={"error": detail},
        status_code=status_code,
        media_type=MediaType.JSON,
    )


def _handle_authentication_error(
    _: Request[Any, Any, Any], exc: AuthenticationError
) -> Response[dict[str, str]]:
    return _error_response(401, str(exc))


def _handle_authorization_error(
    _: Request[Any, Any, Any], exc: AuthorizationError
) -> Response[dict[str, str]]:
    return _error_response(403, str(exc))


def _handle_backend_error(
    _: Request[Any, Any, Any], exc: KeycloakBackendError
) -> Response[dict[str, str]]:
    return _error_response(502, str(exc))


exception_handlers = {
    AuthenticationError: _handle_authentication_error,
    AuthorizationError: _handle_authorization_error,
    KeycloakBackendError: _handle_backend_error,
}
"""Mapping registered by ``KeycloakPlugin.on_app_init`` to convert plugin
exceptions into appropriate HTTP error responses."""
