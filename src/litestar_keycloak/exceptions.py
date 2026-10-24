"""Typed exception hierarchy and Litestar exception handlers.

Every error the plugin can raise inherits from ``KeycloakError`` so
consumers can catch broadly or narrowly.  Leaf exceptions map to specific
failure modes — missing token, expired token, insufficient roles, JWKS
fetch failure, etc.  Companion ``exception_handlers`` dict is registered
by the plugin to translate these into proper HTTP 401/403 responses.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from litestar import MediaType, Response

if TYPE_CHECKING:
    from litestar.connection import Request

logger = logging.getLogger(__name__)


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


class InvalidTokenTypeError(AuthenticationError):
    """Token payload ``typ`` is not the expected access-token type."""

    def __init__(self, expected: str, got: str) -> None:
        self.expected = expected
        self.got = got
        super().__init__(f"Expected token type {expected!r}, got {got!r}")


class TokenInactiveError(AuthenticationError):
    """Keycloak reports the token inactive (session ended, user disabled, ...)."""


class InsufficientAuthenticationError(AuthenticationError):
    """The login is too weak or too old for this route (RFC 9470 step-up).

    A 401 rather than a 403: the user can satisfy the route by signing in
    again with a stronger method, so the client is told what to obtain.
    """

    def __init__(
        self, acr_values: tuple[str, ...] = (), max_age: int | None = None
    ) -> None:
        self.acr_values = acr_values
        self.max_age = max_age
        if acr_values:
            message = "A different authentication level is required"
        else:
            message = "More recent authentication is required"
        super().__init__(message)


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


class InsufficientGroupError(AuthorizationError):
    """User does not belong to one or more required groups."""

    def __init__(self, required: frozenset[str], actual: frozenset[str]) -> None:
        self.required = required
        self.actual = actual
        missing = required - actual
        super().__init__(f"Missing groups: {', '.join(sorted(missing))}")


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
    """Communication with Keycloak failed (e.g. a JWKS fetch)."""


class JWKSFetchError(KeycloakBackendError):
    """Failed to retrieve the JSON Web Key Set from Keycloak."""


class UnknownSigningKeyError(TokenDecodeError, JWKSFetchError):
    """The token names a ``kid`` the realm's JWKS does not hold, even after a refresh.

    The caller's fault, so a 401.  It also stays a ``JWKSFetchError``, as it
    was before 0.3.5, so existing ``except`` clauses still catch it; Litestar
    resolves handlers by MRO, where the ``AuthenticationError`` side comes first.
    """


class SessionRefreshError(KeycloakBackendError):
    """Refreshing the session's tokens failed for a reason other than rejection."""


class TokenEndpointError(KeycloakBackendError):
    """Keycloak's token endpoint failed a code exchange or refresh."""


class ServiceTokenError(KeycloakBackendError):
    """Keycloak did not issue a service token (client_credentials or exchange).

    The message names only the grant and the OAuth ``error`` code, since a
    502 body reaches the caller; Keycloak's ``error_description`` is kept on
    the exception and logged.
    """

    def __init__(
        self,
        grant: str,
        *,
        status: int | None = None,
        error: str | None = None,
        error_description: str | None = None,
    ) -> None:
        self.grant = grant
        self.status = status
        self.error = error
        self.error_description = error_description
        detail = f": {error}" if error else ""
        super().__init__(f"Keycloak did not issue a {grant} token{detail}")


class IntrospectionError(KeycloakBackendError):
    """Keycloak's introspection endpoint could not be reached or refused us."""


# ---------------------------------------------------------------------------
# Litestar exception handlers
# ---------------------------------------------------------------------------


#: RFC 6750 §3 challenges.  A request without credentials gets no error code;
#: the description repeats only what the generic response body already says.
_CHALLENGE_NO_TOKEN = "Bearer"
_CHALLENGE_INVALID = 'Bearer error="invalid_token"'
_CHALLENGE_EXPIRED = 'Bearer error="invalid_token", error_description="Token expired"'
_CHALLENGE_FORBIDDEN = 'Bearer error="insufficient_scope"'


def _error_response(
    status_code: int, detail: str, challenge: str | None = None
) -> Response[dict[str, str]]:
    return Response(
        content={"error": detail},
        status_code=status_code,
        media_type=MediaType.JSON,
        headers={"WWW-Authenticate": challenge} if challenge else None,
    )


def _step_up_challenge(exc: InsufficientAuthenticationError) -> str:
    params = [
        'error="insufficient_user_authentication"',
        f'error_description="{exc}"',
    ]
    if exc.acr_values:
        params.append(f'acr_values="{" ".join(exc.acr_values)}"')
    if exc.max_age is not None:
        params.append(f'max_age="{exc.max_age}"')
    return "Bearer " + ", ".join(params)


def _log_denial(request: Request[Any, Any, Any], exc: KeycloakError) -> None:
    # A denial of an authenticated caller is a security event worth auditing.
    # Read the scope, not ``request.user``, which raises when no auth ran.
    user = request.scope.get("user")
    logger.warning(
        "Authorization denied: %s %s sub=%s: %s",
        request.method,
        request.url.path,
        getattr(user, "sub", None),
        exc,
    )


def _handle_authentication_error(
    request: Request[Any, Any, Any], exc: AuthenticationError
) -> Response[dict[str, str]]:
    # The body stays generic so an unauthenticated caller does not learn the
    # expected issuer, accepted audiences or library error text; the detail
    # goes to the log instead.
    if isinstance(exc, MissingTokenError):
        return _error_response(401, str(exc), _CHALLENGE_NO_TOKEN)
    if isinstance(exc, InsufficientAuthenticationError):
        _log_denial(request, exc)
        return _error_response(401, str(exc), _step_up_challenge(exc))
    logger.info("Authentication failed: %s: %s", type(exc).__name__, exc)
    if isinstance(exc, TokenExpiredError):
        return _error_response(401, "Token expired", _CHALLENGE_EXPIRED)
    return _error_response(401, "Invalid token", _CHALLENGE_INVALID)


def _handle_authorization_error(
    request: Request[Any, Any, Any], exc: AuthorizationError
) -> Response[dict[str, str]]:
    _log_denial(request, exc)
    return _error_response(403, str(exc), _CHALLENGE_FORBIDDEN)


def _handle_backend_error(
    request: Request[Any, Any, Any], exc: KeycloakBackendError
) -> Response[dict[str, str]]:
    # The detail names Keycloak's internal URL and the network error; the
    # caller, often unauthenticated, gets neither.
    logger.warning(
        "Keycloak request failed: %s %s: %s: %s",
        request.method,
        request.url.path,
        type(exc).__name__,
        exc,
    )
    return _error_response(502, "Keycloak request failed")


exception_handlers = {
    AuthenticationError: _handle_authentication_error,
    AuthorizationError: _handle_authorization_error,
    KeycloakBackendError: _handle_backend_error,
}
"""Mapping registered by ``KeycloakPlugin.on_app_init`` to convert plugin
exceptions into appropriate HTTP error responses."""
