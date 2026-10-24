"""Authentication backend that extracts and validates bearer tokens.

Reads the access token from the configured location (``Authorization``
header or cookie), delegates validation to the ``token`` module, and
stores the resulting ``KeycloakUser`` in the connection state so that
downstream dependencies and guards can access it without re-parsing.
Unauthenticated requests are rejected before they reach any route handler.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from typing import TYPE_CHECKING, Any

from litestar.middleware import AbstractAuthenticationMiddleware, AuthenticationResult

from litestar_keycloak.config import TokenLocation
from litestar_keycloak.exceptions import (
    MissingTokenError,
    SessionRefreshError,
    TokenEndpointError,
    TokenExpiredError,
    TokenGrantRejectedError,
    TokenInactiveError,
)
from litestar_keycloak.logout import is_logged_out
from litestar_keycloak.models import KeycloakUser

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from litestar.connection import ASGIConnection

    from litestar_keycloak.config import KeycloakConfig
    from litestar_keycloak.token import TokenVerifier

#: Key used to stash the ``TokenPayload`` on ``connection.state``.
TOKEN_STATE_KEY = "keycloak_token"

#: Key used to stash the raw token string on ``connection.state``.
RAW_TOKEN_STATE_KEY = "keycloak_raw_token"

#: Session keys used by ``callback_response_mode="redirect"`` to persist tokens
#: server-side.  The middleware reads the access token from here when it is not
#: present in the header/cookie.
SESSION_ACCESS_TOKEN_KEY = "keycloak_access_token"
SESSION_REFRESH_TOKEN_KEY = "keycloak_refresh_token"

#: ``session_binding``: the HttpOnly cookie set at login, and the session key
#: holding its SHA-256, without which the session's tokens are not accepted.
BINDING_COOKIE_NAME = "kc_session_binding"
SESSION_BINDING_KEY = "keycloak_session_binding"

logger = logging.getLogger(__name__)


def binding_digest(value: str) -> str:
    """The SHA-256 of a binding cookie value, as kept in the session."""
    return hashlib.sha256(value.encode()).hexdigest()


def session_is_bound(
    connection: ASGIConnection[Any, Any, Any, Any], session: dict[str, Any]
) -> bool:
    """Whether the request carries the binding cookie this session was issued."""
    expected = session.get(SESSION_BINDING_KEY)
    cookie = connection.cookies.get(BINDING_COOKIE_NAME)
    if not isinstance(expected, str) or not cookie:
        return False
    return hmac.compare_digest(binding_digest(cookie).encode(), expected.encode())


def create_auth_middleware(
    config: KeycloakConfig,
    verifier: TokenVerifier,
    refresh: Callable[[str], Awaitable[dict[str, Any]]] | None = None,
) -> type[AbstractAuthenticationMiddleware]:
    """Factory that returns a configured authentication middleware class.

    Using a factory rather than a standalone class avoids the need for
    module-level mutable state — ``config``, ``verifier`` and the optional
    *refresh* grant (for ``session_auto_refresh``) are captured in the closure
    and available to every middleware instance.
    """

    class KeycloakAuthMiddleware(AbstractAuthenticationMiddleware):
        """Litestar authentication middleware for Keycloak bearer tokens."""

        async def authenticate_request(
            self,
            connection: ASGIConnection[Any, Any, Any, Any],
        ) -> AuthenticationResult:
            """Extract, validate, and convert the bearer token.

            Returns an ``AuthenticationResult`` with:
            - ``user``: ``KeycloakUser`` instance
            - ``auth``: ``TokenPayload`` for downstream access

            The raw token string and parsed payload are also placed on
            ``connection.state`` for the DI providers.

            Excluded paths (``exclude_auth_patterns``) and per-handler opt-outs
            are handled by the framework before this method is reached, so any
            request that gets here is expected to carry a token — unless its
            handler opts into optional auth, which yields ``user=None``.
            """
            try:
                raw_token = _extract_token(connection, config)
            except MissingTokenError:
                if _allows_anonymous(connection, config):
                    return AuthenticationResult(user=None, auth=None)
                raise
            try:
                payload = await verifier.verify(raw_token)
            except TokenExpiredError:
                session = _session_dict(connection)
                if (
                    refresh is None
                    or session is None
                    or (raw_token != session.get(SESSION_ACCESS_TOKEN_KEY))
                ):
                    raise
                raw_token = await _refresh_session(session, refresh)
                payload = await verifier.verify(raw_token)

            if config.backchannel_logout and await is_logged_out(
                connection.app.stores.get(config.logout_store), payload
            ):
                raise TokenInactiveError("Session was logged out by Keycloak")

            user = KeycloakUser.from_token(payload, groups_claim=config.groups_claim)

            connection.state[TOKEN_STATE_KEY] = payload
            connection.state[RAW_TOKEN_STATE_KEY] = raw_token

            return AuthenticationResult(user=user, auth=payload)

    return KeycloakAuthMiddleware


async def _refresh_session(
    session: dict[str, Any],
    refresh: Callable[[str], Awaitable[dict[str, Any]]],
) -> str:
    """Renew the session's tokens; return the new access token.

    A refresh Keycloak *rejects* (400/401: session ended, refresh token
    expired or revoked) is a 401; any other failure is Keycloak's, a 502.

    The session is only written on success.  An exception raised here is
    rendered outside the session middleware, so clearing the tokens on failure
    would never be persisted; the next login overwrites them instead.
    """
    refresh_token = session.get(SESSION_REFRESH_TOKEN_KEY)
    if not refresh_token:
        raise TokenExpiredError("Session token expired and cannot be refreshed")
    try:
        token_data = await refresh(str(refresh_token))
    except TokenGrantRejectedError as exc:
        raise TokenExpiredError("Keycloak rejected the session refresh") from exc
    except TokenEndpointError as exc:
        raise SessionRefreshError(f"Session refresh failed: {exc}") from exc

    access_token = str(token_data["access_token"])
    session[SESSION_ACCESS_TOKEN_KEY] = access_token
    session[SESSION_REFRESH_TOKEN_KEY] = token_data.get("refresh_token", refresh_token)
    return access_token


def _session_dict(
    connection: ASGIConnection[Any, Any, Any, Any],
) -> dict[str, Any] | None:
    """The session dict, or ``None`` without session middleware.

    Read from ``scope`` (``connection.session`` raises when no session
    middleware is installed); the session middleware persists changes made to
    this dict when the response is sent.
    """
    session = connection.scope.get("session")
    return session if isinstance(session, dict) else None


def _allows_anonymous(
    connection: ASGIConnection[Any, Any, Any, Any],
    config: KeycloakConfig,
) -> bool:
    route_handler = connection.scope.get("route_handler")
    return bool(
        route_handler is not None
        and route_handler.opt.get(config.optional_auth_opt_key)
    )


def _extract_token(
    connection: ASGIConnection[Any, Any, Any, Any],
    config: KeycloakConfig,
) -> str:
    """Pull the raw JWT string from the request.

    Reads from the configured location (header or cookie); if absent, falls back
    to the server-side session (populated by ``callback_response_mode="redirect"``).
    Raises ``MissingTokenError`` when no token is found in any source.
    """
    try:
        if config.token_location is TokenLocation.HEADER:
            return _extract_from_header(connection)
        return _extract_from_cookie(connection, config.cookie_name)
    except MissingTokenError:
        token = _extract_from_session(connection, config)
        if token:
            return token
        raise


def _extract_from_session(
    connection: ASGIConnection[Any, Any, Any, Any],
    config: KeycloakConfig,
) -> str | None:
    """Return the access token stored in the session, or ``None``.

    Reads ``scope`` directly (rather than ``connection.session``, which raises
    when no session middleware is installed) so the fallback is a no-op for
    header/cookie-only apps.  With ``session_binding``, a token in a session
    whose binding cookie is missing or wrong is ignored.
    """
    session = _session_dict(connection)
    if session is None:
        return None
    token = session.get(SESSION_ACCESS_TOKEN_KEY)
    if not token:
        return None
    if config.session_binding and not session_is_bound(connection, session):
        logger.info("Ignoring session tokens without their binding cookie")
        return None
    return str(token)


def _extract_from_header(
    connection: ASGIConnection[Any, Any, Any, Any],
) -> str:
    auth_header = connection.headers.get("authorization", "")
    if not auth_header:
        raise MissingTokenError("header")

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise MissingTokenError("header (expected 'Bearer <token>')")

    return parts[1]


def _extract_from_cookie(
    connection: ASGIConnection[Any, Any, Any, Any],
    cookie_name: str,
) -> str:
    token = connection.cookies.get(cookie_name)
    if not token:
        raise MissingTokenError(f"cookie '{cookie_name}'")
    return token
