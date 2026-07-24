"""Authentication backend that extracts and validates bearer tokens.

Reads the access token from the configured location (``Authorization``
header or cookie), delegates validation to the ``token`` module, and
stores the resulting ``KeycloakUser`` in the connection state so that
downstream dependencies and guards can access it without re-parsing.
Unauthenticated requests are rejected before they reach any route handler.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from litestar.middleware import AbstractAuthenticationMiddleware, AuthenticationResult

from litestar_keycloak.config import TokenLocation
from litestar_keycloak.exceptions import MissingTokenError
from litestar_keycloak.models import KeycloakUser

if TYPE_CHECKING:
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


def create_auth_middleware(
    config: KeycloakConfig,
    verifier: TokenVerifier,
) -> type[AbstractAuthenticationMiddleware]:
    """Factory that returns a configured authentication middleware class.

    Using a factory rather than a standalone class avoids the need for
    module-level mutable state — ``config`` and ``verifier`` are captured
    in the closure and available to every middleware instance.
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
            request that gets here is expected to carry a token.
            """
            raw_token = _extract_token(connection, config)
            payload = await verifier.verify(raw_token)
            user = KeycloakUser.from_token(payload)

            connection.state[TOKEN_STATE_KEY] = payload
            connection.state[RAW_TOKEN_STATE_KEY] = raw_token

            return AuthenticationResult(user=user, auth=payload)

    return KeycloakAuthMiddleware


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
        token = _extract_from_session(connection)
        if token:
            return token
        raise


def _extract_from_session(
    connection: ASGIConnection[Any, Any, Any, Any],
) -> str | None:
    """Return the access token stored in the session, or ``None``.

    Reads ``scope`` directly (rather than ``connection.session``, which raises
    when no session middleware is installed) so the fallback is a no-op for
    header/cookie-only apps.
    """
    session = connection.scope.get("session")
    if isinstance(session, dict):
        token = session.get(SESSION_ACCESS_TOKEN_KEY)
        if token:
            return str(token)
    return None


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
