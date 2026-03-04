"""Litestar dependency providers for Keycloak identity objects.

Registers injectable dependencies — ``current_user`` (``KeycloakUser``),
``token_payload`` (``TokenPayload``), and ``raw_token`` (``str``) — so
route handlers can declare them as parameters without any manual wiring.
Each provider reads from the connection state populated by the auth backend.
"""

from __future__ import annotations

from typing import Any, cast

from litestar.connection import Request
from litestar.di import Provide

from litestar_keycloak.auth import RAW_TOKEN_STATE_KEY, TOKEN_STATE_KEY
from litestar_keycloak.models import KeycloakUser, TokenPayload


async def _provide_current_user(request: Request[Any, Any, Any]) -> KeycloakUser:
    """Provide the authenticated ``KeycloakUser``.

    Reads from ``request.user`` which is set by
    ``AuthenticationResult`` in the auth middleware.
    """
    return cast(KeycloakUser, request.user)


async def _provide_token_payload(request: Request[Any, Any, Any]) -> TokenPayload:
    """Provide the decoded ``TokenPayload``.

    Reads from ``request.state`` where the auth middleware stashes
    the validated payload.
    """
    return cast(TokenPayload, request.state[TOKEN_STATE_KEY])


async def _provide_raw_token(request: Request[Any, Any, Any]) -> str:
    """Provide the raw JWT string.

    Useful for forwarding the token to downstream services.
    """
    return cast(str, request.state[RAW_TOKEN_STATE_KEY])


def build_dependencies() -> dict[str, Provide]:
    """Construct the dependency mapping registered by the plugin.

    Returns a dict ready to be merged into ``app_config.dependencies``
    during ``KeycloakPlugin.on_app_init``.
    """
    return {
        "current_user": Provide(_provide_current_user),
        "token_payload": Provide(_provide_token_payload),
        "raw_token": Provide(_provide_raw_token),
    }
