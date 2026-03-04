"""Optional OIDC route handlers for login, callback, logout, and refresh.

Mounted only when ``KeycloakConfig.include_routes`` is ``True``.  Implements
the Authorization Code flow: ``/auth/login`` redirects to Keycloak's
authorize endpoint, ``/auth/callback`` exchanges the code for tokens,
``/auth/logout`` terminates both the local and Keycloak sessions, and
``/auth/refresh`` performs a token refresh grant.  All routes are grouped
under a configurable path prefix (default ``/auth``).
"""

from __future__ import annotations

import secrets
import urllib.parse
from typing import TYPE_CHECKING, Any, cast

import aiohttp
from litestar import Controller, Response, get, post
from litestar.exceptions import NotAuthorizedException
from litestar.response import Redirect

if TYPE_CHECKING:
    from litestar.connection import Request

    from litestar_keycloak.config import KeycloakConfig


def build_auth_controller(config: KeycloakConfig) -> type[Controller]:
    """Factory that returns a Litestar ``Controller`` wired to *config*.

    The controller is dynamically created so it captures the immutable
    config in a closure — no global state, no service locator.
    """

    class AuthController(Controller):
        path = config.auth_prefix
        tags = ["auth"]

        @get("/login")
        async def login(self, request: Request[Any, Any, Any]) -> Redirect:
            """Redirect the user to Keycloak's authorization endpoint."""
            state = secrets.token_urlsafe(32)
            request.set_session({"oauth_state": state})

            params = urllib.parse.urlencode(
                {
                    "response_type": "code",
                    "client_id": config.client_id,
                    "redirect_uri": config.redirect_uri,
                    "scope": " ".join(config.scopes),
                    "state": state,
                }
            )
            return Redirect(f"{config.authorization_url}?{params}")

        @get("/callback")
        async def callback(
            self, request: Request[Any, Any, Any]
        ) -> Response[dict[str, Any]]:
            """Exchange the authorization code for tokens."""
            code = request.query_params.get("code")
            state = request.query_params.get("state")

            if not code:
                raise NotAuthorizedException(detail="Missing authorization code")

            saved_state = (request.session or {}).get("oauth_state")
            if not state or state != saved_state:
                raise NotAuthorizedException(detail="Invalid OAuth state")

            token_data = await _exchange_code(config, code)
            return Response(content=token_data)

        @post("/logout")
        async def logout(
            self, request: Request[Any, Any, Any]
        ) -> Response[dict[str, str]]:
            """End both the Keycloak and local sessions."""
            refresh_token = (await request.json()).get("refresh_token", "")

            if refresh_token:
                await _keycloak_logout(config, refresh_token)

            request.clear_session()
            return Response(content={"status": "logged_out"})

        @post("/refresh")
        async def refresh(
            self, request: Request[Any, Any, Any]
        ) -> Response[dict[str, Any]]:
            """Use a refresh token to obtain new access/refresh tokens."""
            body = await request.json()
            refresh_token = body.get("refresh_token", "")

            if not refresh_token:
                raise NotAuthorizedException(detail="Missing refresh_token")

            token_data = await _refresh_token(config, refresh_token)
            return Response(content=token_data)

    return AuthController


# ---------------------------------------------------------------------------
# Keycloak HTTP helpers (async, aiohttp)
# ---------------------------------------------------------------------------


async def _token_request(
    config: KeycloakConfig, form_data: dict[str, str]
) -> dict[str, Any]:
    """POST to Keycloak's token endpoint and return the JSON response."""
    timeout = aiohttp.ClientTimeout(total=config.http_timeout)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(
            config.token_url,
            data=form_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        ) as resp:
            resp.raise_for_status()
            return cast(dict[str, Any], await resp.json(content_type=None))


async def _exchange_code(config: KeycloakConfig, code: str) -> dict[str, Any]:
    """Exchange an authorization code for tokens."""
    return await _token_request(
        config,
        {
            "grant_type": "authorization_code",
            "client_id": config.client_id,
            "client_secret": config.client_secret or "",
            "redirect_uri": config.redirect_uri or "",
            "code": code,
        },
    )


async def _refresh_token(config: KeycloakConfig, refresh_token: str) -> dict[str, Any]:
    """Perform a refresh token grant."""
    return await _token_request(
        config,
        {
            "grant_type": "refresh_token",
            "client_id": config.client_id,
            "client_secret": config.client_secret or "",
            "refresh_token": refresh_token,
        },
    )


async def _keycloak_logout(config: KeycloakConfig, refresh_token: str) -> None:
    """Notify Keycloak's end-session endpoint to invalidate tokens."""
    timeout = aiohttp.ClientTimeout(total=config.http_timeout)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(
            config.logout_url,
            data={
                "client_id": config.client_id,
                "client_secret": config.client_secret or "",
                "refresh_token": refresh_token,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        ) as _:
            # Keycloak returns 204 on success; ignore errors on logout
            # since we clear the local session regardless.
            pass
