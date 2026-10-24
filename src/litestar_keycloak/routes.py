"""Optional OIDC route handlers for login, callback, logout, and refresh.

Mounted only when ``KeycloakConfig.include_routes`` is ``True``.  Implements
the Authorization Code flow: ``/auth/login`` redirects to Keycloak's
authorize endpoint, ``/auth/callback`` exchanges the code for tokens,
``/auth/logout`` terminates the Keycloak session, and ``/auth/refresh``
performs a token refresh grant.  All routes are grouped under a configurable
path prefix (default ``/auth``).

The handlers behave according to ``KeycloakConfig.callback_response_mode``: in
``"json"`` mode (default) the callback returns the token endpoint response as
JSON for a SPA/BFF; in ``"redirect"`` mode it stores the tokens in the
server-side session and redirects into the app.  OAuth ``state`` (CSRF) is kept
in a short-lived HttpOnly cookie, so no session middleware is required for the
``"json"`` flow.
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
import urllib.parse
from typing import TYPE_CHECKING, Any

from litestar import Controller, Response, get, post
from litestar.datastructures import Cookie
from litestar.exceptions import NotAuthorizedException
from litestar.response import Redirect

from litestar_keycloak.auth import SESSION_ACCESS_TOKEN_KEY, SESSION_REFRESH_TOKEN_KEY

if TYPE_CHECKING:
    from litestar.connection import Request

    from litestar_keycloak.config import KeycloakConfig
    from litestar_keycloak.http_client import KeycloakHttpClient
    from litestar_keycloak.token import TokenVerifier

#: Name of the short-lived HttpOnly cookie holding the OAuth ``state`` value.
STATE_COOKIE_NAME = "kc_oauth_state"

#: Short-lived HttpOnly cookies for the PKCE verifier and the OIDC nonce.
#: Separate from the state cookie so a login begun before ``use_pkce`` or
#: ``validate_id_token`` was switched on still completes.
PKCE_COOKIE_NAME = "kc_oauth_pkce"
NONCE_COOKIE_NAME = "kc_oauth_nonce"

#: RFC 6749 §4.1.2.1 limits ``error`` to printable ASCII; echo only a safe
#: subset, since the value arrives in the attacker-controllable query string.
_ERROR_CODE_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")

#: Lifetime (seconds) of the OAuth ``state`` cookie — long enough to complete
#: the round trip to Keycloak, short enough to bound replay.
_STATE_COOKIE_MAX_AGE = 300


def build_auth_controller(
    config: KeycloakConfig, http: KeycloakHttpClient, verifier: TokenVerifier
) -> type[Controller]:
    """Factory that returns a Litestar ``Controller`` wired to *config*.

    The controller is dynamically created so it captures the immutable
    config and the shared HTTP client in a closure — no global state, no
    service locator.
    """

    redirect_mode = config.callback_response_mode == "redirect"

    class AuthController(Controller):
        path = config.auth_prefix
        tags = ["auth"]

        @get("/login")
        async def login(self, request: Request[Any, Any, Any]) -> Redirect:
            """Redirect the user to Keycloak's authorization endpoint."""
            state = secrets.token_urlsafe(32)
            params = {
                "response_type": "code",
                "client_id": config.client_id,
                "redirect_uri": config.redirect_uri,
                "scope": " ".join(config.scopes),
                "state": state,
            }
            cookies = [_flow_cookie(config, STATE_COOKIE_NAME, state)]
            if config.use_pkce:
                verifier_value = secrets.token_urlsafe(64)
                params["code_challenge"] = _s256(verifier_value)
                params["code_challenge_method"] = "S256"
                cookies.append(_flow_cookie(config, PKCE_COOKIE_NAME, verifier_value))
            if config.validate_id_token:
                nonce = secrets.token_urlsafe(32)
                params["nonce"] = nonce
                cookies.append(_flow_cookie(config, NONCE_COOKIE_NAME, nonce))

            query = urllib.parse.urlencode(params)
            response = Redirect(f"{config.authorization_url}?{query}")
            for cookie in cookies:
                response.set_cookie(cookie)
            return response

        @get("/callback")
        async def callback(
            self, request: Request[Any, Any, Any]
        ) -> Response[dict[str, Any]] | Redirect:
            """Exchange the authorization code for tokens.

            In ``"redirect"`` mode the tokens are stored in the server-side
            session and the user is redirected to ``post_login_redirect_uri``; in
            ``"json"`` mode the raw token response is returned as JSON.
            """
            code = request.query_params.get("code")
            state = request.query_params.get("state")
            error = request.query_params.get("error")

            if error:
                code_name = error if _ERROR_CODE_RE.fullmatch(error) else "invalid"
                raise NotAuthorizedException(
                    detail=f"Authorization failed: {code_name}"
                )
            if not code:
                raise NotAuthorizedException(detail="Missing authorization code")

            saved_state = request.cookies.get(STATE_COOKIE_NAME)
            # Bytes, not str: compare_digest raises on non-ASCII str input.
            if not state or not secrets.compare_digest(
                state.encode(), (saved_state or "").encode()
            ):
                raise NotAuthorizedException(detail="Invalid OAuth state")

            token_data = await _exchange_code(
                config,
                code,
                http=http,
                code_verifier=request.cookies.get(PKCE_COOKIE_NAME),
            )
            if config.validate_id_token:
                id_token = token_data.get("id_token")
                if not id_token:
                    raise NotAuthorizedException(detail="Missing ID token")
                await verifier.verify_id_token(
                    id_token, nonce=request.cookies.get(NONCE_COOKIE_NAME, "")
                )

            response: Response[dict[str, Any]] | Redirect
            if redirect_mode:
                _store_session_tokens(request, token_data)
                response = Redirect(config.post_login_redirect_uri)
            else:
                response = Response(content=token_data)

            for name in (STATE_COOKIE_NAME, PKCE_COOKIE_NAME, NONCE_COOKIE_NAME):
                response.delete_cookie(name, path=config.auth_prefix)
            return response

        @post("/logout")
        async def logout(
            self, request: Request[Any, Any, Any]
        ) -> Response[dict[str, str]] | Redirect:
            """End the Keycloak session.

            In ``"redirect"`` mode the refresh token is read from the session and
            the session tokens are cleared; in ``"json"`` mode it comes from the
            request body.
            """
            if redirect_mode:
                refresh_token = _session(request).get(SESSION_REFRESH_TOKEN_KEY, "")
            else:
                refresh_token = (await request.json()).get("refresh_token", "")

            if refresh_token:
                await _keycloak_logout(config, refresh_token, http=http)

            response: Response[dict[str, str]] | Redirect
            if redirect_mode:
                _clear_session_tokens(request)
                if config.post_logout_redirect_uri is not None:
                    response = Redirect(config.post_logout_redirect_uri)
                else:
                    response = Response(content={"status": "logged_out"})
            else:
                response = Response(content={"status": "logged_out"})
            return response

        @post("/refresh")
        async def refresh(
            self, request: Request[Any, Any, Any]
        ) -> Response[dict[str, Any]]:
            """Use a refresh token to obtain new access/refresh tokens.

            In ``"redirect"`` mode the refresh token is read from — and the
            rotated tokens are written back to — the session; in ``"json"`` mode
            the refresh token comes from the request body and new tokens are
            returned as JSON.
            """
            if redirect_mode:
                refresh_token = _session(request).get(SESSION_REFRESH_TOKEN_KEY, "")
            else:
                refresh_token = (await request.json()).get("refresh_token", "")

            if not refresh_token:
                raise NotAuthorizedException(detail="Missing refresh_token")

            token_data = await _refresh_token(config, refresh_token, http=http)

            if redirect_mode:
                _store_session_tokens(request, token_data)
                return Response(content={"status": "refreshed"})
            return Response(content=token_data)

    return AuthController


# ---------------------------------------------------------------------------
# State cookie + server-side session token storage
# ---------------------------------------------------------------------------


def _flow_cookie(config: KeycloakConfig, name: str, value: str) -> Cookie:
    """Build a short-lived HttpOnly cookie for one login transaction value."""
    return Cookie(
        key=name,
        value=value,
        httponly=True,
        secure=config.cookie_secure,
        samesite=config.cookie_samesite,
        max_age=_STATE_COOKIE_MAX_AGE,
        path=config.auth_prefix,
    )


def _s256(verifier: str) -> str:
    """PKCE ``S256`` challenge: unpadded base64url of the verifier's SHA-256."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _client_auth(config: KeycloakConfig) -> dict[str, str]:
    """``client_id`` plus ``client_secret`` — the latter only for confidential
    clients, since a public client sending an empty secret is malformed."""
    if config.client_secret is None:
        return {"client_id": config.client_id}
    return {"client_id": config.client_id, "client_secret": config.client_secret}


def _session(request: Request[Any, Any, Any]) -> dict[str, Any]:
    """Return the request session (raises if no session middleware is installed)."""
    return request.session


def _store_session_tokens(
    request: Request[Any, Any, Any], token_data: dict[str, Any]
) -> None:
    """Persist the access and refresh tokens in the server-side session."""
    session = _session(request)
    session[SESSION_ACCESS_TOKEN_KEY] = token_data.get("access_token", "")
    session[SESSION_REFRESH_TOKEN_KEY] = token_data.get("refresh_token", "")


def _clear_session_tokens(request: Request[Any, Any, Any]) -> None:
    """Remove the Keycloak tokens from the session, leaving other data intact."""
    session = _session(request)
    session.pop(SESSION_ACCESS_TOKEN_KEY, None)
    session.pop(SESSION_REFRESH_TOKEN_KEY, None)


# ---------------------------------------------------------------------------
# Keycloak HTTP helpers (delegate to the shared, pooled client)
# ---------------------------------------------------------------------------


async def _token_request(
    config: KeycloakConfig, form_data: dict[str, str], *, http: KeycloakHttpClient
) -> dict[str, Any]:
    """POST to Keycloak's token endpoint and return the JSON response."""
    return await http.post_form(config.token_url, form_data)


async def _exchange_code(
    config: KeycloakConfig,
    code: str,
    *,
    http: KeycloakHttpClient,
    code_verifier: str | None = None,
) -> dict[str, Any]:
    """Exchange an authorization code for tokens."""
    form = {
        "grant_type": "authorization_code",
        **_client_auth(config),
        "redirect_uri": config.redirect_uri or "",
        "code": code,
    }
    if code_verifier:
        form["code_verifier"] = code_verifier
    return await _token_request(config, form, http=http)


async def _refresh_token(
    config: KeycloakConfig, refresh_token: str, *, http: KeycloakHttpClient
) -> dict[str, Any]:
    """Perform a refresh token grant."""
    return await _token_request(
        config,
        {
            "grant_type": "refresh_token",
            **_client_auth(config),
            "refresh_token": refresh_token,
        },
        http=http,
    )


async def _keycloak_logout(
    config: KeycloakConfig, refresh_token: str, *, http: KeycloakHttpClient
) -> None:
    """Notify Keycloak's end-session endpoint to invalidate tokens.

    Best-effort: a non-2xx status is ignored since the local auth cookies /
    session are cleared regardless.
    """
    await http.post_form_discard(
        config.logout_url,
        {**_client_auth(config), "refresh_token": refresh_token},
    )
