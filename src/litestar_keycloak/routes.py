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
import logging
import re
import secrets
import urllib.parse
from typing import TYPE_CHECKING, Any

import aiohttp
from litestar import Controller, Response, get, post
from litestar.datastructures import Cookie
from litestar.exceptions import NotAuthorizedException, SerializationException
from litestar.response import Redirect

from litestar_keycloak.auth import (
    BINDING_COOKIE_NAME,
    SESSION_ACCESS_TOKEN_KEY,
    SESSION_BINDING_KEY,
    SESSION_REFRESH_TOKEN_KEY,
    binding_digest,
    session_is_bound,
)
from litestar_keycloak.exceptions import AuthenticationError, TokenEndpointError
from litestar_keycloak.logout import record_logout

if TYPE_CHECKING:
    from litestar.connection import Request

    from litestar_keycloak.config import KeycloakConfig
    from litestar_keycloak.http_client import KeycloakHttpClient
    from litestar_keycloak.token import TokenVerifier

logger = logging.getLogger(__name__)

#: RFC 6749 §5.1 for responses carrying tokens; OIDC Back-Channel Logout 1.0
#: §2.8 for the logout endpoint.
_NO_STORE = {"Cache-Control": "no-store"}

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

#: Authorization request parameters a client may pass through ``/auth/login``
#: to answer a step-up challenge (RFC 9470 §4) or force re-authentication,
#: each with the values it may take.  The browser could add them to the
#: authorize URL itself; checking them keeps markup out of the redirect.
_FORWARDED_LOGIN_PARAMS = {
    "acr_values": re.compile(r"[A-Za-z0-9_.:-]{1,64}( [A-Za-z0-9_.:-]{1,64}){0,9}"),
    "max_age": re.compile(r"[0-9]{1,9}"),
    "prompt": re.compile(r"login|consent|select_account"),
}

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
            """Redirect the user to Keycloak's authorization endpoint.

            ``acr_values``, ``max_age`` and ``prompt`` in the query are passed
            on, so a step-up challenge can be answered by sending the user to
            ``/auth/login?acr_values=…`` or ``?max_age=…``.
            """
            state = secrets.token_urlsafe(32)
            params = {
                "response_type": "code",
                "client_id": config.client_id,
                "redirect_uri": config.redirect_uri,
                "scope": " ".join(config.scopes),
                "state": state,
            }
            for name, allowed in _FORWARDED_LOGIN_PARAMS.items():
                value = request.query_params.get(name)
                if value is not None and allowed.fullmatch(value):
                    params[name] = value
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
                if config.session_binding:
                    response.set_cookie(_bind_session(config, request))
            else:
                response = Response(content=token_data, headers=_NO_STORE)

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
                refresh_token = _session_refresh_token(config, request)
            else:
                refresh_token = await _body_refresh_token(request)

            if refresh_token:
                try:
                    await _keycloak_logout(config, refresh_token, http=http)
                except (aiohttp.ClientError, OSError) as exc:
                    logger.warning("Keycloak logout failed: %s", exc)

            response: Response[dict[str, str]] | Redirect
            if redirect_mode:
                _clear_session_tokens(request)
                if config.post_logout_redirect_uri is not None:
                    response = Redirect(config.post_logout_redirect_uri)
                else:
                    response = Response(content={"status": "logged_out"})
                if config.session_binding:
                    response.delete_cookie(BINDING_COOKIE_NAME, path="/")
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
                refresh_token = _session_refresh_token(config, request)
            else:
                refresh_token = await _body_refresh_token(request)

            if not refresh_token:
                raise NotAuthorizedException(detail="Missing refresh_token")

            token_data = await _refresh_token(config, refresh_token, http=http)

            if redirect_mode:
                _store_session_tokens(request, token_data)
                return Response(content={"status": "refreshed"})
            return Response(content=token_data, headers=_NO_STORE)

        if config.backchannel_logout:

            @post("/backchannel-logout", status_code=200)
            async def backchannel_logout(
                self, request: Request[Any, Any, Any]
            ) -> Response[dict[str, str] | None]:
                """Receive Keycloak's logout token and end that session here too.

                Called server-to-server by Keycloak, so it carries no bearer
                token; the signed logout token is the authentication.
                """
                form = await request.form()
                logout_token = form.get("logout_token")
                if not logout_token:
                    return _backchannel_error()
                try:
                    claims = await verifier.verify_logout_token(str(logout_token))
                except AuthenticationError as exc:
                    logger.info("Rejected back-channel logout: %s", exc)
                    return _backchannel_error()
                await record_logout(request.app.stores.get(config.logout_store), claims)
                logger.info(
                    "Back-channel logout: sid=%s sub=%s",
                    claims.get("sid"),
                    claims.get("sub"),
                )
                return Response(content=None, status_code=200, headers=_NO_STORE)

    return AuthController


def _backchannel_error() -> Response[dict[str, str] | None]:
    return Response(
        content={"error": "invalid_request"}, status_code=400, headers=_NO_STORE
    )


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


async def _body_refresh_token(request: Request[Any, Any, Any]) -> str:
    """The ``refresh_token`` of a JSON object body; ``""`` for anything else."""
    try:
        body = await request.json()
    except SerializationException:
        return ""
    token = body.get("refresh_token") if isinstance(body, dict) else None
    return token if isinstance(token, str) else ""


def _session(request: Request[Any, Any, Any]) -> dict[str, Any]:
    """Return the request session (raises if no session middleware is installed)."""
    return request.session


def _session_refresh_token(
    config: KeycloakConfig, request: Request[Any, Any, Any]
) -> str:
    """The session's refresh token; ``""`` if ``session_binding`` refuses it."""
    session = _session(request)
    if config.session_binding and not session_is_bound(request, session):
        return ""
    return str(session.get(SESSION_REFRESH_TOKEN_KEY, ""))


def _bind_session(config: KeycloakConfig, request: Request[Any, Any, Any]) -> Cookie:
    """Issue a fresh binding cookie and record its digest in the session."""
    value = secrets.token_urlsafe(32)
    _session(request)[SESSION_BINDING_KEY] = binding_digest(value)
    return Cookie(
        key=BINDING_COOKIE_NAME,
        value=value,
        httponly=True,
        secure=config.cookie_secure,
        samesite=config.cookie_samesite,
        path="/",
    )


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
    session.pop(SESSION_BINDING_KEY, None)


# ---------------------------------------------------------------------------
# Keycloak HTTP helpers (delegate to the shared, pooled client)
# ---------------------------------------------------------------------------


async def _token_request(
    config: KeycloakConfig, form_data: dict[str, str], *, http: KeycloakHttpClient
) -> dict[str, Any]:
    """POST to Keycloak's token endpoint and return the JSON response.

    Keycloak refusing the grant (400/401: code reused or expired, refresh
    token revoked) is the caller's 401; any other failure is Keycloak's, a 502.
    """
    grant = form_data.get("grant_type", "")
    try:
        token_data = await http.post_form(config.token_url, form_data)
    except aiohttp.ClientResponseError as exc:
        if exc.status in (400, 401):
            logger.info("Keycloak rejected the %s grant: %s", grant, exc.status)
            raise NotAuthorizedException(detail="Token request rejected") from exc
        raise TokenEndpointError(f"Token endpoint failed: {exc}") from exc
    except (aiohttp.ClientError, OSError, ValueError) as exc:
        raise TokenEndpointError(f"Token endpoint failed: {exc}") from exc
    if not isinstance(token_data, dict):
        raise TokenEndpointError("Token endpoint returned a non-object body")
    return token_data


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
