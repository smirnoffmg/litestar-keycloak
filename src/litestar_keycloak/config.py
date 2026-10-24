"""Keycloak connection and behavior configuration.

Provides ``KeycloakConfig`` — a frozen dataclass that holds every setting the
plugin needs: server coordinates, client credentials, token location, JWKS
cache policy, and optional route mounting.  All OIDC endpoint URLs are derived
automatically from ``server_url`` and ``realm``, so consumers never construct
them by hand.
"""

from __future__ import annotations

import enum
import logging
import re
from dataclasses import dataclass, field
from typing import Literal

logger = logging.getLogger(__name__)

#: JWS ``alg`` families a realm's JWKS can verify: its keys are public, so
#: HMAC (``HS*``) and ``none`` never can.
_PUBLIC_KEY_ALG_PREFIXES = ("RS", "PS", "ES", "Ed")

_AUTH_PREFIX_RE = re.compile(r"(/[^/]+)+")


class TokenLocation(enum.Enum):
    """Where the plugin looks for the access token on incoming requests."""

    HEADER = "header"
    COOKIE = "cookie"


@dataclass(frozen=True, slots=True)
class KeycloakConfig:
    """Immutable configuration for the Keycloak plugin.

    Only ``server_url``, ``realm``, and ``client_id`` are required.
    Everything else has sensible defaults suitable for a typical
    confidential-client setup with RS256-signed JWTs.

    Example::

        KeycloakConfig(
            server_url="https://keycloak.example.com",
            realm="my-realm",
            client_id="my-app",
            client_secret="s3cret",
        )
    """

    # -- connection --------------------------------------------------------
    server_url: str
    """Base Keycloak URL without trailing slash (e.g. ``https://kc.example.com``)."""

    realm: str
    """Keycloak realm name."""

    client_id: str
    """OIDC client identifier registered in the realm."""

    client_secret: str | None = None
    """Client secret for confidential clients.  ``None`` for public clients."""

    # -- token -------------------------------------------------------------
    token_location: TokenLocation = TokenLocation.HEADER
    """Where to read the bearer token from: ``Authorization`` header or a cookie."""

    cookie_name: str = "access_token"
    """Cookie name the middleware reads when ``token_location`` is ``COOKIE``.
    The plugin never *sets* this cookie — how the token gets there is the
    application's responsibility (see ``callback_response_mode``)."""

    cookie_secure: bool = True
    """``Secure`` attribute on the OAuth ``state`` cookie the routes set.  Set
    ``False`` for plain-HTTP local development."""

    cookie_samesite: Literal["lax", "strict", "none"] = "lax"
    """``SameSite`` attribute on the OAuth ``state`` cookie the routes set."""

    algorithms: tuple[str, ...] = ("RS256",)
    """Accepted JWT signing algorithms.  Add e.g. ``"ES256"`` or ``"EdDSA"`` when
    the realm signs with an EC or Ed25519 key provider."""

    leeway: int = 0
    """Seconds of clock skew tolerated when checking ``exp``, ``nbf`` and
    ``iat``.  Set a few seconds if the app and Keycloak clocks may drift."""

    scopes: tuple[str, ...] = ("openid",)
    """Scopes requested during the authorization code flow."""

    # -- revocation --------------------------------------------------------
    token_introspection: bool = False
    """Ask Keycloak (RFC 7662) whether each locally valid token is still active.

    A JWT stays valid until ``exp`` even after its session is logged out or
    its user disabled; introspection catches that on the next request, at the
    cost of one call to Keycloak per request (see
    ``introspection_cache_ttl``).  Requires ``client_secret``: Keycloak only
    answers authenticated confidential clients."""

    introspection_cache_ttl: int = 0
    """Seconds to reuse a positive introspection result for the same token.
    ``0`` (default) introspects every request, so a revocation takes effect
    immediately; a positive value trades that delay for fewer calls."""

    # -- JWKS --------------------------------------------------------------
    jwks_cache_ttl: int = 3600
    """How long (seconds) to cache the JWKS before re-fetching."""

    # -- routes ------------------------------------------------------------
    include_routes: bool = False
    """Mount ``/auth/login``, ``/callback``, ``/logout``, ``/refresh`` routes."""

    auth_prefix: str = "/auth"
    """URL prefix for the optional OIDC route group."""

    redirect_uri: str | None = None
    """OAuth2 redirect URI for the authorization code flow.
    Required when ``include_routes`` is ``True``."""

    callback_response_mode: Literal["json", "redirect"] = "json"
    """What ``/auth/callback`` does after exchanging the code:

    - ``"json"`` (default): return the token response as JSON — the SPA/BFF
      stores the access token and sends it as ``Authorization: Bearer``.
    - ``"redirect"``: store the tokens in the **server-side session** and redirect
      to ``post_login_redirect_uri`` — for server-rendered apps.  Requires
      Litestar session middleware (e.g. ``ServerSideSessionConfig``); the auth
      middleware then reads the access token from the session."""

    post_login_redirect_uri: str = "/"
    """Where ``redirect``-mode login redirects after storing tokens in the session."""

    post_logout_redirect_uri: str | None = None
    """Where ``redirect``-mode logout redirects.  Returns JSON status when ``None``."""

    use_pkce: bool = False
    """Send a PKCE ``S256`` code challenge on login (RFC 7636) and prove it on
    the code exchange.  Required for public clients; harmless and recommended
    for confidential ones.  Keycloak can enforce it per client (Advanced →
    "Proof Key for Code Exchange Code Challenge Method")."""

    session_auto_refresh: bool = False
    """In ``"redirect"`` mode, renew an expired access token from the session
    with its refresh token instead of answering 401, and write the new tokens
    back to the session.  A refresh Keycloak rejects (session ended, refresh
    token expired) answers 401; the stale tokens stay in the session until the
    next login replaces them."""

    session_binding: bool = False
    """In ``"redirect"`` mode, bind the session's tokens to an HttpOnly cookie
    set at login and accept them only alongside it.  Litestar keeps the session
    id across login, so without it an attacker who planted a session id in the
    victim's browser shares the victim's login (session fixation).  The cookie
    lasts until the browser closes; sessions from before it was switched on
    must log in again."""

    backchannel_logout: bool = False
    """Mount ``POST {auth_prefix}/backchannel-logout`` for Keycloak's OIDC
    back-channel logout, and refuse tokens from sessions it reports ended.  Set
    the client's *Backchannel logout URL* in Keycloak to this endpoint."""

    logout_store: str = "keycloak_logout"
    """Name of the Litestar store recording back-channel logouts.  The default
    is an in-memory store per process; register a shared store (e.g. Redis)
    under this name when the app runs as several instances."""

    validate_id_token: bool = False
    """Send an OIDC ``nonce`` on login and, in the callback, require the
    returned ID token to be valid for this client and carry that nonce.
    Requires ``"openid"`` in ``scopes``."""

    # -- advanced ----------------------------------------------------------
    audience: str | None = None
    """Expected ``aud`` claim.  Defaults to ``client_id`` when ``None``."""

    expected_issuer: str | None = None
    """Expected ``iss`` claim.  Defaults to ``realm_url`` when ``None``.  Set this
    when Keycloak's frontend/hostname URL differs from ``server_url`` (e.g. behind
    a reverse proxy), so token issuer validation matches the value Keycloak signs."""

    optional_audiences: frozenset[str] = field(default_factory=frozenset)
    """Additional audiences to accept (e.g. service client IDs)."""

    strict_audience: bool = False
    """Accept a token only if its ``aud`` contains an accepted audience.
    ``False`` (default) also accepts a token whose ``azp`` is accepted, because
    Keycloak access tokens often lack the client's own audience.  Before setting
    ``True``, add a Keycloak Audience mapper (``oidc-audience-mapper``) to the
    clients that call this API."""

    expected_token_type: str | None = "Bearer"
    """Required payload ``typ`` claim.  ``"Bearer"`` (default) rejects Keycloak
    ID and Refresh tokens presented as access tokens.  Set to ``None`` to disable
    the check (e.g. non-Keycloak OIDC providers that omit ``typ``)."""

    http_timeout: int = 10
    """Timeout in seconds for outgoing HTTP calls to Keycloak."""

    excluded_paths: frozenset[str] = field(default_factory=frozenset)
    """Exact request paths that skip authentication entirely (e.g. ``/health``).
    Matched literally — for prefixes or subtrees use ``exclude_patterns``."""

    exclude_patterns: tuple[str, ...] = ()
    """Regex patterns whose matching request paths skip authentication.

    Unlike ``excluded_paths`` (exact match), these cover prefixes and subtrees,
    e.g. ``("^/public/", "^/docs")``.  Patterns are matched unanchored against
    the path, so anchor with ``^`` to match from the start."""

    exclude_opt_key: str = "exclude_from_auth"
    """Route-handler ``opt`` key for per-handler opt-out, e.g.
    ``@get("/open", exclude_from_auth=True)``."""

    optional_auth_opt_key: str = "optional_auth"
    """Route-handler ``opt`` key for optional authentication, e.g.
    ``@get("/feed", optional_auth=True)``: a request without a token proceeds
    anonymously (``current_user`` is ``None``), while a token that is present
    must still be valid.  Annotate such handlers with ``OptionalCurrentUser``."""

    groups_claim: str = "groups"
    """Token claim holding the user's groups, as configured on Keycloak's Group
    Membership mapper.  Note that the built-in ``microprofile-jwt`` scope puts
    realm *roles* into a claim of the same name."""

    # -- derived properties ------------------------------------------------

    @property
    def realm_url(self) -> str:
        """``{server_url}/realms/{realm}`` — base for all OIDC endpoints."""
        return f"{self.server_url.rstrip('/')}/realms/{self.realm}"

    @property
    def issuer(self) -> str:
        """Expected ``iss`` claim value.

        Defaults to ``realm_url``.  Set ``expected_issuer`` when Keycloak issues
        tokens under a different base (its configured frontend/hostname URL),
        which is common behind a reverse proxy where the public URL differs from
        the ``server_url`` the backend uses to reach Keycloak.
        """
        if self.expected_issuer is not None:
            return self.expected_issuer
        return self.realm_url

    @property
    def jwks_url(self) -> str:
        """JSON Web Key Set endpoint URL."""
        return f"{self.realm_url}/protocol/openid-connect/certs"

    @property
    def authorization_url(self) -> str:
        """Authorization endpoint for the code flow."""
        return f"{self.realm_url}/protocol/openid-connect/auth"

    @property
    def token_url(self) -> str:
        """Token endpoint for code exchange and refresh."""
        return f"{self.realm_url}/protocol/openid-connect/token"

    @property
    def logout_url(self) -> str:
        """End-session endpoint."""
        return f"{self.realm_url}/protocol/openid-connect/logout"

    @property
    def introspection_url(self) -> str:
        """Token introspection endpoint (RFC 7662)."""
        return f"{self.realm_url}/protocol/openid-connect/token/introspect"

    @property
    def effective_audience(self) -> str:
        """Primary audience for JWT validation (explicit or client_id)."""
        return self.audience if self.audience is not None else self.client_id

    @property
    def accepted_audiences(self) -> frozenset[str]:
        """All audiences accepted for JWT validation (primary + optional_audiences)."""
        return frozenset({self.effective_audience}) | self.optional_audiences

    @property
    def effective_excluded_paths(self) -> frozenset[str]:
        """Paths that skip auth: excluded_paths plus auth routes when include_routes."""
        if not self.include_routes:
            return self.excluded_paths
        auth_paths = {
            f"{self.auth_prefix}/login",
            f"{self.auth_prefix}/callback",
            f"{self.auth_prefix}/logout",
            f"{self.auth_prefix}/refresh",
        }
        if self.backchannel_logout:
            auth_paths.add(f"{self.auth_prefix}/backchannel-logout")
        return self.excluded_paths | auth_paths

    @property
    def exclude_auth_patterns(self) -> list[str] | None:
        """Regex patterns for request paths that bypass the auth middleware.

        Exact ``excluded_paths`` (and the auth routes when ``include_routes``) are
        anchored to ``^…$``; ``exclude_patterns`` are used verbatim.  Returns
        ``None`` when nothing is excluded — an empty pattern list would compile to
        an empty regex that greedily matches every path.
        """
        patterns = [
            f"^{re.escape(path)}$" for path in sorted(self.effective_excluded_paths)
        ]
        patterns.extend(self.exclude_patterns)
        return patterns or None

    def __post_init__(self) -> None:
        if self.include_routes and self.redirect_uri is None:
            raise ValueError("redirect_uri is required when include_routes is True")
        if self.jwks_cache_ttl < 0:
            raise ValueError("jwks_cache_ttl must be non-negative")
        if self.http_timeout <= 0:
            raise ValueError("http_timeout must be positive")
        if self.leeway < 0:
            raise ValueError("leeway must be non-negative")
        if self.token_introspection and self.client_secret is None:
            raise ValueError("token_introspection requires client_secret")
        if self.introspection_cache_ttl < 0:
            raise ValueError("introspection_cache_ttl must be non-negative")
        if self.session_auto_refresh and self.callback_response_mode != "redirect":
            raise ValueError(
                'session_auto_refresh requires callback_response_mode="redirect"'
            )
        if self.session_binding and self.callback_response_mode != "redirect":
            raise ValueError(
                'session_binding requires callback_response_mode="redirect"'
            )
        if self.backchannel_logout and not self.include_routes:
            raise ValueError("backchannel_logout requires include_routes=True")
        if self.validate_id_token and "openid" not in self.scopes:
            raise ValueError('validate_id_token requires "openid" in scopes')
        if self.cookie_samesite == "none" and not self.cookie_secure:
            # Browsers drop such cookies, so every login would fail its state check.
            raise ValueError('cookie_samesite="none" requires cookie_secure=True')
        if not _AUTH_PREFIX_RE.fullmatch(self.auth_prefix):
            raise ValueError(
                f"auth_prefix must look like '/auth' (no trailing slash), "
                f"got {self.auth_prefix!r}"
            )
        self._check_algorithms()
        if self.optional_audiences and not self.strict_audience:
            logger.warning(
                "optional_audiences without strict_audience=True also accepts any "
                "token whose azp is one of them, whatever its aud: %s",
                ", ".join(sorted(self.optional_audiences)),
            )

    def _check_algorithms(self) -> None:
        unusable = [
            alg
            for alg in self.algorithms
            if not alg.startswith(_PUBLIC_KEY_ALG_PREFIXES)
        ]
        if len(unusable) == len(self.algorithms):
            raise ValueError(
                "algorithms must include a public-key algorithm (RS*, PS*, ES*, "
                f"EdDSA), got {self.algorithms!r}"
            )
        if unusable:
            logger.warning(
                "algorithms %s cannot verify Keycloak tokens; tokens using them "
                "are refused",
                ", ".join(unusable),
            )
