"""Keycloak connection and behavior configuration.

Provides ``KeycloakConfig`` — a frozen dataclass that holds every setting the
plugin needs: server coordinates, client credentials, token location, JWKS
cache policy, and optional route mounting.  All OIDC endpoint URLs are derived
automatically from ``server_url`` and ``realm``, so consumers never construct
them by hand.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from typing import Literal


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
    """Accepted JWT signing algorithms."""

    scopes: tuple[str, ...] = ("openid",)
    """Scopes requested during the authorization code flow."""

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

    # -- advanced ----------------------------------------------------------
    audience: str | None = None
    """Expected ``aud`` claim.  Defaults to ``client_id`` when ``None``."""

    expected_issuer: str | None = None
    """Expected ``iss`` claim.  Defaults to ``realm_url`` when ``None``.  Set this
    when Keycloak's frontend/hostname URL differs from ``server_url`` (e.g. behind
    a reverse proxy), so token issuer validation matches the value Keycloak signs."""

    optional_audiences: frozenset[str] = field(default_factory=frozenset)
    """Additional audiences to accept (e.g. service client IDs)."""

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
