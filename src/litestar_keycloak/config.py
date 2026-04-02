"""Keycloak connection and behavior configuration.

Provides ``KeycloakConfig`` — a frozen dataclass that holds every setting the
plugin needs: server coordinates, client credentials, token location, JWKS
cache policy, and optional route mounting.  All OIDC endpoint URLs are derived
automatically from ``server_url`` and ``realm``, so consumers never construct
them by hand.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


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
    """Cookie name when ``token_location`` is ``COOKIE``."""

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

    post_login_redirect: str = "/"
    """Where to redirect after a successful ``/auth/callback`` when using cookie mode.

    This is only used by the optional OIDC route group when ``include_routes=True``.
    """

    cookie_secure: bool = True
    """Whether to set the ``Secure`` flag for the access-token cookie in cookie mode.

    Set this to ``False`` when running over plain HTTP in local development.
    """

    # -- advanced ----------------------------------------------------------
    audience: str | None = None
    """Expected ``aud`` claim.  Defaults to ``client_id`` when ``None``."""

    optional_audiences: frozenset[str] = field(default_factory=frozenset)
    """Additional audiences to accept (e.g. service client IDs)."""

    http_timeout: int = 10
    """Timeout in seconds for outgoing HTTP calls to Keycloak."""

    excluded_paths: frozenset[str] = field(default_factory=frozenset)
    """Request paths that skip authentication entirely (e.g. health checks)."""

    # -- derived properties ------------------------------------------------

    @property
    def realm_url(self) -> str:
        """``{server_url}/realms/{realm}`` — base for all OIDC endpoints."""
        return f"{self.server_url.rstrip('/')}/realms/{self.realm}"

    @property
    def issuer(self) -> str:
        """Expected ``iss`` claim value (same as ``realm_url``)."""
        return self.realm_url

    @property
    def discovery_url(self) -> str:
        """OpenID Connect discovery document URL."""
        return f"{self.realm_url}/.well-known/openid-configuration"

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

    def __post_init__(self) -> None:
        if self.include_routes and self.redirect_uri is None:
            raise ValueError("redirect_uri is required when include_routes is True")
        if self.jwks_cache_ttl < 0:
            raise ValueError("jwks_cache_ttl must be non-negative")
        if self.http_timeout <= 0:
            raise ValueError("http_timeout must be positive")
