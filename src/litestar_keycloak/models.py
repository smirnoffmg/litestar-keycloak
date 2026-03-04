"""Domain models for Keycloak token payloads and user identity.

Defines ``TokenPayload`` (raw decoded JWT claims), ``KeycloakUser`` (the
high-level identity object injected into route handlers), and supporting
types.  Realm and client roles are normalized into a single model so
consumers never need to dig into Keycloak's nested ``realm_access`` /
``resource_access`` claim structure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class TokenPayload:
    """Decoded and validated JWT claims.

    Mirrors the standard OIDC claims plus Keycloak-specific role
    structures.  Constructed by the ``token`` module after successful
    validation — fields are guaranteed to satisfy all configured checks
    (issuer, audience, expiry, algorithm) by the time this object exists.
    """

    # -- standard OIDC claims ---------------------------------------------
    sub: str
    """Subject identifier (Keycloak user ID, typically a UUID)."""

    iss: str
    """Issuer URL (``{server_url}/realms/{realm}``)."""

    aud: str | list[str]
    """Audience — single client ID or a list when multiple audiences are present."""

    exp: int
    """Expiration timestamp (Unix epoch seconds)."""

    iat: int
    """Issued-at timestamp (Unix epoch seconds)."""

    # -- optional standard claims ------------------------------------------
    azp: str | None = None
    """Authorized party — the client that requested the token."""

    scope: str = ""
    """Space-delimited scope string (e.g. ``"openid profile email"``)."""

    jti: str | None = None
    """Unique token identifier."""

    typ: str | None = None
    """Token type (typically ``"Bearer"``)."""

    # -- Keycloak-specific claims ------------------------------------------
    preferred_username: str | None = None
    email: str | None = None
    email_verified: bool = False
    given_name: str | None = None
    family_name: str | None = None
    name: str | None = None

    realm_access: dict[str, Any] = field(default_factory=dict)
    """Raw ``realm_access`` claim (e.g. ``{"roles": ["admin", "user"]}``)."""

    resource_access: dict[str, Any] = field(default_factory=dict)
    """Raw ``resource_access`` claim keyed by client ID."""

    # -- extra claims catchall ---------------------------------------------
    extra: dict[str, Any] = field(default_factory=dict)
    """Any remaining claims not explicitly modeled above."""

    # -- convenience -------------------------------------------------------

    @property
    def realm_roles(self) -> frozenset[str]:
        """Realm-level roles extracted from ``realm_access.roles``."""
        return frozenset(self.realm_access.get("roles", []))

    def client_roles(self, client_id: str) -> frozenset[str]:
        """Roles for a specific client from ``resource_access``."""
        access = self.resource_access.get(client_id, {})
        return frozenset(access.get("roles", []))

    @property
    def scopes(self) -> frozenset[str]:
        """Scope string split into a set for O(1) membership tests."""
        return frozenset(self.scope.split()) if self.scope else frozenset()

    @property
    def expires_at(self) -> datetime:
        """``exp`` as a timezone-aware UTC datetime."""
        return datetime.fromtimestamp(self.exp, tz=UTC)

    @property
    def issued_at(self) -> datetime:
        """``iat`` as a timezone-aware UTC datetime."""
        return datetime.fromtimestamp(self.iat, tz=UTC)

    @classmethod
    def from_claims(cls, claims: dict[str, Any]) -> TokenPayload:
        """Build a ``TokenPayload`` from a raw decoded JWT dict.

        Known fields are mapped to explicit attributes; everything else
        lands in ``extra`` so no claim is silently dropped.
        Keycloak may omit ``aud``; fall back to ``azp`` when building.
        """
        # Normalize aud (Keycloak sometimes omits it; use azp as fallback)
        normalized = dict(claims)
        if not normalized.get("aud"):
            normalized["aud"] = normalized.get("azp") or ""
        known_fields = {f.name for f in cls.__dataclass_fields__.values()} - {"extra"}
        known = {k: v for k, v in normalized.items() if k in known_fields}
        extra = {k: v for k, v in normalized.items() if k not in known_fields}
        return cls(**known, extra=extra)


@dataclass(frozen=True, slots=True)
class KeycloakUser:
    """High-level identity object injected into route handlers.

    Wraps ``TokenPayload`` and exposes a flattened, ergonomic API so
    handlers don't need to know about raw JWT claim structures::

        @get("/me")
        async def me(current_user: KeycloakUser) -> dict:
            return {"name": current_user.name, "roles": current_user.realm_roles}
    """

    sub: str
    """Keycloak user ID."""

    preferred_username: str | None = None
    email: str | None = None
    email_verified: bool = False
    given_name: str | None = None
    family_name: str | None = None
    name: str | None = None

    realm_roles: frozenset[str] = field(default_factory=frozenset)
    """All realm-level roles."""

    client_roles: dict[str, frozenset[str]] = field(default_factory=dict)
    """Client roles keyed by client ID."""

    scopes: frozenset[str] = field(default_factory=frozenset)
    """Token scopes as a set."""

    raw: TokenPayload | None = None
    """Full token payload for advanced use cases."""

    def has_role(self, role: str) -> bool:
        """Check if the user holds a realm role."""
        return role in self.realm_roles

    def has_client_role(self, client_id: str, role: str) -> bool:
        """Check if the user holds a role for a specific client."""
        return role in self.client_roles.get(client_id, frozenset())

    def has_scope(self, scope: str) -> bool:
        """Check if the token carries a specific scope."""
        return scope in self.scopes

    @classmethod
    def from_token(cls, payload: TokenPayload) -> KeycloakUser:
        """Construct from a validated ``TokenPayload``."""
        client_roles = {
            client_id: frozenset(access.get("roles", []))
            for client_id, access in payload.resource_access.items()
        }
        return cls(
            sub=payload.sub,
            preferred_username=payload.preferred_username,
            email=payload.email,
            email_verified=payload.email_verified,
            given_name=payload.given_name,
            family_name=payload.family_name,
            name=payload.name,
            realm_roles=payload.realm_roles,
            client_roles=client_roles,
            scopes=payload.scopes,
            raw=payload,
        )
