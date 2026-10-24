"""Token introspection (RFC 7662) for revocation that takes effect at once.

A locally verified JWT says nothing about what happened after it was issued:
a logged-out session or a disabled user keeps a valid signature until ``exp``.
``TokenIntrospector`` asks Keycloak's introspection endpoint instead, and fails
closed — an unreachable endpoint rejects the request rather than admitting it.
Positive answers may be reused for ``introspection_cache_ttl`` seconds.
"""

from __future__ import annotations

import hashlib
import time
from typing import TYPE_CHECKING

import aiohttp

from litestar_keycloak.exceptions import IntrospectionError, TokenInactiveError

if TYPE_CHECKING:
    from litestar_keycloak.config import KeycloakConfig
    from litestar_keycloak.http_client import KeycloakHttpClient

#: Upper bound on cached positive results, so memory stays capped however
#: many distinct tokens arrive within one TTL.
MAX_CACHED_TOKENS = 10_000


class TokenIntrospector:
    """Checks with Keycloak that a token is still active."""

    def __init__(self, config: KeycloakConfig, http: KeycloakHttpClient) -> None:
        self._url = config.introspection_url
        self._credentials = {
            "client_id": config.client_id,
            "client_secret": config.client_secret or "",
        }
        self._ttl = config.introspection_cache_ttl
        self._http = http
        # Keyed by token digest: 32 bytes per entry instead of a whole JWT.
        # Every entry shares one TTL, so insertion order is expiry order.
        self._active_until: dict[bytes, float] = {}

    @property
    def cached_count(self) -> int:
        return len(self._active_until)

    async def ensure_active(self, raw_token: str) -> None:
        """Return if Keycloak considers *raw_token* active, else raise.

        Raises:
            TokenInactiveError: Keycloak answered ``active`` other than ``true``.
            IntrospectionError: The endpoint failed or rejected our credentials.
        """
        key = hashlib.sha256(raw_token.encode()).digest()
        if self._active_until.get(key, 0.0) > time.monotonic():
            return

        if not await self._introspect(raw_token):
            raise TokenInactiveError("Token is not active")
        if self._ttl:
            self._remember(key)

    async def _introspect(self, raw_token: str) -> bool:
        try:
            body = await self._http.post_form(
                self._url, {"token": raw_token, **self._credentials}
            )
        except (aiohttp.ClientError, OSError) as exc:
            raise IntrospectionError(
                f"Token introspection at {self._url} failed: {exc}"
            ) from exc
        return body.get("active") is True

    def _remember(self, key: bytes) -> None:
        now = time.monotonic()
        entries = self._active_until
        entries.pop(key, None)
        while entries and (
            len(entries) >= MAX_CACHED_TOKENS or next(iter(entries.values())) <= now
        ):
            del entries[next(iter(entries))]
        entries[key] = now + self._ttl
