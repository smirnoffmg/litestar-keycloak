"""Outbound tokens for calling other services as this client.

``ServiceTokenClient`` obtains access tokens from Keycloak's token endpoint
with this app's own client credentials:

- ``client_token()`` — a client_credentials grant, the app acting as itself,
  cached per scope and renewed shortly before it expires;
- ``exchange()`` — RFC 8693 token exchange, turning the caller's token into one
  for another service (Keycloak ≥ 26.2 "standard token exchange", enabled per
  client), so the downstream service sees the user but with its own audience.

The plugin owns one instance; handlers receive it as ``service_tokens``.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING, Any

import aiohttp

from litestar_keycloak.exceptions import ServiceTokenError

if TYPE_CHECKING:
    from litestar_keycloak.config import KeycloakConfig
    from litestar_keycloak.http_client import KeycloakHttpClient

logger = logging.getLogger(__name__)

_TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
_ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"

#: Renew a cached token this many seconds before it expires, so it is not sent
#: just as it lapses (or at half its lifetime, for tokens shorter than twice it).
_RENEWAL_MARGIN = 30


class ServiceTokenClient:
    """Issues access tokens for outbound calls with this app's client credentials."""

    def __init__(self, config: KeycloakConfig, http: KeycloakHttpClient) -> None:
        self._config = config
        self._http = http
        self._cached: dict[str | None, tuple[str, float]] = {}
        self._lock = asyncio.Lock()

    async def client_token(self, *, scope: str | None = None) -> str:
        """An access token for this client itself (client_credentials grant).

        Cached per *scope* until shortly before it expires; concurrent callers
        share one grant.
        """
        cached = self._fresh(scope)
        if cached is not None:
            return cached
        async with self._lock:
            # Another coroutine may have renewed it while we waited on the lock.
            cached = self._fresh(scope)
            if cached is not None:
                return cached
            form = {"grant_type": "client_credentials"}
            if scope:
                form["scope"] = scope
            body = await self._grant("client_credentials", form)
            token = str(body["access_token"])
            self._cached[scope] = (token, _renew_at(body.get("expires_in")))
            return token

    async def exchange(
        self, subject_token: str, *, audience: str, scope: str | None = None
    ) -> str:
        """Exchange *subject_token* for an access token addressed to *audience*.

        Keycloak requires this client to have *Standard token exchange* on, the
        subject token's ``aud`` to include this client, and *audience* to be
        available to it (e.g. through an Audience mapper).  Not cached: each
        exchanged token belongs to one caller.
        """
        form = {
            "grant_type": _TOKEN_EXCHANGE_GRANT,
            "subject_token": subject_token,
            "subject_token_type": _ACCESS_TOKEN_TYPE,
            "audience": audience,
        }
        if scope:
            form["scope"] = scope
        body = await self._grant("token-exchange", form)
        return str(body["access_token"])

    def _fresh(self, scope: str | None) -> str | None:
        entry = self._cached.get(scope)
        if entry is not None and time.monotonic() < entry[1]:
            return entry[0]
        return None

    async def _grant(self, grant: str, form: dict[str, str]) -> dict[str, Any]:
        if self._config.client_secret is None:
            raise ValueError(
                "service tokens require client_secret (a confidential client)"
            )
        credentials = {
            "client_id": self._config.client_id,
            "client_secret": self._config.client_secret,
        }
        # grant_type first, then credentials, then the grant's own parameters.
        data = {"grant_type": form.pop("grant_type"), **credentials, **form}
        try:
            status, body = await self._http.post_form_status(
                self._config.token_url, data
            )
        except (aiohttp.ClientError, OSError) as exc:
            raise ServiceTokenError(grant) from exc
        if status != 200 or "access_token" not in body:
            error = ServiceTokenError(
                grant,
                status=status,
                error=body.get("error"),
                error_description=body.get("error_description"),
            )
            logger.warning(
                "%s (HTTP %s): %s", error, status, error.error_description or "-"
            )
            raise error
        return body


def _renew_at(expires_in: Any) -> float:
    lifetime = float(expires_in) if expires_in else 0.0
    return time.monotonic() + max(lifetime - _RENEWAL_MARGIN, lifetime / 2)
