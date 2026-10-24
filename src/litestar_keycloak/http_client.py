"""Shared, lazily-created aiohttp client for outbound Keycloak calls.

A single ``ClientSession`` is reused across JWKS fetches and OIDC token/logout
requests, so connections are pooled and TLS is negotiated once rather than on
every call.  The session is created lazily inside the running event loop (never
in ``__init__``, where no loop exists) and closed by the plugin on application
shutdown.
"""

from __future__ import annotations

import asyncio
from typing import Any, cast

import aiohttp

_FORM_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}


class KeycloakHttpClient:
    """Owns a single pooled ``aiohttp.ClientSession`` for Keycloak requests."""

    def __init__(self, timeout: int) -> None:
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._session: aiohttp.ClientSession | None = None
        self._lock = asyncio.Lock()

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            async with self._lock:
                if self._session is None or self._session.closed:
                    self._session = aiohttp.ClientSession(timeout=self._timeout)
        return self._session

    async def get_json(
        self, url: str, *, headers: dict[str, str] | None = None
    ) -> dict[str, Any]:
        """GET *url* and return the parsed JSON body (raises on non-2xx)."""
        session = await self._get_session()
        async with session.get(url, headers=headers) as resp:
            resp.raise_for_status()
            return cast("dict[str, Any]", await resp.json(content_type=None))

    async def post_form(self, url: str, data: dict[str, str]) -> dict[str, Any]:
        """POST form-encoded *data*, returning the parsed JSON (raises on non-2xx)."""
        session = await self._get_session()
        async with session.post(url, data=data, headers=_FORM_HEADERS) as resp:
            resp.raise_for_status()
            return cast("dict[str, Any]", await resp.json(content_type=None))

    async def post_form_status(
        self, url: str, data: dict[str, str]
    ) -> tuple[int, dict[str, Any]]:
        """POST form-encoded *data*; return ``(status, JSON body)`` without raising.

        For grants whose error body matters to the caller (RFC 6749 §5.2
        ``error`` / ``error_description``).  A body that is not JSON comes back
        as ``{}``.
        """
        session = await self._get_session()
        async with session.post(url, data=data, headers=_FORM_HEADERS) as resp:
            try:
                body = await resp.json(content_type=None)
            except ValueError:
                body = {}
            return resp.status, body if isinstance(body, dict) else {}

    async def post_form_discard(self, url: str, data: dict[str, str]) -> None:
        """POST *data* as form-encoded, ignoring the response.

        Used for best-effort calls such as logout, where a non-2xx status must
        not abort the surrounding operation.
        """
        session = await self._get_session()
        async with session.post(url, data=data, headers=_FORM_HEADERS):
            pass

    async def close(self) -> None:
        """Close the underlying session if it was ever opened.  Idempotent."""
        if self._session is not None and not self._session.closed:
            await self._session.close()
