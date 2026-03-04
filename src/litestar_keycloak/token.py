"""JWT decoding, validation, and JWKS key management.

Handles the low-level cryptographic concerns: fetching the JWKS from
Keycloak's well-known endpoint (via ``aiohttp``), caching keys with
a configurable TTL, and automatic single-retry rotation when an unknown
``kid`` is encountered.  Validates ``iss``, ``aud``, ``exp``, ``iat``,
and signing algorithm.  Returns a ``TokenPayload`` on success, raises
typed exceptions on failure.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING, Any, cast

import aiohttp
import jwt
from jwt import PyJWK

from litestar_keycloak.exceptions import (
    InvalidAudienceError,
    InvalidIssuerError,
    JWKSFetchError,
    TokenDecodeError,
    TokenExpiredError,
)
from litestar_keycloak.models import TokenPayload

if TYPE_CHECKING:
    from litestar_keycloak.config import KeycloakConfig

logger = logging.getLogger(__name__)


class JWKSCache:
    """Async, TTL-based cache for Keycloak's JSON Web Key Set.

    Keys are fetched via ``aiohttp``.  An ``asyncio.Lock`` serializes
    concurrent refresh attempts so only one network call is made when
    multiple requests hit an expired cache simultaneously.

    On a cache miss for an unknown ``kid``, a single forced refresh is
    attempted before raising ``JWKSFetchError``.
    """

    def __init__(self, jwks_url: str, ttl: int, http_timeout: int) -> None:
        self._jwks_url = jwks_url
        self._ttl = ttl
        self._http_timeout = aiohttp.ClientTimeout(total=http_timeout)

        self._keys: dict[str, PyJWK] = {}
        self._fetched_at: float = 0.0
        self._lock = asyncio.Lock()

    # -- public API --------------------------------------------------------

    async def get_key(self, kid: str) -> PyJWK:
        """Return the signing key for *kid*, refreshing the cache if needed.

        Lookup strategy:
        1. Return from cache if present and TTL not expired.
        2. Refresh cache (TTL expired or unknown ``kid``).
        3. If ``kid`` still missing after refresh, raise ``JWKSFetchError``.
        """
        key = self._lookup(kid)
        if key is not None:
            return key

        await self._refresh()

        key = self._lookup(kid)
        if key is not None:
            return key

        raise JWKSFetchError(f"Key {kid!r} not found in JWKS after refresh")

    async def warm(self) -> None:
        """Pre-populate the cache.  Called once during plugin startup."""
        await self._refresh()

    # -- internals ---------------------------------------------------------

    def _lookup(self, kid: str) -> PyJWK | None:
        if not self._is_expired and kid in self._keys:
            return self._keys[kid]
        return None

    @property
    def _is_expired(self) -> bool:
        if self._ttl == 0:
            return True
        return (time.monotonic() - self._fetched_at) > self._ttl

    async def _refresh(self) -> None:
        async with self._lock:
            # Double-check after acquiring: another coroutine may have
            # already refreshed while we waited on the lock.
            if not self._is_expired and self._keys:
                return

            jwks_data = await self._fetch_jwks()
            keys: dict[str, PyJWK] = {}
            _SIG_ALGS = frozenset({"RS256", "RS384", "RS512"})
            for key_data in jwks_data.get("keys", []):
                kid = key_data.get("kid")
                if kid is None:
                    continue
                if key_data.get("kty") != "RSA":
                    logger.debug(
                        "Skipping non-RSA JWK kid=%s kty=%s", kid, key_data.get("kty")
                    )
                    continue
                use = key_data.get("use")
                alg = key_data.get("alg")
                # Prefer explicit signing alg; RS256 for enc-only keys (same material)
                force_alg: str | None = None
                if use == "enc" or (alg and alg not in _SIG_ALGS):
                    force_alg = "RS256"
                try:
                    keys[kid] = (
                        PyJWK(key_data, algorithm=force_alg)
                        if force_alg
                        else PyJWK(key_data)
                    )
                except Exception as exc:
                    logger.warning("Skipping unparseable JWK kid=%s: %s", kid, exc)

            self._keys = keys
            self._fetched_at = time.monotonic()
            logger.debug("JWKS refreshed, %d keys cached", len(keys))

    async def _fetch_jwks(self) -> dict[str, Any]:
        try:
            async with aiohttp.ClientSession(timeout=self._http_timeout) as session:
                async with session.get(
                    self._jwks_url,
                    headers={"Accept": "application/json"},
                ) as resp:
                    resp.raise_for_status()
                    return cast(dict[str, Any], await resp.json(content_type=None))
        except (aiohttp.ClientError, OSError) as exc:
            raise JWKSFetchError(
                f"Failed to fetch JWKS from {self._jwks_url}: {exc}"
            ) from exc


class TokenVerifier:
    """Validates and decodes Keycloak JWTs.

    Wired together by ``KeycloakPlugin`` and used by the auth backend.
    Stateless aside from holding a reference to the ``JWKSCache`` and
    the immutable ``KeycloakConfig``.
    """

    def __init__(self, config: KeycloakConfig, jwks_cache: JWKSCache) -> None:
        self._config = config
        self._jwks_cache = jwks_cache

    async def verify(self, raw_token: str) -> TokenPayload:
        """Decode and validate *raw_token*, returning a ``TokenPayload``.

        Raises:
            TokenDecodeError: Token is structurally invalid.
            TokenExpiredError: ``exp`` claim is in the past.
            InvalidIssuerError: ``iss`` does not match the realm URL.
            InvalidAudienceError: ``aud`` does not include the client ID.
            JWKSFetchError: Signing key could not be retrieved.
        """
        kid = self._extract_kid(raw_token)
        signing_key = await self._jwks_cache.get_key(kid)

        claims = self._decode(raw_token, signing_key)
        self._validate_claims(claims)

        return TokenPayload.from_claims(claims)

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _extract_kid(raw_token: str) -> str:
        try:
            headers = jwt.get_unverified_header(raw_token)
        except jwt.exceptions.DecodeError as exc:
            raise TokenDecodeError(f"Cannot read JWT header: {exc}") from exc

        kid = headers.get("kid")
        if kid is None:
            raise TokenDecodeError("JWT header missing 'kid'")
        return str(kid)

    def _decode(self, raw_token: str, signing_key: PyJWK) -> dict[str, Any]:
        try:
            return jwt.decode(
                raw_token,
                signing_key.key,
                algorithms=list(self._config.algorithms),
                options={
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_aud": False,  # we validate aud ourselves
                    "verify_iss": False,  # we validate iss ourselves
                },
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenExpiredError(str(exc)) from exc
        except jwt.DecodeError as exc:
            raise TokenDecodeError(str(exc)) from exc

    def _validate_claims(self, claims: dict[str, Any]) -> None:
        expected_iss = self._config.issuer
        actual_iss = claims.get("iss", "")
        if actual_iss != expected_iss:
            raise InvalidIssuerError(expected=expected_iss, got=actual_iss)

        expected_aud = self._config.effective_audience
        actual_aud = claims.get("aud", "")
        # Keycloak may omit aud; accept azp (authorized party) when aud is missing
        if not actual_aud:
            actual_aud = claims.get("azp", "")
        if isinstance(actual_aud, list):
            if expected_aud not in actual_aud:
                raise InvalidAudienceError(expected=expected_aud, got=actual_aud)
        elif actual_aud != expected_aud:
            raise InvalidAudienceError(expected=expected_aud, got=actual_aud)
