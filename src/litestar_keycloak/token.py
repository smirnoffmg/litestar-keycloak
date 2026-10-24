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
from typing import TYPE_CHECKING, Any

import aiohttp
import jwt
from jwt import PyJWK

from litestar_keycloak.exceptions import (
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidTokenTypeError,
    JWKSFetchError,
    TokenDecodeError,
    TokenExpiredError,
)
from litestar_keycloak.models import TokenPayload

if TYPE_CHECKING:
    from litestar_keycloak.config import KeycloakConfig
    from litestar_keycloak.http_client import KeycloakHttpClient
    from litestar_keycloak.introspection import TokenIntrospector

logger = logging.getLogger(__name__)

#: Minimum seconds between refreshes forced by an unknown ``kid``.  Bounds the
#: JWKS fetches an attacker can trigger with tokens carrying made-up ``kid``s,
#: while still picking up a rotated key within seconds.
MIN_FORCED_REFRESH_INTERVAL = 10

_RSA_SIG_ALGS = frozenset({"RS256", "RS384", "RS512"})

#: JWK ``kty`` that verifies each JWS ``alg`` family, keyed by the alg's first
#: two letters (``RS``/``PS`` RSA, ``ES`` ECDSA, ``Ed`` EdDSA).
_KTY_BY_ALG_FAMILY = {"RS": "RSA", "PS": "RSA", "ES": "EC", "Ed": "OKP"}


class JWKSCache:
    """Async, TTL-based cache for Keycloak's JSON Web Key Set.

    Keys are fetched via ``aiohttp``.  An ``asyncio.Lock`` serializes
    concurrent refresh attempts so only one network call is made when
    multiple requests hit an expired cache simultaneously.

    On a cache miss for an unknown ``kid`` (e.g. after key rotation), a single
    forced refresh is attempted before raising ``JWKSFetchError``; forced
    refreshes are throttled to one per ``MIN_FORCED_REFRESH_INTERVAL``.
    """

    def __init__(self, jwks_url: str, ttl: int, http: KeycloakHttpClient) -> None:
        self._jwks_url = jwks_url
        self._ttl = ttl
        self._http = http

        self._keys: dict[str, PyJWK] = {}
        self._fetched_at: float = 0.0
        self._forced_at: float = float("-inf")
        self._lock = asyncio.Lock()

    # -- public API --------------------------------------------------------

    async def get_key(self, kid: str) -> PyJWK:
        """Return the signing key for *kid*, refreshing the cache if needed.

        Lookup strategy:
        1. Return from cache if present and TTL not expired.
        2. Refresh cache (TTL expired or unknown ``kid``).  A refresh forced by
           an unknown ``kid`` is skipped if another forced refresh ran less
           than ``MIN_FORCED_REFRESH_INTERVAL`` seconds ago.
        3. If ``kid`` still missing after refresh, raise ``JWKSFetchError``.
        """
        key = self._lookup(kid)
        if key is not None:
            return key

        await self._refresh(force=True)

        # Not ``_lookup``: with ``ttl == 0`` the keys just fetched already count
        # as expired, and the miss would turn every request into an error.
        key = self._keys.get(kid)
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

    @property
    def _forced_recently(self) -> bool:
        return (time.monotonic() - self._forced_at) < MIN_FORCED_REFRESH_INTERVAL

    async def _refresh(self, *, force: bool = False) -> None:
        async with self._lock:
            # Double-check after acquiring: another coroutine may have already
            # refreshed while we waited on the lock.  For a forced refresh the
            # throttle doubles as that check — coroutines racing on one rotated
            # kid all see the forced fetch the first of them just made.
            fresh = self._keys and not self._is_expired
            if fresh and (not force or self._forced_recently):
                return
            if fresh:
                self._forced_at = time.monotonic()

            jwks_data = await self._fetch_jwks()
            keys: dict[str, PyJWK] = {}
            for key_data in jwks_data.get("keys", []):
                kid = key_data.get("kid")
                if kid is None:
                    continue
                try:
                    key = _parse_signing_jwk(key_data)
                except Exception as exc:
                    logger.warning("Skipping unparseable JWK kid=%s: %s", kid, exc)
                    continue
                if key is not None:
                    keys[kid] = key

            self._keys = keys
            self._fetched_at = time.monotonic()
            logger.debug("JWKS refreshed, %d keys cached", len(keys))

    async def _fetch_jwks(self) -> dict[str, Any]:
        try:
            return await self._http.get_json(
                self._jwks_url, headers={"Accept": "application/json"}
            )
        except (aiohttp.ClientError, OSError) as exc:
            raise JWKSFetchError(
                f"Failed to fetch JWKS from {self._jwks_url}: {exc}"
            ) from exc


def _parse_signing_jwk(key_data: dict[str, Any]) -> PyJWK | None:
    """Build a verification key from a JWK, or ``None`` if it cannot sign.

    RSA keys keep the historical leniency: an encryption key or one with a
    non-signing ``alg`` is parsed as RS256, since the material is the same.
    EC and OKP keys published for encryption (e.g. ``ECDH-ES``) are skipped.
    """
    kty = key_data.get("kty")
    kid = key_data.get("kid")
    if kty == "RSA":
        alg = key_data.get("alg")
        if key_data.get("use") == "enc" or (alg and alg not in _RSA_SIG_ALGS):
            return PyJWK(key_data, algorithm="RS256")
        return PyJWK(key_data)
    if kty in ("EC", "OKP"):
        if key_data.get("use") == "enc":
            logger.debug("Skipping encryption JWK kid=%s kty=%s", kid, kty)
            return None
        return PyJWK(key_data)
    logger.debug("Skipping unsupported JWK kid=%s kty=%s", kid, kty)
    return None


def _check_alg_matches_key(alg: str, kid: str, key: PyJWK) -> None:
    """Reject a token whose ``alg`` belongs to a different key family.

    ``jwt.decode`` gets the raw key object, so an RS256 header pointing at an
    EC ``kid`` would otherwise reach PyJWT as ``InvalidKeyError`` — a 500 that
    any client could trigger once a realm publishes keys of several types.
    """
    expected_kty = _KTY_BY_ALG_FAMILY.get(alg[:2])
    if expected_kty != key.key_type:
        raise TokenDecodeError(
            f"Token alg {alg!r} cannot be verified with {key.key_type} key {kid!r}"
        )


class TokenVerifier:
    """Validates and decodes Keycloak JWTs.

    Wired together by ``KeycloakPlugin`` and used by the auth backend.
    Stateless aside from holding a reference to the ``JWKSCache`` and
    the immutable ``KeycloakConfig``.
    """

    def __init__(
        self,
        config: KeycloakConfig,
        jwks_cache: JWKSCache,
        introspector: TokenIntrospector | None = None,
    ) -> None:
        self._config = config
        self._jwks_cache = jwks_cache
        self._introspector = introspector

    async def verify(self, raw_token: str) -> TokenPayload:
        """Decode and validate *raw_token*, returning a ``TokenPayload``.

        Raises:
            TokenDecodeError: Token is structurally invalid.
            TokenExpiredError: ``exp`` claim is in the past.
            InvalidIssuerError: ``iss`` does not match the realm URL.
            InvalidAudienceError: ``aud`` does not include the client ID.
            JWKSFetchError: Signing key could not be retrieved.
            TokenInactiveError: Introspection reports the token inactive.
            IntrospectionError: Introspection is enabled but failed.
        """
        kid, alg = self._read_header(raw_token)
        signing_key = await self._jwks_cache.get_key(kid)
        _check_alg_matches_key(alg, kid, signing_key)

        claims = self._decode(raw_token, signing_key)
        self._validate_claims(claims)
        if self._introspector is not None:
            await self._introspector.ensure_active(raw_token)

        return TokenPayload.from_claims(claims)

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _read_header(raw_token: str) -> tuple[str, str]:
        """Return the unverified ``(kid, alg)`` from the JWT header."""
        try:
            headers = jwt.get_unverified_header(raw_token)
        except jwt.exceptions.DecodeError as exc:
            raise TokenDecodeError(f"Cannot read JWT header: {exc}") from exc

        kid = headers.get("kid")
        if kid is None:
            raise TokenDecodeError("JWT header missing 'kid'")
        return str(kid), str(headers.get("alg", ""))

    def _decode(self, raw_token: str, signing_key: PyJWK) -> dict[str, Any]:
        try:
            return jwt.decode(
                raw_token,
                signing_key.key,
                algorithms=list(self._config.algorithms),
                leeway=self._config.leeway,
                options={
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_aud": False,  # we validate aud ourselves
                    "verify_iss": False,  # we validate iss ourselves
                },
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenExpiredError(str(exc)) from exc
        except jwt.InvalidTokenError as exc:
            # Base of DecodeError, ImmatureSignatureError, InvalidAlgorithmError and
            # friends — catching only DecodeError let the rest escape as a 500 for
            # what is really a bad client token.  InvalidKeyError is deliberately
            # not caught: a broken JWKS key is a server-side fault.
            raise TokenDecodeError(str(exc)) from exc

    def _validate_claims(self, claims: dict[str, Any]) -> None:
        expected_typ = self._config.expected_token_type
        if expected_typ is not None:
            actual_typ = claims.get("typ", "")
            if actual_typ != expected_typ:
                raise InvalidTokenTypeError(expected=expected_typ, got=str(actual_typ))

        expected_iss = self._config.issuer
        actual_iss = claims.get("iss", "")
        if actual_iss != expected_iss:
            raise InvalidIssuerError(expected=expected_iss, got=actual_iss)

        accepted = self._config.accepted_audiences
        actual_aud = claims.get("aud", "")
        if self._config.strict_audience:
            # Only aud counts; azp is ignored and a missing/empty aud is rejected
            if isinstance(actual_aud, list):
                aud_set = set(actual_aud)
            else:
                aud_set = {actual_aud} if actual_aud else set()
            if not aud_set & accepted:
                raise InvalidAudienceError(
                    expected=", ".join(sorted(accepted)), got=actual_aud
                )
            return
        azp = claims.get("azp", "")
        # Keycloak: user tokens often have aud=client_id;
        # service tokens may have aud="account"
        # Accept if aud (or list of auds) intersects accepted, or azp is in accepted
        if isinstance(actual_aud, list):
            aud_ok = bool(set(actual_aud) & accepted)
        else:
            if not actual_aud:
                actual_aud = azp
            aud_ok = actual_aud in accepted
        if not aud_ok and azp not in accepted:
            raise InvalidAudienceError(
                expected=", ".join(sorted(accepted)), got=actual_aud
            )
