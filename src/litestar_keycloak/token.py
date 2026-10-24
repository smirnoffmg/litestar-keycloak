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
import hmac
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
    UnknownSigningKeyError,
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

#: Seconds after a failed JWKS fetch during which no new fetch is attempted.
#: While Keycloak is unreachable each attempt can take the full HTTP timeout;
#: without the pause every request would queue on the lock for its own.
FAILED_FETCH_BACKOFF = 5

_RSA_SIG_ALGS = frozenset({"RS256", "RS384", "RS512"})

#: ``events`` member that marks a back-channel logout token.
BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"

#: JWK ``kty`` that verifies each JWS ``alg`` family, keyed by the alg's first
#: two letters (``RS``/``PS`` RSA, ``ES`` ECDSA, ``Ed`` EdDSA).
_KTY_BY_ALG_FAMILY = {"RS": "RSA", "PS": "RSA", "ES": "EC", "Ed": "OKP"}
_CURVE_BY_EC_ALG = {
    "ES256": "secp256r1",
    "ES256K": "secp256k1",
    "ES384": "secp384r1",
    "ES512": "secp521r1",
}

#: Claims every access and ID token must carry; ``TokenPayload`` needs both.
_REQUIRED_CLAIMS = ("exp", "iat")


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
        self._attempts = 0
        self._failure: JWKSFetchError | None = None
        self._failed_at: float = float("-inf")
        self._lock = asyncio.Lock()

    # -- public API --------------------------------------------------------

    async def get_key(self, kid: str) -> PyJWK:
        """Return the signing key for *kid*, refreshing the cache if needed.

        Lookup strategy:
        1. Return from cache if present and TTL not expired.
        2. Refresh cache (TTL expired or unknown ``kid``).  A refresh forced by
           an unknown ``kid`` is skipped if another forced refresh ran less
           than ``MIN_FORCED_REFRESH_INTERVAL`` seconds ago.
        3. If ``kid`` still missing after refresh, raise
           ``UnknownSigningKeyError``.

        If Keycloak cannot be reached, a key already cached under *kid* is
        served past its TTL (stale-if-error); otherwise ``JWKSFetchError``.
        """
        key = self._lookup(kid)
        if key is not None:
            return key

        try:
            await self._refresh(force=True)
        except JWKSFetchError:
            stale = self._keys.get(kid)
            if stale is None:
                raise
            logger.warning("JWKS refresh failed; serving cached key kid=%s", kid)
            return stale

        # Not ``_lookup``: with ``ttl == 0`` the keys just fetched already count
        # as expired, and the miss would turn every request into an error.
        key = self._keys.get(kid)
        if key is not None:
            return key

        raise UnknownSigningKeyError(f"Key {kid!r} not found in JWKS after refresh")

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
    def _failed_recently(self) -> bool:
        return (time.monotonic() - self._failed_at) < FAILED_FETCH_BACKOFF

    def _raise_failure(self) -> None:
        if self._failure is not None:
            # A fresh instance: re-raising the shared one from several
            # coroutines would keep growing its traceback.
            raise JWKSFetchError(str(self._failure)) from self._failure

    @property
    def _forced_recently(self) -> bool:
        return (time.monotonic() - self._forced_at) < MIN_FORCED_REFRESH_INTERVAL

    async def _refresh(self, *, force: bool = False) -> None:
        seen = self._attempts
        async with self._lock:
            # Another coroutine fetched while we waited on the lock — share
            # its outcome.  The freshness check below cannot tell: a fetch made
            # on a cold or expired cache sets no throttle mark, so a forced
            # waiter would fetch again.
            if self._attempts != seen or self._failed_recently:
                self._raise_failure()
                return
            fresh = self._keys and not self._is_expired
            if fresh and (not force or self._forced_recently):
                return
            if fresh:
                self._forced_at = time.monotonic()

            try:
                jwks_data = await self._fetch_jwks()
            except JWKSFetchError as exc:
                self._failure = exc
                self._failed_at = time.monotonic()
                raise
            finally:
                # After the await: a coroutine arriving mid-fetch must see the
                # count change, or it would fetch again behind the lock.
                self._attempts += 1
            self._failure = None
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
            jwks = await self._http.get_json(
                self._jwks_url, headers={"Accept": "application/json"}
            )
        except (aiohttp.ClientError, OSError, ValueError) as exc:
            raise JWKSFetchError(
                f"Failed to fetch JWKS from {self._jwks_url}: {exc}"
            ) from exc
        if not isinstance(jwks, dict) or not isinstance(jwks.get("keys", []), list):
            raise JWKSFetchError(f"JWKS from {self._jwks_url} is not a key set")
        return jwks


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
    # PyJWT checks the curve too, but raises InvalidKeyError, which stays a 500.
    expected_curve = _CURVE_BY_EC_ALG.get(alg)
    if key.key_type == "EC" and expected_curve != key.key.curve.name:
        raise TokenDecodeError(
            f"Token alg {alg!r} cannot be verified with {key.key.curve.name} "
            f"key {kid!r}"
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

        claims = self._decode(raw_token, signing_key, require=_REQUIRED_CLAIMS)
        self._validate_claims(claims)
        if self._introspector is not None:
            await self._introspector.ensure_active(raw_token)

        return TokenPayload.from_claims(claims)

    async def verify_id_token(self, raw_token: str, *, nonce: str) -> dict[str, Any]:
        """Validate an ID token from the code exchange (OIDC Core 3.1.3.7).

        Unlike an access token, an ID token is addressed to this client alone
        (``aud`` must contain ``client_id``; ``optional_audiences`` do not
        count) and must carry the *nonce* this login sent, which binds it to
        the transaction and defeats replay.
        """
        kid, alg = self._read_header(raw_token)
        signing_key = await self._jwks_cache.get_key(kid)
        _check_alg_matches_key(alg, kid, signing_key)
        claims = self._decode(raw_token, signing_key, require=_REQUIRED_CLAIMS)

        client_id = self._config.client_id
        actual_typ = claims.get("typ", "")
        if self._config.expected_token_type is not None and actual_typ != "ID":
            raise InvalidTokenTypeError(expected="ID", got=str(actual_typ))
        if claims.get("iss", "") != self._config.issuer:
            raise InvalidIssuerError(
                expected=self._config.issuer, got=claims.get("iss", "")
            )
        aud = claims.get("aud", "")
        audiences = aud if isinstance(aud, list) else [aud]
        azp = claims.get("azp")
        if client_id not in audiences or (
            (azp is not None or len(audiences) > 1) and azp != client_id
        ):
            raise InvalidAudienceError(expected=client_id, got=aud)
        # Bytes, not str: compare_digest raises on non-ASCII str input.
        expected = nonce.encode()
        actual = str(claims.get("nonce", "")).encode()
        if not nonce or not hmac.compare_digest(actual, expected):
            raise TokenDecodeError("ID token nonce does not match the login")
        return claims

    async def verify_logout_token(self, raw_token: str) -> dict[str, Any]:
        """Validate a back-channel logout token (OIDC Back-Channel Logout 2.6).

        Besides signature, ``iss``, ``aud`` (this client) and ``iat``, the token
        must carry the back-channel logout event and a ``sid`` or ``sub``, and
        must not carry a ``nonce`` — that and the ``logout+jwt`` header type
        keep an ID or access token from being replayed as a logout.
        """
        try:
            header_typ = jwt.get_unverified_header(raw_token).get("typ")
        except jwt.exceptions.DecodeError as exc:
            raise TokenDecodeError(f"Cannot read JWT header: {exc}") from exc
        if header_typ is not None and str(header_typ).lower() != "logout+jwt":
            raise TokenDecodeError(f"Not a logout token (typ {header_typ!r})")

        kid, alg = self._read_header(raw_token)
        signing_key = await self._jwks_cache.get_key(kid)
        _check_alg_matches_key(alg, kid, signing_key)
        claims = self._decode(raw_token, signing_key)

        if claims.get("iss", "") != self._config.issuer:
            raise InvalidIssuerError(
                expected=self._config.issuer, got=claims.get("iss", "")
            )
        aud = claims.get("aud", "")
        if self._config.client_id not in (aud if isinstance(aud, list) else [aud]):
            raise InvalidAudienceError(expected=self._config.client_id, got=aud)
        events = claims.get("events")
        if not isinstance(events, dict) or not isinstance(
            events.get(BACKCHANNEL_LOGOUT_EVENT), dict
        ):
            raise TokenDecodeError("Logout token lacks the back-channel logout event")
        if "nonce" in claims:
            raise TokenDecodeError("Logout token must not contain a nonce")
        if "iat" not in claims:
            raise TokenDecodeError("Logout token lacks iat")
        if not claims.get("sid") and not claims.get("sub"):
            raise TokenDecodeError("Logout token names neither sid nor sub")
        return claims

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

    def _decode(
        self, raw_token: str, signing_key: PyJWK, *, require: tuple[str, ...] = ()
    ) -> dict[str, Any]:
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
                    "require": list(require),
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
