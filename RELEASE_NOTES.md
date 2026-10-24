# v0.3.5

Hardening release from a security review of 0.3.4. It fixes requests any client
could turn into a `500` or a leak of internal details, keeps authentication
working while Keycloak is briefly unreachable, and adds opt-in protection against
session fixation. No breaking changes: new protections are opt-in flags, and the
remaining changes turn crashes into the `401`/`502` they should have been.

## Security

- **`session_binding`** (default off, `callback_response_mode="redirect"` only).
  Litestar keeps the session id across login and accepts any id a browser
  presents, so an attacker who planted a `session` cookie in the victim's browser
  shared the victim's login. With this flag the callback also sets an HttpOnly
  `kc_session_binding` cookie and keeps its SHA-256 in the session; the session's
  tokens are accepted only alongside it. **Recommended for every redirect-mode
  app.** Users signed in before it is switched on log in once more; the cookie
  lasts until the browser closes.

- **`502` bodies no longer echo internal details.** They named Keycloak's internal
  URL and the network error to unauthenticated callers. The body is now
  `{"error": "Keycloak request failed"}`; the detail is logged at `WARNING` on
  `litestar_keycloak.exceptions`.

- **`require_sub`** (default off). Refuse a token without `sub` instead of using
  `preferred_username`, which Keycloak 25+ hands out instead of `sub` when a client
  lacks the `basic` scope and which can be reassigned.

- **Warning for lenient audiences.** `optional_audiences` without
  `strict_audience=True` is logged at `WARNING`: the lenient check also accepts any
  token whose `azp` is an optional audience, whatever its `aud`. Consider
  `strict_audience=True`; it becomes the default in 0.4.

## Bug fixes

- **Token endpoint failures are `401`/`502`, not `500`.** A reused authorization
  code, an expired refresh token, an unreachable Keycloak or a malformed request
  body crashed `/auth/callback`, `/auth/refresh` and `/auth/logout`. Keycloak
  refusing a grant is now a `401`, any other failure a `502`. Logout stays
  best-effort: it completes locally even if Keycloak cannot be reached.

- **A token with an unknown `kid` is a `401`, not a `502`.** It raises
  `UnknownSigningKeyError`, which is still a `JWKSFetchError`, so existing
  `except` clauses keep catching it.

- **An `ES256` token on a P-384 key is a `401`, not a `500`.** The alg check now
  compares the EC curve as well as the key type.

- **Tokens without `exp` or `iat` are a `401`.** Access tokens crashed with a
  `500`; ID tokens without `exp` were accepted.

- **Authentication survives a Keycloak outage.** When the JWKS fetch failed, each
  waiting request repeated it in turn, so N concurrent requests took N times the
  HTTP timeout; and after the TTL, cached keys were dropped before a replacement
  arrived. Waiting requests now share one attempt, no new fetch is tried for 5
  seconds after a failure, and cached keys keep verifying tokens while Keycloak
  cannot be reached.

- **Concurrent requests on a cold or expired JWKS cache fetch it once** (0.3.3
  fetched it twice).

- **A guard on an anonymous `optional_auth` request is a `401`** with a `Bearer`
  challenge, not `403 Missing roles: `.

- **Token responses carry `Cache-Control: no-store`** (RFC 6749 §5.1) on
  `/auth/callback` and `/auth/refresh` in JSON mode.

## New

- **`/auth/login` passes on `acr_values`, `max_age` and `prompt`**, so an app can
  answer its own step-up challenge (`401 insufficient_user_authentication`) by
  sending the user to `/auth/login?acr_values=2` or `?max_age=300`. Values are
  checked against strict patterns.

## Configuration checks

`KeycloakConfig` now raises `ValueError` for settings that could not work:

- `cookie_samesite="none"` without `cookie_secure=True` — browsers drop the cookie,
  so every login failed its state check;
- an `auth_prefix` with a trailing slash — `/auth/login` then demanded a token;
- `algorithms` without any `RS*`, `PS*`, `ES*` or `EdDSA` entry. `HS*` or `none`
  next to them is logged at `WARNING`.

## Documentation

The README, `docs/index.md` and the testing guide no longer contradict the code:
every non-excluded route needs a token (not just those declaring `CurrentUser`),
session middleware is needed only in redirect mode, and the test helpers live in
this repository's `tests/conftest.py`, not in the package.

## Tests

390 unit and 36 integration tests. New integration test: a real browser login into
a planted session id, then the same id without the binding cookie, gets `401`.
Two concurrency tests that never actually raced (a bare `AsyncMock` does not yield)
now do, and fail without the lock.

## Upgrading

No changes needed. Recommended:

- redirect mode: `session_binding=True`, and `secure=True` on
  `ServerSideSessionConfig` in production;
- once every client has the `basic` scope: `require_sub=True`;
- if you see the `optional_audiences` warning: add an Audience mapper in Keycloak
  and set `strict_audience=True`.

If you parsed the text of `502` responses, read the log instead.
