# v0.3.5

Hardening release from a security review of 0.3.4: fixes requests any client
could turn into a `500` or a leak of internal details, keeps authentication working
while Keycloak is briefly unreachable, and adds opt-in protection against session
fixation.

## Before you upgrade

- **The app may refuse to start** if its configuration could never have worked.
  `KeycloakConfig` now raises `ValueError` for `cookie_samesite="none"` without
  `cookie_secure=True` (browsers drop the cookie, so every login failed its state
  check), for an `auth_prefix` with a trailing slash (`/auth/login` then demanded a
  token), and for `algorithms` with no `RS*`, `PS*`, `ES*` or `EdDSA` entry.
- **Some status codes change.** If alerts or clients key on them:
  - a token with an unknown `kid` is `401` (was `502`);
  - a guard on an anonymous `optional_auth` request is `401` with a `Bearer`
    challenge (was `403 Missing roles: `);
  - Keycloak refusing a code exchange or refresh is `401`, any other token endpoint
    failure `502` (both were `500`).
- **`502` bodies are now always `{"error": "Keycloak request failed"}`.** The detail
  moved to the `WARNING` log of `litestar_keycloak.exceptions`.

## After you upgrade

- **Redirect mode: set `session_binding=True`**, and `secure=True` on
  `ServerSideSessionConfig` in production. Without it, an attacker who plants a
  `session` cookie in a victim's browser shares the victim's login. Users signed in
  before the switch log in once more.
- **Once every client has the `basic` scope: set `require_sub=True`.** Otherwise a
  token without `sub` is keyed by `preferred_username`, which can be reassigned.
- **If the log warns about `optional_audiences`:** add an Audience mapper in
  Keycloak and set `strict_audience=True`. Without it, a token another API received
  from the same client is accepted too. It becomes the default in 0.4.

## Security

- **`session_binding`** (default off, redirect mode only). Litestar keeps the session
  id across login and accepts any id a browser presents, so the redirect-mode
  callback wrote the victim's tokens into a session the attacker also holds. With the
  flag, the callback sets an HttpOnly `kc_session_binding` cookie and keeps its
  SHA-256 in the session; the session's tokens are accepted only alongside it. The
  cookie lasts until the browser closes.
- **`502` responses no longer reveal Keycloak's internal URL** or the network error
  to unauthenticated callers.
- **`require_sub`** (default off) refuses a token without `sub` with `401`.
- **`optional_audiences` without `strict_audience`** is logged at `WARNING`, and so
  are `HS*` or `none` entries in `algorithms`.

## Bug fixes

- **Authentication survives a Keycloak outage.** Cached keys keep verifying tokens
  past the JWKS TTL while Keycloak cannot be reached. Concurrent requests share one
  fetch attempt, and no new one is tried for 5 seconds after a failure; before, N
  waiting requests took N times the HTTP timeout.
- **No more `500`s from the auth routes.** A reused authorization code, an expired
  refresh token, an unreachable Keycloak or a malformed body crashed
  `/auth/callback`, `/auth/refresh` and `/auth/logout`. Logout now completes locally
  even if Keycloak cannot be reached.
- **No more `500`s from crafted tokens:** an `ES256` header on a P-384 key, or a
  token without `exp` or `iat`, is a `401`. An ID token without `exp` is refused.
- **The unknown-`kid` error is `UnknownSigningKeyError`,** a `TokenDecodeError` that
  is still a `JWKSFetchError`, so existing `except` clauses keep catching it.
- **A cold or expired JWKS cache is fetched once** under concurrent requests (0.3.3
  fetched it twice).
- **Token responses carry `Cache-Control: no-store`** on `/auth/callback` and
  `/auth/refresh` in JSON mode (RFC 6749 §5.1).

## New

- **`/auth/login` passes on `acr_values`, `max_age` and `prompt`,** so an app answers
  its own step-up challenge by sending the user to `/auth/login?acr_values=2` or
  `?max_age=300`. Values outside strict patterns are dropped.

## Also

The README, `docs/index.md` and the testing guide no longer contradict the code;
notably, every route not excluded needs a token, not only those declaring
`CurrentUser`. 390 unit and 36 integration tests.
