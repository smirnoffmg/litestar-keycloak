# v0.3.4

Feature release covering the Keycloak features 0.3.3 lacked: EC and Ed25519 keys,
group and step-up guards, optional authentication, immediate revocation through
introspection, PKCE and ID token checks, session auto-refresh, back-channel logout,
and outbound service tokens. No breaking changes: every behaviour change is an
opt-in flag defaulting to the 0.3.3 behaviour, and every new field has a default.

## Token verification

- **EC and Ed25519 signing keys.** The JWKS cache used to skip every non-RSA key, so
  a realm with an `ecdsa-generated` or `eddsa-generated` key provider had all its
  tokens rejected. Such keys now load; add the algorithm to `algorithms`, e.g.
  `algorithms=("RS256", "ES256")`. EC keys published for encryption (`ECDH-ES`) are
  skipped.

- **`leeway`** (default `0`). Seconds of clock skew tolerated when checking `exp`,
  `nbf` and `iat`.

- **`WWW-Authenticate` challenges (RFC 6750).** `401` without a token carries a bare
  `Bearer`; a rejected token carries `error="invalid_token"` (plus
  `error_description="Token expired"` when expired); `403` carries
  `error="insufficient_scope"`. The response bodies are unchanged.

- **Denied requests are logged.** A `403` or a step-up `401` is logged at `WARNING`
  on the `litestar_keycloak.exceptions` logger with the method, path and the
  caller's `sub` — route that logger to your security event log if denials must be
  audited.

## Identity and guards

- **More of the token on `KeycloakUser`:** `iss`, `azp`, `groups`, `acr`,
  `auth_time`, `sid`, `is_service_account`, and `has_group()`. `TokenPayload` exposes
  `acr`, `auth_time` and `sid` as properties over `extra`, so code reading them from
  `extra` keeps working. Groups come from `groups_claim` (default `"groups"`), the
  claim named on Keycloak's Group Membership mapper.

- **New guards:** `require_groups` (ALL/ANY), `require_acr`,
  `require_recent_auth(max_age)` and `require_user(predicate)`. The step-up guards
  answer `401` with an RFC 9470 challenge (`insufficient_user_authentication`,
  `acr_values` or `max_age`), since the user can pass by signing in again.
  `require_recent_auth` fails closed without `auth_time`, which Keycloak adds only
  through the `basic` scope and only for interactive logins.

- **Optional authentication.** A handler marked `optional_auth=True` serves
  requests without a token, with `current_user`, `token_payload` and `raw_token` set
  to `None`; a token that is present must still be valid. Annotate with
  `OptionalCurrentUser`, `OptionalTokenPayload`, `OptionalRawToken`: a plain
  `CurrentUser` on such a route fails anonymous requests with a 500.

## Immediate revocation

- **`token_introspection`** (default off). A locally verified JWT stays valid until
  `exp` after its session is logged out or its user disabled. With this flag every
  token that passes local validation is also checked at Keycloak's introspection
  endpoint (RFC 7662); anything but `active: true` is a `401`. Junk tokens are
  refused locally first, without a call to Keycloak. It fails closed: an unreachable
  endpoint or rejected client credentials is a `502`. Requires `client_secret`.

- **`introspection_cache_ttl`** (default `0`, ask on every request) reuses positive
  answers for that many seconds, at most 10 000 tokens. Negative answers are not
  cached.

## Login flow

- **`use_pkce`** (default off) adds an S256 code challenge to `/auth/login` and sends
  the verifier on the code exchange (RFC 7636).

- **`validate_id_token`** (default off, requires the `openid` scope) adds a `nonce`
  and makes the callback refuse a login unless the response holds an ID token signed
  by the realm, issued by `issuer`, addressed to `client_id`, unexpired and carrying
  that nonce (OIDC Core 3.1.3.7).

- **The callback reports Keycloak's `?error=`** — denied consent, a refused request —
  as `401 Authorization failed: <code>` instead of "Missing authorization code".

- **Public clients no longer send an empty `client_secret`** on code exchange,
  refresh and logout.

## Session lifecycle

- **`session_auto_refresh`** (default off, `callback_response_mode="redirect"` only).
  An expired access token read from the session is renewed with the refresh token and
  written back; the request continues. A refresh Keycloak rejects is a `401`, any
  other failure a `502`. Bearer header tokens are never refreshed.

- **`backchannel_logout`** (default off, requires `include_routes`) mounts
  `POST {auth_prefix}/backchannel-logout`. It verifies Keycloak's logout token (OIDC
  Back-Channel Logout 1.0) and records the ended session in the `logout_store`
  Litestar store (in-memory by default — **register a shared store when running
  several instances**). From then on every token of that session is a `401`. Set the
  client's *Backchannel logout URL* in Keycloak to this endpoint.

  A refused session is not cleared from the session cookie — Litestar renders auth
  middleware errors outside the session middleware — but every request is refused
  until the next login overwrites it.

## Service-to-service

- **`service_tokens`**, injected as `ServiceTokens` or reached as
  `plugin.service_tokens`. Requires a confidential client.
  - `await service_tokens.client_token(scope=None)` — a `client_credentials` token
    for calling other services as this app, cached per scope and renewed before it
    expires; concurrent callers share one request.
  - `await service_tokens.exchange(token, audience="billing")` — RFC 8693 token
    exchange: the caller's token becomes one for the downstream service, for the same
    user. Needs Keycloak 26.2+ with standard token exchange enabled on the client.
  - A refusal or an unreachable Keycloak raises `ServiceTokenError` (`502`); the body
    names only the OAuth error code.

## Bug fixes

- **A token whose `alg` does not match its key type is a `401`, not a `500`.** With
  keys of several types in the JWKS, a token with `alg: RS256` pointing at an EC
  `kid` reached PyJWT as an unhandled `InvalidKeyError`.

- **Concurrent requests on a cold or expired JWKS cache fetch it once.** Since 0.3.3
  a second coroutine waiting on the refresh lock fetched the JWKS again; the test
  meant to catch this never actually ran its coroutines concurrently.

## Tests

- 327 unit and 35 integration tests, against Keycloak 26.0 and 26.4 (for token
  exchange). Integration tests drive real browser logins, Keycloak's own logout
  tokens and Admin REST API changes; each was checked to fail with its feature's
  code path disabled.
- `make test-integration` timeout raised from 120 s to 300 s.

## Upgrading

No changes needed. Before enabling the new flags:

- **Check that your clients have the `basic` client scope.** Without it Keycloak 25+
  omits `sub` and the plugin falls back to `preferred_username`, which can be
  reassigned; `require_recent_auth` also needs `auth_time` from that scope.
- **`backchannel_logout` with more than one instance** needs a shared Litestar store
  (e.g. Redis) registered under `logout_store`.
