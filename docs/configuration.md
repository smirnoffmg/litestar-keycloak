# Configuration

All plugin behavior is controlled by **KeycloakConfig**, a frozen dataclass. Only three fields are required; the rest have defaults suitable for a typical confidential client using RS256.

## Required

| Field        | Description                                                                     |
| ------------ | ------------------------------------------------------------------------------- |
| `server_url` | Base Keycloak URL without trailing slash (e.g. `https://keycloak.example.com`). |
| `realm`      | Realm name.                                                                     |
| `client_id`  | OIDC client identifier.                                                         |

## Connection and client

| Field           | Default | Description                                                      |
| --------------- | ------- | ---------------------------------------------------------------- |
| `client_secret` | `None`  | Client secret for confidential clients. Omit for public clients. |

## Token location

| Field            | Default                | Description                                                                                                   |
| ---------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------ |
| `token_location` | `TokenLocation.HEADER` | Where the middleware **reads** the token: `HEADER` (Authorization) or `COOKIE`. If absent there, it falls back to the server-side session. |
| `cookie_name`    | `"access_token"`       | Cookie name when `token_location` is `COOKIE`. The plugin never sets this cookie — the app does.              |

## OIDC routes

| Field                    | Default       | Description                                                                                                   |
| ------------------------ | ------------- | ------------------------------------------------------------------------------------------------------------ |
| `include_routes`         | `False`       | If `True`, mount login, callback, logout, refresh under `auth_prefix`.                                        |
| `redirect_uri`           | `None`        | OAuth2 redirect URI. **Required** when `include_routes=True`.                                                 |
| `auth_prefix`            | `"/auth"`     | URL prefix for the mounted routes (e.g. `/auth/login`).                                                       |
| `scopes`                 | `("openid",)` | Scopes requested in the authorization code flow.                                                             |
| `callback_response_mode` | `"json"`      | `"json"`: callback returns tokens as JSON (SPA/BFF). `"redirect"`: stores tokens in the server-side session and redirects (requires session middleware). |
| `post_login_redirect_uri`| `"/"`         | Where `"redirect"`-mode login lands after storing tokens.                                                    |
| `post_logout_redirect_uri`| `None`       | Where `"redirect"`-mode logout redirects; returns JSON status when `None`.                                    |
| `cookie_secure`          | `True`        | `Secure` flag on the OAuth `state` cookie. Set `False` for plain-HTTP local dev.                              |
| `cookie_samesite`        | `"lax"`       | `SameSite` on the OAuth `state` cookie.                                                                       |
| `use_pkce`               | `False`       | Send a PKCE `S256` challenge on login and its verifier on the code exchange (RFC 7636). **Enable it for public clients**; recommended for confidential ones. |
| `validate_id_token`      | `False`       | Send an OIDC `nonce` on login and require the callback's ID token to be valid for this client and carry that nonce. Requires `"openid"` in `scopes`. |

For the redirect-mode flow (session middleware, endpoint behavior) see the [OIDC routes guide](guides/oidc-routes.md).

## JWT validation

| Field                 | Default       | Description                                                                                                                                                                       |
| --------------------- | ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `audience`            | `None`        | Expected `aud` claim; defaults to `client_id` when `None`.                                                                                                                        |
| `optional_audiences`  | `frozenset()` | Additional audiences to accept (e.g. a service client ID). Tokens with `aud` or `azp` in this set (or the primary audience) are accepted; with `strict_audience=True`, only `aud` counts. |
| `strict_audience`     | `False`       | If `True`, accept a token only when its `aud` (string or list) contains the primary audience or one of `optional_audiences`. `azp` is ignored, and a token without `aud` gets `401`. Add a Keycloak Audience mapper before enabling it — see [Service-to-service](guides/service-to-service.md#requiring-the-audience-in-aud-strict_audience). |
| `expected_issuer`     | `None`        | Expected `iss` claim; defaults to `{server_url}/realms/{realm}`. Set when Keycloak's frontend/hostname URL differs from `server_url` (e.g. behind a reverse proxy), so `iss` validation matches the value Keycloak signs. |
| `algorithms`          | `("RS256",)`  | Accepted JWT signing algorithms. RSA (`RS*`, `PS*`), EC (`ES*`) and Ed25519 (`EdDSA`) keys are supported; add e.g. `"ES256"` when the realm signs with an `ecdsa-generated` key provider. A token whose `alg` does not match the key type of its `kid` gets `401`. |
| `groups_claim`        | `"groups"`    | Claim holding the user's groups, as named on Keycloak's Group Membership mapper. See [Guards](guides/guards.md#groups-require_groups). |
| `leeway`              | `0`           | Seconds of clock skew tolerated when checking `exp`, `nbf` and `iat`. Set a few seconds if the app and Keycloak clocks may drift. |
| `expected_token_type` | `"Bearer"`    | Required payload `typ` claim. The default rejects Keycloak ID and Refresh tokens presented as access tokens. Set to `None` to disable the check (e.g. providers that omit `typ`). |

## Revocation (token introspection)

A JWT is checked locally against the realm's keys, so it stays valid until `exp` even after its session is logged out or its user disabled. Enable introspection to ask Keycloak about every locally valid token:

| Field                     | Default | Description |
| ------------------------- | ------- | ----------- |
| `token_introspection`     | `False` | Call Keycloak's introspection endpoint (RFC 7662) for each request whose token passed local validation. An inactive token gets `401`; if Keycloak cannot be reached or rejects the client's credentials, the request gets `502` — it is never let through. Requires `client_secret`. |
| `introspection_cache_ttl` | `0`     | Seconds to reuse a positive answer for the same token. `0` asks on every request, so a logout or a disabled user takes effect on the very next request; a positive value cuts the calls to Keycloak and lets a revoked token through for up to that many seconds. |

Verified against Keycloak 26: an admin-ended session and a disabled user both introspect as inactive at once. Without introspection, the only bound on how long a revoked token keeps working is the realm's access-token lifespan — keep it short (minutes) either way.

## JWKS and HTTP

| Field            | Default | Description                                                           |
| ---------------- | ------- | --------------------------------------------------------------------- |
| `jwks_cache_ttl` | `3600`  | Seconds to cache the JWKS before re-fetching. A token with an unknown `kid` (key rotation) forces a re-fetch regardless, at most once per 10 seconds. |
| `http_timeout`   | `10`    | Timeout in seconds for HTTP calls to Keycloak (JWKS, token endpoint). |

The plugin warms the JWKS cache on startup, but the warm-up is **best-effort**: if Keycloak is unreachable at boot the app still starts (a warning is logged) and keys are fetched on the first request. That request returns `502` until Keycloak becomes reachable, so a readiness probe on a protected route still reflects Keycloak availability.

## Path exclusions

There are three ways to let a request skip authentication:

| Field              | Default              | Description                                                                                          |
| ------------------ | -------------------- | --------------------------------------------------------------------------------------------------- |
| `excluded_paths`   | `frozenset()`        | Exact request paths that skip auth, e.g. `{"/", "/health"}`. Matched literally (`/health` ≠ `/health/`). |
| `exclude_patterns` | `()`                 | Regex patterns for prefixes/subtrees, e.g. `("^/public/", "^/docs")`. Anchor with `^` to match from the start. |
| `exclude_opt_key`  | `"exclude_from_auth"`| Route-handler `opt` key for per-handler opt-out.                                                     |
| `optional_auth_opt_key` | `"optional_auth"` | Route-handler `opt` key for [optional authentication](#optional-authentication).                  |

Per-handler opt-out marks a single route public regardless of the config lists:

```python
from litestar import get

@get("/webhook", exclude_from_auth=True)
async def webhook() -> dict:
    return {"ok": True}
```

## Optional authentication

A route can serve both anonymous and signed-in callers. Mark it with the `optional_auth_opt_key` (default `"optional_auth"`) and annotate the parameter with `OptionalCurrentUser`:

```python
from litestar import get
from litestar_keycloak import OptionalCurrentUser

@get("/feed", optional_auth=True)
async def feed(current_user: OptionalCurrentUser) -> dict:
    return {"personalized": current_user is not None}
```

Without a token the request proceeds with `current_user`, `token_payload` and `raw_token` set to `None` (use `OptionalTokenPayload` / `OptionalRawToken`). A token that *is* sent must still be valid — a bad one gets `401`, not a silent downgrade to anonymous. Keep the `Optional…` annotations on such routes: a plain `CurrentUser` there makes an anonymous request fail with `500` (`msgspec.ValidationError … at $.current_user`).

`OPTIONS` requests bypass authentication by default (CORS preflight). When `include_routes=True`, the auth routes under `auth_prefix` are automatically excluded so unauthenticated users can reach login and callback.

## Derived URLs

The plugin derives all Keycloak URLs from `server_url` and `realm`; you never build them manually.

| Property            | Value                                                     |
| ------------------- | --------------------------------------------------------- |
| `realm_url`         | `{server_url}/realms/{realm}`                             |
| `issuer`            | `{server_url}/realms/{realm}`, or `expected_issuer` when set (used to validate `iss`). |
| `jwks_url`          | `{realm_url}/protocol/openid-connect/certs`               |
| `authorization_url` | `{realm_url}/protocol/openid-connect/auth`                |
| `token_url`         | `{realm_url}/protocol/openid-connect/token`               |
| `logout_url`        | `{realm_url}/protocol/openid-connect/logout`              |
| `introspection_url` | `{realm_url}/protocol/openid-connect/token/introspect`     |

Endpoint URLs are built from the template above — the plugin does not fetch the OIDC discovery document.

## Validation

- `include_routes=True` and `redirect_uri=None` -> `ValueError`.
- `jwks_cache_ttl < 0` -> `ValueError`.
- `http_timeout <= 0` -> `ValueError`.
- `leeway < 0` -> `ValueError`.
- `token_introspection=True` and `client_secret=None` -> `ValueError`.
- `introspection_cache_ttl < 0` -> `ValueError`.
- `validate_id_token=True` without `"openid"` in `scopes` -> `ValueError`.

## Example

```python
from litestar_keycloak import KeycloakConfig, TokenLocation

config = KeycloakConfig(
    server_url="https://keycloak.example.com",
    realm="my-realm",
    client_id="my-app",
    client_secret="s3cret",
    token_location=TokenLocation.HEADER,
    include_routes=True,
    redirect_uri="https://app.example.com/auth/callback",
    auth_prefix="/auth",
    excluded_paths=frozenset({"/", "/health"}),
    optional_audiences=frozenset({"my-service"}),  # accept service tokens too
    jwks_cache_ttl=3600,
)
```
