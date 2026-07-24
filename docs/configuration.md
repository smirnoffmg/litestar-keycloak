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

For the redirect-mode flow (session middleware, endpoint behavior) see the [OIDC routes guide](guides/oidc-routes.md).

## JWT validation

| Field                 | Default       | Description                                                                                                                                                                       |
| --------------------- | ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `audience`            | `None`        | Expected `aud` claim; defaults to `client_id` when `None`.                                                                                                                        |
| `optional_audiences`  | `frozenset()` | Additional audiences to accept (e.g. a service client ID). Tokens with `aud` or `azp` in this set (or the primary audience) are accepted.                                         |
| `expected_issuer`     | `None`        | Expected `iss` claim; defaults to `{server_url}/realms/{realm}`. Set when Keycloak's frontend/hostname URL differs from `server_url` (e.g. behind a reverse proxy), so `iss` validation matches the value Keycloak signs. |
| `algorithms`          | `("RS256",)`  | Accepted JWT signing algorithms.                                                                                                                                                  |
| `expected_token_type` | `"Bearer"`    | Required payload `typ` claim. The default rejects Keycloak ID and Refresh tokens presented as access tokens. Set to `None` to disable the check (e.g. providers that omit `typ`). |

## JWKS and HTTP

| Field            | Default | Description                                                           |
| ---------------- | ------- | --------------------------------------------------------------------- |
| `jwks_cache_ttl` | `3600`  | Seconds to cache the JWKS before re-fetching.                         |
| `http_timeout`   | `10`    | Timeout in seconds for HTTP calls to Keycloak (JWKS, token endpoint). |

The plugin warms the JWKS cache on startup, but the warm-up is **best-effort**: if Keycloak is unreachable at boot the app still starts (a warning is logged) and keys are fetched on the first request. That request returns `502` until Keycloak becomes reachable, so a readiness probe on a protected route still reflects Keycloak availability.

## Path exclusions

There are three ways to let a request skip authentication:

| Field              | Default              | Description                                                                                          |
| ------------------ | -------------------- | --------------------------------------------------------------------------------------------------- |
| `excluded_paths`   | `frozenset()`        | Exact request paths that skip auth, e.g. `{"/", "/health"}`. Matched literally (`/health` ≠ `/health/`). |
| `exclude_patterns` | `()`                 | Regex patterns for prefixes/subtrees, e.g. `("^/public/", "^/docs")`. Anchor with `^` to match from the start. |
| `exclude_opt_key`  | `"exclude_from_auth"`| Route-handler `opt` key for per-handler opt-out.                                                     |

Per-handler opt-out marks a single route public regardless of the config lists:

```python
from litestar import get

@get("/webhook", exclude_from_auth=True)
async def webhook() -> dict:
    return {"ok": True}
```

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

Endpoint URLs are built from the template above — the plugin does not fetch the OIDC discovery document.

## Validation

- `include_routes=True` and `redirect_uri=None` -> `ValueError`.
- `jwks_cache_ttl < 0` -> `ValueError`.
- `http_timeout <= 0` -> `ValueError`.

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
