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

| Field            | Default                | Description                                                           |
| ---------------- | ---------------------- | --------------------------------------------------------------------- |
| `token_location` | `TokenLocation.HEADER` | Where to read the Bearer token: `HEADER` (Authorization) or `COOKIE`. |
| `cookie_name`    | `"access_token"`       | Cookie name when `token_location` is `COOKIE`.                        |

## OIDC routes

| Field            | Default       | Description                                                            |
| ---------------- | ------------- | ---------------------------------------------------------------------- |
| `include_routes` | `False`       | If `True`, mount login, callback, logout, refresh under `auth_prefix`. |
| `redirect_uri`   | `None`        | OAuth2 redirect URI. **Required** when `include_routes=True`.          |
| `auth_prefix`    | `"/auth"`     | URL prefix for the mounted routes (e.g. `/auth/login`).                |
| `scopes`         | `("openid",)` | Scopes requested in the authorization code flow.                       |

## JWT validation

| Field                | Default       | Description                                                                                                                               |
| -------------------- | ------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `audience`           | `None`        | Expected `aud` claim; defaults to `client_id` when `None`.                                                                                |
| `optional_audiences` | `frozenset()` | Additional audiences to accept (e.g. a service client ID). Tokens with `aud` or `azp` in this set (or the primary audience) are accepted. |
| `algorithms`         | `("RS256",)`  | Accepted JWT signing algorithms.                                                                                                          |

## JWKS and HTTP

| Field            | Default | Description                                                           |
| ---------------- | ------- | --------------------------------------------------------------------- |
| `jwks_cache_ttl` | `3600`  | Seconds to cache the JWKS before re-fetching.                         |
| `http_timeout`   | `10`    | Timeout in seconds for HTTP calls to Keycloak (JWKS, token endpoint). |

## Path exclusions

| Field            | Default       | Description                                                                    |
| ---------------- | ------------- | ------------------------------------------------------------------------------ |
| `excluded_paths` | `frozenset()` | Request paths that skip authentication (exact match, e.g. `"/"`, `"/health"`). |

When `include_routes=True`, the auth routes under `auth_prefix` are automatically excluded so unauthenticated users can hit login and callback.

## Derived URLs

The plugin derives all Keycloak URLs from `server_url` and `realm`; you never build them manually.

| Property            | Value                                          |
| ------------------- | ---------------------------------------------- |
| `realm_url`         | `{server_url}/realms/{realm}`                  |
| `issuer`            | Same as `realm_url` (used to validate `iss`).  |
| `discovery_url`     | `{realm_url}/.well-known/openid-configuration` |
| `jwks_url`          | `{realm_url}/protocol/openid-connect/certs`    |
| `authorization_url` | `{realm_url}/protocol/openid-connect/auth`     |
| `token_url`         | `{realm_url}/protocol/openid-connect/token`    |
| `logout_url`        | `{realm_url}/protocol/openid-connect/logout`   |

## Validation

- `include_routes=True` and `redirect_uri=None` → `ValueError`.
- `jwks_cache_ttl < 0` → `ValueError`.
- `http_timeout <= 0` → `ValueError`.

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
