# litestar-keycloak

Keycloak OIDC/OAuth2 authentication plugin for [Litestar](https://litestar.dev/). It uses Litestar's plugin protocol, dependency injection, and guard system so you can protect routes with Bearer tokens and optional login/callback/logout flows.

## Features

- **OIDC discovery and JWKS** — Fetches and caches Keycloak's JSON Web Key Set with configurable TTL; retries once on key rotation.
- **Bearer token validation** — Reads the token from the `Authorization` header or a cookie; validates signature, issuer, audience, and expiry.
- **Guards** — Realm roles, client roles, and scopes with ALL/ANY match strategies.
- **Dependency injection** — `KeycloakUser`, `TokenPayload`, and raw token string are available as request dependencies.
- **Optional OIDC routes** — Mount `/auth/login`, `/auth/callback`, `/auth/logout`, `/auth/refresh` when `include_routes=True` (requires session middleware).
- **Service-to-service** — Accept tokens from multiple audiences (e.g. a service client) via `optional_audiences`; supports client_credentials and token forwarding.

## Installation

```bash
pip install litestar-keycloak
```

Requires Python 3.12+. Dependencies: `litestar[standard]` ≥ 2.0, `aiohttp`, `PyJWT[crypto]`.

## Quick start

```python
from litestar import Litestar, get
from litestar_keycloak import KeycloakPlugin, KeycloakConfig, KeycloakUser

@get("/me")
async def me(current_user: KeycloakUser) -> dict:
    return {
        "sub": current_user.sub,
        "username": current_user.preferred_username,
        "roles": list(current_user.realm_roles),
    }

app = Litestar(
    route_handlers=[me],
    plugins=[
        KeycloakPlugin(
            KeycloakConfig(
                server_url="https://keycloak.example.com",
                realm="my-realm",
                client_id="my-app",
            )
        )
    ],
)
```

Any route that declares `current_user: KeycloakUser` (or `token_payload` / `raw_token`) requires a valid Bearer token. Requests without a token or with an invalid token receive `401 Unauthorized`.

## Configuration

The plugin is configured with a single **KeycloakConfig** instance. Only `server_url`, `realm`, and `client_id` are required; the rest have defaults.

| Option               | Default                | Description                                              |
| -------------------- | ---------------------- | -------------------------------------------------------- |
| `server_url`         | —                      | Base Keycloak URL (no trailing slash).                   |
| `realm`              | —                      | Realm name.                                              |
| `client_id`          | —                      | OIDC client ID.                                          |
| `client_secret`      | `None`                 | Client secret for confidential clients.                  |
| `token_location`     | `TokenLocation.HEADER` | Where to read the token: `HEADER` or `COOKIE`.           |
| `cookie_name`        | `"access_token"`       | Cookie name when using `COOKIE`.                         |
| `include_routes`     | `False`                | Mount login/callback/logout/refresh under `auth_prefix`. |
| `redirect_uri`       | `None`                 | Required when `include_routes=True`.                     |
| `auth_prefix`        | `"/auth"`              | URL prefix for OIDC routes.                              |
| `excluded_paths`     | `frozenset()`          | Paths that skip authentication (exact match).            |
| `audience`           | `None`                 | Expected `aud` claim; defaults to `client_id`.           |
| `optional_audiences` | `frozenset()`          | Extra audiences (e.g. service client IDs) to accept.     |
| `jwks_cache_ttl`     | `3600`                 | JWKS cache TTL in seconds.                               |
| `algorithms`         | `("RS256",)`           | Accepted JWT algorithms.                                 |
| `http_timeout`       | `10`                   | Timeout for HTTP calls to Keycloak.                      |

See [Configuration](configuration.md) for full detail and derived URLs.

## Guards

Use guards to require specific realm roles, client roles, or scopes:

```python
from litestar import get
from litestar_keycloak import require_roles, require_client_roles, require_scopes, MatchStrategy

@get("/admin", guards=[require_roles("admin")])
async def admin() -> dict:
    return {"msg": "admin only"}

@get("/staff", guards=[require_roles("admin", "manager", strategy=MatchStrategy.ANY)])
async def staff() -> dict:
    return {"msg": "admin or manager"}

@get("/billing", guards=[require_client_roles("billing-service", "read")])
async def billing() -> dict:
    return {"msg": "billing read"}

@get("/reports", guards=[require_scopes("reports:read")])
async def reports() -> dict:
    return {"msg": "reports"}
```

See [Guards](guides/guards.md).

## OIDC routes (login / callback / logout / refresh)

Set `include_routes=True` and provide `redirect_uri` to mount:

| Method and path      | Description                                                        |
| -------------------- | ------------------------------------------------------------------ |
| `GET /auth/login`    | Redirects to Keycloak's authorization endpoint.                    |
| `GET /auth/callback` | Exchanges the authorization code for tokens (returns JSON).        |
| `POST /auth/logout`  | Ends session (Keycloak + local); body may include `refresh_token`. |
| `POST /auth/refresh` | Body: `{"refresh_token": "..."}`; returns new tokens.              |

**Session required** — Login stores OAuth `state` in the session; callback validates it. You must add Litestar's session middleware (e.g. `CookieBackendConfig` or `ServerSideSessionConfig`) yourself.

See [OIDC routes](guides/oidc-routes.md).

## Service-to-service

To accept tokens from both your user client and a service client (e.g. client_credentials):

1. Add the service client ID to **optional_audiences**.
2. Tokens with `aud` or `azp` equal to that client are accepted (Keycloak often sets `aud="account"` for service tokens; the plugin accepts by `azp` when configured).

```python
KeycloakConfig(
    server_url="https://keycloak.example.com",
    realm="my-realm",
    client_id="my-app",
    client_secret="...",
    optional_audiences=frozenset({"my-service-client"}),
)
```

Use the **raw_token** dependency to forward the caller's token to a downstream API. See [Service-to-service](guides/service-to-service.md).

## Dependency injection

The plugin registers these dependencies (by parameter name):

| Parameter       | Type           | Description                              |
| --------------- | -------------- | ---------------------------------------- |
| `current_user`  | `KeycloakUser` | Identity built from the validated token. |
| `token_payload` | `TokenPayload` | Decoded JWT claims (OIDC + Keycloak).    |
| `raw_token`     | `str`          | Raw JWT string (e.g. for forwarding).    |

Use them in route handlers; they are only available on authenticated requests.

## Testing

- **Unit tests** — Use `create_test_token()` and `MockKeycloakPlugin()` from `tests/conftest.py` so no Keycloak server is needed.
- **Integration tests** — Use testcontainers and the realm export under `tests/fixtures/`.

See [Testing](guides/testing.md).

## Example app

The **examples** directory in the repo contains a full Litestar app with docker-compose, Dockerfile, and a smoke script:

- User and admin routes, guards, optional OIDC routes.
- Service-to-service: client_credentials and user token forwarding.
- `./examples/test.sh` runs smoke tests; see `examples/README.md`.

## API reference

[API Reference](api.md) — Generated from the public package surface: `KeycloakPlugin`, `KeycloakConfig`, `TokenLocation`, `KeycloakUser`, `TokenPayload`, guards, and `MatchStrategy`.
