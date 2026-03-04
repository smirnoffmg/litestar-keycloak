# litestar-keycloak

Keycloak authentication plugin for [Litestar](https://litestar.dev/).
OIDC/OAuth2 integration using Litestar's native plugin protocol, dependency injection, and guard system.

## Features

- OIDC discovery and JWKS caching with automatic key rotation
- Bearer token validation (header or cookie)
- Realm and client role guards
- Scope-based access control
- `KeycloakUser` injection via Litestar DI
- Optional login/callback/logout route group
- Async HTTP via aiohttp for token exchange and JWKS requests

## Installation

```bash
pip install litestar-keycloak
```

## Quick Start

```python
from litestar import Litestar, get
from litestar_keycloak import KeycloakPlugin, KeycloakConfig, KeycloakUser

@get("/me")
async def me(current_user: KeycloakUser) -> dict:
    return {
        "sub": current_user.sub,
        "username": current_user.preferred_username,
        "roles": current_user.realm_roles,
    }

app = Litestar(
    route_handlers=[me],
    plugins=[KeycloakPlugin(
        KeycloakConfig(
            server_url="https://keycloak.example.com",
            realm="my-realm",
            client_id="my-app",
        )
    )],
)
```

Any route that declares `current_user: KeycloakUser` automatically requires a valid Bearer token.

## Guards

Restrict access by roles or scopes:

```python
from litestar import get
from litestar_keycloak import require_roles, require_scopes

@get("/admin", guards=[require_roles("admin")])
async def admin_panel() -> dict:
    return {"msg": "welcome, admin"}

@get("/reports", guards=[require_scopes("reports:read")])
async def reports() -> dict:
    return {"msg": "here are your reports"}
```

## Configuration

```python
KeycloakConfig(
    server_url="https://keycloak.example.com",
    realm="my-realm",
    client_id="my-app",
    client_secret="secret",            # confidential clients
    token_location=TokenLocation.HEADER,  # HEADER (default) or COOKIE
    jwks_cache_ttl=3600,               # JWKS cache lifetime in seconds
    algorithms=("RS256",),             # JWT signing algorithms
    include_routes=False,              # mount /auth/login, /callback, /logout
)
```

When `include_routes=True`, the plugin mounts:

| Endpoint             | Description                        |
| -------------------- | ---------------------------------- |
| `GET /auth/login`    | Redirect to Keycloak authorize     |
| `GET /auth/callback` | Handle authorization code exchange |
| `POST /auth/logout`  | End session (Keycloak + local)     |
| `POST /auth/refresh` | Refresh access token               |

## Testing

### Unit tests (no Keycloak required)

Test utilities live in `tests/conftest.py`: `create_test_token()` and `MockKeycloakPlugin()`. Use them in your tests (e.g. when running pytest from this repo, or import from conftest):

```python
from tests.conftest import create_test_token, MockKeycloakPlugin

# Mint a fake JWT with arbitrary claims
token = create_test_token(sub="user-1", realm_roles=["admin"])

# Use MockKeycloakPlugin to skip real JWKS validation
app = Litestar(
    route_handlers=[...],
    plugins=[MockKeycloakPlugin()],
)
```

### Integration tests (real Keycloak via testcontainers)

```python
from testcontainers.keycloak import KeycloakContainer

kc = (
    KeycloakContainer("quay.io/keycloak/keycloak:26.0")
    .with_command("start-dev --import-realm")
    .with_volume_mapping(
        "tests/fixtures/realm-export.json",
        "/opt/keycloak/data/import/realm-export.json",
        "ro",
    )
)
kc.start()
```

See `tests/fixtures/realm-export.json` for a pre-configured realm with test users and roles.

## Dependencies

| Package             | Purpose                          |
| ------------------- | -------------------------------- |
| `litestar[standard]` ≥ 2.0 | Web framework (plugin target)   |
| `aiohttp`           | Async HTTP for token/JWKS calls  |
| `PyJWT[crypto]`     | JWT validation                   |

## License

MIT
