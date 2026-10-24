# litestar-keycloak

[![PyPI version](https://img.shields.io/pypi/v/litestar-keycloak)](https://pypi.org/project/litestar-keycloak/)
[![Python versions](https://img.shields.io/pypi/pyversions/litestar-keycloak)](https://pypi.org/project/litestar-keycloak/)
[![License](https://img.shields.io/pypi/l/litestar-keycloak)](https://pypi.org/project/litestar-keycloak/)
[![CI](https://img.shields.io/github/actions/workflow/status/smirnoffmg/litestar-keycloak/ci.yml?branch=main)](https://github.com/smirnoffmg/litestar-keycloak/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/codecov/c/github/smirnoffmg/litestar-keycloak)](https://codecov.io/gh/smirnoffmg/litestar-keycloak)
[![Checked with mypy](https://img.shields.io/badge/mypy-strict-2a6db2)](https://mypy-lang.org/)

Keycloak OIDC/OAuth2 authentication plugin for [Litestar](https://litestar.dev/) —
token validation, dependency injection, and guards via Litestar's native plugin protocol.

📖 **[Documentation](https://smirnoffmg.dev/litestar-keycloak/)**

## Features

- Bearer token validation (header, cookie, or server-side session)
- JWKS caching with automatic key rotation
- Realm/client role, group, scope and step-up (`acr`, recent login) guards
- Optional token introspection, so a logout or a disabled user takes effect at once
- Outbound service tokens: cached client_credentials and RFC 8693 token exchange
- `KeycloakUser` injection via Litestar DI
- Optional login/callback/logout/refresh routes — SPA (JSON) or server-rendered (session) flow

## Installation

```bash
uv add litestar-keycloak
```

## Quick start

```python
from litestar import Litestar, get
from litestar_keycloak import KeycloakPlugin, KeycloakConfig, CurrentUser

@get("/me")
async def me(current_user: CurrentUser) -> dict:
    return {"sub": current_user.sub, "roles": current_user.realm_roles}

app = Litestar(
    route_handlers=[me],
    plugins=[KeycloakPlugin(KeycloakConfig(
        server_url="https://keycloak.example.com",
        realm="my-realm",
        client_id="my-app",
    ))],
)
```

Every route requires a valid Bearer token unless it is excluded (`excluded_paths`, `exclude_patterns`, `exclude_from_auth=True`) or marked `optional_auth=True`; declaring `current_user: CurrentUser` only gives the handler the user.

## Guards

```python
from litestar_keycloak import require_roles, require_scopes

@get("/admin", guards=[require_roles("admin")])
async def admin_panel() -> dict: ...

@get("/reports", guards=[require_scopes("reports:read")])
async def reports() -> dict: ...
```

## Documentation

Configuration, guards, OIDC routes, and the SPA / server-rendered flows are covered in the
**[full documentation](https://smirnoffmg.dev/litestar-keycloak/)**. A runnable
[example app](examples/) with docker-compose is included.

## License

MIT
