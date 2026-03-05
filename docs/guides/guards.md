# Guards

Guards restrict route access by realm roles, client roles, or scopes. They run after the auth middleware, so `connection.user` is already set to a **KeycloakUser**. If the guard condition is not met, it raises an error that is mapped to `403 Forbidden` by the plugin's exception handlers.

## Realm roles: `require_roles`

Require one or more **realm-level** roles. By default the user must have **all** listed roles; use `MatchStrategy.ANY` to require at least one.

```python
from litestar import get
from litestar_keycloak import require_roles, MatchStrategy

@get("/admin", guards=[require_roles("admin")])
async def admin_only() -> dict:
    return {"msg": "admin"}

@get("/staff", guards=[require_roles("admin", "manager", strategy=MatchStrategy.ANY)])
async def staff() -> dict:
    return {"msg": "admin or manager"}
```

- **ALL** (default) — User must have every role in the list.
- **ANY** — User must have at least one of the roles.

## Client roles: `require_client_roles`

Require roles for a **specific Keycloak client** (from the token's `resource_access`). Use this for client-specific permissions (e.g. a "billing-service" client with roles `read`, `write`).

```python
from litestar_keycloak import require_client_roles

@get("/billing", guards=[require_client_roles("billing-service", "read")])
async def billing_read() -> dict:
    return {"msg": "billing read"}

@get("/billing/write", guards=[require_client_roles("billing-service", "read", "write")])
async def billing_write() -> dict:
    return {"msg": "billing read and write"}
```

Same **ALL** / **ANY** semantics via `strategy=MatchStrategy.ANY`.

## Scopes: `require_scopes`

Require one or more **scope** values from the token's `scope` claim (space-separated string, normalized to a set).

```python
from litestar_keycloak import require_scopes

@get("/reports", guards=[require_scopes("reports:read")])
async def reports() -> dict:
    return {"msg": "reports"}
```

## MatchStrategy

- **MatchStrategy.ALL** — User must satisfy every required role/scope (default).
- **MatchStrategy.ANY** — User must satisfy at least one.

## Errors

When a guard fails it raises:

- **InsufficientRoleError** — For `require_roles` and `require_client_roles`; handled as `403` with a JSON body.
- **InsufficientScopeError** — For `require_scopes`; handled as `403`.

If `connection.user` is not a **KeycloakUser** (e.g. excluded path returning `None`), the role guards raise **InsufficientRoleError** as well.

## Combining guards

You can pass multiple guards; all must pass for the request to reach the handler.

```python
@get("/premium", guards=[require_roles("user"), require_scopes("premium")])
async def premium() -> dict:
    return {"msg": "premium"}
```
