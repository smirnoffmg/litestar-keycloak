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

## Groups: `require_groups`

Require membership in one or more **groups** from the token's groups claim (`groups` by default, see `groups_claim`). Keycloak puts groups into the token only through a **Group Membership** mapper on the client or a client scope; names are compared exactly as the token carries them, so with the mapper's *Full group path* on, write `"/parent/child"`.

```python
from litestar_keycloak import MatchStrategy, require_groups

@get("/ops", guards=[require_groups("ops", "sre", strategy=MatchStrategy.ANY)])
async def ops_panel() -> dict:
    return {"msg": "ops"}
```

The built-in `microprofile-jwt` client scope also emits a `groups` claim, but it holds realm **roles**, not groups. If both are active on a client, point `groups_claim` at a different claim name for the group mapper.

## Step-up: `require_acr` and `require_recent_auth`

For sensitive operations, require a stronger or a fresher login:

```python
from litestar_keycloak import require_acr, require_recent_auth

@post("/payments", guards=[require_acr("2")])           # e.g. password + OTP
async def pay() -> dict: ...

@delete("/account", guards=[require_recent_auth(300)])  # signed in ≤ 5 min ago
async def close_account() -> None: ...
```

A failed check returns **`401`** with an RFC 9470 challenge, not `403`: the user *can* get through by signing in again, and the challenge tells the client what to ask Keycloak for —

```
WWW-Authenticate: Bearer error="insufficient_user_authentication",
  error_description="A different authentication level is required", acr_values="2"
```

(or `max_age="300"` for `require_recent_auth`). The client then restarts the login with `acr_values=2` or `max_age=300` in the authorization request. With `include_routes=True` that is `/auth/login?acr_values=2` or `/auth/login?max_age=300`: the login route passes `acr_values`, `max_age` and `prompt=login` on to Keycloak. For `acr_values` to take effect, the realm needs a step-up browser flow and an ACR-to-LoA mapping (*Realm settings → General → ACR to LoA Mapping*).

Keycloak adds `acr` through the `acr` client scope and `auth_time` through the `basic` scope, and `auth_time` only for interactive logins (not, for example, for password grants). `require_recent_auth` rejects a token without `auth_time`, since its login age is unknown.

## Any condition: `require_user`

When the check is not a plain role/group/scope test, pass a predicate over the `KeycloakUser`:

```python
from litestar_keycloak import require_user

@get("/reports", guards=[require_user(
    lambda u: u.has_role("auditor") or u.has_group("finance"),
    detail="Auditors or finance only",
)])
async def reports() -> dict: ...
```

`False` produces a `403` with `detail` as the error.

## MatchStrategy

- **MatchStrategy.ALL** — User must satisfy every required role/scope (default).
- **MatchStrategy.ANY** — User must satisfy at least one.

## Errors

When a guard fails it raises:

- **InsufficientRoleError** — For `require_roles` and `require_client_roles`; handled as `403` with a JSON body.
- **InsufficientGroupError** — For `require_groups`; handled as `403`.
- **InsufficientScopeError** — For `require_scopes`; handled as `403`.
- **AuthorizationError** — For `require_user`; handled as `403` with its `detail`.
- **InsufficientAuthenticationError** — For `require_acr` and `require_recent_auth`; handled as `401` with the step-up challenge above.

Every `403` carries `WWW-Authenticate: Bearer error="insufficient_scope"` (RFC 6750). Every denial — a `403` or a step-up `401` — is logged at `WARNING` on the `litestar_keycloak.exceptions` logger with the method, path, the caller's `sub` and the reason; route that logger to your security event log if denied requests must be audited.

If `connection.user` is not a **KeycloakUser** (e.g. an excluded path, or an anonymous request on an optional-auth route), every guard raises **InsufficientRoleError** (`403`).

## Identifying the user

`KeycloakUser` exposes `iss`, `sub`, `azp`, `groups`, `acr`, `auth_time`, `sid` and `is_service_account` (true for client_credentials tokens). To key data by user, use `iss` together with `sub` — never `preferred_username`, which can be reassigned.

Since Keycloak 25, `sub` comes from the `basic` client scope. A client whose default scopes leave `basic` out gets access tokens **without `sub`**, and the plugin then falls back to `preferred_username` for `KeycloakUser.sub`. Keep `basic` among the client's default scopes.

## Combining guards

You can pass multiple guards; all must pass for the request to reach the handler.

```python
@get("/premium", guards=[require_roles("user"), require_scopes("premium")])
async def premium() -> dict:
    return {"msg": "premium"}
```
