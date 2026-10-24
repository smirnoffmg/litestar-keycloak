# Testing

## Unit tests (no Keycloak)

`litestar_keycloak.testing` (since 0.3.6) has helpers that need no real Keycloak server: `create_test_token` signs tokens with a key that exists only in the test process, and `MockKeycloakPlugin` is the real plugin with that key in place of the realm's JWKS. Guards, dependencies, routes and error responses behave as in production.

### create_test_token()

Builds a JWT signed with a fixed test key. Use it with **MockKeycloakPlugin** so validation succeeds without JWKS.

```python
from litestar_keycloak.testing import create_test_token, MockKeycloakPlugin
from litestar import Litestar, get
from litestar.testing import TestClient
from litestar_keycloak import CurrentUser

@get("/me")
async def me(current_user: CurrentUser) -> dict:
    return {"sub": current_user.sub, "roles": list(current_user.realm_roles)}

app = Litestar(route_handlers=[me], plugins=[MockKeycloakPlugin()])

def test_me():
    token = create_test_token(sub="user-1", realm_roles=["admin"])
    with TestClient(app) as client:
        resp = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["roles"] == ["admin"]
```

You can pass extra claims: `create_test_token(..., email="u@example.com", **kwargs)`; `exp_offset=-60` gives an expired token. Its defaults (`iss`, `aud`) match the defaults of `MockKeycloakPlugin()`.

### MockKeycloakPlugin()

A plugin that validates tokens using the same test key as `create_test_token()`. No JWKS fetch. Keyword arguments are any **KeycloakConfig** fields (e.g. `include_routes=True`, `strict_audience=True`); calls that do reach Keycloak — the auth routes, introspection, service tokens — still need it mocked.

## Integration tests (real Keycloak)

Use **pytest** with the `integration` marker. The test suite uses **testcontainers** to start Keycloak, import the realm from **tests/fixtures/realm-export.json**, and obtain real tokens.

Run only integration tests:

```bash
uv run pytest -m integration -v --timeout=120
```

Realm export defines:

- Realm: `test-realm`
- Client: `test-app` (secret `test-secret`), redirect URI for localhost
- Service client: `test-service` (secret `service-secret`), service account enabled
- Users: e.g. `testuser` / `testpass`, `testadmin` / `testpass`

Use the **keycloak_config** and **keycloak_container** fixtures; get tokens via the **user_token**, **admin_token**, or **obtain_token** helper in **tests/integration/conftest.py**.

## Examples smoke test

The **examples** app has a shell script that hits the main endpoints (public, user, admin, service-to-service). Keycloak and the example app must be running. From the repo root:

```bash
./examples/test.sh
# or: make test-examples
```

See **examples/README.md** for how to start Keycloak and the app (Docker or locally).
