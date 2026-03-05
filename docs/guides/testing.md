# Testing

## Unit tests (no Keycloak)

Use the helpers in **tests/conftest.py** so you don't need a real Keycloak server.

### create_test_token()

Builds a JWT signed with a fixed test key. Use it with **MockKeycloakPlugin** so validation succeeds without JWKS.

```python
from tests.conftest import create_test_token, MockKeycloakPlugin
from litestar import Litestar, get
from litestar.testing import TestClient
from litestar_keycloak import KeycloakUser

@get("/me")
async def me(current_user: KeycloakUser) -> dict:
    return {"sub": current_user.sub, "roles": list(current_user.realm_roles)}

app = Litestar(route_handlers=[me], plugins=[MockKeycloakPlugin()])

def test_me():
    token = create_test_token(sub="user-1", realm_roles=["admin"])
    with TestClient(app) as client:
        resp = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["roles"] == ["admin"]
```

You can pass extra claims: `create_test_token(..., email="u@example.com", **kwargs)`.

### MockKeycloakPlugin()

A plugin that validates tokens using the same test key as `create_test_token()`. No HTTP calls to Keycloak; no JWKS fetch. Optional kwargs match **KeycloakConfig** (e.g. `server_url`, `realm`, `client_id`) for consistency but are not used for network calls.

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
