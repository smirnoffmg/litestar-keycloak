# litestar-keycloak example

A minimal Litestar app using the Keycloak plugin with OIDC routes (login, callback, logout, refresh), session-backed OAuth state, and role guards.

## Quick start with Docker

From the **repository root**:

```bash
docker compose -f examples/docker-compose.yml up --build
```

- **App**: http://localhost:8000
- **Keycloak**: http://localhost:8080 (admin: `admin` / `admin`)

The example app uses `network_mode: host` so it can reach Keycloak at `localhost:8080` and the token issuer matches. On **Docker Desktop (Mac/Windows)** the app may not be reachable at `localhost:8000` from your machine; use “Run app locally” below or run the app container and call the API from inside it.

### Try it

1. Open http://localhost:8000 — landing with links.
2. **Login (browser)**: open http://localhost:8000/auth/login — redirects to Keycloak. Log in with:
   - **testuser** / **testpass** (realm role `user`)
   - **testadmin** / **testpass** (realm roles `admin`, `user`)
3. **API with token**: after login, `/auth/callback` returns JSON with `access_token`. Use it:
   ```bash
   curl -H "Authorization: Bearer <access_token>" http://localhost:8000/me
   curl -H "Authorization: Bearer <access_token>" http://localhost:8000/admin  # requires admin
   ```
4. **OpenAPI**: http://localhost:8000/schema
5. **Service-to-service** (see below).

## Service-to-service communication

Two patterns are demonstrated:

### 1. Service account (client_credentials)

The app obtains a token as the **test-service** client (no user) and calls an internal backend:

- **GET /service/call-backend** — no user token. The app calls Keycloak with `grant_type=client_credentials` for `test-service` / `service-secret`, then calls `GET /internal/backend` with that token. Use this for machine-to-machine or backend-to-backend calls.

### 2. User token forwarding

The current user’s token is forwarded to a downstream API so the backend sees the same identity:

- **GET /user/forward** — requires a valid user Bearer token. Forwards that token to `GET /internal/backend` and returns the backend response. Use this when the downstream service should authorize the same user.

### Internal backend

- **GET /internal/backend** — requires any valid Bearer token (user or service). Returns `called_by_sub`, `called_by_client` (azp), and roles. In production you could protect it with `require_client_roles("test-service", "read")` so only the service account (or users with that client role) can call it.

Env (optional): `KEYCLOAK_SERVICE_CLIENT_ID`, `KEYCLOAK_SERVICE_CLIENT_SECRET` (defaults: `test-service`, `service-secret`), `BACKEND_BASE_URL` (default: `http://127.0.0.1:8000` for self-calls).

## Running the smoke tests

With Keycloak and the example app already running (Docker or locally):

```bash
./examples/test.sh
```

Optional env: `KEYCLOAK_URL` (default `http://localhost:8080`), `APP_URL` (default `http://localhost:8000`), `REALM`, `CLIENT_ID`, `CLIENT_SECRET`, `SERVICE_CLIENT_ID`, `SERVICE_CLIENT_SECRET`. The script checks public routes, user/admin tokens, and service-to-service endpoints; exit 0 if all pass.

From the repo root you can run `make test-examples` (Keycloak and the example app must already be running).

## Run app locally (Keycloak in Docker)

If you prefer not to use `network_mode: host` for the app:

1. Start Keycloak only:

   ```bash
   docker compose -f examples/docker-compose.yml up keycloak --build
   ```

2. From the repo root (with the project installed, e.g. `pip install -e .`):

   ```bash
   cd examples/app && python -m uvicorn main:app --reload --port 8000
   ```

   Or:

   ```bash
   KEYCLOAK_SERVER_URL=http://localhost:8080 python -m uvicorn main:app --reload --port 8000 --app-dir examples/app
   ```

3. Use the app at http://localhost:8000 as above.

## Realm and users

The compose file imports `tests/fixtures/realm-export.json`, which defines:

- **Realm**: `test-realm`
- **Client**: `test-app` (confidential, secret `test-secret`), redirect URI `http://localhost:8000/auth/callback`
- **Service client**: `test-service` (confidential, secret `service-secret`, service account enabled) — for client_credentials / service-to-service
- **Users**: `testuser` / `testpass`, `testadmin` / `testpass`, `testnorolesuser` / `testpass`

## What the example shows

- **KeycloakPlugin** with `KeycloakConfig`: `server_url`, `realm`, `client_id`, `client_secret`, `include_routes=True`, `redirect_uri`.
- **Session middleware** (server-side with `MemoryStore`) for OAuth `state` between `/auth/login` and `/auth/callback`.
- **Excluded paths**: `/` and `/health` do not require auth.
- **Protected routes**: `/me` (any valid token), `/admin` (guard `require_roles("admin")`).
- **Optional OIDC routes**: `/auth/login`, `/auth/callback`, `/auth/logout`, `/auth/refresh`.
- **Service-to-service**: `/service/call-backend` (client_credentials), `/user/forward` (forward user token), `/internal/backend` (accepts any valid token).

## Build the app image only

From the repo root:

```bash
docker build -f examples/Dockerfile -t litestar-keycloak-example .
```

Run with Keycloak already available at `localhost:8080` (e.g. started by the compose above):

```bash
docker run --network host -e KEYCLOAK_SERVER_URL=http://localhost:8080 litestar-keycloak-example
```

Then open http://localhost:8000.
