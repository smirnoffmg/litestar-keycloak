# OIDC routes

When **include_routes** is `True`, the plugin mounts a route group under **auth_prefix** (default `/auth`) that implements the authorization code flow and token refresh.

## Endpoints

| Method and path      | Description                                                                                                                                                       |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /auth/login`    | Redirects the user to Keycloak's authorization endpoint with `response_type=code`, `client_id`, `redirect_uri`, `scope`, and a random `state`.                    |
| `GET /auth/callback` | Expects `code` and `state` in the query string; verifies `state` against the session, exchanges the code for tokens, and returns the token response as JSON.      |
| `POST /auth/logout`  | Optional body: `{"refresh_token": "..."}`. If provided, calls Keycloak's end-session endpoint; then clears the local session. Returns `{"status": "logged_out"}`. |
| `POST /auth/refresh` | Body: `{"refresh_token": "..."}`. Exchanges the refresh token for new tokens and returns the JSON response.                                                       |

## Session requirement

The login handler stores a random **state** in the session to mitigate CSRF. The callback reads that state and rejects the request if it does not match. Therefore you **must** add Litestar's session middleware to your app when using these routes.

Example with server-side session and in-memory store:

```python
from litestar import Litestar
from litestar.middleware.session.server_side import ServerSideSessionConfig
from litestar.stores.memory import MemoryStore
from litestar_keycloak import KeycloakPlugin, KeycloakConfig

config = KeycloakConfig(
    server_url="https://keycloak.example.com",
    realm="my-realm",
    client_id="my-app",
    client_secret="secret",
    include_routes=True,
    redirect_uri="https://app.example.com/auth/callback",
)

session_config = ServerSideSessionConfig(store="sessions")

app = Litestar(
    route_handlers=[...],
    plugins=[KeycloakPlugin(config)],
    middleware=[session_config.middleware],
    stores={"sessions": MemoryStore()},
)
```

Without session middleware, callback will fail (state mismatch or missing session).

## Redirect URI

Set **redirect_uri** to the full URL of your callback as registered in Keycloak (e.g. `https://app.example.com/auth/callback`). It must match the client's configured redirect URI in the realm.

## Callback response

The callback returns the **raw token endpoint response** as JSON (e.g. `access_token`, `refresh_token`, `expires_in`). The application can then:

- Store tokens in cookies or session for browser-based access.
- Return them to a SPA or client that will use the access token in the `Authorization` header.

The plugin does not set cookies for you; you can add a custom route or middleware to do that if needed.

## Logout

POST to `/auth/logout` with optional `refresh_token` in the body. The plugin will try to invalidate the refresh token at Keycloak and then clear the local session. Even if the Keycloak call fails, the local session is always cleared.
