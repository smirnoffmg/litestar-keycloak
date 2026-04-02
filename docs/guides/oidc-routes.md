# OIDC routes

When **include_routes** is `True`, the plugin mounts a route group under **auth_prefix** (default `/auth`) that implements the authorization code flow and token refresh.

## Endpoints

| Method and path      | Description                                                                                                                                                                                                                                                                                                                                              |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /auth/login`    | Redirects the user to Keycloak's authorization endpoint with `response_type=code`, `client_id`, `redirect_uri`, `scope`, and a random `state`.                                                                                                                                                                                                           |
| `GET /auth/callback` | Expects `code` and `state` in the query string; verifies `state` against the session and exchanges the code for tokens. In `TokenLocation.HEADER`, returns the raw token response as JSON. In `TokenLocation.COOKIE`, sets an HttpOnly access-token cookie, stores the refresh token server-side in the session, and redirects to `post_login_redirect`. |
| `POST /auth/logout`  | In `TokenLocation.HEADER`, optional body: `{"refresh_token": "..."}` (used to call Keycloak's end-session endpoint). In `TokenLocation.COOKIE`, the refresh token is read from the session. In both cases, the local session is cleared and the access-token cookie is deleted in cookie mode. Returns `{"status": "logged_out"}`.                       |
| `POST /auth/refresh` | In `TokenLocation.HEADER`, body: `{"refresh_token": "..."}` and the endpoint returns the raw token response as JSON. In `TokenLocation.COOKIE`, the refresh token is read from the session, the access-token cookie is updated, and the endpoint returns `{"status": "refreshed"}`.                                                                      |

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

The callback behavior depends on `KeycloakConfig.token_location`:

- `TokenLocation.HEADER`: returns the raw token endpoint response as JSON.
- `TokenLocation.COOKIE`: sets an HttpOnly access-token cookie (cookie flags: `Secure` controlled by `cookie_secure`, `SameSite=Lax`, `Path=/`), stores the refresh token in server-side session storage, and redirects to `post_login_redirect`.

In cookie mode, the refresh token is not written to a browser cookie by this plugin.

## Logout

POST to `/auth/logout` to clear local state and end the Keycloak session (best effort).

- `TokenLocation.HEADER`: optional `refresh_token` in the body is used to call Keycloak's end-session endpoint; then the local session is cleared.
- `TokenLocation.COOKIE`: the refresh token is read from server-side session storage, the access-token cookie is deleted, and the local session is cleared. The request body is ignored in this mode.
