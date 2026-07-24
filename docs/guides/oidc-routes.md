# OIDC routes

When **include_routes** is `True`, the plugin mounts a route group under **auth_prefix** (default `/auth`) that implements the authorization code flow and token refresh.

The routes behave according to **callback_response_mode**:

- **`"json"`** (default) — a SPA/BFF flow. The callback returns the raw token endpoint response as JSON; your frontend stores the access token and sends it as `Authorization: Bearer …`.
- **`"redirect"`** — a server-rendered flow. The callback stores the tokens in the **server-side session** and redirects to `post_login_redirect_uri`. The browser only ever holds the session id cookie — the JWT is never exposed to it, so there is no cookie-size limit and the refresh token never leaves the server.

> Why not put the access token in a cookie? `token_location` controls where the middleware *reads* the token; *how* it gets there is the application's job. Keycloak's role-heavy tokens routinely exceed the ~4 KB cookie limit, so for browser flows a server-side session is the correct model.

## Endpoints

| Method and path      | `"json"` mode                                                                                     | `"redirect"` mode                                                                                       |
| -------------------- | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `GET /auth/login`    | Redirects to Keycloak (`response_type=code`, `client_id`, `redirect_uri`, `scope`, random `state`); sets the `state` cookie. | Same.                                                                                     |
| `GET /auth/callback` | Verifies `state`, exchanges the code, returns the token response as JSON.                          | Verifies `state`, exchanges the code, stores the tokens in the session, redirects to `post_login_redirect_uri`. |
| `POST /auth/logout`  | Optional body `{"refresh_token": "…"}`; calls end-session, returns `{"status": "logged_out"}`.     | Reads the refresh token from the session, calls end-session, clears the session tokens, redirects to `post_logout_redirect_uri` (or returns `{"status": "logged_out"}`). |
| `POST /auth/refresh` | Body `{"refresh_token": "…"}`; returns the new token response as JSON.                             | Reads the refresh token from the session, rotates it, writes new tokens back to the session, returns `{"status": "refreshed"}`. |

## OAuth state (both modes)

The `state` value used to mitigate CSRF is stored in a short-lived HttpOnly cookie (`kc_oauth_state`), set by `/auth/login` and verified by `/auth/callback`. It honors `cookie_secure` (default `True` — set `False` only for plain-HTTP local development) and `cookie_samesite` (default `"lax"`). No session middleware is required for state.

## Redirect mode: session middleware required

`"redirect"` mode stores tokens in the server-side session, and the auth middleware reads the access token from the session on subsequent requests. You must add Litestar session middleware; the plugin's auth middleware is registered so it runs **after** it.

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
    callback_response_mode="redirect",
    post_login_redirect_uri="/",
)

session_config = ServerSideSessionConfig()

app = Litestar(
    route_handlers=[...],
    plugins=[KeycloakPlugin(config)],
    middleware=[session_config.middleware],
    stores={"sessions": MemoryStore()},
)
```

For the default `"json"` mode no session middleware is needed — `state` lives in the cookie above and tokens are returned to the caller.

## Redirect URI

Set **redirect_uri** to the full URL of your callback as registered in Keycloak (e.g. `https://app.example.com/auth/callback`). It must match the client's configured redirect URI in the realm.
