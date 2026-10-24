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

## PKCE and ID token validation

Two opt-in settings harden the code flow:

- **`use_pkce=True`** — `/auth/login` adds a `code_challenge` (`S256`) and keeps the verifier in a short-lived HttpOnly cookie (`kc_oauth_pkce`); `/auth/callback` sends it with the code exchange. Keycloak can *require* PKCE per client (*Advanced → Proof Key for Code Exchange Code Challenge Method → S256*); then a login without it fails at Keycloak, and the callback answers `401` with `Authorization failed: invalid_request`. A **public client** (no `client_secret`) should always use PKCE — its code exchange is otherwise unauthenticated.
- **`validate_id_token=True`** — `/auth/login` adds a random `nonce` (cookie `kc_oauth_nonce`), and `/auth/callback` refuses the login (`401`) unless the token response holds an ID token that is signed by the realm, issued by `issuer`, addressed to `client_id` (`aud`/`azp`), unexpired and carrying that nonce.

Both cookies follow `cookie_secure` / `cookie_samesite` like the `state` cookie and are cleared by the callback. If Keycloak redirects back with `?error=` (denied consent, refused request), the callback answers `401` naming the error code.

## Session lifecycle

**Auto-refresh (`session_auto_refresh=True`, redirect mode).** Keycloak access tokens live minutes, a server-rendered session hours. With this flag, a request whose *session* access token has expired is not answered `401`: the middleware runs a refresh-token grant, writes the new tokens back to the session and continues. If Keycloak rejects the refresh (the SSO session ended, the refresh token expired or was revoked), the request gets `401` — and so does every following one until the user signs in again, which overwrites the session's tokens. A token sent in the `Authorization` header is never refreshed; that is the caller's job. With Keycloak's *Revoke Refresh Token* enabled, two concurrent requests refreshing the same session race, and the loser gets `401`.

**Back-channel logout (`backchannel_logout=True`).** When a user logs out elsewhere, or an admin ends their session, Keycloak POSTs a signed *logout token* to each client's *Backchannel logout URL* (client settings → *Logout settings*). Point it at `{your app}/auth/backchannel-logout` and keep *Backchannel logout session required* on, so the token names the session (`sid`). The endpoint verifies the token (signature, `iss`, `aud`, the logout event, no `nonce`) and records the session as ended in the `logout_store`; from then on every token from that session — session-stored or Bearer — gets `401`. A logout token naming only `sub` ends all of that user's sessions issued before it. The endpoint answers `400` to anything that is not a valid logout token.

Keycloak must be able to reach the endpoint, and it carries no bearer token (the plugin excludes it from authentication). If you enable Litestar's CSRF middleware, exclude this path from it too. Records are kept for 24 hours in an in-memory store by default; with several app instances, register a shared store (e.g. Redis) as `logout_store`, or a logout reaches only the instance Keycloak happened to call.

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
