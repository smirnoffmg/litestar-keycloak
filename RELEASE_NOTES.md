# v0.3.0

Server-side session login flow for the built-in OIDC routes, plus a round of
hardening across auth exclusion, HTTP, issuer validation, and startup resilience.

## Highlights

- **Server-side session login flow.** The mounted OIDC routes gain
  `callback_response_mode`: `"json"` (default, unchanged for SPAs) returns tokens
  as JSON; `"redirect"` stores the access/refresh tokens in the **server-side
  session** and redirects into your app, so the JWT never reaches the browser.
  The auth middleware reads the token from the session on subsequent requests.
  Addresses #1.
- **Flexible auth exclusion.** Skip authentication with regex `exclude_patterns`
  (prefixes/subtrees) and per-handler `exclude_from_auth=True`, in addition to
  exact `excluded_paths`. `OPTIONS` requests bypass auth by default.
- **Pooled HTTP client.** JWKS and token/logout calls now share one
  connection-pooled `aiohttp` session, created lazily and closed on shutdown,
  instead of a new session per request.
- **`expected_issuer` override.** Validate `iss` against Keycloak's
  frontend/hostname URL when it differs from `server_url` (e.g. behind a reverse
  proxy).
- **Best-effort JWKS warm-up.** If Keycloak is unreachable at startup, the app
  now boots anyway (a warning is logged) and fetches keys on the first request,
  instead of aborting startup.
- **Integration tests** covering the service-to-service, SPA, and server-rendered
  (session) scenarios against real Keycloak.

## Breaking changes

- Removed the unused `OIDCDiscoveryError` exception and
  `KeycloakConfig.discovery_url` property. Endpoint URLs are derived from
  `server_url` + `realm`; the plugin does not fetch the OIDC discovery document.
  If you caught `OIDCDiscoveryError`, catch `JWKSFetchError` /
  `KeycloakBackendError` instead.

## Migration

- Remove any imports of `OIDCDiscoveryError` or uses of `config.discovery_url`.
- Existing SPA / Bearer usage is unchanged — `callback_response_mode` defaults to
  `"json"`.
- For a server-rendered session flow, set `callback_response_mode="redirect"` and
  add Litestar session middleware (`ServerSideSessionConfig`).
