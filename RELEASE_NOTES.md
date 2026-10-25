# v0.3.6

Fixes a 0.3.5 regression in session auto-refresh, ships the testing helpers in the
package, and warns when back-channel logouts cannot reach every instance.

## Before you upgrade

- **Nothing to change.** Apps with `backchannel_logout=True` and no store registered
  under `logout_store` now log a `WARNING` at start-up; see below.

## Bug fixes

- **A rejected session refresh is a proper `401` again** (regression in 0.3.5). With
  `session_auto_refresh=True`, when Keycloak refused the refresh (session ended,
  refresh token expired or revoked), the `401` came without its
  `WWW-Authenticate: Bearer error="invalid_token", error_description="Token expired"`
  challenge and with Litestar's default body instead of `{"error": "Token expired"}`;
  an unreachable Keycloak raised `TokenEndpointError` instead of the documented
  `SessionRefreshError` (still a `502`). The auth routes' own `401` for a refused code
  exchange or refresh now carries the same challenge too; it is raised as the new
  `TokenGrantRejectedError`.

## New

- **`litestar_keycloak.testing`** ships `create_test_token` and `MockKeycloakPlugin`,
  so a test suite imports them instead of copying them from this repository:

  ```python
  from litestar_keycloak.testing import MockKeycloakPlugin, create_test_token
  ```

  The signing key is generated at import and exists only in the test process.

- **Start-up warning for a per-process logout store.** With `backchannel_logout=True`
  and nothing registered under `logout_store`, Litestar hands each process its own
  in-memory store, so on several instances Keycloak's logout reaches only one of them.
  Register a shared store (e.g. Redis) under that name to silence it; a
  `StoreRegistry` you pass in is trusted as is.

## Tests

`JOURNEYS.md` maps how developers meet the plugin and the HTTP journeys their services
support, and ten new integration tests walk each journey end to end against real
Keycloak — SPA and server-rendered sign-in, optional auth, `client_credentials`
between two services, token exchange accepted by the downstream service, key
rotation on a running app, and Keycloak going away. Walking them found the regression
above. 395 unit and 46 integration tests.
