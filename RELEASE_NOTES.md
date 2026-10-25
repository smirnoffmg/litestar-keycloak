# v0.3.6

Fixes a 0.3.5 regression in session auto-refresh, ships the testing helpers in the
package, and warns when back-channel logouts cannot reach every instance.

## Before you upgrade

No code or configuration changes. New at start-up: a `WARNING` if
`backchannel_logout=True` and no store is registered under `logout_store` (see below).

## Bug fixes

- **`session_auto_refresh`: a refused refresh sends its challenge again** (regression
  in 0.3.5). Affects apps with `session_auto_refresh=True`. When Keycloak refuses the
  refresh — the session ended, the refresh token expired or was revoked — the `401`
  carries `WWW-Authenticate: Bearer error="invalid_token", error_description="Token expired"`
  and the body `{"error": "Token expired"}` again; 0.3.5 sent neither. An unreachable
  Keycloak raises `SessionRefreshError` again, as documented (still a `502`).

  The auth routes' `401` for a refused code exchange or refresh now carries the same
  challenge. If you catch exceptions yourself: that refusal is the new
  `TokenGrantRejectedError`, an `AuthenticationError`.

## New

- **`litestar_keycloak.testing`** ships `create_test_token` and `MockKeycloakPlugin`.
  Import them in your tests instead of copying them from this repository:

  ```python
  from litestar_keycloak.testing import MockKeycloakPlugin, create_test_token
  ```

  The signing key is generated at import and exists only in the test process.

- **Start-up warning for a per-process logout store.** With `backchannel_logout=True`
  and nothing registered under `logout_store`, each process gets its own in-memory
  store, so on several instances Keycloak's logout reaches only one of them. Register
  a shared store (e.g. Redis) under that name to silence it; a `StoreRegistry` you
  pass in is trusted as is.
