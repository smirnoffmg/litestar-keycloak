# v0.3.1

Patch release. Two bug fixes around token rejection and the testing helpers, plus
a substantially expanded test suite.

## Bug fixes

- **Malformed tokens now return 401 instead of 500.** `TokenVerifier` caught
  `jwt.DecodeError` but not its siblings under `jwt.InvalidTokenError`, so a token
  with a future `nbf` (`ImmatureSignatureError`) or one signed with an algorithm
  outside `algorithms` (`InvalidAlgorithmError`) escaped the verifier uncaught and
  surfaced as an unhandled 500. Both are now converted to `TokenDecodeError` and
  rendered as 401, matching every other invalid-token path.

  This was never an authentication bypass — such tokens were always rejected. The
  impact was the status class: any unauthenticated caller could trigger a 500 on a
  protected route, which pollutes error tracking and, with `debug=True`, returned a
  stack trace. Note the wrong-algorithm case is the shape of an *alg confusion*
  probe; the verifier already refused it correctly because it pins `algorithms`.

  `jwt.InvalidKeyError` is deliberately still uncaught: a broken JWKS key is a
  server-side fault, not a bad client token.

- **`MockKeycloakPlugin` no longer raises on app shutdown.** The testing helper set
  only `_config`, `_jwks_cache`, and `_verifier`, but the inherited `_on_shutdown`
  closes `self._http` — so exiting a `TestClient` context raised
  `AttributeError: '_MockPlugin' object has no attribute '_http'`. It now
  constructs a `KeycloakHttpClient`, which is never used (the JWKS cache is
  in-memory) and whose `close()` no-ops when no session was opened. This affected
  anyone following `docs/guides/testing.md`.

## Tests

- Coverage raised from 98% to **99%**; `models.py`, `routes.py`, and `token.py` are
  now at 100%. 177 unit tests and 20 integration tests.
- New regression tests for both fixes above, each verified to fail against the
  unfixed code.
- New integration tests: token expiry against real Keycloak (via a short-lived
  client), scope guards against real token scopes, and logout invalidating the
  refresh token.
- `TESTING.md` rewritten to describe the suite as built, including its deliberate
  non-goals (no token revocation checking, no OIDC discovery).

## Upgrading

No API or configuration changes. If you assert on status codes for malformed
tokens, expect 401 where you previously saw 500.
