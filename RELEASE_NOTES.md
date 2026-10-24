# v0.3.4

Token verification release. Realms that sign with EC or Ed25519 keys now work,
clock skew can be tolerated, and 401/403 responses follow RFC 6750. No breaking
changes: every new behaviour is either additive or off by default.

## New

- **EC and Ed25519 signing keys.** The JWKS cache used to skip every non-RSA key, so
  a realm with an `ecdsa-generated` or `eddsa-generated` key provider had all its
  tokens rejected. Such keys now load; add the algorithm to `algorithms`, e.g.
  `algorithms=("RS256", "ES256")`. EC keys published for encryption (`ECDH-ES`) are
  skipped. Verified against real Keycloak 26 tokens signed with ES256 and EdDSA.

- **`leeway`** (default `0`). Seconds of clock skew tolerated when checking `exp`,
  `nbf` and `iat`. Set a few seconds if the app and Keycloak clocks may drift.

- **`WWW-Authenticate` challenges (RFC 6750).** `401` without a token carries a bare
  `Bearer`; a rejected token carries `error="invalid_token"` (plus
  `error_description="Token expired"` when expired); `403` carries
  `error="insufficient_scope"`. The response bodies are unchanged.

- **Denied requests are logged.** A `403` is logged at `WARNING` on the
  `litestar_keycloak.exceptions` logger with the method, path, the caller's `sub` and
  the missing roles or scopes — route that logger to your security event log if
  denials must be audited.

## Bug fixes

- **A token whose `alg` does not match its key type is a 401, not a 500.** Once a
  JWKS holds keys of several types, a token with `alg: RS256` pointing at an EC `kid`
  reached PyJWT as `InvalidKeyError` — an unhandled 500 any client could trigger. The
  verifier now checks the `alg` family against the key's `kty` first.

## Tests

- 212 unit and 22 integration tests. The new integration tests add ES256 and EdDSA
  key providers through the Admin REST API; both fail against 0.3.3.
- `make test-integration` timeout raised from 120 s to 300 s: a cold Keycloak
  container start can exceed 120 s.

## Upgrading

No changes needed. If you configured a WAF or client to detect auth failures by body
text, the `WWW-Authenticate` header is now the standard signal.
