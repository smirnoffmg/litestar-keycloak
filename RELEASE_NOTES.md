# v0.3.3

Patch release. Fixes JWKS key rotation, which did not work in 0.3.2 and earlier.

## Bug fixes

- **Rotated signing keys are now picked up immediately.** `JWKSCache` was documented
  to refetch the JWKS when a token carried an unknown `kid`, but the refresh returned
  early whenever the cache was non-empty and within `jwks_cache_ttl`. After a key
  rotation in Keycloak, every token signed with the new key was rejected with **502**
  until the TTL expired — up to an hour with the default `jwks_cache_ttl=3600`.

  An unknown `kid` now forces a refetch. Forced refetches are throttled to one per
  10 seconds (`MIN_FORCED_REFRESH_INTERVAL`), so tokens with made-up `kid`s cannot
  turn every request into a call to Keycloak; concurrent requests on the same new
  key share a single fetch.

- **`jwks_cache_ttl=0` now works.** The configuration accepted it, but every request
  then failed with `JWKSFetchError` (502): the lookup after a refresh treated the
  keys it had just fetched as already expired. With `0`, the JWKS is now fetched on
  every request, as the setting implies.

## Tests

- Regression tests for both fixes, each verified to fail against the unfixed code:
  rotation on a warm cache, concurrent requests on a rotated key, the throttle and
  its reset, and a TTL-expiry refresh not counting toward the throttle. 197 unit and
  20 integration tests.
- Two cache tests asked for a missing `kid` outside their mocked fetch and passed only
  because no refetch happened; they now keep the call inside the mock.

## Upgrading

No API or configuration changes. If you lowered `jwks_cache_ttl` to work around
rotation failures, you can restore the default.
