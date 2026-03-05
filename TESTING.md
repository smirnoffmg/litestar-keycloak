# Testing Plan: litestar-keycloak

## Overview

Two test layers, same principle across both: **unit tests prove the logic, integration tests prove the wiring.**

| Layer       | Runner                  | Marker                     | Dependencies                        |
| ----------- | ----------------------- | -------------------------- | ----------------------------------- |
| Unit        | `pytest` (default)      | unmarked                   | None — mock JWKSCache, fake JWTs    |
| Integration | `pytest -m integration` | `@pytest.mark.integration` | Keycloak container (testcontainers) |

Current state: **45 tests** across 7 files. Coverage is solid on the happy paths but thin on edge cases, error responses, and several modules have zero dedicated tests.


## Current Coverage Map

| Module            | Unit tests | Integration tests | Assessment                                        |
| ----------------- | ---------- | ----------------- | ------------------------------------------------- |
| `config.py`       | **0**      | 0                 | Missing — validation logic untested               |
| `models.py`       | **0**      | 0                 | Missing — `from_claims`, `from_token`, properties |
| `exceptions.py`   | **0**      | 0                 | Missing — exception handlers untested             |
| `token.py`        | 9          | 1                 | Good on verification, missing JWKSCache logic     |
| `auth.py`         | 6          | 0                 | Good on extraction, missing edge cases            |
| `guards.py`       | 11         | 0                 | Good                                              |
| `dependencies.py` | **0**      | 0                 | Missing — providers never tested directly         |
| `plugin.py`       | 6          | 0                 | Good on registration, missing override tests      |
| `routes.py`       | 6          | 0                 | Fair — mostly mock-based, real flow untested      |
| End-to-end        | 0          | 3                 | Thin — only `/me` with user/admin tokens          |


## Test Plan by Module

### 1. `config.py` — 0 existing, 10 needed

Validation in `__post_init__` and derived properties are completely untested.

**Unit tests:**

```
test_minimal_config_requires_server_url_realm_client_id
test_frozen_config_rejects_mutation
test_include_routes_without_redirect_uri_raises_value_error
test_negative_jwks_cache_ttl_raises_value_error
test_zero_http_timeout_raises_value_error
test_realm_url_strips_trailing_slash
test_discovery_url_derived_correctly
test_jwks_url_derived_correctly
test_authorization_url_derived_correctly
test_token_url_derived_correctly
test_logout_url_derived_correctly
test_effective_audience_defaults_to_client_id
test_effective_audience_uses_explicit_override
test_default_values_are_sensible
```

Priority: **high** — config validation is the first line of defense against misconfiguration.


### 2. `models.py` — 0 existing, 14 needed

Both dataclasses and their factory methods are untested.

**Unit tests — `TokenPayload`:**

```
test_from_claims_maps_standard_oidc_fields
test_from_claims_maps_keycloak_specific_fields
test_from_claims_puts_unknown_keys_in_extra
test_from_claims_handles_minimal_claims (only required fields)
test_realm_roles_extracts_from_realm_access
test_realm_roles_returns_empty_frozenset_when_missing
test_client_roles_extracts_from_resource_access
test_client_roles_returns_empty_frozenset_for_unknown_client
test_scopes_splits_space_delimited_string
test_scopes_returns_empty_frozenset_for_empty_string
test_expires_at_returns_utc_datetime
test_issued_at_returns_utc_datetime
```

**Unit tests — `KeycloakUser`:**

```
test_from_token_maps_all_identity_fields
test_from_token_normalizes_realm_roles_to_frozenset
test_from_token_normalizes_client_roles_per_client
test_from_token_preserves_raw_payload
test_has_role_returns_true_for_present_role
test_has_role_returns_false_for_absent_role
test_has_client_role_checks_correct_client
test_has_client_role_returns_false_for_unknown_client
test_has_scope_returns_true_for_present_scope
test_has_scope_returns_false_for_absent_scope
```

Priority: **high** — these are the core data structures everything else relies on.


### 3. `exceptions.py` — 0 existing, 8 needed

Exception construction and handler responses.

**Unit tests — exception classes:**

```
test_missing_token_error_stores_location
test_invalid_issuer_error_stores_expected_and_got
test_invalid_audience_error_stores_expected_and_got
test_insufficient_role_error_computes_missing_roles_in_message
test_insufficient_scope_error_computes_missing_scopes_in_message
test_all_exceptions_inherit_from_keycloak_error
```

**Unit tests — exception handlers:**

```
test_authentication_error_handler_returns_401_json
test_authorization_error_handler_returns_403_json
test_backend_error_handler_returns_502_json
test_handler_does_not_leak_stack_trace
```

Priority: **medium** — the exceptions are simple, but the handlers are part of the public contract.


### 4. `token.py` — 9 existing, 9 needed

`TokenVerifier` is well-covered. `JWKSCache` has zero direct tests.

**Unit tests — `JWKSCache`:**

```
test_warm_populates_cache
test_get_key_returns_cached_key_without_refetch
test_get_key_refreshes_on_ttl_expiry
test_get_key_refreshes_on_unknown_kid
test_get_key_raises_after_refresh_if_kid_still_missing
test_concurrent_refreshes_only_fetch_once (double-check pattern)
test_ttl_zero_always_refetches
test_fetch_failure_raises_jwks_fetch_error
test_malformed_jwks_response_skips_bad_keys
```

These require mocking `_fetch_jwks` or injecting a fake aiohttp response. The double-check / concurrent refresh test is the most important — it validates the `asyncio.Lock` pattern.

Priority: **high** — the cache is the only stateful component in the hot path.


### 5. `auth.py` — 6 existing, 4 needed

Good extraction coverage. Missing edge cases.

**Unit tests:**

```
test_bearer_case_insensitive (e.g. "bearer", "BEARER", "Bearer")
test_extra_whitespace_in_authorization_header
test_excluded_path_does_not_set_state_keys
test_verifier_exception_propagates_unchanged
```

Priority: **low** — existing tests cover the critical paths.


### 6. `guards.py` — 11 existing, 3 needed

Well-covered. Minor gaps.

**Unit tests:**

```
test_require_roles_with_superset_of_roles_passes
test_require_client_roles_all_strategy_missing_one_raises
test_empty_roles_argument_passes_any_user
```

Priority: **low** — existing 11 tests are thorough.


### 7. `dependencies.py` — 0 existing, 3 needed

Never tested. Thin but important — these are the DI wiring contract.

**Unit tests:**

```
test_provide_current_user_returns_connection_user
test_provide_token_payload_returns_state_value
test_provide_raw_token_returns_state_value
```

Priority: **medium** — if the DI wiring breaks, every handler breaks.


### 8. `plugin.py` — 6 existing, 4 needed

Registration is tested. Override behavior and startup lifecycle are not.

**Unit tests:**

```
test_user_exception_handler_overrides_plugin_default
test_user_dependency_overrides_plugin_default
test_on_startup_calls_jwks_warm
test_middleware_inserted_at_position_zero
```

Priority: **medium**.


### 9. `routes.py` — 6 existing, 6 needed

Current tests are mock-heavy. Some real flow gaps.

**Unit tests:**

```
test_login_includes_scopes_from_config
test_login_state_is_cryptographically_random
test_logout_clears_session_even_when_keycloak_call_fails
test_refresh_forwards_correct_grant_type
test_callback_calls_exchange_with_correct_code
test_callback_returns_full_token_response
```

Priority: **medium** — routes are optional but security-sensitive when enabled.


### 10. Integration Tests — 3 existing, 12 needed

Currently only tests `/me` with valid/missing tokens. Needs real Keycloak flows.

**Token validation against real Keycloak:**

```
test_valid_user_token_returns_200_with_user_claims
test_valid_admin_token_includes_admin_role
test_expired_token_returns_401
test_token_from_wrong_realm_returns_401
test_revoked_token_returns_401 (logout then reuse)
test_tampered_token_signature_returns_401
```

**Guards against real tokens:**

```
test_admin_guard_allows_admin_token
test_admin_guard_rejects_user_token_with_403
test_scope_guard_validates_real_token_scopes
```

**JWKS lifecycle:**

```
test_jwks_warm_on_startup_fetches_real_keys
test_app_handles_keycloak_restart_gracefully (stop/start container)
```

**Routes (real Keycloak):**

```
test_full_authorization_code_flow (login redirect -> callback -> tokens)
test_refresh_with_real_refresh_token
test_logout_invalidates_refresh_token
```

Priority: **high** — integration tests are the only way to catch real Keycloak behavior differences.


### 11. Realm Export Enhancements

The current `realm-export.json` needs additions to support the full test plan:

```diff
 "clients": [
   {
     "clientId": "test-app",
+    "defaultClientScopes": ["openid", "profile", "email"],
+    "optionalClientScopes": ["reports"]
-  }
+  },
+  {
+    "clientId": "test-service",
+    "enabled": true,
+    "publicClient": false,
+    "secret": "service-secret",
+    "serviceAccountsEnabled": true
+  }
 ],
 "roles": {
   "realm": [
     { "name": "admin" },
     { "name": "user" }
-  ]
+  ],
+  "client": {
+    "test-service": [
+      { "name": "read" },
+      { "name": "write" }
+    ]
+  }
 },
 "users": [
+  {
+    "username": "testnorolesuser",
+    "enabled": true,
+    "credentials": [{ "type": "password", "value": "testpass", "temporary": false }],
+    "realmRoles": []
+  }
 ]
```

This adds: a second client for client-role testing, client-level roles, scopes, a service account, and a user with no roles.


## Test Execution Strategy

### Local development

```bash
# fast feedback — unit tests only (default)
pytest

# full suite including container
pytest -m integration

# single module
pytest tests/unit/test_token.py -v
```

### CI pipeline

```yaml
jobs:
  unit:
    runs-on: ubuntu-latest
    steps:
      - run: uv run pytest --cov=litestar_keycloak --cov-report=xml

  integration:
    runs-on: ubuntu-latest
    steps:
      - run: uv run pytest -m integration --timeout=120
```

Unit and integration run as separate jobs. Unit is fast (~2s), gates merge. Integration is slow (~60s container startup), runs in parallel, non-blocking on PRs initially.

### Coverage targets

| Module            | Current (est.)        | Target |
| ----------------- | --------------------- | ------ |
| `config.py`       | 0%                    | 95%    |
| `models.py`       | 0%                    | 95%    |
| `exceptions.py`   | ~30% (hit indirectly) | 90%    |
| `token.py`        | ~70%                  | 90%    |
| `auth.py`         | ~80%                  | 90%    |
| `guards.py`       | ~90%                  | 95%    |
| `dependencies.py` | 0%                    | 90%    |
| `plugin.py`       | ~60%                  | 85%    |
| `routes.py`       | ~50%                  | 80%    |


## Priority Summary

| Priority | Tests to add                                     | Effort   |
| -------- | ------------------------------------------------ | -------- |
| **P0**   | `config`, `models`, `JWKSCache` unit tests       | ~2 hours |
| **P1**   | Integration tests (real Keycloak flows, guards)  | ~3 hours |
| **P2**   | `exceptions`, `dependencies`, `plugin` overrides | ~1 hour  |
| **P3**   | `routes` edge cases, `auth` minor gaps           | ~1 hour  |

P0 + P1 bring the most confidence per hour invested. P0 catches logic bugs without a container. P1 catches the Keycloak-specific behaviors that no mock can reproduce.
