# Testing: litestar-keycloak

How the test suite is organised, what it covers, and what it deliberately does not.

## Overview

Two layers, one principle: **unit tests prove the logic, integration tests prove the wiring.**

| Layer       | Runner                  | Marker                     | Dependencies                        | Runtime |
| ----------- | ----------------------- | -------------------------- | ----------------------------------- | ------- |
| Unit        | `pytest` (default)      | unmarked                   | None — fake JWTs, in-memory JWKS    | ~2s     |
| Integration | `pytest -m integration` | `@pytest.mark.integration` | Keycloak container (testcontainers) | ~60s+   |

Current state: **197 tests across 18 files** — 177 unit, 20 integration — at **99% coverage**.

Integration tests are **excluded by default** (`addopts = "-m 'not integration'"`), so a bare
`pytest` is always the fast path. `asyncio_mode = "auto"` means `async def test_*` needs no
marker. Litestar deprecation warnings are promoted to errors via `filterwarnings`.

## Layout

```
tests/
├── conftest.py                 # public testing API: create_test_token, MockKeycloakPlugin
├── test_plugin.py              # plugin registration (drives on_app_init directly)
├── test_routes.py              # OIDC routes with mocked Keycloak calls
├── test_testing_api.py         # the public helpers in conftest.py (nothing else uses them)
├── fixtures/realm-export.json  # realm imported by the container
├── unit/
│   ├── conftest.py             # RSA keypair, JWKS double, make_token factory
│   └── test_{auth,config,dependencies,exceptions,guards,http_client,jwks_cache,models,token}.py
└── integration/
    ├── conftest.py             # Keycloak container, config, token fixtures
    └── test_{guards_integration,jwks_refresh,oidc_flow,routes_integration,scenarios,token_validation}.py
```

`tests/unit/` and `tests/integration/` have no `__init__.py`, so **cross-file imports between
test modules do not work** — shared helpers belong in the nearest `conftest.py` (as fixtures)
or are duplicated locally. Note `test_plugin.py` and `test_routes.py` sit at the top level
rather than under `unit/`, though they are unit tests.

## Coverage

Measured with `uv run pytest --cov=litestar_keycloak --cov-report=term-missing` (unit only).

| Module            | Tests | Coverage | Uncovered |
| ----------------- | ----- | -------- | --------- |
| `__init__.py`     | —     | 100%     | |
| `auth.py`         | 15    | 100%     | |
| `config.py`       | 24    | 100%     | |
| `dependencies.py` | 4     | 82%      | `39-42` — litestar < 2.23 import shim |
| `exceptions.py`   | 10    | 100%     | |
| `guards.py`       | 17    | 100%     | |
| `http_client.py`  | 7     | 97%      | `31->33` — lock double-check branch |
| `models.py`       | 25    | 100%     | |
| `plugin.py`       | 13    | 100%     | |
| `routes.py`       | 26    | 100%     | |
| `token.py`        | 23    | 100%     | |
| **Total**         | 177   | **99%**  | |

There is no `fail_under` threshold; `--cov` is not in `addopts`, so coverage runs only when
asked for.

## Fixtures

### `tests/conftest.py` — the public testing API

Documented in `docs/guides/testing.md` for **downstream users** of the package. `tests/
test_testing_api.py` is the only thing exercising them — it exists because a regression here
(the plugin raising on shutdown) was otherwise invisible to the suite. Keep the signatures
stable, and keep that file passing.

- `create_test_token(sub, realm_roles, exp_offset, iss, aud, typ, headers, **extra_claims)` —
  mints a JWT signed with a fixed module-level RSA key.
- `MockKeycloakPlugin(server_url, realm, client_id, **kwargs)` — a `KeycloakPlugin` whose JWKS
  cache serves that same key, so apps can be tested with no Keycloak running.
- Exposed as fixtures `create_test_token_factory` / `mock_keycloak_plugin_factory`.

### `tests/unit/conftest.py`

| Fixture | Scope | Provides |
| --- | --- | --- |
| `rsa_keypair` | session | 2048-bit RSA `(private, public)` |
| `test_jwk` | session | `PyJWK` for the public key, kid `test-kid` |
| `mock_jwks_cache` | function | `MockJWKSCache` duck-typed as `JWKSCache` |
| `keycloak_config` | function | config for `http://localhost:8080`, realm `test-realm`, client `test-app` |
| `token_verifier` | function | `TokenVerifier` wired to the two above |
| `make_token` | function | JWT factory matching that issuer/audience |

Signatures are **really verified** — only the JWKS lookup is doubled, never the crypto.
`make_token` passes `iss`/`aud` overrides through `**extra_claims`, and `headers={}` yields a
token with no `kid`.

### `tests/integration/conftest.py`

| Fixture | Scope | Provides |
| --- | --- | --- |
| `keycloak_container` | session | started `quay.io/keycloak/keycloak:26.0` with the realm imported |
| `keycloak_config` | session | config pointed at the mapped random port |
| `user_token` / `admin_token` | function | access token for `testuser` / `testadmin` |
| `user_token_response` | function | full token dict, including `refresh_token` |
| `shortlived_token` | function | token from `test-shortlived` (expires in 1s) |

The container start is gated twice: `kc.start()`, then an `HttpWaitStrategy` polling the realm's
`.well-known/openid-configuration` for a 200 (120s timeout). A malformed `realm-export.json`
therefore fails as a **timeout on every integration test**, not as a clear parse error — check
the realm file first when the whole layer goes red at once.

Module-level `obtain_token(base_url, username, password, *, client_id, client_secret, scope)`
does a direct grant (test-only).

### Realm contents (`tests/fixtures/realm-export.json`)

**Clients** — `test-app` (secret `test-secret`, direct grant + standard flow, default scopes
`openid profile email roles`), `test-service` (secret `service-secret`, service account, client
roles `read`/`write`), `test-shortlived` (secret `shortlived-secret`, `access.token.lifespan=1`).

**Realm roles** — `admin`, `user`.

> **Do not add a top-level `clientScopes` array to this file.** Keycloak treats it as the
> realm's complete scope list rather than an addition, which drops the built-in `roles` scope
> and silently strips `realm_access.roles` from every token — every role assertion in the suite
> then fails on an empty list. Scope tests use the scopes Keycloak already issues.

**Users** (all password `testpass`) — `testuser` (`user`), `testadmin` (`admin`, `user`),
`testnorolesuser` (none — currently unused by any test).

`compose.test.yml` runs the same realm on a fixed `localhost:8080` for manual poking.

## Non-goals

Deliberate design limits. Do not write tests asserting the opposite — they cannot pass.

**No token revocation checking.** `TokenVerifier.verify` validates entirely offline: JWKS
signature plus the `typ`, `iss`, `aud`, `exp` claims. There is no introspection call anywhere in
the package. **An access token remains valid after logout until its `exp`** — the standard
stateless-JWT tradeoff. Refresh tokens *are* validated server-side by Keycloak, so logout does
invalidate those; that is what `test_logout_invalidates_refresh_token` covers. Applications
needing immediate revocation should shorten `access.token.lifespan` or add introspection.

**No OIDC discovery.** Endpoint URLs are derived directly from `server_url` + `realm` in
`config.py`; `.well-known/openid-configuration` is never fetched. There is no `discovery_url`.

**The auth middleware is appended, not prepended.** `plugin.py:on_app_init` appends it so it
runs *after* app-level session middleware — required for `callback_response_mode="redirect"`,
where the token is read out of the session. `test_middleware_appended_after_existing` locks
this in.

## Known gaps

- `dependencies.py:39-42` — the `except ImportError` shim for litestar < 2.23. Unreachable on
  the installed version without faking the import failure; this is the whole reason that
  module sits at 82%.
- `http_client.py:31->33` — the inner half of the double-checked lock in `_get_session`, i.e.
  the branch where another coroutine created the session first. Not deterministically
  triggerable without instrumenting the lock.
- Keycloak restart / key-rotation resilience is covered only at unit level
  (`test_get_key_refreshes_on_unknown_kid`). A container restart would remap the host port and
  invalidate the session-scoped `keycloak_config` for every other test, so it is not tested
  end-to-end.

## Running

```bash
make check              # ruff check + ruff format --check + mypy src/ + unit tests
make test-unit          # unit only (the pytest default)
make test-integration   # -m integration --timeout=120; needs Docker
make test               # both
make test-examples      # ./examples/test.sh against a running app

uv run pytest tests/unit/test_token.py -v                    # one module
uv run pytest -m integration -o log_cli=true -o log_cli_level=INFO   # container logs
```

## CI

`.github/workflows/ci.yml` runs two jobs:

- **`lint-and-test`** — ruff check, ruff format check, mypy, then
  `uv run pytest --cov --cov-report=xml` (unit only, via `addopts`), with a conditional
  Codecov upload.
- **`integration-tests`** — `uv run pytest -m integration -v --timeout=120` on a
  Docker-enabled runner.

`build-docs` / `deploy-pages` gate on both. `publish.yml` re-runs lint + unit tests before
building the package. The pre-commit hook runs `uv run pytest -m "not integration"` on every
commit.

## Conventions

- `litestar.testing.TestClient` used synchronously as a context manager — the suite uses
  neither `AsyncTestClient` nor `create_test_client`.
- No `pytest.mark.parametrize` anywhere; tests are written out individually.
- Unit tests mock only at system boundaries: the JWKS cache, `aiohttp.ClientSession`, or the
  module-level `_exchange_code` / `_refresh_token` / `_keycloak_logout` helpers.
- Integration tests mock nothing.
- Every integration test carries `@pytest.mark.integration` and, in most files,
  `@pytest.mark.timeout(120)` to override the global 30s cap.
