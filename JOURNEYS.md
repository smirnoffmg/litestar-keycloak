# Journeys

A journey map of litestar-keycloak and the tests that walk it. Two views, after
Hoskins, _The Product-Minded Engineer_ (ch. 1–3) and Torres, _Continuous Discovery
Habits_ (ch. 4):

- **Part 1 — customer journey.** The customer of a library is the developer who
  builds a service with it. One actor per map; each step says what they do, where,
  what they see, and where the journey breaks today.
- **Part 2 — blueprint.** The HTTP journeys that developer's service must support:
  its users, the services calling it, the services it calls, and Keycloak itself.
  These are what stages D3, D4 and D6 promise.

Every step is a claim that a test checks; a step with no test is a hunch. Errors are
grouped by who fixes them and when (Hoskins, table 3-2):

| Error kind                   | Who fixes it, when             | What the plugin must show                                                 |
| ---------------------------- | ------------------------------ | ------------------------------------------------------------------------- |
| Developer's invalid argument | developer, at development time | `ValueError` when the app is built, not at the first request              |
| Preconditions not met        | end user or caller, at runtime | `401` (sign in) or `403` (no permission), with an RFC 6750/9470 challenge |
| System error                 | nobody right now; retry        | `502` with a generic body, detail in the log; cached keys keep working    |

`int/` is `tests/integration/`, `unit/` is `tests/unit/`.

## Part 1. Developer of a Litestar service

**Actor.** A backend developer at a company whose identity provider is Keycloak (as
in CORSAR). **Scenario.** Their service must accept only the company's users and
services, sign users in, and call neighbouring services on their behalf.
**Expectations.** Working in an afternoon; mistakes reported at start-up, not in
production; standard responses that clients and gateways understand; 0.3.x upgrades
that do not break the service; a Keycloak hiccup that does not take the service down.

### D1. Connects the plugin

| Step                                    | Does                                                                                     | Where       | Sees                                                                             | Breaks today                | Test                                                                                        |
| --------------------------------------- | ---------------------------------------------------------------------------------------- | ----------- | -------------------------------------------------------------------------------- | --------------------------- | ------------------------------------------------------------------------------------------- |
| 1. Configures                           | `KeycloakConfig(server_url, realm, client_id, …)`                                        | app code    | a ready app, or `ValueError` naming the bad setting                              | —                           | `unit/test_config.py`                                                                       |
| 2. Starts the app                       | runs it                                                                                  | process log | start-up even if Keycloak is down; a `WARNING` that the JWKS warm-up was skipped | —                           | `test_plugin.py::test_on_startup_survives_keycloak_unavailable`, `int/test_jwks_refresh.py` |
| 3. Sends a first request                | `curl` with a real token                                                                 | terminal    | `200`, or `401` with `WWW-Authenticate`                                          | —                           | `int/test_token_validation.py`                                                              |
| 4. Gets a setting wrong                 | e.g. `algorithms=("HS256",)`, `auth_prefix="/auth/"`, `samesite="none"` without `secure` | start-up    | `ValueError` at construction                                                     | —                           | `unit/test_config.py`                                                                       |
| 5. Uses service tokens without a secret | `service_tokens.client_token()` on a public client                                       | first call  | `ValueError` — **only at that first call**, not at start-up                      | accepted: see Opportunities | `unit/test_service_tokens.py`                                                               |

### D2. Protects the API

| Step                                      | Does                                                                        | Where            | Sees                                                                    | Breaks today | Test                                                           |
| ----------------------------------------- | --------------------------------------------------------------------------- | ---------------- | ----------------------------------------------------------------------- | ------------ | -------------------------------------------------------------- |
| 1. Leaves routes as they are              | —                                                                           | —                | every route not excluded requires a token                               | —            | `int/test_oidc_flow.py`                                        |
| 2. Opens public routes                    | `excluded_paths`, `exclude_from_auth=True`                                  | app code         | those routes answer without a token                                     | —            | `unit/test_auth.py`                                            |
| 3. Adds guards                            | `require_roles`, `require_client_roles`, `require_groups`, `require_scopes` | route decorators | `403 insufficient_scope` for a caller without them, logged at `WARNING` | —            | `int/test_guards_integration.py`, `int/test_identity.py`       |
| 4. Asks for a stronger login              | `require_acr`, `require_recent_auth`                                        | route decorators | `401 insufficient_user_authentication` with `acr_values`/`max_age`      | —            | `int/test_identity.py::test_step_up_guards_on_a_browser_login` |
| 5. Serves anonymous and signed-in callers | `optional_auth=True`, `OptionalCurrentUser`                                 | route            | `None` without a token, the user with one, `401` for a bad one          | —            | `test_optional_auth.py`, `int/test_journey_visitor.py`         |
| 6. Wants revocation at once               | `token_introspection=True`                                                  | config           | a logged-out or disabled user refused at the next request               | —            | `int/test_revocation.py`                                       |

### D3. Signs users in — Part 2, B1–B3

| Step                                | Does                                                                 | Where                            | Sees                                                                    | Breaks today | Test                                                           |
| ----------------------------------- | -------------------------------------------------------------------- | -------------------------------- | ----------------------------------------------------------------------- | ------------ | -------------------------------------------------------------- |
| 1. Mounts the routes                | `include_routes=True`, `redirect_uri`                                | config                           | `/auth/login`, `/auth/callback`, `/auth/refresh`, `/auth/logout`        | —            | `test_routes.py`                                               |
| 2. Picks a mode                     | `callback_response_mode="json"` (SPA) or `"redirect"` (server pages) | config                           | tokens as JSON, or in the server-side session                           | —            | `int/test_scenarios.py`                                        |
| 3. Hardens the login                | `use_pkce`, `validate_id_token`, `session_binding`                   | config                           | Keycloak's PKCE requirement met; a planted session id refused           | —            | `int/test_login_hardening.py`, `int/test_session_lifecycle.py` |
| 4. Keeps sessions alive and in sync | `session_auto_refresh`, `backchannel_logout`                         | config, Keycloak client settings | long sessions on short tokens; a logout elsewhere ends the session here | —            | `int/test_session_lifecycle.py`                                |

### D4. Connects services — Part 2, B4–B6

| Step                                  | Does                                                           | Where            | Sees                                                            | Breaks today                                                                                                  | Test                                                                                    |
| ------------------------------------- | -------------------------------------------------------------- | ---------------- | --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| 1. Accepts another service            | `optional_audiences` or an Audience mapper + `strict_audience` | config, Keycloak | the calling service's token accepted, `is_service_account=True` | —                                                                                                             | `int/test_scenarios.py::test_service_to_service_token_accepted`, `int/test_identity.py` |
| 2. Calls another service as itself    | `await service_tokens.client_token()`                          | handler          | a cached token the other service accepts                        | —                                                                                                             | `int/test_journey_services.py` (B5)                                                     |
| 3. Calls another service for the user | `await service_tokens.exchange(token, audience=…)`             | handler          | a token for that service, same user                             | without `strict_audience` on the caller, a token exchanged _for_ another service is accepted back here (B6.5) | `int/test_outbound_tokens.py::test_exchange_journey` (B6)                               |
| 4. Keycloak refuses                   | wrong secret, audience not allowed                             | handler          | `ServiceTokenError`, a `502` with a generic body if unhandled   | —                                                                                                             | `int/test_journey_services.py::test_wrong_client_secret_is_a_generic_502`, B6.6         |

### D5. Tests the service

| Step                 | Does                                                                   | Where          | Sees                   | Breaks today                                | Test                  |
| -------------------- | ---------------------------------------------------------------------- | -------------- | ---------------------- | ------------------------------------------- | --------------------- |
| 1. Writes unit tests | `litestar_keycloak.testing`: `create_test_token`, `MockKeycloakPlugin` | own test suite | tests without Keycloak | — (`litestar_keycloak.testing` since 0.3.6) | `test_testing_api.py` |

### D6. Runs it in production — operator's view, Part 2, B7–B8

| Step                          | Does                            | Where         | Sees                                                                                                                         | Breaks today | Test                                                                              |
| ----------------------------- | ------------------------------- | ------------- | ---------------------------------------------------------------------------------------------------------------------------- | ------------ | --------------------------------------------------------------------------------- |
| 1. Rotates signing keys       | adds a key provider in Keycloak | admin console | new tokens accepted without a restart, old ones still valid                                                                  | —            | `int/test_journey_operations.py::test_signing_key_rotation_needs_no_restart`      |
| 2. Loses Keycloak for a while | —                               | —             | valid tokens still accepted on cached keys; `502` only where a key is missing                                                | —            | `int/test_journey_operations.py::test_keycloak_outage_keeps_valid_tokens_working` |
| 3. Ends a user's access       | logout or disable in Keycloak   | admin console | refused at once with introspection, at `exp` without                                                                         | —            | `int/test_revocation.py`                                                          |
| 4. Runs several instances     | —                               | deployment    | back-channel logouts reach every instance only through a shared `logout_store`; a start-up `WARNING` while it is per-process | —            | `test_plugin.py::test_backchannel_logout_warns_about_a_per_process_store`         |
| 5. Reads the logs             | —                               | log pipeline  | denials and Keycloak failures at `WARNING` with method, path, `sub`                                                          | —            | `unit/test_exceptions.py`                                                         |

### D7. Upgrades within 0.3.x

| Step                       | Does                                          | Where          | Sees                                                                 | Breaks today | Test       |
| -------------------------- | --------------------------------------------- | -------------- | -------------------------------------------------------------------- | ------------ | ---------- |
| 1. Reads the release notes | —                                             | GitHub release | what may change at start-up and in status codes, then what to enable | —            | review     |
| 2. Bumps the version       | `uv lock --upgrade-package litestar-keycloak` | lock file      | the service starts and behaves as before                             | —            | full suite |

## Part 2. Blueprint: HTTP journeys the service supports

Each row is one step of one test; the test walks the whole row set in order.

### B1. User of a SPA (json mode) — `int/test_journey_spa.py`

| Step | Does                                                                          | Sees                                                         |
| ---- | ----------------------------------------------------------------------------- | ------------------------------------------------------------ |
| 1    | calls the API without a token                                                 | `401`, `WWW-Authenticate: Bearer`                            |
| 2    | signs in through `/auth/login` → Keycloak → `/auth/callback` (PKCE, ID token) | tokens, `Cache-Control: no-store`                            |
| 3    | calls the API with the access token                                           | `200`                                                        |
| 4    | waits past the access token's lifetime                                        | `401` with `error_description="Token expired"`               |
| 5    | `POST /auth/refresh`                                                          | new tokens that work                                         |
| 6    | `POST /auth/logout`                                                           | `{"status": "logged_out"}`                                   |
| 7    | tries the refresh token again                                                 | `401`, not `500`                                             |
| alt  | an attacker replays the authorization code                                    | `401`, and Keycloak ends the victim's session: refresh `401` |

### B2. User of a server-rendered app (redirect mode) — `int/test_journey_web.py`

| Step | Does                                                              | Sees                                                           |
| ---- | ----------------------------------------------------------------- | -------------------------------------------------------------- |
| 1    | opens a page without a session                                    | `401`                                                          |
| 2    | signs in                                                          | redirected; the session authenticates, with the binding cookie |
| 3    | keeps working past the access token's lifetime                    | `200` (auto-refresh)                                           |
| 4    | opens a page that needs a recent login                            | `401` with `max_age`                                           |
| 5    | goes to `/auth/login?max_age=0`, signs in again                   | Keycloak asked for `max_age=0`; the page opens                 |
| 6    | signs out                                                         | `401` again                                                    |
| alt  | the Keycloak session is ended by an admin, then the token expires | `401` at the next request, not `500`                           |

### B3. Visitor of an `optional_auth` page — `int/test_journey_visitor.py`

| Step | Does                                             | Sees                             |
| ---- | ------------------------------------------------ | -------------------------------- |
| 1    | opens the page anonymously                       | the anonymous version            |
| 2    | opens it with a token                            | the personal version             |
| 3    | sends a broken token                             | `401`, not the anonymous version |
| 4    | opens a guarded `optional_auth` page anonymously | `401` with a `Bearer` challenge  |

### B4. A service calling this API (inbound `client_credentials`) — `int/test_journey_services.py`

| Step | Does                                                                              | Sees                             |
| ---- | --------------------------------------------------------------------------------- | -------------------------------- |
| 1    | gets a token for its service account, addressed to this API by an Audience mapper | —                                |
| 2    | calls a route guarded by a client role it holds                                   | `200`, `is_service_account=True` |
| 3    | another service without the role calls it                                         | `403`                            |
| 4    | a service whose token is not addressed to this API calls it (`strict_audience`)   | `401`                            |

### B5. This service calling another as itself (outbound `client_credentials`) — `int/test_journey_services.py`

| Step | Does                                                                | Sees                           |
| ---- | ------------------------------------------------------------------- | ------------------------------ |
| 1    | `client_token()` in a handler                                       | a token                        |
| 2    | the receiving service (its own plugin, `strict_audience`) checks it | `200`, caller is this service  |
| 3    | calls again                                                         | the cached token               |
| 4    | calls after half the token's lifetime                               | a renewed token, also accepted |
| 5    | runs with a wrong client secret                                     | `502`, generic body            |

### B6. This service calling another for the user (token exchange, Keycloak ≥ 26.2) — `int/test_outbound_tokens.py`, extended

| Step | Does                                                           | Sees                                                                   |
| ---- | -------------------------------------------------------------- | ---------------------------------------------------------------------- |
| 1    | the user calls this service (`orders-api`) with a token for it | `200`                                                                  |
| 2    | `exchange(token, audience="billing")`                          | a token for `billing`                                                  |
| 3    | `billing` (its own plugin, `strict_audience`) checks it        | `200`, the same user                                                   |
| 4    | `billing` is sent the user's original token                    | `401` — not addressed to it                                            |
| 5    | `orders-api` is sent the exchanged token                       | `401` — not addressed to it; only with `strict_audience`, see Findings |
| 6    | exchange to an audience the client may not use                 | `502`, generic body                                                    |

### B7. Keycloak changes: rotation, logout, revocation

| Step | Does                                                              | Sees                          | Test                             |
| ---- | ----------------------------------------------------------------- | ----------------------------- | -------------------------------- |
| 1    | a new signing key takes over while the app runs                   | new and old tokens both `200` | `int/test_journey_operations.py` |
| 2    | a user logs out elsewhere (back-channel)                          | that session's tokens `401`   | `int/test_session_lifecycle.py`  |
| 3    | an admin ends the session or disables the user (introspection on) | `401` at once                 | `int/test_revocation.py`         |

### B8. Keycloak unreachable — `int/test_journey_operations.py`

| Step | Does                                                                    | Sees                      |
| ---- | ----------------------------------------------------------------------- | ------------------------- |
| 1    | the app warms its keys, then Keycloak goes away and the JWKS TTL passes | a valid token still `200` |
| 2    | a token names a key the app never saw                                   | `502` with a generic body |

## Findings

What walking the journeys against real Keycloak turned up:

- **B2 alt — a regression in 0.3.5.** A session refresh Keycloak rejected came back
  as `401` without its `WWW-Authenticate` challenge and with a Litestar error body:
  0.3.5 changed the token endpoint helper, and the auto-refresh path still expected
  the old exception. Unit tests missed it because they mocked the helper rather than
  the HTTP client. Fixed in `baa6887`.
- **B1 alt — Keycloak ends the session on a replayed code.** Replaying an
  authorization code not only fails; Keycloak treats it as theft and revokes the
  session the code opened. An app sees its user signed out, which is the safe outcome
  and worth knowing when debugging "random" logouts.
- **B6.5 — lenient audience checking accepts tokens meant for others.** With
  `strict_audience=False`, `orders-api` accepts the token it exchanged _for_
  `billing` (`aud: billing`, `azp: orders-api`), because the lenient check also
  accepts any token whose `azp` is this client. Evidence for making
  `strict_audience=True` the default in 0.4.

## Opportunities

- **D1.5 — accepted as is.** A missing `client_secret` for service tokens surfaces
  at the first call, as a `ValueError` that names it. Moving it to start-up would
  need an opt-in flag, which only helps the developer who remembers to set it — the
  same one who would set the secret.
- **D5.1 — done.** `litestar_keycloak.testing` ships the helpers (`fd61af7`).
- **D6.4 — done.** Start-up warns while back-channel logouts use a per-process store
  (`14282bd`).
