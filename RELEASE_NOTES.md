# v0.3.2

Patch release. Two hardening changes to how bearer tokens are rejected: 401
response bodies no longer disclose validation details, and a new opt-in
`strict_audience` setting stops accepting tokens that were issued for another API.

## Security

- **401 responses no longer reveal why a token was rejected.** The body used to
  carry the exception text: the expected issuer and the one in the token, the full
  list of accepted audiences (your internal client IDs), and PyJWT error messages.
  Any unauthenticated caller could read them. The body is now one of three fixed
  messages:

  | Situation                                                  | Body                                   |
  | ---------------------------------------------------------- | -------------------------------------- |
  | Token expired                                              | `{"error": "Token expired"}`           |
  | No token in the request                                    | unchanged, e.g. `{"error": "No token found in header"}` |
  | Any other failure: issuer, audience, `typ`, signature, algorithm, malformed JWT | `{"error": "Invalid token"}` |

  Status codes and the `{"error": ...}` shape are unchanged, and so are 403
  (missing roles or scopes) and 502 (Keycloak unreachable) bodies.

  The detailed reason now goes to the `litestar_keycloak.exceptions` logger at
  `INFO`, for example:

  ```
  Authentication failed: InvalidIssuerError: Expected issuer 'https://kc.example.com/realms/my-realm', got 'https://other.example.com/realms/my-realm'
  ```

  Requests without a token are not logged. The raw token is never logged.

## Added

- **`strict_audience` setting, default `False`.** By default the plugin accepts a
  token whose `aud` names another service as long as `azp` is your client or one
  of `optional_audiences`. Default Keycloak realms depend on this, because
  Keycloak does not put the requesting client into the access token's `aud`.
  With `strict_audience=True`, only `aud` counts: the token must list your
  `audience` (or `client_id`) or one of `optional_audiences`, and a token without
  `aud` is rejected with 401 `{"error": "Invalid token"}` at request time.

  Before enabling it, add an Audience mapper (`oidc-audience-mapper`) to every
  client that requests tokens for your API. The steps are in
  [Service-to-service](docs/guides/service-to-service.md#requiring-the-audience-in-aud-strict_audience).

## Tests

- 192 unit tests (was 177): both audience modes, the exact 401 bodies for each
  failure type, the log line, and route-level checks that a wrong-issuer token
  gets `{"error": "Invalid token"}` while a 403 body still names the missing role.
- Integration tests are unchanged: the default audience behaviour is the same as
  in 0.3.1.

## Upgrading

No API changes; `strict_audience` defaults to `False`, so token acceptance is the
same as in 0.3.1.

- If your clients, tests or monitoring match on 401 message text, switch them to
  the three messages above, or to the status code. For the detailed reason, read
  the `litestar_keycloak.exceptions` logger at `INFO`.
- To adopt strict mode: add the Audience mapper in Keycloak, check that a fresh
  token's `aud` contains your client ID, then set `strict_audience=True`.
