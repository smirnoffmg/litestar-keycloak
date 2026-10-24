# API Reference

Public API of **litestar-keycloak**. Import from the top-level package:

```python
from litestar_keycloak import (
    KeycloakPlugin,
    KeycloakConfig,
    TokenLocation,
    KeycloakUser,
    TokenPayload,
    CurrentUser,
    CurrentTokenPayload,
    CurrentRawToken,
    OptionalCurrentUser,
    OptionalTokenPayload,
    OptionalRawToken,
    ServiceTokens,
    ServiceTokenClient,
    require_roles,
    require_client_roles,
    require_groups,
    require_scopes,
    require_acr,
    require_recent_auth,
    require_user,
    MatchStrategy,
)
```

## Plugin and config

::: litestar_keycloak.plugin.KeycloakPlugin
    options:
      show_source: true
      show_root_heading: true
      members: true

::: litestar_keycloak.config.KeycloakConfig
    options:
      show_source: true
      show_root_heading: true
      members: true

::: litestar_keycloak.config.TokenLocation
    options:
      show_source: true
      show_root_heading: true
      members: true

## Models

::: litestar_keycloak.models.KeycloakUser
    options:
      show_source: true
      show_root_heading: true
      members: true

::: litestar_keycloak.models.TokenPayload
    options:
      show_source: true
      show_root_heading: true
      members: true

## Handler annotations

Annotate handler parameters with these; the parameter names must stay
`current_user`, `token_payload` and `raw_token`, since injection is name-based.

| Annotation            | Injects        |
| --------------------- | -------------- |
| `CurrentUser`         | `KeycloakUser` |
| `CurrentTokenPayload` | `TokenPayload` |
| `CurrentRawToken`     | `str`          |
| `OptionalCurrentUser`  | `KeycloakUser \| None` — for [optional-auth](configuration.md#optional-authentication) routes |
| `OptionalTokenPayload` | `TokenPayload \| None` |
| `OptionalRawToken`     | `str \| None` |
| `ServiceTokens`        | `ServiceTokenClient` (parameter name `service_tokens`) — outbound tokens, see [Service-to-service](guides/service-to-service.md#calling-other-services-service_tokens) |

## Outbound tokens

::: litestar_keycloak.service_tokens.ServiceTokenClient
    options:
      show_source: true
      show_root_heading: true
      members: true

## Guards

::: litestar_keycloak.guards.MatchStrategy
    options:
      show_source: true
      show_root_heading: true
      members: true

::: litestar_keycloak.guards.require_roles
    options:
      show_source: true
      show_root_heading: true

::: litestar_keycloak.guards.require_client_roles
    options:
      show_source: true
      show_root_heading: true

::: litestar_keycloak.guards.require_groups
    options:
      show_source: true
      show_root_heading: true

::: litestar_keycloak.guards.require_scopes
    options:
      show_source: true
      show_root_heading: true

::: litestar_keycloak.guards.require_acr
    options:
      show_source: true
      show_root_heading: true

::: litestar_keycloak.guards.require_recent_auth
    options:
      show_source: true
      show_root_heading: true

::: litestar_keycloak.guards.require_user
    options:
      show_source: true
      show_root_heading: true

## Testing

::: litestar_keycloak.testing.create_test_token
    options:
      show_source: true
      show_root_heading: true

::: litestar_keycloak.testing.MockKeycloakPlugin
    options:
      show_source: true
      show_root_heading: true
