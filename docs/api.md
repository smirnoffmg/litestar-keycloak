# API Reference

Public API of **litestar-keycloak**. Import from the top-level package:

```python
from litestar_keycloak import (
    KeycloakPlugin,
    KeycloakConfig,
    TokenLocation,
    KeycloakUser,
    TokenPayload,
    require_roles,
    require_client_roles,
    require_scopes,
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

::: litestar_keycloak.guards.require_scopes
    options:
      show_source: true
      show_root_heading: true
