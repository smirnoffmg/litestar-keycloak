# Service-to-service

The plugin can accept tokens from **multiple audiences**: your main client (e.g. frontend or API client) and one or more **service clients** used for machine-to-machine or backend-to-backend calls.

## Accepting service tokens: `optional_audiences`

Add the service client ID(s) to **optional_audiences**. The plugin will accept a token if:

- Its `aud` claim (or list of audiences) includes the primary audience or any optional audience, or
- Its `azp` (authorized party) claim is in the accepted set.

Keycloak often issues client_credentials tokens with `aud="account"` and `azp` set to the client ID; the plugin treats `azp` as accepted when it is in **optional_audiences** (or the primary audience).

```python
KeycloakConfig(
    server_url="https://keycloak.example.com",
    realm="my-realm",
    client_id="my-app",
    client_secret="...",
    optional_audiences=frozenset({"my-service-client"}),
)
```

Then both user tokens (aud/azp = `my-app`) and service tokens (azp = `my-service-client`) are valid.

## Obtaining a service token (client_credentials)

Outside the plugin you request a token from Keycloak's token endpoint:

```http
POST /realms/{realm}/protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=my-service-client&client_secret=...
```

Use the returned `access_token` in the `Authorization: Bearer ...` header when calling your Litestar app (or another service that validates the same realm).

## Forwarding the user token

When your Litestar app calls a downstream API that also validates Keycloak tokens, you can forward the current user's token so the downstream service sees the same identity.

Inject the **raw_token** dependency and pass it in the request:

```python
from litestar import get
from litestar_keycloak import KeycloakUser
import aiohttp

@get("/proxy/downstream")
async def call_downstream(raw_token: str) -> dict:
    async with aiohttp.ClientSession() as session:
        async with session.get(
            "https://downstream.example.com/api/data",
            headers={"Authorization": f"Bearer {raw_token}"},
        ) as resp:
            resp.raise_for_status()
            return await resp.json()
```

The downstream service must be configured to accept tokens from the same Keycloak realm (and typically the same client or audience).

## Excluding service-only routes

Routes that are only meant to be called with a service token (e.g. an internal health or admin endpoint) can still use the same plugin; the service account must have the required roles if you use guards. If a route should be callable **without** any token (e.g. a callback used by the app with its own client_credentials token), add that path to **excluded_paths** and perform your own token validation or leave it unauthenticated as appropriate.
