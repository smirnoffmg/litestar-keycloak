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

## Requiring the audience in `aud`: `strict_audience`

By default the plugin falls back to `azp`. It accepts a token whose `aud` names another service, as long as `azp` is `my-app` or one of **optional_audiences**. Keycloak needs this fallback out of the box: it does not put the requesting client into the access token's `aud`, so a default-realm token often carries only `aud="account"`.

The fallback also means a token that Keycloak issued for a different API passes your audience check. To accept only tokens that were issued for your API, set **strict_audience**:

```python
KeycloakConfig(
    server_url="https://keycloak.example.com",
    realm="my-realm",
    client_id="my-app",
    client_secret="...",
    optional_audiences=frozenset({"my-service-client"}),
    strict_audience=True,
)
```

With `strict_audience=True` a token is accepted only if its `aud` (a string or a list) contains `my-app` or `my-service-client`. The `azp` claim is ignored. A token with no `aud` or an empty one is rejected with `401`.

Before you enable it, make Keycloak put your API into `aud`. For every client that requests tokens for your API — the frontend client for user tokens, the service client for client_credentials tokens:

1. In the Keycloak admin console, open **Clients** → the calling client → **Client scopes** → `<client-id>-dedicated`.
2. Choose **Configure a new mapper** (or **Add mapper** → **By configuration**) and select **Audience** (provider id `oidc-audience-mapper`).
3. Set **Included Client Audience** (`included.client.audience`) to your API's client ID, e.g. `my-app`. To add a value that is not a client ID, use **Included Custom Audience** instead.
4. Turn **Add to access token** on and save.

Then check a fresh token: its `aud` must contain `my-app`. In the admin console, **Client scopes** → **Evaluate** on the calling client shows the generated access token. Tokens issued before the change keep their old `aud` until they expire.

We recommend enabling `strict_audience` once every calling client has the mapper. Keycloak describes the mapper in the Server Administration Guide, section "Hardcoded audience".

## Calling other services: `service_tokens`

The plugin owns a `ServiceTokenClient` that obtains outbound tokens with this app's own client credentials (`client_id` + `client_secret`, so the client must be confidential). Handlers receive it as `service_tokens`; code outside handlers uses `plugin.service_tokens` once the app is initialised.

### As this service: `client_token()`

A client_credentials grant — the app calls another service as itself (its *service account*; enable *Service accounts roles* on the client in Keycloak):

```python
from litestar import get
from litestar_keycloak import ServiceTokens

@get("/reports/nightly", exclude_from_auth=True)
async def nightly(service_tokens: ServiceTokens) -> dict:
    token = await service_tokens.client_token()          # or client_token(scope="reports:read")
    ...  # Authorization: Bearer {token}
```

Tokens are cached per `scope` and renewed 30 seconds before they expire (at half-life for tokens shorter than a minute); concurrent callers share one grant. Tokens carrying a `client_id` claim are recognised on the receiving side as `KeycloakUser.is_service_account`.

### On behalf of the user: `exchange()`

Forwarding the caller's own token (below) hands the downstream service a token addressed to *you*. Token exchange (RFC 8693) instead asks Keycloak for a token for the downstream service, for the same user:

```python
from litestar_keycloak import CurrentRawToken, ServiceTokens

@get("/orders/{order_id:int}/invoice")
async def invoice(order_id: int, raw_token: CurrentRawToken, service_tokens: ServiceTokens) -> dict:
    billing_token = await service_tokens.exchange(raw_token, audience="billing")
    ...  # call billing with Authorization: Bearer {billing_token}
```

This uses Keycloak's **standard token exchange**, available from **Keycloak 26.2**. On this app's client enable *Standard token exchange* (attribute `standard.token.exchange.enabled`), and make sure

- the incoming token's `aud` contains this client — e.g. an Audience mapper on the frontend client (and then `strict_audience=True` here costs nothing);
- the requested `audience` is available to this client — e.g. an Audience mapper for `billing` on this client.

Exchanged tokens are not cached. If Keycloak refuses (`audience` not available, exchange not enabled, invalid subject token) or cannot be reached, the call raises `ServiceTokenError` — a `502` if left unhandled. Its `error` and `error_description` attributes (also logged at `WARNING`) say why; the response body is a generic `Keycloak request failed`.

## Forwarding the user token
When your Litestar app calls a downstream API that also validates Keycloak tokens, you can forward the current user's token so the downstream service sees the same identity.

Inject the **raw_token** dependency and pass it in the request:

```python
from litestar import get
from litestar_keycloak import CurrentRawToken
import aiohttp

@get("/proxy/downstream")
async def call_downstream(raw_token: CurrentRawToken) -> dict:
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
