"""Registry of sessions ended by Keycloak's back-channel logout.

Keycloak announces a logout by POSTing a logout token to the client; the app
cannot reach into its session store by Keycloak ``sid``, so it records the
ended session instead and refuses any later token from it.  Records live in a
Litestar ``Store`` — a ``MemoryStore`` by default, which every app instance
must share (e.g. a Redis store) for a logout to reach all of them.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from litestar.stores.base import Store

    from litestar_keycloak.models import TokenPayload

#: How long a logout is remembered: longer than any sane access-token
#: lifespan, after which no token from the ended session can still be valid.
LOGOUT_RECORD_TTL = 24 * 3600


async def record_logout(store: Store, claims: dict[str, Any]) -> None:
    """Remember a verified logout token's session, or all of its subject's.

    A token with ``sid`` ends that session.  One with only ``sub`` ends every
    session of the user, so tokens issued up to its ``iat`` are refused.
    """
    if claims.get("sid"):
        await store.set(f"sid:{claims['sid']}", b"1", expires_in=LOGOUT_RECORD_TTL)
    else:
        await store.set(
            f"sub:{claims['sub']}",
            str(int(claims["iat"])).encode(),
            expires_in=LOGOUT_RECORD_TTL,
        )


async def is_logged_out(store: Store, payload: TokenPayload) -> bool:
    """Whether *payload* belongs to a session Keycloak has logged out."""
    if payload.sid and await store.exists(f"sid:{payload.sid}"):
        return True
    logged_out_at = await store.get(f"sub:{payload.sub}")
    return logged_out_at is not None and payload.iat <= int(logged_out_at)
