"""Unit tests for the back-channel logout registry."""

import time

from litestar.stores.memory import MemoryStore

from litestar_keycloak.logout import is_logged_out, record_logout
from litestar_keycloak.models import TokenPayload


def _payload(**claims) -> TokenPayload:
    now = int(time.time())
    return TokenPayload.from_claims(
        {"sub": "user-1", "iss": "i", "aud": "a", "exp": now + 60, "iat": now, **claims}
    )


async def test_logged_out_session_is_revoked_other_sessions_are_not():
    store = MemoryStore()
    await record_logout(store, {"sid": "s-1", "sub": "user-1", "iat": 0})
    assert await is_logged_out(store, _payload(sid="s-1"))
    assert not await is_logged_out(store, _payload(sid="s-2"))


async def test_subject_logout_revokes_tokens_issued_before_it():
    """Without sid, every session of the user ends — but not a later login."""
    store = MemoryStore()
    now = int(time.time())
    await record_logout(store, {"sub": "user-1", "iat": now})
    assert await is_logged_out(store, _payload(iat=now - 5, sid="old"))
    assert not await is_logged_out(store, _payload(iat=now + 5, sid="new"))
    assert not await is_logged_out(store, _payload(sub="user-2", iat=now - 5))
