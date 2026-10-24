"""Optional authentication: routes that serve anonymous and signed-in callers."""

from litestar import Litestar, get
from litestar.testing import TestClient

from litestar_keycloak import (
    CurrentUser,
    OptionalCurrentUser,
    OptionalRawToken,
    OptionalTokenPayload,
)
from tests.conftest import MockKeycloakPlugin, create_test_token


@get("/feed", optional_auth=True)
async def _feed(current_user: OptionalCurrentUser) -> dict:
    return {"sub": current_user.sub if current_user else None}


@get("/feed-token", optional_auth=True)
async def _feed_token(
    token_payload: OptionalTokenPayload, raw_token: OptionalRawToken
) -> dict:
    return {"payload": token_payload is not None, "raw": raw_token is not None}


@get("/feed-custom", public_ok=True)
async def _feed_custom(current_user: OptionalCurrentUser) -> dict:
    return {"sub": current_user.sub if current_user else None}


@get("/me")
async def _me(current_user: CurrentUser) -> dict:
    return {"sub": current_user.sub}


def _client(**kwargs) -> TestClient:
    app = Litestar(
        route_handlers=[_feed, _feed_token, _feed_custom, _me],
        plugins=[MockKeycloakPlugin(**kwargs)],
    )
    return TestClient(app)


def _bearer(**claims) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_test_token(**claims)}"}


def test_optional_route_serves_anonymous_caller():
    with _client() as client:
        resp = client.get("/feed")
    assert resp.status_code == 200
    assert resp.json() == {"sub": None}


def test_optional_route_still_authenticates_a_token():
    with _client() as client:
        resp = client.get("/feed", headers=_bearer(sub="user-1"))
    assert resp.json() == {"sub": "user-1"}


def test_optional_route_rejects_an_invalid_token():
    """A bad token is an error, not a silent downgrade to anonymous."""
    with _client() as client:
        resp = client.get("/feed", headers=_bearer(exp_offset=-60))
    assert resp.status_code == 401


def test_optional_route_injects_none_for_payload_and_raw_token():
    with _client() as client:
        anonymous = client.get("/feed-token").json()
        signed_in = client.get("/feed-token", headers=_bearer()).json()
    assert anonymous == {"payload": False, "raw": False}
    assert signed_in == {"payload": True, "raw": True}


def test_other_routes_still_require_a_token():
    with _client() as client:
        assert client.get("/me").status_code == 401


def test_optional_auth_opt_key_is_configurable():
    with _client(optional_auth_opt_key="public_ok") as client:
        assert client.get("/feed-custom").json() == {"sub": None}
        assert client.get("/feed").status_code == 401
