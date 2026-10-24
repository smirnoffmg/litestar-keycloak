"""Session lifecycle: auto-refresh of session tokens and back-channel logout."""

from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import jwt
import pytest
from litestar import Litestar, Request, get
from litestar.middleware.session.server_side import ServerSideSessionConfig
from litestar.stores.memory import MemoryStore
from litestar.testing import TestClient

from litestar_keycloak import CurrentUser
from tests.conftest import _TEST_PRIVATE_KEY, MockKeycloakPlugin, create_test_token

BACKCHANNEL_EVENT = "http://schemas.openid.net/event/backchannel-logout"


@get("/me")
async def _me(current_user: CurrentUser) -> dict:
    return {"sub": current_user.sub}


@get("/debug/session", exclude_from_auth=True)
async def _session(request: Request) -> dict:
    return {
        "access": request.session.get("keycloak_access_token"),
        "refresh": request.session.get("keycloak_refresh_token"),
    }


def _app(**config) -> Litestar:
    return Litestar(
        route_handlers=[_me, _session],
        plugins=[
            MockKeycloakPlugin(
                include_routes=True,
                redirect_uri="http://localhost:8000/auth/callback",
                cookie_secure=False,
                callback_response_mode="redirect",
                **config,
            )
        ],
        middleware=[ServerSideSessionConfig().middleware],
        stores={"sessions": MemoryStore()},
    )


def _sign_in(client, access_token: str, refresh_token: str = "rt-1") -> None:
    """Complete login + callback so the tokens land in the server-side session."""
    with patch(
        "litestar_keycloak.routes._exchange_code",
        new_callable=AsyncMock,
        return_value={"access_token": access_token, "refresh_token": refresh_token},
    ):
        login = client.get("/auth/login", follow_redirects=False)
        state = login.headers["location"].split("state=")[1].split("&")[0]
        client.get(f"/auth/callback?code=c&state={state}", follow_redirects=False)


def _refresh_mock(**kwargs):
    return patch(
        "litestar_keycloak.plugin._refresh_token", new_callable=AsyncMock, **kwargs
    )


# -- auto-refresh ---------------------------------------------------------------


def test_expired_session_token_is_refreshed_and_persisted():
    fresh = create_test_token(sub="user-1")
    with TestClient(_app(session_auto_refresh=True)) as client:
        _sign_in(client, create_test_token(sub="user-1", exp_offset=-60))
        with _refresh_mock(
            return_value={"access_token": fresh, "refresh_token": "rt-2"}
        ) as refresh:
            first = client.get("/me")
            second = client.get("/me")
            session = client.get("/debug/session").json()
    assert first.status_code == 200 and second.status_code == 200
    assert refresh.await_count == 1
    assert refresh.await_args.args[1] == "rt-1"
    assert session == {"access": fresh, "refresh": "rt-2"}


def test_without_the_flag_an_expired_session_token_is_401():
    with TestClient(_app()) as client:
        _sign_in(client, create_test_token(exp_offset=-60))
        with _refresh_mock() as refresh:
            assert client.get("/me").status_code == 401
    refresh.assert_not_awaited()


def test_expired_bearer_header_is_not_refreshed():
    """Only the session's own tokens are refreshed; a header token is the caller's."""
    expired = create_test_token(exp_offset=-60)
    with (
        TestClient(_app(session_auto_refresh=True)) as client,
        _refresh_mock() as refresh,
    ):
        resp = client.get("/me", headers={"Authorization": f"Bearer {expired}"})
    assert resp.status_code == 401
    refresh.assert_not_awaited()


def _token_endpoint(**kwargs):
    """Mock at the HTTP boundary, so the refresh path's own error mapping runs."""
    return patch(
        "litestar_keycloak.http_client.KeycloakHttpClient.post_form",
        new_callable=AsyncMock,
        **kwargs,
    )


def test_rejected_refresh_is_401_until_the_next_login():
    """An expired or revoked refresh token keeps the session signed out."""
    rejected = aiohttp.ClientResponseError(MagicMock(), (), status=400)
    with TestClient(_app(session_auto_refresh=True)) as client:
        _sign_in(client, create_test_token(exp_offset=-60))
        with _token_endpoint(side_effect=rejected):
            first = client.get("/me")
            assert client.get("/me").status_code == 401
        _sign_in(client, create_test_token(sub="user-1"))
        assert client.get("/me").status_code == 200
    assert first.status_code == 401
    assert first.headers["www-authenticate"] == (
        'Bearer error="invalid_token", error_description="Token expired"'
    )
    assert first.json() == {"error": "Token expired"}


def test_keycloak_unreachable_during_refresh_is_502():
    with TestClient(_app(session_auto_refresh=True)) as client:
        _sign_in(client, create_test_token(exp_offset=-60))
        with (
            _token_endpoint(side_effect=aiohttp.ClientConnectionError("refused")),
            patch("litestar_keycloak.exceptions.logger") as log,
        ):
            assert client.get("/me").status_code == 502
    assert "SessionRefreshError" in log.warning.call_args.args


# -- back-channel logout ----------------------------------------------------------


def _logout_token(**claims) -> str:
    import time

    payload = {
        "iss": "http://localhost:8080/realms/test-realm",
        "aud": "test-app",
        "iat": int(time.time()),
        "exp": int(time.time()) + 120,
        "sub": "user-1",
        "sid": "s-1",
        "events": {BACKCHANNEL_EVENT: {}},
        **claims,
    }
    return jwt.encode(
        payload,
        _TEST_PRIVATE_KEY,
        algorithm="RS256",
        headers={"kid": "test-kid", "typ": "logout+jwt"},
    )


def test_backchannel_logout_ends_the_session_and_its_tokens():
    token = create_test_token(sub="user-1", sid="s-1")
    with TestClient(_app(backchannel_logout=True)) as client:
        _sign_in(client, token)
        assert client.get("/me").status_code == 200
        resp = client.post(
            "/auth/backchannel-logout", data={"logout_token": _logout_token()}
        )
        assert resp.status_code == 200
        assert resp.headers["cache-control"] == "no-store"
        assert client.get("/me").status_code == 401
        assert client.get("/me").status_code == 401
        bearer = client.get("/me", headers={"Authorization": f"Bearer {token}"})
        other = create_test_token(sub="user-1", sid="s-2")
        other_resp = client.get("/me", headers={"Authorization": f"Bearer {other}"})
    assert bearer.status_code == 401
    assert other_resp.status_code == 200


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"logout_token": "garbage"},
        {"logout_token": create_test_token(sid="s-1")},  # an access token
    ],
    ids=["missing", "garbage", "access-token"],
)
def test_backchannel_logout_rejects_invalid_requests(data):
    with TestClient(_app(backchannel_logout=True)) as client:
        resp = client.post("/auth/backchannel-logout", data=data)
        session_alive = client.get(
            "/me", headers={"Authorization": f"Bearer {create_test_token(sid='s-1')}"}
        )
    assert resp.status_code == 400
    assert resp.json() == {"error": "invalid_request"}
    assert session_alive.status_code == 200


def test_backchannel_logout_route_is_absent_by_default():
    with TestClient(_app()) as client:
        resp = client.post("/auth/backchannel-logout", data={"logout_token": "x"})
    assert resp.status_code != 200


def test_session_without_refresh_token_is_401():
    with TestClient(_app(session_auto_refresh=True)) as client:
        _sign_in(client, create_test_token(exp_offset=-60), refresh_token="")
        with _refresh_mock() as refresh:
            assert client.get("/me").status_code == 401
    refresh.assert_not_awaited()


def test_keycloak_server_error_during_refresh_is_502():
    """A 5xx is Keycloak's fault, not a sign that the session ended."""
    broken = aiohttp.ClientResponseError(MagicMock(), (), status=503)
    with TestClient(_app(session_auto_refresh=True)) as client:
        _sign_in(client, create_test_token(exp_offset=-60))
        with _token_endpoint(side_effect=broken):
            assert client.get("/me").status_code == 502
