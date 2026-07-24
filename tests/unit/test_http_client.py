"""Unit tests for KeycloakHttpClient (lazy session, reuse, close, requests)."""

from unittest.mock import patch

from litestar_keycloak.http_client import KeycloakHttpClient


class _FakeResp:
    def __init__(self, data: dict) -> None:
        self._data = data
        self.raised = False

    async def __aenter__(self) -> "_FakeResp":
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    def raise_for_status(self) -> None:
        self.raised = True

    async def json(self, content_type: object = None) -> dict:
        return self._data


class _FakeSession:
    instances = 0

    def __init__(self, **_kwargs) -> None:
        type(self).instances += 1
        self.closed = False
        self.calls: list[tuple] = []

    def get(self, url, headers=None) -> _FakeResp:
        self.calls.append(("GET", url, headers))
        return _FakeResp({"keys": []})

    def post(self, url, data=None, headers=None) -> _FakeResp:
        self.calls.append(("POST", url, data, headers))
        return _FakeResp({"access_token": "at"})

    async def close(self) -> None:
        self.closed = True


# --- session lifecycle (the core P3 behaviour) ---


async def test_session_is_lazy_and_reused():
    """No session is created in __init__; repeated use reuses one instance."""
    _FakeSession.instances = 0
    client = KeycloakHttpClient(10)
    with patch("litestar_keycloak.http_client.aiohttp.ClientSession", _FakeSession):
        assert _FakeSession.instances == 0
        s1 = await client._get_session()
        s2 = await client._get_session()
    assert s1 is s2
    assert _FakeSession.instances == 1


async def test_close_is_idempotent():
    """close() closes the session and can be called again safely."""
    client = KeycloakHttpClient(10)
    with patch("litestar_keycloak.http_client.aiohttp.ClientSession", _FakeSession):
        session = await client._get_session()
        await client.close()
        assert session.closed is True
        await client.close()  # no error, still closed


async def test_close_without_use_is_noop():
    """close() before any request does not create or require a session."""
    _FakeSession.instances = 0
    client = KeycloakHttpClient(10)
    with patch("litestar_keycloak.http_client.aiohttp.ClientSession", _FakeSession):
        await client.close()
    assert _FakeSession.instances == 0


async def test_new_session_created_after_close():
    """A request after close() re-creates the session."""
    _FakeSession.instances = 0
    client = KeycloakHttpClient(10)
    with patch("litestar_keycloak.http_client.aiohttp.ClientSession", _FakeSession):
        await client._get_session()
        await client.close()
        await client._get_session()
    assert _FakeSession.instances == 2


# --- request helpers ---


async def test_get_json_returns_body():
    client = KeycloakHttpClient(10)
    with patch("litestar_keycloak.http_client.aiohttp.ClientSession", _FakeSession):
        result = await client.get_json("http://kc/jwks", headers={"Accept": "x"})
        session = await client._get_session()
    assert result == {"keys": []}
    assert session.calls[0] == ("GET", "http://kc/jwks", {"Accept": "x"})


async def test_post_form_sets_urlencoded_header_and_returns_body():
    client = KeycloakHttpClient(10)
    with patch("litestar_keycloak.http_client.aiohttp.ClientSession", _FakeSession):
        result = await client.post_form("http://kc/token", {"grant_type": "x"})
        session = await client._get_session()
    assert result == {"access_token": "at"}
    method, url, data, headers = session.calls[0]
    assert (method, url, data) == ("POST", "http://kc/token", {"grant_type": "x"})
    assert headers["Content-Type"] == "application/x-www-form-urlencoded"


async def test_post_form_discard_ignores_response():
    client = KeycloakHttpClient(10)
    with patch("litestar_keycloak.http_client.aiohttp.ClientSession", _FakeSession):
        result = await client.post_form_discard("http://kc/logout", {"a": "b"})
        session = await client._get_session()
    assert result is None
    assert session.calls[0][0] == "POST"
