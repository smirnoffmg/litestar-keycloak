"""Journeys B7.1 and B8 (JOURNEYS.md): Keycloak changing or vanishing under the app.

B8 puts a TCP proxy between the app and Keycloak and shuts it down mid-test, so
the app loses Keycloak while the suite's shared container keeps running.
"""

import base64
import dataclasses
import json
import socket
import threading
import time
import urllib.parse
from collections.abc import Iterator

import httpx
import jwt
import pytest
from litestar import Litestar, get
from litestar.testing import TestClient

from litestar_keycloak import CurrentUser, KeycloakPlugin

pytestmark = pytest.mark.integration


@get("/me")
async def me(current_user: CurrentUser) -> dict:
    return {"username": current_user.preferred_username}


def _password_token(base_url: str) -> str:
    resp = httpx.post(
        f"{base_url}/realms/test-realm/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "test-app",
            "client_secret": "test-secret",
            "username": "testuser",
            "password": "testpass",
        },
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --- B7.1: key rotation -----------------------------------------------------------


def test_signing_key_rotation_needs_no_restart(
    keycloak_container, keycloak_config, admin_api
):
    """A new active key: its tokens and the old key's tokens are both accepted."""
    base_url = keycloak_container.get_url()
    old_token = _password_token(base_url)
    app = Litestar(route_handlers=[me], plugins=[KeycloakPlugin(keycloak_config)])
    with TestClient(app) as client:
        assert client.get("/me", headers=_bearer(old_token)).status_code == 200

        resp = admin_api.post(
            "/components",
            json={
                "name": "rotation-it",
                "providerId": "rsa-generated",
                "providerType": "org.keycloak.keys.KeyProvider",
                "config": {"priority": ["1000"], "keySize": ["2048"]},
            },
        )
        assert resp.status_code == 201, resp.text
        component = resp.headers["location"].rsplit("/", 1)[-1]
        try:
            new_token = _password_token(base_url)
            assert (
                jwt.get_unverified_header(new_token)["kid"]
                != jwt.get_unverified_header(old_token)["kid"]
            )
            assert client.get("/me", headers=_bearer(new_token)).status_code == 200
            assert client.get("/me", headers=_bearer(old_token)).status_code == 200
        finally:
            admin_api.delete(f"/components/{component}").raise_for_status()


# --- B8: Keycloak unreachable -------------------------------------------------------


class _Proxy:
    """A TCP forwarder to Keycloak that can be cut, connections and all."""

    def __init__(self, target_host: str, target_port: int) -> None:
        self._target = (target_host, target_port)
        self._listener = socket.create_server(("127.0.0.1", 0))
        self._sockets: list[socket.socket] = []
        self.port = self._listener.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            try:
                downstream, _ = self._listener.accept()
            except OSError:
                return
            upstream = socket.create_connection(self._target)
            self._sockets += [downstream, upstream]
            for src, dst in ((downstream, upstream), (upstream, downstream)):
                threading.Thread(
                    target=self._pipe, args=(src, dst), daemon=True
                ).start()

    @staticmethod
    def _pipe(src: socket.socket, dst: socket.socket) -> None:
        try:
            while data := src.recv(65536):
                dst.sendall(data)
        except OSError:
            pass
        finally:
            dst.close()

    def cut(self) -> None:
        self._listener.close()
        for sock in self._sockets:
            sock.close()


@pytest.fixture
def keycloak_proxy(keycloak_container) -> Iterator[_Proxy]:
    url = urllib.parse.urlparse(keycloak_container.get_url())
    proxy = _Proxy(url.hostname or "localhost", url.port or 80)
    yield proxy
    proxy.cut()


def _with_kid(token: str, kid: str) -> str:
    header, payload, signature = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(header + "=="))
    forged = base64.urlsafe_b64encode(json.dumps({**claims, "kid": kid}).encode())
    return ".".join([forged.rstrip(b"=").decode(), payload, signature])


def test_keycloak_outage_keeps_valid_tokens_working(
    keycloak_container, keycloak_config, keycloak_proxy
):
    token = _password_token(keycloak_container.get_url())
    config = dataclasses.replace(
        keycloak_config,
        server_url=f"http://127.0.0.1:{keycloak_proxy.port}",
        # Tokens name the address they were issued at, not the proxy's.
        expected_issuer=keycloak_config.issuer,
        jwks_cache_ttl=1,
        http_timeout=2,
    )
    app = Litestar(route_handlers=[me], plugins=[KeycloakPlugin(config)])
    with TestClient(app) as client:
        # B8.1. Keys warmed through the proxy; then Keycloak goes and the TTL passes.
        assert client.get("/me", headers=_bearer(token)).status_code == 200
        keycloak_proxy.cut()
        time.sleep(1.5)
        assert client.get("/me", headers=_bearer(token)).json() == {
            "username": "testuser"
        }

        # B8.2. A key the app never saw cannot be fetched: a generic 502.
        unknown = client.get("/me", headers=_bearer(_with_kid(token, "never-seen")))
        assert unknown.status_code == 502
        assert unknown.json() == {"error": "Keycloak request failed"}
