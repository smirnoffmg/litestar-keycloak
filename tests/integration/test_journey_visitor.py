"""Journey B3 (JOURNEYS.md): a visitor of a page that serves everyone.

``optional_auth`` routes answer anonymous callers and personalise for signed-in
ones; a guarded one still asks an anonymous caller to sign in.
"""

import pytest
from litestar import Litestar, get
from litestar.testing import TestClient

from litestar_keycloak import KeycloakPlugin, OptionalCurrentUser, require_roles

pytestmark = pytest.mark.integration


@get("/feed", optional_auth=True)
async def feed(current_user: OptionalCurrentUser) -> dict:
    return {"for": current_user.preferred_username if current_user else None}


@get("/drafts", optional_auth=True, guards=[require_roles("user")])
async def drafts(current_user: OptionalCurrentUser) -> dict:
    return {"for": current_user.preferred_username if current_user else None}


def test_visitor_journey(keycloak_config, user_token):
    app = Litestar(
        route_handlers=[feed, drafts], plugins=[KeycloakPlugin(keycloak_config)]
    )
    with TestClient(app) as client:
        # 1. Anonymous: the public version.
        assert client.get("/feed").json() == {"for": None}

        # 2. Signed in: the personal version.
        bearer = {"Authorization": f"Bearer {user_token}"}
        assert client.get("/feed", headers=bearer).json() == {"for": "testuser"}

        # 3. A broken token is refused, not downgraded to anonymous.
        broken = {"Authorization": f"Bearer {user_token[:-4]}AAAA"}
        assert client.get("/feed", headers=broken).status_code == 401

        # 4. A guarded page asks an anonymous visitor to sign in.
        anonymous = client.get("/drafts")
        assert anonymous.status_code == 401
        assert anonymous.headers["www-authenticate"] == "Bearer"
        assert client.get("/drafts", headers=bearer).json() == {"for": "testuser"}
