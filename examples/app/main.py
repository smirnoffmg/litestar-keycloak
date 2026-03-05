"""Example Litestar app with Keycloak OIDC authentication.

Run with Keycloak available (e.g. docker-compose up keycloak):
  KEYCLOAK_SERVER_URL=http://localhost:8080 python main.py

Or run fully in Docker (see examples/README.md).
"""

from __future__ import annotations

import os
from typing import Any

import aiohttp
from litestar import Litestar, get
from litestar.middleware.session.server_side import ServerSideSessionConfig
from litestar.stores.memory import MemoryStore

from litestar_keycloak import (
    KeycloakConfig,
    KeycloakPlugin,
    KeycloakUser,
    TokenLocation,
    TokenPayload,
    require_roles,
)

# ---------------------------------------------------------------------------
# Configuration (override via env in production)
# ---------------------------------------------------------------------------
KEYCLOAK_SERVER_URL = os.environ.get("KEYCLOAK_SERVER_URL", "http://localhost:8080")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "test-realm")
KEYCLOAK_CLIENT_ID = os.environ.get("KEYCLOAK_CLIENT_ID", "test-app")
KEYCLOAK_CLIENT_SECRET = os.environ.get("KEYCLOAK_CLIENT_SECRET", "test-secret")
REDIRECT_URI = os.environ.get("REDIRECT_URI", "http://localhost:8000/auth/callback")
# Service account for service-to-service (client_credentials)
KEYCLOAK_SERVICE_CLIENT_ID = os.environ.get(
    "KEYCLOAK_SERVICE_CLIENT_ID", "test-service"
)
KEYCLOAK_SERVICE_CLIENT_SECRET = os.environ.get(
    "KEYCLOAK_SERVICE_CLIENT_SECRET", "service-secret"
)
# Base URL of this app (for self-calls in service-to-service demo)
BACKEND_BASE_URL = os.environ.get("BACKEND_BASE_URL", "http://127.0.0.1:8000")

# ---------------------------------------------------------------------------
# Keycloak plugin config
# ---------------------------------------------------------------------------
keycloak_config = KeycloakConfig(
    server_url=KEYCLOAK_SERVER_URL,
    realm=KEYCLOAK_REALM,
    client_id=KEYCLOAK_CLIENT_ID,
    client_secret=KEYCLOAK_CLIENT_SECRET,
    token_location=TokenLocation.HEADER,
    include_routes=True,
    redirect_uri=REDIRECT_URI,
    auth_prefix="/auth",
    excluded_paths=frozenset({"/", "/health", "/service/call-backend"}),
    optional_audiences=frozenset({KEYCLOAK_SERVICE_CLIENT_ID}),  # accept service tokens
)

# Session middleware (required for OAuth state in login/callback)
session_config = ServerSideSessionConfig(store="sessions")


async def get_service_token() -> str:
    """Obtain an access token via client_credentials (service account)."""
    token_url = (
        f"{KEYCLOAK_SERVER_URL.rstrip('/')}/realms/{KEYCLOAK_REALM}"
        "/protocol/openid-connect/token"
    )
    timeout = aiohttp.ClientTimeout(total=10)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": KEYCLOAK_SERVICE_CLIENT_ID,
                "client_secret": KEYCLOAK_SERVICE_CLIENT_SECRET,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        ) as resp:
            resp.raise_for_status()
            data: dict[str, Any] = await resp.json()
            return data["access_token"]


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------
@get("/")
async def index() -> dict[str, str]:
    """Public landing with link to login."""
    return {
        "message": "Litestar + Keycloak example",
        "docs": "OpenAPI at /schema",
        "login": "/auth/login",
        "me": "GET /me (requires Bearer token)",
        "admin": "GET /admin (requires admin role)",
        "service_to_service": (
            "GET /service/call-backend, GET /user/forward (user token)"
        ),
    }


@get("/health")
async def health() -> dict[str, str]:
    """Health check (no auth)."""
    return {"status": "ok"}


@get("/me")
async def me(current_user: KeycloakUser) -> dict:
    """Current user info (requires valid Bearer token)."""
    return {
        "sub": current_user.sub,
        "preferred_username": current_user.preferred_username,
        "email": current_user.email,
        "realm_roles": list(current_user.realm_roles),
        "client_roles": {k: list(v) for k, v in current_user.client_roles.items()},
    }


@get("/admin", guards=[require_roles("admin")])
async def admin_panel(current_user: KeycloakUser) -> dict:
    """Admin-only area (guard: realm role 'admin')."""
    return {
        "message": f"Welcome, {current_user.preferred_username or current_user.sub}",
        "roles": list(current_user.realm_roles),
    }


# ---------------------------------------------------------------------------
# Service-to-service: internal backend (any valid token; in production
# you might use require_client_roles("test-service", "read"))
# ---------------------------------------------------------------------------
@get("/internal/backend")
async def internal_backend(
    current_user: KeycloakUser,
    token_payload: TokenPayload,
) -> dict[str, Any]:
    """Backend: any valid token. In production use require_client_roles."""
    return {
        "message": "backend",
        "called_by_sub": current_user.sub,
        "called_by_client": token_payload.azp,
        "realm_roles": list(current_user.realm_roles),
        "client_roles_test_service": list(
            current_user.client_roles.get("test-service", set()),
        ),
    }


# ---------------------------------------------------------------------------
# Service-to-service: app calls backend with service account token
# ---------------------------------------------------------------------------
@get("/service/call-backend")
async def service_call_backend() -> dict[str, Any]:
    """Obtain a token via client_credentials (test-service) and call /internal/backend.
    No user token required — demonstrates machine-to-machine / service-to-service.
    """
    token = await get_service_token()
    url = f"{BACKEND_BASE_URL.rstrip('/')}/internal/backend"
    timeout = aiohttp.ClientTimeout(total=10)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
        ) as resp:
            resp.raise_for_status()
            return await resp.json()


# ---------------------------------------------------------------------------
# Service-to-service: forward current user's token to downstream
# ---------------------------------------------------------------------------
@get("/user/forward")
async def user_forward(
    raw_token: str,
) -> dict[str, Any]:
    """Forward the current user's Bearer token to the internal backend.
    Demonstrates user-context propagation to a downstream service.
    """
    url = f"{BACKEND_BASE_URL.rstrip('/')}/internal/backend"
    timeout = aiohttp.ClientTimeout(total=10)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(
            url,
            headers={"Authorization": f"Bearer {raw_token}"},
        ) as resp:
            resp.raise_for_status()
            return await resp.json()


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = Litestar(
    route_handlers=[
        index,
        health,
        me,
        admin_panel,
        internal_backend,
        service_call_backend,
        user_forward,
    ],
    plugins=[KeycloakPlugin(keycloak_config)],
    middleware=[session_config.middleware],
    stores={"sessions": MemoryStore()},
)
