"""Unit tests for TokenPayload and KeycloakUser models."""

import time

from litestar_keycloak.models import KeycloakUser, TokenPayload

# --- TokenPayload.from_claims ---


def test_from_claims_maps_standard_oidc_fields():
    """from_claims maps sub, iss, aud, exp, iat to TokenPayload."""
    now = int(time.time())
    claims = {
        "sub": "user-123",
        "iss": "https://kc/realms/r",
        "aud": "my-client",
        "exp": now + 3600,
        "iat": now,
    }
    payload = TokenPayload.from_claims(claims)
    assert payload.sub == "user-123"
    assert payload.iss == "https://kc/realms/r"
    assert payload.aud == "my-client"
    assert payload.exp == now + 3600
    assert payload.iat == now


def test_from_claims_maps_keycloak_specific_fields():
    """from_claims maps preferred_username, email, name, realm_access."""
    claims = {
        "sub": "u1",
        "iss": "https://kc/realms/r",
        "aud": "c",
        "exp": 999,
        "iat": 0,
        "preferred_username": "jdoe",
        "email": "j@example.com",
        "email_verified": True,
        "given_name": "Jane",
        "family_name": "Doe",
        "name": "Jane Doe",
        "realm_access": {"roles": ["admin", "user"]},
        "resource_access": {"my-client": {"roles": ["read", "write"]}},
    }
    payload = TokenPayload.from_claims(claims)
    assert payload.preferred_username == "jdoe"
    assert payload.email == "j@example.com"
    assert payload.email_verified is True
    assert payload.given_name == "Jane"
    assert payload.family_name == "Doe"
    assert payload.name == "Jane Doe"
    assert payload.realm_access == {"roles": ["admin", "user"]}
    assert payload.resource_access == {"my-client": {"roles": ["read", "write"]}}


def test_from_claims_puts_unknown_keys_in_extra():
    """Unknown claim keys land in extra."""
    claims = {
        "sub": "u1",
        "iss": "https://kc/realms/r",
        "aud": "c",
        "exp": 999,
        "iat": 0,
        "custom_claim": "value",
        "another": 42,
    }
    payload = TokenPayload.from_claims(claims)
    assert payload.extra.get("custom_claim") == "value"
    assert payload.extra.get("another") == 42


def test_from_claims_handles_minimal_claims():
    """from_claims works with only required fields (sub, iss, aud, exp, iat)."""
    claims = {
        "sub": "u1",
        "iss": "https://kc/realms/r",
        "aud": "c",
        "exp": 999,
        "iat": 0,
    }
    payload = TokenPayload.from_claims(claims)
    assert payload.sub == "u1"
    assert payload.preferred_username is None
    assert payload.scope == ""
    assert payload.realm_access == {}
    assert payload.resource_access == {}
    assert payload.extra == {}


def test_from_claims_aud_fallback_to_azp():
    """When aud is missing, from_claims uses azp as fallback."""
    claims = {
        "sub": "u1",
        "iss": "https://kc/realms/r",
        "azp": "my-client",
        "exp": 999,
        "iat": 0,
    }
    payload = TokenPayload.from_claims(claims)
    assert payload.aud == "my-client"


# --- TokenPayload properties ---


def test_realm_roles_extracts_from_realm_access():
    """realm_roles returns frozenset from realm_access.roles."""
    payload = TokenPayload(
        sub="u1",
        iss="https://kc/realms/r",
        aud="c",
        exp=999,
        iat=0,
        realm_access={"roles": ["admin", "user"]},
    )
    assert payload.realm_roles == frozenset({"admin", "user"})


def test_realm_roles_returns_empty_frozenset_when_missing():
    """realm_roles returns empty frozenset when realm_access has no roles."""
    payload = TokenPayload(
        sub="u1",
        iss="https://kc/realms/r",
        aud="c",
        exp=999,
        iat=0,
        realm_access={},
    )
    assert payload.realm_roles == frozenset()


def test_client_roles_extracts_from_resource_access():
    """client_roles(client_id) returns roles for that client."""
    payload = TokenPayload(
        sub="u1",
        iss="https://kc/realms/r",
        aud="c",
        exp=999,
        iat=0,
        resource_access={"svc-a": {"roles": ["read"]}, "svc-b": {"roles": ["write"]}},
    )
    assert payload.client_roles("svc-a") == frozenset({"read"})
    assert payload.client_roles("svc-b") == frozenset({"write"})


def test_client_roles_returns_empty_frozenset_for_unknown_client():
    """client_roles(unknown_client) returns empty frozenset."""
    payload = TokenPayload(
        sub="u1",
        iss="https://kc/realms/r",
        aud="c",
        exp=999,
        iat=0,
        resource_access={"svc-a": {"roles": ["read"]}},
    )
    assert payload.client_roles("unknown") == frozenset()


def test_scopes_splits_space_delimited_string():
    """scopes property splits scope string into frozenset."""
    payload = TokenPayload(
        sub="u1",
        iss="https://kc/realms/r",
        aud="c",
        exp=999,
        iat=0,
        scope="openid profile email",
    )
    assert payload.scopes == frozenset({"openid", "profile", "email"})


def test_scopes_returns_empty_frozenset_for_empty_string():
    """scopes returns empty frozenset when scope is empty."""
    payload = TokenPayload(
        sub="u1",
        iss="https://kc/realms/r",
        aud="c",
        exp=999,
        iat=0,
        scope="",
    )
    assert payload.scopes == frozenset()


def test_expires_at_returns_utc_datetime():
    """expires_at returns exp as UTC datetime."""
    exp_ts = 2000000000  # 2033
    payload = TokenPayload(
        sub="u1",
        iss="https://kc/realms/r",
        aud="c",
        exp=exp_ts,
        iat=0,
    )
    dt = payload.expires_at
    assert dt.tzinfo is not None
    assert dt.timestamp() == exp_ts


def test_issued_at_returns_utc_datetime():
    """issued_at returns iat as UTC datetime."""
    iat_ts = 1000000000  # 2001
    payload = TokenPayload(
        sub="u1",
        iss="https://kc/realms/r",
        aud="c",
        exp=999,
        iat=iat_ts,
    )
    dt = payload.issued_at
    assert dt.tzinfo is not None
    assert dt.timestamp() == iat_ts


# --- KeycloakUser.from_token ---


def test_from_token_maps_all_identity_fields():
    """from_token maps sub, preferred_username, email, name, etc."""
    payload = TokenPayload(
        sub="user-uuid",
        iss="https://kc/realms/r",
        aud="c",
        exp=999,
        iat=0,
        preferred_username="jdoe",
        email="j@example.com",
        given_name="Jane",
        family_name="Doe",
        name="Jane Doe",
    )
    user = KeycloakUser.from_token(payload)
    assert user.sub == "user-uuid"
    assert user.preferred_username == "jdoe"
    assert user.email == "j@example.com"
    assert user.given_name == "Jane"
    assert user.family_name == "Doe"
    assert user.name == "Jane Doe"


def test_from_token_normalizes_realm_roles_to_frozenset():
    """from_token sets realm_roles from payload.realm_roles (frozenset)."""
    payload = TokenPayload(
        sub="u1",
        iss="https://kc/realms/r",
        aud="c",
        exp=999,
        iat=0,
        realm_access={"roles": ["admin", "user"]},
    )
    user = KeycloakUser.from_token(payload)
    assert user.realm_roles == frozenset({"admin", "user"})


def test_from_token_normalizes_client_roles_per_client():
    """from_token builds client_roles dict with frozenset per client."""
    payload = TokenPayload(
        sub="u1",
        iss="https://kc/realms/r",
        aud="c",
        exp=999,
        iat=0,
        resource_access={
            "client-a": {"roles": ["read"]},
            "client-b": {"roles": ["write", "admin"]},
        },
    )
    user = KeycloakUser.from_token(payload)
    assert user.client_roles["client-a"] == frozenset({"read"})
    assert user.client_roles["client-b"] == frozenset({"write", "admin"})


def test_from_token_preserves_raw_payload():
    """from_token sets raw to the TokenPayload."""
    payload = TokenPayload(
        sub="u1",
        iss="https://kc/realms/r",
        aud="c",
        exp=999,
        iat=0,
    )
    user = KeycloakUser.from_token(payload)
    assert user.raw is payload


# --- KeycloakUser.has_role / has_client_role / has_scope ---


def test_has_role_returns_true_for_present_role():
    """has_role returns True when user has the realm role."""
    user = KeycloakUser(sub="u1", realm_roles=frozenset({"admin", "user"}))
    assert user.has_role("admin") is True
    assert user.has_role("user") is True


def test_has_role_returns_false_for_absent_role():
    """has_role returns False when user does not have the realm role."""
    user = KeycloakUser(sub="u1", realm_roles=frozenset({"user"}))
    assert user.has_role("admin") is False


def test_has_client_role_checks_correct_client():
    """has_client_role(client_id, role) checks that client's roles."""
    user = KeycloakUser(
        sub="u1",
        client_roles={
            "svc-a": frozenset({"read"}),
            "svc-b": frozenset({"write"}),
        },
    )
    assert user.has_client_role("svc-a", "read") is True
    assert user.has_client_role("svc-b", "write") is True
    assert user.has_client_role("svc-a", "write") is False


def test_has_client_role_returns_false_for_unknown_client():
    """has_client_role returns False for unknown client_id."""
    user = KeycloakUser(sub="u1", client_roles={"svc-a": frozenset({"read"})})
    assert user.has_client_role("unknown", "read") is False


def test_has_scope_returns_true_for_present_scope():
    """has_scope returns True when token has the scope."""
    user = KeycloakUser(sub="u1", scopes=frozenset({"openid", "profile"}))
    assert user.has_scope("openid") is True
    assert user.has_scope("profile") is True


def test_has_scope_returns_false_for_absent_scope():
    """has_scope returns False when token does not have the scope."""
    user = KeycloakUser(sub="u1", scopes=frozenset({"openid"}))
    assert user.has_scope("profile") is False
