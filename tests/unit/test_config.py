"""Unit tests for KeycloakConfig validation and derived properties."""

import pytest

from litestar_keycloak.config import KeycloakConfig, TokenLocation

# --- Validation ---


def test_minimal_config_requires_server_url_realm_client_id():
    """Valid minimal config with only required fields."""
    config = KeycloakConfig(
        server_url="https://keycloak.example.com",
        realm="my-realm",
        client_id="my-app",
    )
    assert config.server_url == "https://keycloak.example.com"
    assert config.realm == "my-realm"
    assert config.client_id == "my-app"


def test_include_routes_without_redirect_uri_raises_value_error():
    """include_routes=True without redirect_uri raises ValueError."""
    with pytest.raises(ValueError) as exc_info:
        KeycloakConfig(
            server_url="https://kc.example.com",
            realm="r",
            client_id="c",
            include_routes=True,
        )
    assert (
        "redirect_uri" in str(exc_info.value).lower()
        or "include_routes" in str(exc_info.value).lower()
    )


def test_negative_jwks_cache_ttl_raises_value_error():
    """Negative jwks_cache_ttl raises ValueError."""
    with pytest.raises(ValueError) as exc_info:
        KeycloakConfig(
            server_url="https://kc.example.com",
            realm="r",
            client_id="c",
            jwks_cache_ttl=-1,
        )
    assert (
        "jwks_cache_ttl" in str(exc_info.value).lower()
        or "non-negative" in str(exc_info.value).lower()
    )


def test_zero_http_timeout_raises_value_error():
    """Zero http_timeout raises ValueError."""
    with pytest.raises(ValueError) as exc_info:
        KeycloakConfig(
            server_url="https://kc.example.com",
            realm="r",
            client_id="c",
            http_timeout=0,
        )
    assert (
        "http_timeout" in str(exc_info.value).lower()
        or "positive" in str(exc_info.value).lower()
    )


def test_frozen_config_rejects_mutation():
    """Frozen config cannot be mutated."""
    config = KeycloakConfig(
        server_url="https://kc.example.com",
        realm="r",
        client_id="c",
    )
    with pytest.raises((AttributeError, Exception)):
        config.server_url = "https://other.com"  # type: ignore[misc]
    with pytest.raises((AttributeError, Exception)):
        config.realm = "other"  # type: ignore[misc]


# --- Derived URLs ---


def test_realm_url_strips_trailing_slash():
    """realm_url strips trailing slash from server_url."""
    config = KeycloakConfig(
        server_url="https://keycloak.example.com/",
        realm="my-realm",
        client_id="c",
    )
    assert config.realm_url == "https://keycloak.example.com/realms/my-realm"
    assert not config.realm_url.endswith("//")


def test_jwks_url_derived_correctly():
    """jwks_url is realm_url + /protocol/openid-connect/certs."""
    config = KeycloakConfig(
        server_url="https://kc.example.com",
        realm="r",
        client_id="c",
    )
    assert (
        config.jwks_url
        == "https://kc.example.com/realms/r/protocol/openid-connect/certs"
    )


def test_authorization_url_derived_correctly():
    """authorization_url is realm_url + /protocol/openid-connect/auth."""
    config = KeycloakConfig(
        server_url="https://kc.example.com",
        realm="r",
        client_id="c",
    )
    assert (
        config.authorization_url
        == "https://kc.example.com/realms/r/protocol/openid-connect/auth"
    )


def test_token_url_derived_correctly():
    """token_url is realm_url + /protocol/openid-connect/token."""
    config = KeycloakConfig(
        server_url="https://kc.example.com",
        realm="r",
        client_id="c",
    )
    assert (
        config.token_url
        == "https://kc.example.com/realms/r/protocol/openid-connect/token"
    )


def test_logout_url_derived_correctly():
    """logout_url is realm_url + /protocol/openid-connect/logout."""
    config = KeycloakConfig(
        server_url="https://kc.example.com",
        realm="r",
        client_id="c",
    )
    assert (
        config.logout_url
        == "https://kc.example.com/realms/r/protocol/openid-connect/logout"
    )


# --- Audience ---


def test_effective_audience_defaults_to_client_id():
    """When audience is None, effective_audience is client_id."""
    config = KeycloakConfig(
        server_url="https://kc.example.com",
        realm="r",
        client_id="my-client",
    )
    assert config.effective_audience == "my-client"


def test_effective_audience_uses_explicit_override():
    """When audience is set, effective_audience returns it."""
    config = KeycloakConfig(
        server_url="https://kc.example.com",
        realm="r",
        client_id="my-client",
        audience="custom-audience",
    )
    assert config.effective_audience == "custom-audience"


# --- issuer ---


def test_issuer_defaults_to_realm_url():
    """Without expected_issuer, issuer equals realm_url."""
    config = KeycloakConfig(server_url="https://kc.internal", realm="r", client_id="c")
    assert config.issuer == config.realm_url == "https://kc.internal/realms/r"


def test_expected_issuer_overrides_derived_issuer():
    """expected_issuer takes precedence — for frontend/backend URL splits."""
    config = KeycloakConfig(
        server_url="https://kc.internal",
        realm="r",
        client_id="c",
        expected_issuer="https://sso.public.example.com/realms/r",
    )
    assert config.issuer == "https://sso.public.example.com/realms/r"
    # backend endpoints still use server_url
    assert config.jwks_url.startswith("https://kc.internal/")


# --- Other ---


def test_default_values_are_sensible():
    """Default values match typical RS256 confidential client."""
    config = KeycloakConfig(
        server_url="https://kc.example.com",
        realm="r",
        client_id="c",
    )
    assert config.token_location is TokenLocation.HEADER
    assert config.cookie_name == "access_token"
    assert config.algorithms == ("RS256",)
    assert config.scopes == ("openid",)
    assert config.jwks_cache_ttl == 3600
    assert config.include_routes is False
    assert config.auth_prefix == "/auth"
    assert config.redirect_uri is None
    assert config.audience is None
    assert config.http_timeout == 10
    assert config.excluded_paths == frozenset()
    assert config.issuer == config.realm_url


def test_oidc_route_defaults():
    """Defaults for the OIDC route settings."""
    config = KeycloakConfig(
        server_url="https://kc.example.com",
        realm="r",
        client_id="c",
    )
    assert config.callback_response_mode == "json"
    assert config.cookie_secure is True
    assert config.cookie_samesite == "lax"
    assert config.post_login_redirect_uri == "/"
    assert config.post_logout_redirect_uri is None


def test_effective_excluded_paths_includes_auth_paths_when_include_routes():
    """When include_routes=True, effective_excluded_paths includes auth prefix paths."""
    config = KeycloakConfig(
        server_url="https://kc.example.com",
        realm="r",
        client_id="c",
        include_routes=True,
        redirect_uri="https://app/callback",
        auth_prefix="/auth",
        excluded_paths=frozenset({"/health"}),
    )
    effective = config.effective_excluded_paths
    assert "/health" in effective
    assert "/auth/login" in effective
    assert "/auth/callback" in effective
    assert "/auth/logout" in effective
    assert "/auth/refresh" in effective


def test_effective_excluded_paths_without_routes_returns_only_excluded_paths():
    """When include_routes=False, effective_excluded_paths is just excluded_paths."""
    config = KeycloakConfig(
        server_url="https://kc.example.com",
        realm="r",
        client_id="c",
        excluded_paths=frozenset({"/health", "/public"}),
    )
    assert config.effective_excluded_paths == frozenset({"/health", "/public"})


# --- exclusion patterns ---


def _cfg(**kwargs):
    return KeycloakConfig(
        server_url="https://kc.example.com", realm="r", client_id="c", **kwargs
    )


def test_exclude_defaults():
    """New exclusion fields default to empty / the standard opt key."""
    config = _cfg()
    assert config.exclude_patterns == ()
    assert config.exclude_opt_key == "exclude_from_auth"


def test_exclude_auth_patterns_none_when_nothing_excluded():
    """No excluded paths or patterns yields None (an empty regex matches all)."""
    assert _cfg().exclude_auth_patterns is None


def test_exclude_auth_patterns_anchors_exact_paths():
    """excluded_paths become anchored ^…$ regexes so they match exactly."""
    config = _cfg(excluded_paths=frozenset({"/health"}))
    assert config.exclude_auth_patterns == ["^/health$"]


def test_exclude_auth_patterns_escapes_regex_metacharacters():
    """Exact paths are regex-escaped, not treated as patterns."""
    config = _cfg(excluded_paths=frozenset({"/a.b"}))
    assert config.exclude_auth_patterns == [r"^/a\.b$"]


def test_exclude_auth_patterns_appends_user_patterns_verbatim():
    """exclude_patterns are added as-is after the anchored exact paths."""
    config = _cfg(
        excluded_paths=frozenset({"/health"}),
        exclude_patterns=("^/public/", "^/docs"),
    )
    assert config.exclude_auth_patterns == ["^/health$", "^/public/", "^/docs"]


def test_exclude_auth_patterns_includes_auth_routes_when_include_routes():
    """Auth routes are anchored into the exclusion patterns when mounted."""
    config = _cfg(include_routes=True, redirect_uri="https://app/callback")
    patterns = config.exclude_auth_patterns
    assert patterns is not None
    assert "^/auth/login$" in patterns
    assert "^/auth/callback$" in patterns
