"""Unit tests for KeycloakConfig validation and derived properties."""

import logging

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


def test_negative_leeway_raises_value_error():
    """leeway < 0 raises ValueError."""
    with pytest.raises(ValueError, match="leeway"):
        KeycloakConfig(server_url="https://kc", realm="r", client_id="c", leeway=-1)


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


def test_token_introspection_requires_client_secret():
    """Keycloak authenticates the introspecting client, so a secret is needed."""
    with pytest.raises(ValueError, match="client_secret"):
        KeycloakConfig(
            server_url="https://kc", realm="r", client_id="c", token_introspection=True
        )


def test_negative_introspection_cache_ttl_raises_value_error():
    with pytest.raises(ValueError, match="introspection_cache_ttl"):
        KeycloakConfig(
            server_url="https://kc",
            realm="r",
            client_id="c",
            client_secret="s",
            introspection_cache_ttl=-1,
        )


def test_introspection_url_is_derived_from_realm():
    config = KeycloakConfig(server_url="https://kc/", realm="r", client_id="c")
    assert (
        config.introspection_url
        == "https://kc/realms/r/protocol/openid-connect/token/introspect"
    )


def _routes(**kwargs) -> KeycloakConfig:
    return KeycloakConfig(
        server_url="https://kc",
        realm="r",
        client_id="c",
        include_routes=True,
        redirect_uri="https://app/auth/callback",
        **kwargs,
    )


def test_session_auto_refresh_requires_redirect_mode():
    with pytest.raises(ValueError, match="session_auto_refresh"):
        _routes(session_auto_refresh=True)
    _routes(session_auto_refresh=True, callback_response_mode="redirect")


def test_backchannel_logout_requires_routes():
    with pytest.raises(ValueError, match="backchannel_logout"):
        KeycloakConfig(
            server_url="https://kc", realm="r", client_id="c", backchannel_logout=True
        )


def test_backchannel_logout_path_skips_auth():
    """Keycloak calls it without a bearer token."""
    assert (
        "/auth/backchannel-logout"
        in _routes(backchannel_logout=True).effective_excluded_paths
    )
    assert "/auth/backchannel-logout" not in _routes().effective_excluded_paths


def test_session_binding_requires_redirect_mode():
    with pytest.raises(ValueError, match="session_binding"):
        KeycloakConfig(
            server_url="http://kc", realm="r", client_id="c", session_binding=True
        )


# --- configurations that cannot work are refused at construction ---


def _cfg(**kwargs):
    return KeycloakConfig(server_url="http://kc", realm="r", client_id="c", **kwargs)


def test_samesite_none_requires_secure_cookies():
    """Browsers drop SameSite=None cookies without Secure: every login would fail."""
    with pytest.raises(ValueError, match="cookie_samesite"):
        _cfg(cookie_samesite="none", cookie_secure=False)
    _cfg(cookie_samesite="none", cookie_secure=True)


@pytest.mark.parametrize("prefix", ["/auth/", "auth", "/", "", "/a//b"])
def test_auth_prefix_must_be_a_clean_path(prefix):
    """A trailing slash broke the auth route exclusions: /auth/login needed a token."""
    with pytest.raises(ValueError, match="auth_prefix"):
        _cfg(auth_prefix=prefix)


@pytest.mark.parametrize("prefix", ["/auth", "/api/v1/auth"])
def test_auth_prefix_accepts_nested_paths(prefix):
    assert _cfg(auth_prefix=prefix).auth_prefix == prefix


@pytest.mark.parametrize("algorithms", [(), ("HS256",), ("none",)])
def test_algorithms_must_include_a_public_key_algorithm(algorithms):
    """JWKS keys are public: HMAC or none can never verify a Keycloak token."""
    with pytest.raises(ValueError, match="algorithms"):
        _cfg(algorithms=algorithms)


def test_unusable_extra_algorithm_is_logged(caplog):
    with caplog.at_level(logging.WARNING, logger="litestar_keycloak.config"):
        _cfg(algorithms=("RS256", "HS256"))
    assert "HS256" in caplog.text


def test_optional_audiences_without_strict_audience_is_logged(caplog):
    """Lenient checking accepts any token whose azp is an optional audience."""
    with caplog.at_level(logging.WARNING, logger="litestar_keycloak.config"):
        _cfg(optional_audiences=frozenset({"frontend-spa"}))
    assert "strict_audience" in caplog.text
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="litestar_keycloak.config"):
        _cfg(optional_audiences=frozenset({"frontend-spa"}), strict_audience=True)
    assert caplog.text == ""
