"""Unit tests for exception classes and exception handlers."""

from unittest.mock import MagicMock

from litestar_keycloak.exceptions import (
    AuthenticationError,
    AuthorizationError,
    InsufficientRoleError,
    InsufficientScopeError,
    InvalidAudienceError,
    InvalidIssuerError,
    JWKSFetchError,
    KeycloakBackendError,
    KeycloakError,
    MissingTokenError,
    exception_handlers,
)

# --- Exception attributes ---


def test_missing_token_error_stores_location():
    """MissingTokenError stores location and includes it in the message."""
    err = MissingTokenError(location="cookie 'access_token'")
    assert err.location == "cookie 'access_token'"
    assert "cookie" in str(err) and "access_token" in str(err)


def test_invalid_issuer_error_stores_expected_and_got():
    """InvalidIssuerError stores expected and got issuer."""
    err = InvalidIssuerError(
        expected="https://kc/realms/r", got="https://wrong/realms/r"
    )
    assert err.expected == "https://kc/realms/r"
    assert err.got == "https://wrong/realms/r"
    assert "Expected issuer" in str(err) and "wrong" in str(err)


def test_invalid_audience_error_stores_expected_and_got():
    """InvalidAudienceError stores expected and got audience."""
    err = InvalidAudienceError(expected="my-client", got="other-client")
    assert err.expected == "my-client"
    assert err.got == "other-client"
    assert "Expected audience" in str(err)


def test_insufficient_role_error_computes_missing_roles_in_message():
    """InsufficientRoleError message includes missing roles."""
    err = InsufficientRoleError(
        required=frozenset({"admin", "user"}),
        actual=frozenset({"user"}),
    )
    assert err.required == frozenset({"admin", "user"})
    assert err.actual == frozenset({"user"})
    assert "admin" in str(err) and "Missing roles" in str(err)


def test_insufficient_scope_error_computes_missing_scopes_in_message():
    """InsufficientScopeError message includes missing scopes."""
    err = InsufficientScopeError(
        required=frozenset({"read", "write"}),
        actual=frozenset({"read"}),
    )
    assert err.required == frozenset({"read", "write"})
    assert err.actual == frozenset({"read"})
    assert "write" in str(err) and "Missing scopes" in str(err)


def test_all_exceptions_inherit_from_keycloak_error():
    """All plugin exceptions inherit from KeycloakError."""
    assert issubclass(MissingTokenError, KeycloakError)
    assert issubclass(InvalidIssuerError, KeycloakError)
    assert issubclass(InvalidAudienceError, KeycloakError)
    assert issubclass(InsufficientRoleError, KeycloakError)
    assert issubclass(InsufficientScopeError, KeycloakError)
    assert issubclass(JWKSFetchError, KeycloakError)
    assert issubclass(AuthenticationError, KeycloakError)
    assert issubclass(AuthorizationError, KeycloakError)
    assert issubclass(KeycloakBackendError, KeycloakError)


# --- Exception handlers ---


def _mock_request():
    return MagicMock()


def test_authentication_error_handler_returns_401_json():
    """Authentication error handler returns 401 with JSON body."""
    handler = exception_handlers[AuthenticationError]
    exc = MissingTokenError("header")
    response = handler(_mock_request(), exc)
    assert response.status_code == 401
    assert response.media_type == "application/json"
    content = response.content
    assert isinstance(content, dict) and "error" in content
    assert "header" in content["error"] or "token" in content["error"].lower()


def test_authorization_error_handler_returns_403_json():
    """Authorization error handler returns 403 with JSON body."""
    handler = exception_handlers[AuthorizationError]
    exc = InsufficientRoleError(required=frozenset({"admin"}), actual=frozenset())
    response = handler(_mock_request(), exc)
    assert response.status_code == 403
    assert response.media_type == "application/json"
    content = response.content
    assert isinstance(content, dict) and "error" in content
    assert "admin" in content["error"] or "Missing roles" in content["error"]


def test_backend_error_handler_returns_502_json():
    """Backend error handler returns 502 with JSON body."""
    handler = exception_handlers[KeycloakBackendError]
    exc = JWKSFetchError("Failed to fetch JWKS")
    response = handler(_mock_request(), exc)
    assert response.status_code == 502
    assert response.media_type == "application/json"
    content = response.content
    assert isinstance(content, dict) and "error" in content


def test_handler_does_not_leak_stack_trace():
    """Exception handler response body does not contain stack trace."""
    handler = exception_handlers[AuthenticationError]
    exc = MissingTokenError("header")
    response = handler(_mock_request(), exc)
    content = response.content
    content_str = str(content)
    assert "Traceback" not in content_str
    assert "  File " not in content_str
