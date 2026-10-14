import pytest

from wristband.django_auth.models import RawUserInfo, UserInfo, UserInfoRole
from wristband.django_auth.utils import (
    derive_fallback_login_url,
    derive_tenant_root_domain,
    is_tenant_placeholder_position_valid,
    map_userinfo_claims,
    validate_return_url,
)

####################################
# USERINFO MAPPING TESTS
####################################


def test_map_userinfo_claims_minimal_fields():
    """Test mapping with only required fields."""
    raw = RawUserInfo(
        sub="user_123",
        tnt_id="tenant_123",
        app_id="app_123",
        idp_name="Wristband",
    )

    result = map_userinfo_claims(raw)

    assert isinstance(result, UserInfo)
    assert result.user_id == "user_123"
    assert result.tenant_id == "tenant_123"
    assert result.application_id == "app_123"
    assert result.identity_provider_name == "Wristband"
    # All optional fields should be None
    assert result.full_name is None
    assert result.email is None
    assert result.roles is None


def test_map_userinfo_claims_all_fields():
    """Test mapping with all optional fields populated."""
    roles = [UserInfoRole(id="role_1", name="admin", display_name="Administrator")]

    raw = RawUserInfo(
        sub="user_123",
        tnt_id="tenant_123",
        app_id="app_123",
        idp_name="Wristband",
        name="John Doe Smith",
        given_name="John",
        family_name="Smith",
        middle_name="Doe",
        nickname="Johnny",
        preferred_username="jsmith",
        picture="https://example.com/pic.jpg",
        email="john@example.com",
        email_verified=True,
        gender="male",
        birthdate="1990-01-01",
        zoneinfo="America/Los_Angeles",
        locale="en-US",
        phone_number="+16045551234",
        phone_number_verified=True,
        updated_at=1640995200,
        roles=roles,
        custom_claims={"department": "engineering", "level": 5},
    )

    result = map_userinfo_claims(raw)

    assert isinstance(result, UserInfo)
    # Verify required field mappings
    assert result.user_id == "user_123"
    assert result.tenant_id == "tenant_123"
    assert result.application_id == "app_123"
    assert result.identity_provider_name == "Wristband"

    # Verify optional field mappings
    assert result.full_name == "John Doe Smith"
    assert result.given_name == "John"
    assert result.family_name == "Smith"
    assert result.middle_name == "Doe"
    assert result.nickname == "Johnny"
    assert result.display_name == "jsmith"
    assert result.picture_url == "https://example.com/pic.jpg"
    assert result.email == "john@example.com"
    assert result.email_verified is True
    assert result.gender == "male"
    assert result.birthdate == "1990-01-01"
    assert result.time_zone == "America/Los_Angeles"
    assert result.locale == "en-US"
    assert result.phone_number == "+16045551234"
    assert result.phone_number_verified is True
    assert result.updated_at == 1640995200
    assert result.roles is not None
    assert len(result.roles) == 1
    assert result.custom_claims == {"department": "engineering", "level": 5}


def test_map_userinfo_claims_claim_name_mappings():
    """Test that OIDC claim names are correctly mapped to User entity field names."""
    raw = RawUserInfo(
        sub="user_123",
        tnt_id="tenant_123",
        app_id="app_123",
        idp_name="Wristband",
        name="Full Name",  # maps to full_name
        preferred_username="username",  # maps to display_name
        picture="https://pic.jpg",  # maps to picture_url
        zoneinfo="America/New_York",  # maps to time_zone
    )

    result = map_userinfo_claims(raw)

    # Verify the specific mappings that differ between OIDC and User entity
    assert result.full_name == "Full Name"  # name -> full_name
    assert result.display_name == "username"  # preferred_username -> display_name
    assert result.picture_url == "https://pic.jpg"  # picture -> picture_url
    assert result.time_zone == "America/New_York"  # zoneinfo -> time_zone


def test_map_userinfo_claims_with_roles():
    """Test mapping preserves roles array correctly."""
    roles = [
        UserInfoRole(id="role_1", name="admin", display_name="Administrator"),
        UserInfoRole(id="role_2", name="user", display_name="User"),
        UserInfoRole(id="role_3", name="viewer", display_name="Viewer"),
    ]

    raw = RawUserInfo(
        sub="user_123",
        tnt_id="tenant_123",
        app_id="app_123",
        idp_name="Wristband",
        roles=roles,
    )

    result = map_userinfo_claims(raw)

    assert result.roles is not None
    assert len(result.roles) == 3
    assert result.roles[0].id == "role_1"
    assert result.roles[1].name == "user"
    assert result.roles[2].display_name == "Viewer"


def test_map_userinfo_claims_with_custom_claims():
    """Test mapping preserves custom_claims dict correctly."""
    custom_claims = {
        "department": "engineering",
        "level": 5,
        "manager": "jane_doe",
        "metadata": {"hire_date": "2020-01-01", "office": "SF"},
    }

    raw = RawUserInfo(
        sub="user_123",
        tnt_id="tenant_123",
        app_id="app_123",
        idp_name="Wristband",
        custom_claims=custom_claims,
    )

    result = map_userinfo_claims(raw)

    assert result.custom_claims is not None
    assert result.custom_claims["department"] == "engineering"
    assert result.custom_claims["level"] == 5
    assert result.custom_claims["metadata"]["office"] == "SF"


def test_map_userinfo_claims_none_values():
    """Test that None values are preserved during mapping."""
    raw = RawUserInfo(
        sub="user_123",
        tnt_id="tenant_123",
        app_id="app_123",
        idp_name="Wristband",
        email=None,
        email_verified=None,
        roles=None,
        custom_claims=None,
    )

    result = map_userinfo_claims(raw)

    assert result.email is None
    assert result.email_verified is None
    assert result.roles is None
    assert result.custom_claims is None


def test_map_userinfo_claims_profile_scope_only():
    """Test mapping with only profile scope fields."""
    raw = RawUserInfo(
        sub="user_123",
        tnt_id="tenant_123",
        app_id="app_123",
        idp_name="Wristband",
        name="John Smith",
        given_name="John",
        family_name="Smith",
        nickname="Johnny",
        picture="https://example.com/pic.jpg",
        birthdate="1990-01-01",
        locale="en-US",
    )

    result = map_userinfo_claims(raw)

    # Profile fields should be populated
    assert result.full_name == "John Smith"
    assert result.given_name == "John"
    assert result.family_name == "Smith"

    # Email and phone fields should be None
    assert result.email is None
    assert result.email_verified is None
    assert result.phone_number is None
    assert result.phone_number_verified is None


def test_map_userinfo_claims_email_scope_only():
    """Test mapping with only email scope fields."""
    raw = RawUserInfo(
        sub="user_123",
        tnt_id="tenant_123",
        app_id="app_123",
        idp_name="Wristband",
        email="john@example.com",
        email_verified=True,
    )

    result = map_userinfo_claims(raw)

    # Email fields should be populated
    assert result.email == "john@example.com"
    assert result.email_verified is True

    # Profile and phone fields should be None
    assert result.full_name is None
    assert result.phone_number is None


def test_map_userinfo_claims_phone_scope_only():
    """Test mapping with only phone scope fields."""
    raw = RawUserInfo(
        sub="user_123",
        tnt_id="tenant_123",
        app_id="app_123",
        idp_name="Wristband",
        phone_number="+16045551234",
        phone_number_verified=True,
    )

    result = map_userinfo_claims(raw)

    # Phone fields should be populated
    assert result.phone_number == "+16045551234"
    assert result.phone_number_verified is True

    # Email and profile fields should be None
    assert result.email is None
    assert result.full_name is None


def test_map_userinfo_claims_boolean_fields():
    """Test that boolean fields are correctly mapped."""
    raw = RawUserInfo(
        sub="user_123",
        tnt_id="tenant_123",
        app_id="app_123",
        idp_name="Wristband",
        email_verified=False,
        phone_number_verified=False,
    )

    result = map_userinfo_claims(raw)

    assert result.email_verified is False
    assert result.phone_number_verified is False


def test_map_userinfo_claims_empty_roles_list():
    """Test mapping with empty roles list."""
    raw = RawUserInfo(
        sub="user_123",
        tnt_id="tenant_123",
        app_id="app_123",
        idp_name="Wristband",
        roles=[],
    )

    result = map_userinfo_claims(raw)

    assert result.roles is not None
    assert len(result.roles) == 0


def test_map_userinfo_claims_empty_custom_claims():
    """Test mapping with empty custom_claims dict."""
    raw = RawUserInfo(
        sub="user_123",
        tnt_id="tenant_123",
        app_id="app_123",
        idp_name="Wristband",
        custom_claims={},
    )

    result = map_userinfo_claims(raw)

    assert result.custom_claims is not None
    assert result.custom_claims == {}


####################################
# TENANT PLACEHOLDER TESTS
####################################


@pytest.mark.parametrize(
    "login_url,expected",
    [
        ("https://{tenant_name}.myapp.com/api/auth/login", "https://myapp.com/api/auth/login"),
        ("http://{tenant_name}.localhost:6001/api/auth/login", "http://localhost:6001/api/auth/login"),
        ("https://myapp.com/api/auth/login", ""),
        ("", ""),
        (None, ""),
    ],
)
def test_derive_fallback_login_url(login_url, expected):
    assert derive_fallback_login_url(login_url) == expected


@pytest.mark.parametrize(
    "login_url,expected",
    [
        ("https://{tenant_name}.myapp.com/api/auth/login", "myapp.com"),
        ("http://{tenant_name}.localhost:6001/api/auth/login", "localhost"),
        ("https://myapp.com/api/auth/login", ""),
        (None, ""),
    ],
)
def test_derive_tenant_root_domain(login_url, expected):
    assert derive_tenant_root_domain(login_url) == expected


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://myapp.com/api/auth/login", True),
        ("https://{tenant_name}.myapp.com/api/auth/login", True),
        ("http://{tenant_name}.localhost:6001/api/auth/login", True),
        ("https://app.{tenant_name}.myapp.com/api/auth/login", False),
        ("https://myapp.com/{tenant_name}/api/auth/login", False),
        ("https://{tenant_name}/api/auth/login", False),
        ("https://{tenant_name}.myapp.com/{tenant_name}/login", False),
    ],
)
def test_is_tenant_placeholder_position_valid(url, expected):
    assert is_tenant_placeholder_position_valid(url) is expected


####################################
# RETURN URL VALIDATION TESTS
####################################

ROOT_DOMAIN = "myapp.com"
TENANT = "acme"
TENANT_HOST = "acme.myapp.com"


def _validate(return_url, host=TENANT_HOST, scheme="https", app_level=True, root_domain=ROOT_DOMAIN):
    return validate_return_url(return_url, scheme, host, TENANT, app_level, root_domain)


def test_validate_return_url_requires_tenant_name():
    with pytest.raises(ValueError, match="Tenant name is required"):
        validate_return_url("/settings", "https", TENANT_HOST, "", True, ROOT_DOMAIN)


@pytest.mark.parametrize("return_url", [None, ""])
def test_validate_return_url_missing(return_url):
    assert _validate(return_url) is None


@pytest.mark.parametrize(
    "return_url",
    ["/settings?tab=1#top", "https://acme.myapp.com/dashboard", "https://ACME.myapp.com/dashboard"],
)
def test_validate_return_url_allows_request_host(return_url):
    assert _validate(return_url) == return_url


def test_validate_return_url_allows_root_domain_without_rewrite_when_app_level_disabled():
    assert _validate("https://myapp.com/dashboard", app_level=False) == "https://myapp.com/dashboard"


def test_validate_return_url_rewrites_root_domain_to_tenant_subdomain_when_app_level_enabled():
    assert _validate("https://myapp.com/dashboard?x=1#y") == "https://acme.myapp.com/dashboard?x=1#y"


def test_validate_return_url_rewrite_preserves_port():
    assert _validate("https://myapp.com:8443/home", host="acme.myapp.com:8443") == "https://acme.myapp.com:8443/home"


def test_validate_return_url_allows_request_host_without_tenant_subdomains():
    assert _validate("https://myapp.com/dashboard", host="myapp.com", root_domain="") == "https://myapp.com/dashboard"


def test_validate_return_url_allows_relative_path_on_http_request():
    assert _validate("/home", host="acme.localhost:6001", scheme="http", root_domain="localhost") == "/home"


@pytest.mark.parametrize(
    "return_url",
    [
        "https://evil.com/phish",
        "//evil.com/phish",
        "/\\evil.com",
        "/\t/evil.com",
        "\n//evil.com",
        "https://other.myapp.com/dashboard",
        "https://myapp.com.evil.com/dashboard",
        "http://acme.myapp.com/dashboard",
        "javascript:alert(1)",
        "data:text/html,hi",
        "https://acme.myapp.com:99999/dashboard",
    ],
)
def test_validate_return_url_rejects_untrusted_urls(return_url):
    assert _validate(return_url) is None


def test_validate_return_url_rejects_root_domain_when_tenant_subdomains_not_used():
    assert _validate("https://myapp.com/dashboard", host="acme.example.com", root_domain="") is None


def test_validate_return_url_returns_normalized_url_when_normalization_changes_it():
    assert _validate(" /settings ") == "https://acme.myapp.com/settings"
