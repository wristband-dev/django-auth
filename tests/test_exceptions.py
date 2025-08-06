import pytest

from wristband.django_auth.exceptions import InvalidGrantError, WristbandError


class TestWristbandError:
    """Test cases for WristbandError base exception class."""

    def test_wristband_error_creation_with_both_parameters(self):
        """Test WristbandError creation with both error and error_description."""
        error = "test_error"
        error_description = "This is a test error description"

        exception = WristbandError(error, error_description)

        assert exception.error == error
        assert exception.error_description == error_description
        assert str(exception) == f"{error}: {error_description}"

    def test_wristband_error_creation_with_error_only(self):
        """Test WristbandError creation with only error parameter."""
        error = "test_error"

        exception = WristbandError(error)

        assert exception.error == error
        assert exception.error_description == ""
        assert str(exception) == f"{error}: "

    def test_wristband_error_creation_with_empty_error_description(self):
        """Test WristbandError creation with explicitly empty error_description."""
        error = "test_error"
        error_description = ""

        exception = WristbandError(error, error_description)

        assert exception.error == error
        assert exception.error_description == error_description
        assert str(exception) == f"{error}: "

    def test_wristband_error_get_error_method(self):
        """Test WristbandError get_error method."""
        error = "authentication_failed"
        error_description = "Invalid credentials provided"

        exception = WristbandError(error, error_description)

        assert exception.get_error() == error

    def test_wristband_error_get_error_description_method(self):
        """Test WristbandError get_error_description method."""
        error = "authentication_failed"
        error_description = "Invalid credentials provided"

        exception = WristbandError(error, error_description)

        assert exception.get_error_description() == error_description

    def test_wristband_error_get_error_description_empty(self):
        """Test WristbandError get_error_description when description is empty."""
        error = "test_error"

        exception = WristbandError(error)

        assert exception.get_error_description() == ""

    def test_wristband_error_inheritance(self):
        """Test that WristbandError properly inherits from Exception."""
        error = "test_error"
        error_description = "Test description"

        exception = WristbandError(error, error_description)

        assert isinstance(exception, Exception)
        assert isinstance(exception, WristbandError)

    def test_wristband_error_can_be_raised_and_caught(self):
        """Test that WristbandError can be raised and caught properly."""
        error = "test_error"
        error_description = "Test description"

        with pytest.raises(WristbandError) as exc_info:
            raise WristbandError(error, error_description)

        caught_exception = exc_info.value
        assert caught_exception.error == error
        assert caught_exception.error_description == error_description
        assert str(caught_exception) == f"{error}: {error_description}"

    def test_wristband_error_caught_as_exception(self):
        """Test that WristbandError can be caught as base Exception."""
        error = "test_error"
        error_description = "Test description"

        with pytest.raises(Exception) as exc_info:
            raise WristbandError(error, error_description)

        caught_exception = exc_info.value
        assert isinstance(caught_exception, WristbandError)
        assert caught_exception.error == error

    def test_wristband_error_with_special_characters(self):
        """Test WristbandError with special characters in messages."""
        error = "special_error"
        error_description = "Error with special chars: üñíçødé & symbols!"

        exception = WristbandError(error, error_description)

        assert exception.error == error
        assert exception.error_description == error_description
        assert str(exception) == f"{error}: {error_description}"

    def test_wristband_error_with_long_messages(self):
        """Test WristbandError with very long error messages."""
        error = "long_error_code_that_is_very_descriptive_and_detailed"
        error_description = (
            "This is a very long error description that contains "
            "multiple sentences and provides detailed information "
            "about what went wrong during the authentication process "
            "and how it might be resolved by the calling application."
        )

        exception = WristbandError(error, error_description)

        assert exception.error == error
        assert exception.error_description == error_description
        assert str(exception) == f"{error}: {error_description}"

    def test_wristband_error_with_none_like_strings(self):
        """Test WristbandError with string values that look like None."""
        error = "None"
        error_description = "null"

        exception = WristbandError(error, error_description)

        assert exception.error == "None"
        assert exception.error_description == "null"
        assert str(exception) == "None: null"


class TestInvalidGrantError:
    """Test cases for InvalidGrantError specialized exception class."""

    def test_invalid_grant_error_creation_with_description(self):
        """Test InvalidGrantError creation with error_description."""
        error_description = "The authorization grant is invalid or expired"

        exception = InvalidGrantError(error_description)

        assert exception.error == "invalid_grant"
        assert exception.error_description == error_description
        assert str(exception) == f"invalid_grant: {error_description}"

    def test_invalid_grant_error_creation_without_description(self):
        """Test InvalidGrantError creation without error_description."""
        exception = InvalidGrantError()

        assert exception.error == "invalid_grant"
        assert exception.error_description == ""
        assert str(exception) == "invalid_grant: "

    def test_invalid_grant_error_creation_with_empty_description(self):
        """Test InvalidGrantError creation with explicitly empty error_description."""
        error_description = ""

        exception = InvalidGrantError(error_description)

        assert exception.error == "invalid_grant"
        assert exception.error_description == error_description
        assert str(exception) == "invalid_grant: "

    def test_invalid_grant_error_inheritance(self):
        """Test that InvalidGrantError properly inherits from WristbandError."""
        error_description = "Grant has expired"

        exception = InvalidGrantError(error_description)

        assert isinstance(exception, WristbandError)
        assert isinstance(exception, InvalidGrantError)
        assert isinstance(exception, Exception)

    def test_invalid_grant_error_get_error_method(self):
        """Test InvalidGrantError inherited get_error method."""
        error_description = "Authorization code has been used"

        exception = InvalidGrantError(error_description)

        assert exception.get_error() == "invalid_grant"

    def test_invalid_grant_error_get_error_description_method(self):
        """Test InvalidGrantError inherited get_error_description method."""
        error_description = "Authorization code has been used"

        exception = InvalidGrantError(error_description)

        assert exception.get_error_description() == error_description

    def test_invalid_grant_error_get_error_description_empty(self):
        """Test InvalidGrantError get_error_description when description is empty."""
        exception = InvalidGrantError()

        assert exception.get_error_description() == ""

    def test_invalid_grant_error_can_be_raised_and_caught_as_invalid_grant(self):
        """Test that InvalidGrantError can be raised and caught as InvalidGrantError."""
        error_description = "Refresh token is invalid"

        with pytest.raises(InvalidGrantError) as exc_info:
            raise InvalidGrantError(error_description)

        caught_exception = exc_info.value
        assert caught_exception.error == "invalid_grant"
        assert caught_exception.error_description == error_description
        assert str(caught_exception) == f"invalid_grant: {error_description}"

    def test_invalid_grant_error_can_be_raised_and_caught_as_wristband_error(self):
        """Test that InvalidGrantError can be caught as WristbandError."""
        error_description = "Refresh token is invalid"

        with pytest.raises(WristbandError) as exc_info:
            raise InvalidGrantError(error_description)

        caught_exception = exc_info.value
        assert isinstance(caught_exception, InvalidGrantError)
        assert caught_exception.error == "invalid_grant"
        assert caught_exception.error_description == error_description

    def test_invalid_grant_error_can_be_raised_and_caught_as_exception(self):
        """Test that InvalidGrantError can be caught as base Exception."""
        error_description = "Refresh token is invalid"

        with pytest.raises(Exception) as exc_info:
            raise InvalidGrantError(error_description)

        caught_exception = exc_info.value
        assert isinstance(caught_exception, InvalidGrantError)
        assert isinstance(caught_exception, WristbandError)
        assert caught_exception.error == "invalid_grant"

    def test_invalid_grant_error_with_detailed_description(self):
        """Test InvalidGrantError with detailed error description."""
        error_description = (
            "The provided authorization grant (authorization code, "
            "resource owner credentials, client credentials) or refresh "
            "token is invalid, expired, revoked, does not match the "
            "redirection URI used in the authorization request, or was "
            "issued to another client."
        )

        exception = InvalidGrantError(error_description)

        assert exception.error == "invalid_grant"
        assert exception.error_description == error_description
        assert str(exception) == f"invalid_grant: {error_description}"

    def test_invalid_grant_error_error_code_is_immutable(self):
        """Test that InvalidGrantError always has 'invalid_grant' as error code."""
        # Test with different descriptions to ensure error code is always the same
        descriptions = [
            "First description",
            "Second description",
            "",
            "Very long description with lots of details about the error",
        ]

        for description in descriptions:
            exception = InvalidGrantError(description)
            assert exception.error == "invalid_grant"
            assert exception.get_error() == "invalid_grant"
