"""
Exception classes for the Wristband Django Authentication SDK.

This module provides custom exception classes for handling authentication-related
errors that may occur during OAuth flows, token operations, and other Wristband
authentication processes.
"""


class WristbandError(Exception):
    """
    Base exception class for all Wristband authentication-related errors.

    This is the parent class for all custom exceptions in the Wristband Django SDK.
    It provides a structured way to handle authentication errors with both an error
    code and a descriptive message, following OAuth 2.0 error response conventions.

    Attributes:
        error (str): The error code identifying the type of error that occurred.
        error_description (str): A human-readable description providing additional
            details about the error.
    """

    def __init__(self, error: str, error_description: str = "") -> None:
        """
        Initialize a WristbandError with an error code and optional description.

        Args:
            error (str): The error code identifying the type of error.
            error_description (str, optional): A human-readable description
                providing additional details about the error. Defaults to empty string.

        Note:
            The exception message will be formatted as "{error}: {error_description}".
        """
        super().__init__(f"{error}: {error_description}")
        self.error = error
        self.error_description = error_description

    def get_error(self) -> str:
        """
        Get the error code for this exception.

        Returns:
            str: The error code that identifies the type of error that occurred.
        """
        return self.error

    def get_error_description(self) -> str:
        """
        Get the human-readable error description for this exception.

        Returns:
            str: A descriptive message providing additional details about the error.
                This is intended for human consumption and may be displayed to users
                or included in logs for debugging purposes.
        """
        return self.error_description


class InvalidGrantError(WristbandError):
    """
    Exception raised when an OAuth grant is invalid, expired, or revoked.

    This exception is a specialized form of WristbandError that specifically handles
    OAuth 2.0 "invalid_grant" errors. It's typically raised during token exchange
    operations when:

    - An authorization code has expired or been used already
    - A refresh token is invalid, expired, or revoked
    - The grant doesn't match the redirection URI used in the authorization request
    - The grant was issued to a different client

    The error code is automatically set to "invalid_grant" following OAuth 2.0
    specifications (RFC 6749, Section 5.2).

    Attributes:
        error (str): Always set to "invalid_grant" for this exception type.
        error_description (str): A human-readable description of why the grant
            is invalid.

    See Also:
        RFC 6749 Section 5.2: https://tools.ietf.org/html/rfc6749#section-5.2
    """

    def __init__(self, error_description: str = "") -> None:
        """
        Initialize an InvalidGrantError with an optional description.

        Args:
            error_description (str, optional): A human-readable description
                explaining why the grant is invalid. This might include details
                about expiration, revocation, or mismatched parameters.
                Defaults to empty string.

        Note:
            The error code is automatically set to "invalid_grant" and cannot
            be overridden.
        """
        super().__init__("invalid_grant", error_description)
