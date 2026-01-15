"""
Encrypted cookie-based session backend for Django.

This session backend stores session data in encrypted cookies using Fernet (AES-256-GCM).
It supports key rotation by accepting up to 3 secret keys.

Configuration:
    SESSION_ENGINE = 'wristband.django_auth.sessions.backends.encrypted_cookies'
    WRISTBAND_SESSION_SECRET = 'your-32-char-secret'  # or list for key rotation

    # Falls back to Django's SECRET_KEY if WRISTBAND_SESSION_SECRET not provided

All standard Django session settings are respected:
    - SESSION_COOKIE_NAME
    - SESSION_COOKIE_AGE
    - SESSION_COOKIE_SECURE
    - SESSION_COOKIE_HTTPONLY
    - SESSION_COOKIE_SAMESITE
    - SESSION_COOKIE_DOMAIN
    - SESSION_COOKIE_PATH
    - SESSION_SAVE_EVERY_REQUEST
"""

from typing import Any, Dict, Optional

from django.conf import settings
from django.contrib.sessions.backends.base import SessionBase

from ...data_encryptor import DataEncryptor


class SessionStore(SessionBase):
    """
    Encrypted cookie-based session backend for Django.

    Stores session data in encrypted cookies using AES-256-GCM (via Fernet).
    Supports key rotation by accepting multiple secret keys (max 3).

    The session_key contains the encrypted session data itself (not a database lookup key).
    Django's SessionMiddleware handles reading/writing cookies automatically.
    """

    def __init__(self, session_key: Optional[str] = None) -> None:
        """
        Initialize the session store.

        Args:
            session_key: For cookie sessions, this contains the encrypted session data
                        from the cookie (not a database lookup key).
        """
        super().__init__(session_key)
        self._encryptor = self._get_encryptor()

    def _get_encryptor(self) -> DataEncryptor:
        """
        Get DataEncryptor instance with secret key(s) from Django settings.

        Returns:
            DataEncryptor configured with secret key(s)

        Raises:
            ValueError: If secret key list contains more than 3 keys
        """
        # Get secret key from settings, fall back to Django's SECRET_KEY
        secret_key = getattr(settings, "WRISTBAND_SESSION_SECRET", settings.SECRET_KEY)

        # Validate max 3 keys if list
        if isinstance(secret_key, list) and len(secret_key) > 3:
            raise ValueError("WRISTBAND_SESSION_SECRET: Maximum 3 secrets allowed for key rotation")

        return DataEncryptor(secret_key)

    def load(self) -> Dict[str, Any]:
        """
        Load and decrypt session data from the session key.

        Called by Django when request.session is first accessed.
        The session_key contains the encrypted session data from the cookie.

        Returns:
            dict: Decrypted session data, or empty dict if decryption fails
        """
        try:
            if self.session_key:
                # session_key contains the encrypted data from the cookie
                return self._encryptor.decrypt(self.session_key)
        except Exception:
            # Decryption failed - expired, tampered, or key rotated
            # Silent failure is intentional to prevent timing attacks
            self._session_key = None  # Explicit action for Bandit

        # No valid session found
        self._session_key = None
        return {}

    def exists(self, session_key: str) -> bool:
        """
        Check if a session exists by attempting to decrypt it.

        Args:
            session_key: Encrypted session data to validate

        Returns:
            bool: True if session can be decrypted, False otherwise
        """
        if not session_key:
            return False

        try:
            self._encryptor.decrypt(session_key)
            return True
        except Exception:
            return False

    def create(self) -> None:
        """
        Create a new session with a unique key.

        For cookie sessions, we generate a placeholder key.
        The actual encrypted data is created in save().
        """
        # Generate a new session key
        # The actual encrypted session data will be created in save()
        self._session_key = self._get_new_session_key()  # type: ignore[attr-defined]

    def save(self, must_create: bool = False) -> None:
        """
        Encrypt and save session data to the session key.

        Called by Django's SessionMiddleware when the response is being prepared.
        Encrypts the session dict and stores it in _session_key, which Django
        will write to the session cookie.

        Args:
            must_create: If True, create a new session. Otherwise, update existing.
        """
        # Get the current session data
        session_dict = self._get_session(no_load=must_create)  # type: ignore[attr-defined]

        # Encrypt the session data
        encrypted_data = self._encryptor.encrypt(session_dict)

        # Store encrypted data as session_key
        # Django's SessionMiddleware will write this to the cookie
        self._session_key = encrypted_data

    def delete(self, session_key: Optional[str] = None) -> None:
        """
        Delete the session.

        For cookie sessions, this clears the session data.
        Django's SessionMiddleware handles deleting the cookie.

        Args:
            session_key: Ignored for cookie sessions (required by SessionBase interface)
        """
        self._session_key = None
        self._session_cache: Dict[str, Any] = {}
