import pytest
from django.conf import settings

from wristband.django_auth.sessions.backends.encrypted_cookies import SessionStore


class TestEncryptedCookieSession:
    """Test encrypted cookie session backend."""

    def test_create_session(self):
        """Test creating a new session."""
        session_store = SessionStore()
        session_store.create()
        assert session_store.session_key is not None

    def test_save_and_load_session(self):
        """Test saving and loading session data."""
        session_store = SessionStore()
        session_store.create()
        session_store['user_id'] = 'test_user'
        session_store['tenant_id'] = 'test_tenant'
        session_store.save()

        # Load session with the encrypted key
        loaded_session = SessionStore(session_key=session_store.session_key)
        assert loaded_session['user_id'] == 'test_user'
        assert loaded_session['tenant_id'] == 'test_tenant'

    def test_session_exists(self):
        """Test checking if session exists."""
        session_store = SessionStore()
        session_store.create()
        session_store['test'] = 'data'
        session_store.save()

        # session_key is guaranteed to be str after save()
        assert session_store.session_key is not None
        assert session_store.exists(session_store.session_key)
        assert not session_store.exists('invalid_key')
        assert not session_store.exists('')

    def test_delete_session(self):
        """Test deleting a session."""
        session_store = SessionStore()
        session_store.create()
        session_store['test'] = 'data'
        session_store.save()

        session_store.delete()
        assert session_store.session_key is None

    def test_load_invalid_session(self):
        """Test loading an invalid/tampered session."""
        invalid_session = SessionStore(session_key='invalid_encrypted_data')
        data = invalid_session.load()
        assert data == {}
        assert invalid_session.session_key is None

    def test_load_empty_session_key(self):
        """Test loading with None session key."""
        session_store = SessionStore(session_key=None)
        data = session_store.load()
        assert data == {}

    def test_key_rotation_with_multiple_secrets(self):
        """Test key rotation with multiple secrets."""
        # Override settings for this test
        original_secret = settings.WRISTBAND_SESSION_SECRET
        settings.WRISTBAND_SESSION_SECRET = [
            'new_secret_key_32_chars_long_11!',
            'old_secret_key_32_chars_long_22!'
        ]
        
        try:
            # Create session with first key
            session_store = SessionStore()
            session_store.create()
            session_store['test'] = 'rotation'
            session_store.save()
            encrypted_key = session_store.session_key

            # Should be able to decrypt with rotated keys
            new_session = SessionStore(session_key=encrypted_key)
            assert new_session['test'] == 'rotation'
        finally:
            # Restore original secret
            settings.WRISTBAND_SESSION_SECRET = original_secret

    def test_max_secrets_validation(self):
        """Test that more than 3 secrets raises error."""
        original_secret = settings.WRISTBAND_SESSION_SECRET
        settings.WRISTBAND_SESSION_SECRET = ['key1_32chars!!!!!!!!!!!!!!!', 
                                               'key2_32chars!!!!!!!!!!!!!!!', 
                                               'key3_32chars!!!!!!!!!!!!!!!', 
                                               'key4_32chars!!!!!!!!!!!!!!!']
        
        try:
            with pytest.raises(ValueError, match="Maximum 3 secrets allowed"):
                SessionStore()
        finally:
            settings.WRISTBAND_SESSION_SECRET = original_secret

    def test_fallback_to_django_secret_key(self):
        """Test fallback to Django's SECRET_KEY."""
        # Remove WRISTBAND_SESSION_SECRET temporarily
        original_secret = getattr(settings, 'WRISTBAND_SESSION_SECRET', None)
        if hasattr(settings, 'WRISTBAND_SESSION_SECRET'):
            delattr(settings, 'WRISTBAND_SESSION_SECRET')
        
        try:
            session_store = SessionStore()
            session_store.create()
            session_store['test'] = 'fallback'
            session_store.save()

            # Should work with Django's SECRET_KEY
            loaded = SessionStore(session_key=session_store.session_key)
            assert loaded['test'] == 'fallback'
        finally:
            # Restore original setting
            if original_secret is not None:
                settings.WRISTBAND_SESSION_SECRET = original_secret

    def test_save_must_create(self):
        """Test saving with must_create=True."""
        session_store = SessionStore()
        session_store.create()
        session_store['key'] = 'value'
        session_store.save(must_create=True)
        
        assert session_store.session_key is not None
        
        # Verify can load
        loaded = SessionStore(session_key=session_store.session_key)
        assert loaded['key'] == 'value'
