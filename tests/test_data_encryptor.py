import pytest
from cryptography.fernet import InvalidToken

from wristband.django_auth.data_encryptor import DataEncryptor

SECRET = "a" * 32  # valid 32-char secret
LONG_SECRET = "a" * 64  # longer than 32 chars


####################################
# DATA ENCRYPTOR - SINGLE KEY TESTS
####################################


def test_encrypt_and_decrypt_roundtrip():
    enc = DataEncryptor(SECRET)
    data = {"user_id": "123", "email": "user@example.com"}
    encrypted = enc.encrypt(data)
    assert isinstance(encrypted, str)
    decrypted = enc.decrypt(encrypted)
    assert decrypted == data


def test_encrypt_rejects_non_dict():
    enc = DataEncryptor(SECRET)
    with pytest.raises(TypeError, match="Data must be a dictionary"):
        enc.encrypt(["not", "a", "dict"])  # type: ignore


def test_decrypt_rejects_empty_string():
    enc = DataEncryptor(SECRET)
    with pytest.raises(ValueError, match="Empty encrypted string cannot be decrypted"):
        enc.decrypt("")


def test_decrypt_rejects_invalid_token():
    enc = DataEncryptor(SECRET)
    with pytest.raises(InvalidToken):
        enc.decrypt("invalid.encrypted.string")


def test_short_secret_raises():
    with pytest.raises(ValueError, match="secret_key at index 0 must be at least 32 characters long"):
        DataEncryptor("short")


def test_missing_secret_raises():
    with pytest.raises(ValueError, match="secret_key is required"):
        DataEncryptor(None)  # type: ignore


def test_empty_string_secret_raises():
    with pytest.raises(ValueError, match="secret_key at index 0 cannot be empty"):
        DataEncryptor("")


def test_exactly_32_char_secret():
    """Test that exactly 32 characters works correctly."""
    enc = DataEncryptor(SECRET)
    data = {"test": "value"}
    encrypted = enc.encrypt(data)
    decrypted = enc.decrypt(encrypted)
    assert decrypted == data


def test_long_secret_truncated():
    """Test that secrets longer than 32 chars are properly truncated."""
    enc = DataEncryptor(LONG_SECRET)
    data = {"test": "value"}
    encrypted = enc.encrypt(data)
    decrypted = enc.decrypt(encrypted)
    assert decrypted == data


def test_different_keys_cannot_decrypt():
    """Test that data encrypted with one key cannot be decrypted with another."""
    enc1 = DataEncryptor("a" * 32)
    enc2 = DataEncryptor("b" * 32)

    data = {"user_id": "123"}
    encrypted = enc1.encrypt(data)

    with pytest.raises(InvalidToken):
        enc2.decrypt(encrypted)


def test_encrypt_various_data_types():
    """Test encryption/decryption with various data types in the dictionary."""
    enc = DataEncryptor(SECRET)
    data = {
        "string": "test",
        "number": 42,
        "float": 3.14,
        "boolean": True,
        "null": None,
        "list": [1, 2, 3],
        "nested_dict": {"key": "value"},
    }
    encrypted = enc.encrypt(data)
    decrypted = enc.decrypt(encrypted)
    assert decrypted == data


def test_encrypt_empty_dict():
    """Test that empty dictionaries can be encrypted and decrypted."""
    enc = DataEncryptor(SECRET)
    data = {}
    encrypted = enc.encrypt(data)
    decrypted = enc.decrypt(encrypted)
    assert decrypted == data


def test_encrypted_strings_are_different():
    """Test that encrypting the same data twice produces different encrypted strings."""
    enc = DataEncryptor(SECRET)
    data = {"user_id": "123"}
    encrypted1 = enc.encrypt(data)
    encrypted2 = enc.encrypt(data)
    # Fernet includes timestamp and random IV, so encryptions should be different
    assert encrypted1 != encrypted2
    # But both should decrypt to the same data
    assert enc.decrypt(encrypted1) == data
    assert enc.decrypt(encrypted2) == data


def test_unicode_data():
    """Test encryption/decryption with unicode characters."""
    enc = DataEncryptor(SECRET)
    data = {"name": "José", "emoji": "🔐", "chinese": "你好"}
    encrypted = enc.encrypt(data)
    decrypted = enc.decrypt(encrypted)
    assert decrypted == data


####################################
# DATA ENCRYPTOR - KEY ROTATION
####################################


def test_init_with_multiple_keys():
    """Test initialization with multiple keys for key rotation."""
    keys = ["a" * 32, "b" * 32, "c" * 32]
    enc = DataEncryptor(keys)
    assert enc.cipher is not None
    # Should be able to encrypt and decrypt
    data = {"test": "value"}
    encrypted = enc.encrypt(data)
    decrypted = enc.decrypt(encrypted)
    assert decrypted == data


def test_single_key_as_list():
    """Test that a single key provided as a list works correctly."""
    enc = DataEncryptor([SECRET])
    data = {"test": "value"}
    encrypted = enc.encrypt(data)
    decrypted = enc.decrypt(encrypted)
    assert decrypted == data


def test_encrypt_with_multiple_keys_uses_first():
    """Test that encryption with multiple keys uses the first key."""
    key1 = "a" * 32
    key2 = "b" * 32

    # Encrypt with multi-key encryptor
    enc_multi = DataEncryptor([key1, key2])
    data = {"user_id": "123"}
    encrypted = enc_multi.encrypt(data)

    # Should be decryptable with first key only
    enc_first = DataEncryptor(key1)
    decrypted = enc_first.decrypt(encrypted)
    assert decrypted == data


def test_decrypt_with_old_key_in_list():
    """Test that old sessions encrypted with a previous key can still be decrypted."""
    old_key = "a" * 32
    new_key = "b" * 32

    # Encrypt with old key
    enc_old = DataEncryptor(old_key)
    data = {"user_id": "123"}
    encrypted = enc_old.encrypt(data)

    # Decrypt with new encryptor that has both keys (new key first for new encryptions)
    enc_rotated = DataEncryptor([new_key, old_key])
    decrypted = enc_rotated.decrypt(encrypted)
    assert decrypted == data


def test_decrypt_with_middle_key_in_list():
    """Test that data encrypted with middle key in rotation list can be decrypted."""
    key1 = "a" * 32
    key2 = "b" * 32
    key3 = "c" * 32

    # Encrypt with middle key
    enc_middle = DataEncryptor(key2)
    data = {"user_id": "middle"}
    encrypted = enc_middle.encrypt(data)

    # Decrypt with all three keys
    enc_multi = DataEncryptor([key1, key2, key3])
    decrypted = enc_multi.decrypt(encrypted)
    assert decrypted == data


def test_empty_key_list_raises():
    """Test that empty key list raises ValueError."""
    with pytest.raises(ValueError, match="secret_key is required"):
        DataEncryptor([])


def test_short_key_in_list_raises():
    """Test that a short key in a list of keys raises ValueError."""
    with pytest.raises(ValueError, match="secret_key at index 1 must be at least 32 characters"):
        DataEncryptor(["a" * 32, "short"])


def test_empty_string_in_list_raises():
    """Test that empty string in key list raises ValueError."""
    with pytest.raises(ValueError, match="secret_key at index 1 cannot be empty"):
        DataEncryptor(["a" * 32, ""])


def test_all_keys_in_list_too_short():
    """Test that all keys being too short raises error on first key."""
    with pytest.raises(ValueError, match="secret_key at index 0 must be at least 32 characters"):
        DataEncryptor(["short1", "short2", "short3"])


def test_mixed_valid_invalid_keys_in_list():
    """Test that mixed valid/invalid keys raises error on first invalid."""
    with pytest.raises(ValueError, match="secret_key at index 1 must be at least 32 characters"):
        DataEncryptor(["a" * 32, "short", "c" * 32])


def test_whitespace_secret_raises():
    """Test that whitespace-only secret raises ValueError for insufficient length."""
    with pytest.raises(ValueError, match="secret_key at index 0 must be at least 32 characters"):
        DataEncryptor("   ")


####################################
# DATA ENCRYPTOR - EDGE CASES
####################################


def test_encrypt_with_none_raises():
    """Test that encrypting None raises TypeError."""
    enc = DataEncryptor(SECRET)
    with pytest.raises(TypeError, match="Data must be a dictionary"):
        enc.encrypt(None)  # type: ignore


def test_decrypt_with_none_raises():
    """Test that decrypting None raises appropriate error."""
    enc = DataEncryptor(SECRET)
    with pytest.raises(ValueError, match="Empty encrypted string cannot be decrypted"):
        enc.decrypt(None)  # type: ignore


def test_encrypt_with_string_raises():
    """Test that encrypting a string raises TypeError."""
    enc = DataEncryptor(SECRET)
    with pytest.raises(TypeError, match="Data must be a dictionary"):
        enc.encrypt("not a dict")  # type: ignore


def test_encrypt_with_int_raises():
    """Test that encrypting an int raises TypeError."""
    enc = DataEncryptor(SECRET)
    with pytest.raises(TypeError, match="Data must be a dictionary"):
        enc.encrypt(42)  # type: ignore


def test_encrypt_large_dict():
    """Test encryption/decryption of large dictionary."""
    enc = DataEncryptor(SECRET)
    # Create a large dict with 1000 keys
    data = {f"key_{i}": f"value_{i}" for i in range(1000)}
    encrypted = enc.encrypt(data)
    decrypted = enc.decrypt(encrypted)
    assert decrypted == data
    assert len(decrypted) == 1000


def test_encrypt_deeply_nested_data():
    """Test encryption/decryption of deeply nested structures."""
    enc = DataEncryptor(SECRET)
    data = {
        "level1": {
            "level2": {
                "level3": {
                    "level4": {
                        "level5": {
                            "deep_value": "found me!",
                            "deep_list": [1, 2, 3],
                            "deep_dict": {"a": "b"},
                        }
                    }
                }
            }
        },
        "another_branch": {"nested": [{"item": 1}, {"item": 2, "subitems": [{"x": "y"}]}]},
    }
    encrypted = enc.encrypt(data)
    decrypted = enc.decrypt(encrypted)
    assert decrypted == data
    assert decrypted["level1"]["level2"]["level3"]["level4"]["level5"]["deep_value"] == "found me!"
    assert decrypted["another_branch"]["nested"][1]["subitems"][0]["x"] == "y"
