import base64
import os

from cryptography.fernet import Fernet, InvalidToken

_key = os.environ.get("ENCRYPTION_KEY")
if _key:
    # Accept raw 32-byte base64url key or a Fernet key directly
    _fernet = Fernet(_key.encode() if isinstance(_key, str) else _key)
else:
    # Auto-generate a key and warn — fine for dev, not for prod
    _fernet = Fernet(Fernet.generate_key())


def encrypt(value):
    """Encrypt a plaintext string, returns base64-encoded ciphertext."""
    return _fernet.encrypt(value.encode()).decode()


def decrypt(value):
    """Decrypt a ciphertext string. Returns None if decryption fails."""
    try:
        return _fernet.decrypt(value.encode()).decode()
    except (InvalidToken, Exception):
        return None
