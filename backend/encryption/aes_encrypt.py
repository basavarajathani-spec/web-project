"""
AES-256-CBC encryption for secret images.

Design notes:
- AES-256 in CBC mode with PKCS7 padding and a random 16-byte IV per encryption.
- A SHA-256 hash of the *original* (plaintext) image bytes is computed alongside
  encryption so the decrypt/extract side can verify integrity after the full
  encrypt -> embed -> extract -> decrypt round trip.
- The key is generated here if not supplied, so the caller (API layer) can hand
  it back to the user (e.g. as a QR code) and never needs to store it server-side.
"""

import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

AES_KEY_SIZE = 32   # AES-256
AES_IV_SIZE = 16    # CBC block size


def generate_key() -> bytes:
    """Generate a cryptographically secure random AES-256 key."""
    return get_random_bytes(AES_KEY_SIZE)


def encrypt_bytes(plaintext: bytes, key: bytes = None) -> dict:
    """
    Encrypt raw bytes with AES-256-CBC.

    Returns a dict with encrypted_data, key, iv, sha256 (of the plaintext),
    and original_size. Raises ValueError on bad key length.
    """
    if key is None:
        key = generate_key()
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"AES-256 key must be {AES_KEY_SIZE} bytes, got {len(key)}")

    iv = get_random_bytes(AES_IV_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext, AES.block_size)
    encrypted = cipher.encrypt(padded)
    sha256_hash = hashlib.sha256(plaintext).hexdigest()

    return {
        "encrypted_data": encrypted,
        "key": key,
        "iv": iv,
        "sha256": sha256_hash,
        "original_size": len(plaintext),
    }


def encrypt_image(image_path: str, key: bytes = None) -> dict:
    """Convenience wrapper: read an image file from disk and encrypt its bytes."""
    with open(image_path, "rb") as f:
        image_bytes = f.read()
    return encrypt_bytes(image_bytes, key=key)


def key_to_hex(key: bytes) -> str:
    """Human/QR-friendly representation of an AES key."""
    return key.hex()


def key_from_hex(key_hex: str) -> bytes:
    key = bytes.fromhex(key_hex)
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"Decoded key must be {AES_KEY_SIZE} bytes, got {len(key)}")
    return key
