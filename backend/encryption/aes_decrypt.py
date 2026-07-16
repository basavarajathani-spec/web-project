"""
AES-256-CBC decryption + SHA-256 integrity verification.
Mirrors encryption/aes_encrypt.py.
"""

import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

AES_KEY_SIZE = 32
AES_IV_SIZE = 16


def decrypt_bytes(encrypted_data: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt AES-256-CBC ciphertext back to the original plaintext bytes."""
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"AES-256 key must be {AES_KEY_SIZE} bytes, got {len(key)}")
    if len(iv) != AES_IV_SIZE:
        raise ValueError(f"IV must be {AES_IV_SIZE} bytes, got {len(iv)}")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(encrypted_data)
    try:
        return unpad(padded, AES.block_size)
    except ValueError as e:
        # Wrong key/IV usually surfaces here as a padding error
        raise ValueError(
            "Decryption failed - padding invalid. Likely wrong key/IV or corrupted data."
        ) from e


def verify_integrity(data: bytes, expected_sha256_hex: str) -> bool:
    """Compare SHA-256 of `data` against an expected hex digest."""
    return hashlib.sha256(data).hexdigest() == expected_sha256_hex


def decrypt_image(encrypted_data: bytes, key: bytes, iv: bytes, expected_sha256_hex: str = None) -> dict:
    """
    Decrypt and (optionally) verify integrity in one call.
    Returns {"data": bytes, "integrity_ok": bool | None}.
    """
    plaintext = decrypt_bytes(encrypted_data, key, iv)
    integrity_ok = None
    if expected_sha256_hex is not None:
        integrity_ok = verify_integrity(plaintext, expected_sha256_hex)
    return {"data": plaintext, "integrity_ok": integrity_ok}
