"""
Envelope Encryption Service for Ethio-Cyber-Shield (ECS).
Provides AES-256-GCM encryption and decryption for sensitive secrets stored at rest.
"""
import os
import base64
import hashlib
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

# Default master key fallback for local development (32 bytes = 256 bits)
DEFAULT_DEV_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


def _get_master_key() -> bytes:
    """Derives a 256-bit AES master key from environment or default."""
    raw_key = os.getenv("ECS_MASTER_ENCRYPTION_KEY", DEFAULT_DEV_KEY)
    # Ensure key is exactly 32 bytes using SHA-256
    return hashlib.sha256(raw_key.encode('utf-8')).digest()


def encrypt_secret(plaintext: str) -> str:
    """
    Encrypts a plaintext secret using AES-256-GCM.
    Returns a formatted string: "enc:v1:<base64_nonce>:<base64_ciphertext_and_tag>"
    """
    if not plaintext:
        return ""
    if plaintext.startswith("enc:v1:"):
        return plaintext  # Already encrypted

    master_key = _get_master_key()
    aesgcm = AESGCM(master_key)
    nonce = os.urandom(12)  # 96-bit standard nonce for AES-GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)

    nonce_b64 = base64.b64encode(nonce).decode('utf-8')
    ct_b64 = base64.b64encode(ciphertext).decode('utf-8')
    return f"enc:v1:{nonce_b64}:{ct_b64}"


def decrypt_secret(encrypted_value: str) -> str:
    """
    Decrypts an AES-256-GCM formatted secret.
    If the value is not encrypted (e.g. legacy plain secret), returns it as-is for backward compatibility.
    """
    if not encrypted_value:
        return ""
    if not encrypted_value.startswith("enc:v1:"):
        return encrypted_value  # Legacy plaintext fallback

    try:
        parts = encrypted_value.split(":")
        if len(parts) != 4:
            raise ValueError("Malformed encrypted secret format")

        nonce = base64.b64decode(parts[2])
        ciphertext = base64.b64decode(parts[3])
        master_key = _get_master_key()
        aesgcm = AESGCM(master_key)

        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        raise ValueError("Failed to decrypt secret: invalid key or tampered ciphertext")
