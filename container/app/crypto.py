"""AES-256-GCM at-rest secret encryption and WireGuard Curve25519 key utilities."""

from __future__ import annotations

import base64
import binascii
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


AES_KEY_SIZE = 32
AES_GCM_NONCE_SIZE = 12
AES_GCM_TAG_SIZE = 16
TOKEN_PREFIX = "v1:"


class CryptoError(ValueError):
    """Raised when encryption, decryption, or key validation fails."""


def ensure_master_key(master_key_path: Path | str) -> bytes:
    """Load or atomically create a 32-byte AES-256 master key (`0600`)."""
    path = Path(master_key_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass

    if not path.exists():
        key = os.urandom(AES_KEY_SIZE)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        try:
            fd = os.open(str(path), flags, 0o600)
            try:
                os.write(fd, key)
            finally:
                os.close(fd)
        except FileExistsError:
            pass
        else:
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            return key

    raw = path.read_bytes()
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass

    if len(raw) == AES_KEY_SIZE:
        return raw

    stripped = raw.strip()
    if len(stripped) == 64:
        try:
            decoded_hex = bytes.fromhex(stripped.decode("ascii"))
            if len(decoded_hex) == AES_KEY_SIZE:
                return decoded_hex
        except (ValueError, UnicodeDecodeError):
            pass
    try:
        decoded_b64 = base64.b64decode(stripped, validate=True)
        if len(decoded_b64) == AES_KEY_SIZE:
            return decoded_b64
    except (binascii.Error, ValueError):
        pass

    raise CryptoError(f"Invalid master key in {path}: expected {AES_KEY_SIZE} bytes, got {len(raw)}")


def _validate_master_key(master_key: bytes) -> None:
    if not isinstance(master_key, (bytes, bytearray)) or len(master_key) != AES_KEY_SIZE:
        raise CryptoError(f"Master key must be exactly {AES_KEY_SIZE} bytes")


def encrypt_secret(plaintext: str, master_key: bytes, aad: bytes | None = None) -> str:
    """Encrypt a UTF-8 secret with AES-256-GCM using a fresh 96-bit random nonce."""
    _validate_master_key(master_key)
    if plaintext is None:
        raise CryptoError("Cannot encrypt None; use encrypt_optional for nullable fields")
    nonce = os.urandom(AES_GCM_NONCE_SIZE)
    aesgcm = AESGCM(bytes(master_key))
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)
    payload = base64.b64encode(nonce + ciphertext).decode("ascii")
    return f"{TOKEN_PREFIX}{payload}"


def decrypt_secret(token: str, master_key: bytes, aad: bytes | None = None) -> str:
    """Decrypt an AES-256-GCM token produced by `encrypt_secret`."""
    _validate_master_key(master_key)
    if not token or not isinstance(token, str):
        raise CryptoError("Ciphertext token must be a non-empty string")
    encoded = token[len(TOKEN_PREFIX) :] if token.startswith(TOKEN_PREFIX) else token
    try:
        raw = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError) as exc:
        raise CryptoError("Malformed base64 ciphertext token") from exc

    if len(raw) < AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE:
        raise CryptoError("Ciphertext token is truncated")

    nonce = raw[:AES_GCM_NONCE_SIZE]
    ciphertext = raw[AES_GCM_NONCE_SIZE:]
    aesgcm = AESGCM(bytes(master_key))
    try:
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise CryptoError("AES-256-GCM authentication tag verification failed") from exc
    return plaintext_bytes.decode("utf-8")


def encrypt_optional(plaintext: str | None, master_key: bytes, aad: bytes | None = None) -> str | None:
    """Encrypt an optional secret, preserving None/empty as None."""
    if plaintext is None or plaintext == "":
        return None
    return encrypt_secret(plaintext, master_key, aad=aad)


def decrypt_optional(token: str | None, master_key: bytes, aad: bytes | None = None) -> str | None:
    """Decrypt an optional secret, preserving None/empty as None."""
    if token is None or token == "":
        return None
    return decrypt_secret(token, master_key, aad=aad)


def is_valid_wg_key(key_b64: str) -> bool:
    """Return True if `key_b64` is a valid 32-byte base64-encoded WireGuard key."""
    if not isinstance(key_b64, str) or len(key_b64) != 44 or not key_b64.endswith("="):
        return False
    try:
        raw = base64.b64decode(key_b64.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        return False
    return len(raw) == 32 and base64.b64encode(raw).decode("ascii") == key_b64


def derive_wg_public_key(private_key_b64: str) -> str:
    """Derive the base64 Curve25519 WireGuard public key from a base64 private key."""
    if not is_valid_wg_key(private_key_b64):
        raise CryptoError("Invalid WireGuard private key")
    priv_bytes = base64.b64decode(private_key_b64.encode("ascii"))
    priv_obj = X25519PrivateKey.from_private_bytes(priv_bytes)
    pub_bytes = priv_obj.public_key().public_bytes_raw()
    return base64.b64encode(pub_bytes).decode("ascii")


def generate_wg_keypair() -> tuple[str, str]:
    """Generate a clamped RFC 7748 Curve25519 WireGuard `(private_key, public_key)` pair."""
    raw = bytearray(os.urandom(32))
    raw[0] &= 248
    raw[31] = (raw[31] & 127) | 64
    priv_obj = X25519PrivateKey.from_private_bytes(bytes(raw))
    priv_b64 = base64.b64encode(priv_obj.private_bytes_raw()).decode("ascii")
    pub_b64 = base64.b64encode(priv_obj.public_key().public_bytes_raw()).decode("ascii")
    return priv_b64, pub_b64


def generate_wg_psk() -> str:
    """Generate a 256-bit WireGuard PresharedKey (base64)."""
    return base64.b64encode(os.urandom(32)).decode("ascii")
