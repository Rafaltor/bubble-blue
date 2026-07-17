"""
Ed25519 signatures for control-plane attestations (ANNOUNCE PoP, signed rekey).

Signing keys are derived from the node identity seed via HKDF so a single
persisted secret yields both X25519 (ECDH) and Ed25519 (sign) key pairs.
Peers learn ``ed25519_pub`` alongside ``x25519_pub`` in Hello / ANNOUNCE.
"""

from __future__ import annotations

from typing import Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ED25519_PUBLIC_KEY_SIZE: Final = 32
ED25519_SIGNATURE_SIZE: Final = 64
_SIGNING_HKDF_SALT: Final = b"bb-ed25519-v1"
_SIGNING_HKDF_INFO: Final = b"bubble-blue-signing"


def ed25519_private_from_identity_seed(seed: bytes) -> Ed25519PrivateKey:
    """Derive Ed25519 private key from the 32-byte identity seed."""
    if len(seed) != 32:
        raise ValueError(f"identity seed must be 32 bytes (got {len(seed)})")
    raw = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_SIGNING_HKDF_SALT,
        info=_SIGNING_HKDF_INFO,
    ).derive(seed)
    return Ed25519PrivateKey.from_private_bytes(raw)


def ed25519_public_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes_raw()


def sign(private_key: Ed25519PrivateKey, message: bytes) -> bytes:
    """Return 64-byte Ed25519 signature."""
    sig = private_key.sign(message)
    if len(sig) != ED25519_SIGNATURE_SIZE:
        raise RuntimeError(f"unexpected signature length {len(sig)}")
    return sig


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify Ed25519 signature; False on any failure (never raises)."""
    if len(public_key) != ED25519_PUBLIC_KEY_SIZE:
        return False
    if len(signature) != ED25519_SIGNATURE_SIZE:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False
