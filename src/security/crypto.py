from __future__ import annotations

import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


AES_KEY_SIZE = 32      # bytes (AES-256)
AES_NONCE_SIZE = 12    # bytes (recommended GCM nonce size)
AES_TAG_SIZE = 16      # bytes (GCM tag size)
SESSION_KEY_SIZE = 32  # bytes (AES-256 session key)
ENC_SESSION_KEY_SIZE = 60  # nonce(12) + ciphertext(32) + tag(16)

# Per-packet keys from derive_packet_key() are unique — fixed zero nonce is safe.
_ZERO_NONCE = bytes(AES_NONCE_SIZE)


def generate_session_key() -> bytes:
    """Generate a random 32-byte session key using os.urandom."""
    # Session keys are one-time keys (per packet) to limit blast radius.
    return os.urandom(SESSION_KEY_SIZE)


def encrypt_session_key(group_key: bytes, session_key: bytes) -> bytes:
    """
    Encrypt session_key with group_key using AES-256-GCM.
    Returns nonce(12) + ciphertext(32) + tag(16) = 60 bytes.
    Raises ValueError if keys are not correct length.
    """
    # group_key is the pre-shared group secret (Solution B MVP).
    if len(group_key) != AES_KEY_SIZE:
        raise ValueError(f"group_key must be {AES_KEY_SIZE} bytes (got {len(group_key)})")
    if len(session_key) != SESSION_KEY_SIZE:
        raise ValueError(f"session_key must be {SESSION_KEY_SIZE} bytes (got {len(session_key)})")

    aesgcm = AESGCM(group_key)
    nonce = os.urandom(AES_NONCE_SIZE)  # unique per encryption under the same key

    # No AAD is specified for wrapping the session key; we rely on GCM integrity.
    ciphertext_with_tag = aesgcm.encrypt(nonce, session_key, None)

    # For a 32-byte plaintext, AESGCM returns 32 bytes ciphertext + 16 bytes tag = 48 bytes.
    encrypted = nonce + ciphertext_with_tag
    if len(encrypted) != ENC_SESSION_KEY_SIZE:
        raise RuntimeError(
            f"Unexpected wrapped session key length: {len(encrypted)} (expected {ENC_SESSION_KEY_SIZE})"
        )
    return encrypted


def decrypt_session_key(group_key: bytes, encrypted: bytes) -> bytes:
    """
    Decrypt encrypted session key.
    Input: nonce(12) + ciphertext(32) + tag(16) = 60 bytes.
    Returns 32-byte session key.
    Raises InvalidTag if group_key is wrong (tampered/wrong group).
    Raises ValueError if encrypted is wrong length.
    """
    if len(group_key) != AES_KEY_SIZE:
        raise ValueError(f"group_key must be {AES_KEY_SIZE} bytes (got {len(group_key)})")
    if len(encrypted) != ENC_SESSION_KEY_SIZE:
        raise ValueError(f"encrypted session key must be {ENC_SESSION_KEY_SIZE} bytes (got {len(encrypted)})")

    nonce = encrypted[:AES_NONCE_SIZE]
    ciphertext_with_tag = encrypted[AES_NONCE_SIZE:]

    # AESGCM.decrypt verifies the tag and raises InvalidTag on failure.
    aesgcm = AESGCM(group_key)
    session_key = aesgcm.decrypt(nonce, ciphertext_with_tag, None)

    if len(session_key) != SESSION_KEY_SIZE:
        raise RuntimeError(
            f"Unexpected decrypted session key length: {len(session_key)} (expected {SESSION_KEY_SIZE})"
        )
    return session_key


def encrypt_payload(session_key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext with AES-256-GCM.
    aad = routing header bytes (authenticated but not encrypted).
    Returns (nonce, ciphertext_with_tag).
    nonce is 12 random bytes.
    ciphertext_with_tag = ciphertext + 16-byte tag.
    """
    if len(session_key) != AES_KEY_SIZE:
        raise ValueError(f"session_key must be {AES_KEY_SIZE} bytes (got {len(session_key)})")

    # AAD (routing header) is integrity-protected but remains in cleartext for forwarding.
    nonce = os.urandom(AES_NONCE_SIZE)
    aesgcm = AESGCM(session_key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext_with_tag


def decrypt_payload(session_key: bytes, nonce: bytes, ciphertext_with_tag: bytes, aad: bytes) -> bytes:
    """
    Decrypt and verify payload.
    Returns plaintext.
    Raises InvalidTag if verification fails.
    """
    if len(session_key) != AES_KEY_SIZE:
        raise ValueError(f"session_key must be {AES_KEY_SIZE} bytes (got {len(session_key)})")
    if len(nonce) != AES_NONCE_SIZE:
        raise ValueError(f"nonce must be {AES_NONCE_SIZE} bytes (got {len(nonce)})")
    if len(ciphertext_with_tag) < AES_TAG_SIZE:
        raise ValueError("ciphertext_with_tag is too short (missing tag)")

    # Tag verification also covers the AAD; any changes to routing header bytes will fail.
    aesgcm = AESGCM(session_key)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, aad)


# Convenience aliases that match package exports.
def encrypt(session_key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    return encrypt_payload(session_key, plaintext, aad)


def decrypt(session_key: bytes, nonce: bytes, ciphertext_with_tag: bytes, aad: bytes) -> bytes:
    return decrypt_payload(session_key, nonce, ciphertext_with_tag, aad)


def encrypt_with_key(packet_key: bytes, plaintext: bytes, aad: bytes) -> dict[str, bytes]:
    """
    Encrypt payload with a per-packet AES-256-GCM key (derived externally).

    Uses a fixed zero nonce — safe because ``packet_key`` is unique per packet
    (``derive_packet_key()`` mixes seq + ts_ms).

    Returns ``{"ciphertext": bytes}`` (ciphertext + 16-byte GCM tag; no nonce on wire).
    """
    if len(packet_key) != AES_KEY_SIZE:
        raise ValueError(f"packet_key must be {AES_KEY_SIZE} bytes (got {len(packet_key)})")

    aesgcm = AESGCM(packet_key)
    ciphertext_with_tag = aesgcm.encrypt(_ZERO_NONCE, plaintext, aad)
    return {"ciphertext": ciphertext_with_tag}


def decrypt_with_key(packet_key: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """
    Decrypt and verify payload encrypted with ``encrypt_with_key``.

    Raises ``InvalidTag`` if the key is wrong or the packet was tampered.
    """
    if len(packet_key) != AES_KEY_SIZE:
        raise ValueError(f"packet_key must be {AES_KEY_SIZE} bytes (got {len(packet_key)})")
    if len(ciphertext) < AES_TAG_SIZE:
        raise ValueError("ciphertext is too short (missing tag)")

    aesgcm = AESGCM(packet_key)
    return aesgcm.decrypt(_ZERO_NONCE, ciphertext, aad)


# Deprecated: session-key wrapping — migrate to encrypt_with_key + derive_packet_key (keys.py).
def encrypt_for_group(group_key: bytes, plaintext: bytes, aad: bytes) -> dict:
    """
    Full BB encryption (Solution B — shared group key).

    Steps:
    1. Generate random session_key
    2. Encrypt plaintext with session_key → (nonce, ciphertext_with_tag)
    3. Encrypt session_key with group_key → enc_session_key (60 bytes)

    Returns dict with keys:
      session_key_enc: bytes  (60 bytes)
      nonce: bytes            (12 bytes)
      ciphertext: bytes       (len(plaintext) + 16 bytes tag)
    """
    # (1) One session key per packet.
    session_key = generate_session_key()

    # (2) Encrypt the payload, authenticate routing header (AAD).
    nonce, ciphertext_with_tag = encrypt_payload(session_key, plaintext, aad)

    # (3) Wrap the session key once for the whole group using the shared group_key.
    session_key_enc = encrypt_session_key(group_key, session_key)

    return {
        "session_key_enc": session_key_enc,
        "nonce": nonce,
        "ciphertext": ciphertext_with_tag,
    }


# Deprecated: session-key wrapping — migrate to decrypt_with_key + derive_packet_key (keys.py).
def decrypt_from_group(
    group_key: bytes,
    session_key_enc: bytes,
    nonce: bytes,
    ciphertext: bytes,
    aad: bytes,
) -> bytes:
    """
    Full BB decryption (Solution B).

    Steps:
    1. Decrypt session_key from session_key_enc using group_key
    2. Decrypt ciphertext using session_key and nonce
    3. Verify aad (routing header)

    Returns plaintext.
    Raises InvalidTag if group_key is wrong or packet tampered.
    """
    # (1) Recover per-packet session key; InvalidTag here means wrong group key / tampered wrapper.
    session_key = decrypt_session_key(group_key, session_key_enc)

    # (2) Decrypt payload; InvalidTag here means tampered payload and/or AAD mismatch.
    return decrypt_payload(session_key, nonce, ciphertext, aad)


if __name__ == "__main__":
    group_key = os.urandom(32)
    message = b"Hello BB Phase 1A"
    aad = b"routing_header_placeholder"

    # New API: per-packet key passed in (normally from derive_packet_key).
    packet_key = os.urandom(32)
    enc = encrypt_with_key(packet_key, message, aad)
    assert decrypt_with_key(packet_key, enc["ciphertext"], aad) == message
    print("✅ encrypt_with_key / decrypt_with_key: OK")

    try:
        decrypt_with_key(os.urandom(32), enc["ciphertext"], aad)
        print("❌ wrong packet key should have failed!")
    except InvalidTag:
        print("✅ wrong packet key rejected: OK")

    tampered = bytearray(enc["ciphertext"])
    tampered[0] ^= 0xFF
    try:
        decrypt_with_key(packet_key, bytes(tampered), aad)
        print("❌ tampered payload should have failed!")
    except InvalidTag:
        print("✅ tampered payload rejected: OK")

    try:
        decrypt_with_key(packet_key, enc["ciphertext"], b"wrong_routing_header")
        print("❌ tampered AAD should have failed!")
    except InvalidTag:
        print("✅ tampered routing header rejected: OK")

    print(f"\n📦 New wire overhead (no session key / nonce): ciphertext+tag only")
    print(f"   ciphertext+tag  : {len(enc['ciphertext'])} bytes")
    print(f"   message         : {len(message)} bytes")
    print(f"   tag overhead    : 16 bytes")

    # Deprecated API still works (migration compat).
    result: dict[str, Any] = encrypt_for_group(group_key, message, aad)
    recovered = decrypt_from_group(
        group_key,
        result["session_key_enc"],
        result["nonce"],
        result["ciphertext"],
        aad,
    )
    assert recovered == message
    print("✅ deprecated encrypt_for_group / decrypt_from_group: OK")

    print("\n✅ All crypto self-tests passed")

