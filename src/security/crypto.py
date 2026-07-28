from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


AES_KEY_SIZE = 32      # bytes (AES-256)
AES_NONCE_SIZE = 12    # bytes (recommended GCM nonce size)
AES_TAG_SIZE = 16      # bytes (GCM tag size)
SESSION_KEY_SIZE = 32  # bytes (AES-256 session / message key)
WRAPPED_MSG_KEY_SIZE = 48  # ciphertext(32) + tag(16); zero nonce on wire

# Per-packet keys from derive_packet_key() are unique — fixed zero nonce is safe.
_ZERO_NONCE = bytes(AES_NONCE_SIZE)


def generate_session_key() -> bytes:
    """Generate a random 32-byte key (message keys, self-tests)."""
    return os.urandom(SESSION_KEY_SIZE)


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


def wrap_msg_key(wrap_key: bytes, k_msg: bytes, aad: bytes) -> bytes:
    """
    AES-256-GCM encrypt a 32-byte message key under a per-(message, recipient) wrap key.

    Uses a fixed zero nonce — safe because ``wrap_key`` is unique per packet and recipient
    (``derive_wrap_key()`` mixes pairwise secret + src + seq + ts_ms).

    ``aad`` is typically the 8-byte recipient tag so a case cannot be replayed to another slot.
    Returns ciphertext + tag (48 bytes).
    """
    if len(wrap_key) != AES_KEY_SIZE:
        raise ValueError(f"wrap_key must be {AES_KEY_SIZE} bytes (got {len(wrap_key)})")
    if len(k_msg) != SESSION_KEY_SIZE:
        raise ValueError(f"k_msg must be {SESSION_KEY_SIZE} bytes (got {len(k_msg)})")

    aesgcm = AESGCM(wrap_key)
    blob = aesgcm.encrypt(_ZERO_NONCE, k_msg, aad)
    if len(blob) != WRAPPED_MSG_KEY_SIZE:
        raise RuntimeError(
            f"Unexpected wrapped msg key length: {len(blob)} (expected {WRAPPED_MSG_KEY_SIZE})"
        )
    return blob


def unwrap_msg_key(wrap_key: bytes, blob: bytes, aad: bytes) -> bytes:
    """
    Decrypt a 48-byte case blob produced by ``wrap_msg_key``.

    Returns the 32-byte ``k_msg``. Raises ``InvalidTag`` on wrong wrap key, tampered blob,
    or AAD mismatch (wrong recipient slot).
    """
    if len(wrap_key) != AES_KEY_SIZE:
        raise ValueError(f"wrap_key must be {AES_KEY_SIZE} bytes (got {len(wrap_key)})")
    if len(blob) != WRAPPED_MSG_KEY_SIZE:
        raise ValueError(f"blob must be {WRAPPED_MSG_KEY_SIZE} bytes (got {len(blob)})")

    aesgcm = AESGCM(wrap_key)
    k_msg = aesgcm.decrypt(_ZERO_NONCE, blob, aad)
    if len(k_msg) != SESSION_KEY_SIZE:
        raise RuntimeError(
            f"Unexpected unwrapped msg key length: {len(k_msg)} (expected {SESSION_KEY_SIZE})"
        )
    return k_msg


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

    # PKT_SUBGROUP: per-recipient message-key wrapping
    k_msg = generate_session_key()
    recipient_tag = b"\xaa" * 8
    wrap_key = os.urandom(32)
    wrapped = wrap_msg_key(wrap_key, k_msg, recipient_tag)
    assert len(wrapped) == WRAPPED_MSG_KEY_SIZE
    assert unwrap_msg_key(wrap_key, wrapped, recipient_tag) == k_msg
    print("✅ wrap_msg_key / unwrap_msg_key: OK")

    try:
        unwrap_msg_key(os.urandom(32), wrapped, recipient_tag)
        print("❌ wrong wrap key should have failed!")
    except InvalidTag:
        print("✅ wrong wrap key rejected: OK")

    try:
        unwrap_msg_key(wrap_key, wrapped, b"\xbb" * 8)
        print("❌ tampered recipient AAD should have failed!")
    except InvalidTag:
        print("✅ tampered recipient AAD rejected: OK")

    print("\n✅ All crypto self-tests passed")

