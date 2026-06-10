from __future__ import annotations

import warnings

warnings.warn(
    "src.security.legacy is deprecated and will be removed in Phase 2. "
    "Use encrypt_with_key / decrypt_with_key from src.security.crypto.",
    DeprecationWarning,
    stacklevel=2,
)

from .crypto import (
    decrypt_payload,
    decrypt_session_key,
    encrypt_payload,
    encrypt_session_key,
    generate_session_key,
)


def encrypt_for_group(group_key: bytes, plaintext: bytes, aad: bytes) -> dict[str, bytes]:
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
