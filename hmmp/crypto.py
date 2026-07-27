# Copyright 2026 The HMMP Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Cryptographic utilities for HMMP protocol.

Implements:
- HMAC-SHA256 signature computation
- AES-256-GCM encryption/decryption for config transport
- HKDF-SHA256 key derivation
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from typing import NamedTuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from .constants import MAGIC_NUMBER, PROTOCOL_VERSION
from .exceptions import DecryptionError


def compute_signature(secret: str, client_id: str, timestamp: int) -> str:
    """Compute base HMAC-SHA256 signature.

    sig = Hex(HMAC_SHA256(secret, client_id + timestamp))

    Args:
        secret: Shared secret key
        client_id: Client identifier
        timestamp: Milliseconds since epoch

    Returns:
        Lowercase hex string of signature
    """
    message = f"{client_id}{timestamp}".encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), message, hashlib.sha256)
    return sig.hexdigest()


def compute_signature_v2(
    secret: str, client_id: str, timestamp: int, server_nonce: bytes
) -> str:
    """Compute extended HMAC-SHA256 signature with nonce (anti-replay).

    sig = Hex(HMAC_SHA256(secret, client_id + timestamp + server_nonce_hex))

    Args:
        secret: Shared secret key
        client_id: Client identifier
        timestamp: Milliseconds since epoch
        server_nonce: 32-byte server nonce

    Returns:
        Lowercase hex string of signature
    """
    nonce_hex = server_nonce.hex()
    message = f"{client_id}{timestamp}{nonce_hex}".encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), message, hashlib.sha256)
    return sig.hexdigest()


def verify_signature(
    secret: str, client_id: str, timestamp: int, signature: str
) -> bool:
    """Verify base HMAC-SHA256 signature."""
    expected = compute_signature(secret, client_id, timestamp)
    return hmac.compare_digest(expected, signature)


def verify_signature_v2(
    secret: str, client_id: str, timestamp: int, server_nonce: bytes, signature: str
) -> bool:
    """Verify extended HMAC-SHA256 signature with nonce."""
    expected = compute_signature_v2(secret, client_id, timestamp, server_nonce)
    return hmac.compare_digest(expected, signature)


def derive_session_secret(client_id: str, timestamp: int, shared_key: str) -> bytes:
    """Derive session secret for key derivation.

    session_secret = HMAC-SHA256(client_id + timestamp, shared_key)
    """
    message = f"{client_id}{timestamp}".encode("utf-8")
    return hmac.new(shared_key.encode("utf-8"), message, hashlib.sha256).digest()


def derive_cek(session_secret: bytes, config_key_id: str) -> bytes:
    """Derive Content Encryption Key using HKDF-SHA256.

    CEK = HKDF-SHA256(
        ikm  = session_secret,
        salt = "hmmp-config-encrypt-v1",
        info = config_key_id,
        length = 32 bytes
    )
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"hmmp-config-encrypt-v1",
        info=config_key_id.encode("utf-8"),
    )
    return hkdf.derive(session_secret)


class EncryptedPayload(NamedTuple):
    """Encrypted payload structure."""
    iv: bytes
    ciphertext: bytes  # Includes 16-byte GCM auth tag


def build_aad(magic: int, version: int, stream_id: int, body_type: int) -> bytes:
    """Build Additional Authenticated Data for AES-GCM.

    AAD = magic(2B) || version(1B) || stream_id(4B) || body_type(2B)
    """
    return struct.pack("!HBIH", magic, version, stream_id, body_type)


def encrypt_config_body(
    plaintext: bytes,
    cek: bytes,
    stream_id: int,
    body_type: int,
) -> bytes:
    """Encrypt config body using AES-256-GCM.

    Encrypted Body Layout:
    - iv_len (u8): 12
    - IV (12 bytes)
    - ciphertext_len (u32): includes 16-byte GCM tag
    - ciphertext (variable)

    Args:
        plaintext: Standard body layout bytes
        cek: 32-byte Content Encryption Key
        stream_id: Frame stream ID
        body_type: OpCode value

    Returns:
        Encrypted body layout bytes
    """
    iv = os.urandom(12)
    aad = build_aad(MAGIC_NUMBER, PROTOCOL_VERSION, stream_id, body_type)

    aesgcm = AESGCM(cek)
    ciphertext = aesgcm.encrypt(iv, plaintext, aad)  # Includes 16-byte tag

    # Build encrypted body layout
    result = struct.pack("!B", 12)  # iv_len
    result += iv
    result += struct.pack("!I", len(ciphertext))
    result += ciphertext

    return result


def decrypt_config_body(
    encrypted_body: bytes,
    cek: bytes,
    stream_id: int,
    body_type: int,
) -> bytes:
    """Decrypt config body using AES-256-GCM.

    Args:
        encrypted_body: Encrypted body layout bytes
        cek: 32-byte Content Encryption Key
        stream_id: Frame stream ID
        body_type: OpCode value

    Returns:
        Decrypted plaintext bytes

    Raises:
        DecryptionError: If decryption or tag verification fails
    """
    if len(encrypted_body) < 1:
        raise DecryptionError("Encrypted body too short")

    offset = 0
    iv_len = encrypted_body[offset]
    offset += 1

    if iv_len != 12:
        raise DecryptionError(f"Invalid IV length: {iv_len}, expected 12")

    if len(encrypted_body) < offset + iv_len + 4:
        raise DecryptionError("Encrypted body too short for IV and length")

    iv = encrypted_body[offset:offset + iv_len]
    offset += iv_len

    ciphertext_len = struct.unpack("!I", encrypted_body[offset:offset + 4])[0]
    offset += 4

    if len(encrypted_body) < offset + ciphertext_len:
        raise DecryptionError("Encrypted body too short for ciphertext")

    ciphertext = encrypted_body[offset:offset + ciphertext_len]

    aad = build_aad(MAGIC_NUMBER, PROTOCOL_VERSION, stream_id, body_type)

    try:
        aesgcm = AESGCM(cek)
        plaintext = aesgcm.decrypt(iv, ciphertext, aad)
    except Exception as e:
        raise DecryptionError(f"AES-GCM decryption failed: {e}")

    return plaintext


def compute_md5(data: bytes) -> bytes:
    """Compute MD5 hash (16 bytes raw binary)."""
    return hashlib.md5(data).digest()


def verify_md5(data: bytes, expected_md5: bytes) -> bool:
    """Verify MD5 hash."""
    return hmac.compare_digest(compute_md5(data), expected_md5)


def generate_nonce() -> bytes:
    """Generate a cryptographically secure 32-byte nonce."""
    return os.urandom(32)
