# -*- coding: utf-8 -*-

import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def _hchacha20(key: bytes, nonce: bytes) -> bytes:
    """Implements HChaCha20 as per RFC 8439 appendix B.2."""
    constants = b"expand 32-byte k"

    def rotl32(v, n):
        return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n))

    def quarter_round(x, a, b, c, d):
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF
        x[d] = rotl32(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF
        x[b] = rotl32(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF
        x[d] = rotl32(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF
        x[b] = rotl32(x[b] ^ x[c], 7)

    # initialize state (16 words of 32 bits)
    st = list(struct.unpack("<4I8I4I", constants + key + nonce))
    for _ in range(10):  # 20 rounds, 2 per iteration
        # column rounds
        quarter_round(st, 0, 4, 8, 12)
        quarter_round(st, 1, 5, 9, 13)
        quarter_round(st, 2, 6, 10, 14)
        quarter_round(st, 3, 7, 11, 15)
        # diagonal rounds
        quarter_round(st, 0, 5, 10, 15)
        quarter_round(st, 1, 6, 11, 12)
        quarter_round(st, 2, 7, 8, 13)
        quarter_round(st, 3, 4, 9, 14)

    return struct.pack("<8I", *st[:4], *st[12:])


def xchacha20poly1305_encrypt(
    key: bytes, nonce: bytes, plaintext: bytes, aad: bytes
) -> bytes:
    """Emulates XChaCha20-Poly1305 AEAD using cryptography's ChaCha20Poly1305."""
    if len(nonce) != 24:
        raise ValueError("XChaCha20 nonce must be 24 bytes")
    subkey = _hchacha20(key, nonce[:16])
    chacha_nonce = b"\x00\x00\x00\x00" + nonce[16:24]  # 12-byte nonce
    return ChaCha20Poly1305(subkey).encrypt(chacha_nonce, plaintext, aad)


def xchacha20poly1305_decrypt(
    key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes
) -> bytes:
    """Decrypt counterpart."""
    if len(nonce) != 24:
        raise ValueError("XChaCha20 nonce must be 24 bytes")
    subkey = _hchacha20(key, nonce[:16])
    chacha_nonce = b"\x00\x00\x00\x00" + nonce[16:24]
    return ChaCha20Poly1305(subkey).decrypt(chacha_nonce, ciphertext, aad)


def xchacha20_xor(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """Apply the XChaCha20 stream cipher to data."""
    if len(key) != 32 or len(nonce) != 24:
        raise ValueError("XChaCha20 requires a 32-byte key and 24-byte nonce")
    subkey = _hchacha20(key, nonce[:16])
    chacha_nonce = b"\x00" * 8 + nonce[16:]
    cipher = Cipher(algorithms.ChaCha20(subkey, chacha_nonce), mode=None)
    return cipher.encryptor().update(data)
