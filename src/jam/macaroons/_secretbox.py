"""NaCl-compatible XSalsa20-Poly1305, without a PyNaCl runtime dependency.

Salsa20/HSalsa20 follow https://cr.yp.to/snuffle/spec.pdf and
https://cr.yp.to/snuffle/xsalsa-20081128.pdf. Python integer operations do
not promise constant-time execution. Authentication uses cryptography's
constant-time Poly1305 verification, before any plaintext is produced.
"""

from __future__ import annotations

import secrets
import struct

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.poly1305 import Poly1305


_MASK32 = (1 << 32) - 1
_COUNTER_LIMIT = 1 << 64
_MAX_MESSAGE_BYTES = 64 * _COUNTER_LIMIT - 32
_SIGMA = struct.unpack("<4I", b"expand 32-byte k")


def _rotate_left32(value: int, shift: int) -> int:
    value &= _MASK32
    return ((value << shift) | (value >> (32 - shift))) & _MASK32


def _salsa20_rounds(state: list[int]) -> list[int]:
    """Apply ten column/row double rounds (twenty Salsa20 rounds)."""
    words = state.copy()
    columns = ((0, 4, 8, 12), (5, 9, 13, 1), (10, 14, 2, 6), (15, 3, 7, 11))
    rows = ((0, 1, 2, 3), (5, 6, 7, 4), (10, 11, 8, 9), (15, 12, 13, 14))
    for _ in range(10):
        for a, b, c, d in columns + rows:
            words[b] ^= _rotate_left32(words[a] + words[d], 7)
            words[c] ^= _rotate_left32(words[b] + words[a], 9)
            words[d] ^= _rotate_left32(words[c] + words[b], 13)
            words[a] ^= _rotate_left32(words[d] + words[c], 18)
    return words


def _salsa20_state(key: bytes, input_words: tuple[int, ...]) -> list[int]:
    key_words = struct.unpack("<8I", key)
    return [
        _SIGMA[0],
        *key_words[:4],
        _SIGMA[1],
        *input_words,
        _SIGMA[2],
        *key_words[4:],
        _SIGMA[3],
    ]


def _hsalsa20(key: bytes, nonce: bytes) -> bytes:
    """Derive a subkey using the first sixteen XSalsa20 nonce bytes."""
    state = _salsa20_state(key, struct.unpack("<4I", nonce))
    words = _salsa20_rounds(state)
    # HSalsa20 omits feed-forward and selects these eight output words.
    return struct.pack("<8I", *(words[i] for i in (0, 5, 10, 15, 6, 7, 8, 9)))


def _salsa20_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    """Generate one block, with a little-endian 64-bit block counter."""
    if not 0 <= counter < _COUNTER_LIMIT:
        raise ValueError("Salsa20 block counter out of range")
    state = _salsa20_state(
        key,
        (*struct.unpack("<2I", nonce), counter & _MASK32, counter >> 32),
    )
    words = _salsa20_rounds(state)
    return struct.pack(
        "<16I",
        *((word + initial) & _MASK32 for word, initial in zip(words, state)),
    )


def _validate_key(key: bytes) -> None:
    if len(key) != 32:
        raise ValueError("SecretBox key must contain exactly 32 bytes")


def _validate_message_length(length: int) -> None:
    if not 0 <= length <= _MAX_MESSAGE_BYTES:
        raise ValueError("SecretBox message exceeds the Salsa20 counter range")


def _xsalsa20_setup(key: bytes, nonce: bytes) -> tuple[bytes, bytes]:
    subkey = _hsalsa20(key, nonce[:16])
    return subkey, _salsa20_block(subkey, nonce[16:], 0)


def _xor_message(
    key: bytes, nonce: bytes, message: bytes, first_block: bytes
) -> bytes:
    # NaCl reserves stream bytes 0..31 for the one-time Poly1305 key.
    output = bytearray(len(message))
    position = 0
    counter = 0
    stream = first_block[32:]
    while position < len(message):
        count = min(len(stream), len(message) - position)
        for index in range(count):
            output[position + index] = message[position + index] ^ stream[index]
        position += count
        if position < len(message):
            counter += 1
            stream = _salsa20_block(key, nonce, counter)
    return bytes(output)


def encrypt(key: bytes, plaintext: bytes, nonce: bytes | None = None) -> bytes:
    """Return nonce || Poly1305 tag || ciphertext in NaCl SecretBox format.

    Explicit nonces must never be reused with the same key. By default a
    fresh, cryptographically random 24-byte nonce is generated.
    """
    _validate_key(key)
    _validate_message_length(len(plaintext))
    if nonce is None:
        nonce = secrets.token_bytes(24)
    if len(nonce) != 24:
        raise ValueError("SecretBox nonce must contain exactly 24 bytes")
    subkey, first_block = _xsalsa20_setup(key, nonce)
    ciphertext = _xor_message(subkey, nonce[16:], plaintext, first_block)
    # NaCl authenticates ciphertext only, not AEAD length/padding fields.
    tag = Poly1305.generate_tag(first_block[:32], ciphertext)
    return nonce + tag + ciphertext


def decrypt(key: bytes, box: bytes) -> bytes:
    """Authenticate a SecretBox, raising InvalidTag before decrypting."""
    _validate_key(key)
    if len(box) < 40:
        raise ValueError(
            "SecretBox must contain a 24-byte nonce and 16-byte tag"
        )
    _validate_message_length(len(box) - 40)
    nonce, tag, ciphertext = box[:24], box[24:40], box[40:]
    subkey, first_block = _xsalsa20_setup(key, nonce)
    try:
        Poly1305.verify_tag(first_block[:32], ciphertext, tag)
    except InvalidSignature:
        raise InvalidTag("SecretBox authentication failed") from None
    return _xor_message(subkey, nonce[16:], ciphertext, first_block)
