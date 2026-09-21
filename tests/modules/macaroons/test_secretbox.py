"""Independent known-answer and differential tests for NaCl SecretBox."""

import random

from cryptography.exceptions import InvalidTag
import pytest

from jam.macaroons import _secretbox


# Published NaCl vector, as retained by libsodium:
# https://github.com/jedisct1/libsodium/blob/1.0.20/test/default/secretbox.c
# https://github.com/jedisct1/libsodium/blob/1.0.20/test/default/secretbox.exp
# The legacy API's 32 input/16 output zero-prefix bytes are omitted here.
KEY = bytes.fromhex(
    "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389"
)
NONCE = bytes.fromhex("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37")
PLAINTEXT = bytes.fromhex(
    "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffc"
    "e5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb31"
    "0e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde"
    "048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f93776384864"
    "5e0705"
)
TAG_AND_CIPHERTEXT = bytes.fromhex(
    "f3ffc7703f9400e52a7dfb4b3d3305d9"
    "8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186a"
    "c0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738"
    "b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da"
    "99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74"
    "e355a5"
)
BOUNDARY_LENGTHS = (0, 1, 31, 32, 33, 63, 64, 65, 4096, 16385)


@pytest.mark.parametrize(
    ("length", "tag"),
    [
        (0, "28fd82cd7386c5471a24d8ad2a525b6e"),
        (1, "b57abcd350b7528b8bd575a2753d0f3b"),
        (31, "b7605a2f0bd79e3f9d9efe701d1cadb2"),
        (32, "407e929c5dfb750373fb73cc7775094b"),
        (33, "0c84897f207a6349b0507c5cba7b70b9"),
        (63, "f7c1d7e9ff94db9b6cbf08547753cede"),
        (64, "2c512877fc4afad107e9f887d566e745"),
        (65, "2033bed53c6b9c9aa7f9347ff02fd375"),
    ],
)
def test_committed_libsodium_boundary_vectors(length, tag):
    """Use fixed PyNaCl/libsodium outputs without a reference dependency."""
    # Generated using PyNaCl 1.6.2 SecretBox(bytes(range(32))).encrypt(
    # bytes(range(length)), bytes(range(24))). Ciphertext shares a prefix;
    # each tag authenticates its own message length.
    ciphertext = bytes.fromhex(
        "5efe3a4cc3cfa417b33585356482449842b454cc983029f80fbb7d8f49dabffe"
        "a3fad7f66195d32591a4cab2564b856c13705aacc7a2ea7884261d86265ca9ca9c"
    )
    key, nonce = bytes(range(32)), bytes(range(24))
    plaintext = bytes(range(length))
    expected = nonce + bytes.fromhex(tag) + ciphertext[:length]
    assert _secretbox.encrypt(key, plaintext, nonce) == expected
    assert _secretbox.decrypt(key, expected) == plaintext


def test_published_nacl_vector():
    """Match the independently published bytes in both directions."""
    box = NONCE + TAG_AND_CIPHERTEXT
    assert _secretbox.encrypt(KEY, PLAINTEXT, NONCE) == box
    assert _secretbox.decrypt(KEY, box) == PLAINTEXT


@pytest.mark.parametrize("length", BOUNDARY_LENGTHS)
def test_roundtrip_boundaries(length):
    """Exercise the reserved half-block and subsequent block boundaries."""
    plaintext = bytes(index % 256 for index in range(length))
    box = _secretbox.encrypt(KEY, plaintext, NONCE)
    assert len(box) == length + 40
    assert box[:24] == NONCE
    assert _secretbox.decrypt(KEY, box) == plaintext


def test_secure_nonce_generation(monkeypatch):
    """Request a full nonce from the cryptographic random generator."""
    requested = []

    def token_bytes(length):
        requested.append(length)
        return NONCE

    monkeypatch.setattr(_secretbox.secrets, "token_bytes", token_bytes)
    assert _secretbox.encrypt(KEY, PLAINTEXT) == NONCE + TAG_AND_CIPHERTEXT
    assert requested == [24]


def test_default_nonces_differ():
    """Generate a fresh nonce even when encrypting an empty message."""
    assert _secretbox.encrypt(KEY, b"") != _secretbox.encrypt(KEY, b"")


@pytest.mark.parametrize("length", (0, 1, 31, 33, 64))
def test_invalid_key_lengths(length):
    """Reject malformed keys for both operations."""
    with pytest.raises(ValueError):
        _secretbox.encrypt(bytes(length), b"", NONCE)
    with pytest.raises(ValueError):
        _secretbox.decrypt(bytes(length), NONCE + TAG_AND_CIPHERTEXT)


@pytest.mark.parametrize("length", (0, 1, 16, 23, 25, 32))
def test_invalid_nonce_lengths(length):
    """Reject explicit nonces rather than truncating or padding them."""
    with pytest.raises(ValueError):
        _secretbox.encrypt(KEY, b"", bytes(length))


@pytest.mark.parametrize("length", range(40))
def test_truncated_box(length):
    """Require both a complete nonce and a complete tag."""
    with pytest.raises(ValueError):
        _secretbox.decrypt(KEY, bytes(length))


@pytest.mark.parametrize("plaintext", (b"", PLAINTEXT))
def test_every_byte_authenticated_before_decryption(monkeypatch, plaintext):
    """Reject all nonce, tag, and body mutations before plaintext processing."""
    box = _secretbox.encrypt(KEY, plaintext, NONCE)

    def forbidden_decrypt(*args):
        pytest.fail("Plaintext processing reached before authentication")

    monkeypatch.setattr(_secretbox, "_xor_message", forbidden_decrypt)
    for index in range(len(box)):
        damaged = bytearray(box)
        damaged[index] ^= 1
        with pytest.raises(InvalidTag):
            _secretbox.decrypt(KEY, bytes(damaged))
    with pytest.raises(InvalidTag):
        _secretbox.decrypt(bytes(32), box)
    with pytest.raises(InvalidTag):
        _secretbox.decrypt(KEY, box + b"\x00")
    if plaintext:
        with pytest.raises(InvalidTag):
            _secretbox.decrypt(KEY, box[:-1])


def test_counter_encoding_and_bounds(monkeypatch):
    """Check the full 64-bit counter and prevent counter wraparound."""
    states = []

    def rounds(state):
        states.append(state)
        return state

    monkeypatch.setattr(_secretbox, "_salsa20_rounds", rounds)
    for counter in (0, 1, (1 << 32) - 1, 1 << 32, (1 << 64) - 1):
        _secretbox._salsa20_block(KEY, NONCE[16:], counter)
        assert states[-1][8:10] == [counter & ((1 << 32) - 1), counter >> 32]
    for counter in (-1, 1 << 64):
        with pytest.raises(ValueError):
            _secretbox._salsa20_block(KEY, NONCE[16:], counter)
    maximum = (1 << 70) - 32
    _secretbox._validate_message_length(maximum)
    for length in (-1, maximum + 1):
        with pytest.raises(ValueError):
            _secretbox._validate_message_length(length)


def test_differential_libsodium():
    """Cross-check deterministic random vectors against optional PyNaCl."""
    secret = pytest.importorskip("nacl.secret")
    rng = random.Random(0x5853414C53413230)
    lengths = [*BOUNDARY_LENGTHS, *(rng.randrange(8193) for _ in range(200))]
    for length in lengths:
        key = rng.randbytes(32)
        nonce = rng.randbytes(24)
        plaintext = rng.randbytes(length)
        reference = secret.SecretBox(key)
        expected = bytes(reference.encrypt(plaintext, nonce))
        actual = _secretbox.encrypt(key, plaintext, nonce)
        assert actual == expected
        assert _secretbox.decrypt(key, expected) == plaintext
        assert reference.decrypt(actual) == plaintext
