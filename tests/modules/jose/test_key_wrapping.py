"""Key wrapping round trips and wrong-key/tampering failures."""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap
import pytest

from jam.jose.__algorithms__ import (
    ECDHKeyAlgorithm,
    AESKeyWrapAlgorithm,
    PBES2KeyAlgorithm,
)


@pytest.mark.parametrize(
    "alg,curve",
    [
        ("ECDH-ES+A128KW", ec.SECP256R1),
        ("ECDH-ES+A192KW", ec.SECP384R1),
        ("ECDH-ES+A256KW", ec.SECP521R1),
    ],
)
def test_ecdh_key_wrap_roundtrip_and_wrong_recipient(alg, curve):
    private = ec.generate_private_key(curve())
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    cek = b"c" * 32
    wrapped, header = ECDHKeyAlgorithm(alg, public_pem, None).wrap_key(cek)
    assert header["epk"]["kty"] == "EC"
    assert (
        ECDHKeyAlgorithm(alg, private, None).unwrap_key(wrapped, header) == cek
    )
    with pytest.raises(InvalidUnwrap):
        ECDHKeyAlgorithm(
            alg, ec.generate_private_key(curve()), None
        ).unwrap_key(wrapped, header)


@pytest.mark.parametrize(
    "alg,size", [("A128KW", 16), ("A192KW", 24), ("A256KW", 32)]
)
def test_aes_key_wrap_tampering(alg, size):
    wrap = AESKeyWrapAlgorithm(alg, b"k" * size, None)
    cek = b"c" * 32
    wrapped, header = wrap.wrap_key(cek)
    assert wrap.unwrap_key(wrapped, header) == cek
    with pytest.raises(InvalidUnwrap):
        wrap.unwrap_key(bytes([wrapped[0] ^ 1]) + wrapped[1:], header)


def test_password_key_wrap_rejects_wrong_password():
    wrap = PBES2KeyAlgorithm("PBES2-HS256+A128KW", b"", b"password")
    wrapped, header = wrap.wrap_key(b"c" * 32)
    assert wrap.unwrap_key(wrapped, header) == b"c" * 32
    with pytest.raises(InvalidUnwrap):
        PBES2KeyAlgorithm("PBES2-HS256+A128KW", b"", b"wrong").unwrap_key(
            wrapped, header
        )
