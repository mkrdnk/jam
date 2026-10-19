"""Version-specific PASETO key guards retain domain errors."""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
import pytest

from jam.exceptions import JamError
from jam.paseto import PASETOv1, PASETOv2, PASETOv3, PASETOv4


@pytest.mark.parametrize("cls", [PASETOv1, PASETOv2, PASETOv3, PASETOv4])
@pytest.mark.parametrize("purpose", ["public", "local"])
@pytest.mark.parametrize("key", [None, b"invalid", 123])
def test_invalid_key_material_raises_domain_error(cls, purpose, key):
    with pytest.raises(JamError):
        cls(purpose=purpose, secret_key=key)


@pytest.mark.parametrize(
    "cls,private",
    [
        (
            PASETOv1,
            lambda: rsa.generate_private_key(
                public_exponent=65537, key_size=2048
            ),
        ),
        (PASETOv2, ed25519.Ed25519PrivateKey.generate),
        (PASETOv3, lambda: ec.generate_private_key(ec.SECP384R1())),
        (PASETOv4, ed25519.Ed25519PrivateKey.generate),
    ],
)
@pytest.mark.parametrize(
    "encoding", [serialization.Encoding.PEM, serialization.Encoding.DER]
)
def test_public_key_can_verify_but_cannot_issue(cls, private, encoding):
    key = private()
    material = key.public_key().public_bytes(
        encoding, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    verifier = cls(purpose="public", secret_key=material)
    signer = cls(purpose="public", secret_key=key)
    token = signer.encode({"sub": "user"})
    assert verifier.decode(token)[0]["sub"] == "user"
    with pytest.raises(JamError):
        verifier.encode({"sub": "user"})
