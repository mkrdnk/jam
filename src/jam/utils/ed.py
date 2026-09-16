# -*- coding: utf-8 -*-

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519


_ECDSA_CURVES = {
    "P-256": ec.SECP256R1,
    "P-384": ec.SECP384R1,
    "P-521": ec.SECP521R1,
}


def generate_ed25519_keypair() -> dict[str, str]:
    """Generate Ed25519 key.

    Returns:
        dict[str, str]: {'private': KEY, 'public': KEY}
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return {"private": pem_private, "public": pem_public}


def generate_ecdsa_keypair(curve: str = "P-384") -> dict[str, str]:
    """Generate an ECDSA key pair for a named NIST curve.

    Args:
        curve (str): Curve name (P-256, P-384, or P-521).

    Returns:
        dict[str, str]: {'private': KEY, 'public': KEY}

    Raises:
        ValueError: If the curve is unsupported.
    """
    try:
        curve_type = _ECDSA_CURVES[curve.upper()]
    except KeyError as exc:
        raise ValueError(f"Unsupported ECDSA curve: {curve}") from exc
    private_key = ec.generate_private_key(curve_type())
    public_key = private_key.public_key()

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return {"private": pem_private, "public": pem_public}


def generate_ecdsa_p384_keypair() -> dict[str, str]:
    """Generate ECDSA P-384 key pair.

    Returns:
        dict[str, str]: {'private': KEY, 'public': KEY}
    """
    return generate_ecdsa_keypair("P-384")
