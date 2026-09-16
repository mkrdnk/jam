# -*- coding: utf-8 -*-

"""Various utilities that help with authorization."""

from .aes import generate_aes_key
from .basic_auth import basic_auth_decode, basic_auth_encode
from .ed import (
    generate_ecdsa_keypair,
    generate_ecdsa_p384_keypair,
    generate_ed25519_keypair,
)
from .otp_keys import generate_otp_key, otp_key_from_string
from .rsa import generate_rsa_key_pair
from .salt_hash import (
    check_password,
    deserialize_hash,
    hash_password,
    serialize_hash,
)
from .symmetric import generate_symmetric_key
from .xor import xor_my_data


__all__ = [
    "generate_aes_key",
    "generate_otp_key",
    "otp_key_from_string",
    "generate_rsa_key_pair",
    "check_password",
    "deserialize_hash",
    "hash_password",
    "serialize_hash",
    "generate_ed25519_keypair",
    "generate_ecdsa_keypair",
    "generate_ecdsa_p384_keypair",
    "generate_symmetric_key",
    "xor_my_data",
    "basic_auth_encode",
    "basic_auth_decode",
]
