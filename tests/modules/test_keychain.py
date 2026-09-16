# -*- coding: utf-8 -*-

import base64

from cryptography.hazmat.primitives import serialization
import pytest

from jam.exceptions import JamKeyChainError
from jam.jose import JWT
from jam.keychain import FileStorage, KeyStatus, Memory


_EC_ALGORITHMS = [
    ("ES256", "secp256r1", 64),
    ("ES384", "secp384r1", 96),
    ("ES512", "secp521r1", 132),
]


def _signature_size(token: str) -> int:
    signature = token.rsplit(".", 1)[1]
    return len(base64.urlsafe_b64decode(signature + "==="))


@pytest.mark.parametrize(("algorithm", "curve", "size"), _EC_ALGORITHMS)
@pytest.mark.parametrize("storage", ["memory", "file"])
def test_ec_generation_and_jwt_integration(
    tmp_path, algorithm, curve, size, storage
):
    if storage == "memory":
        chain = Memory(algorithm)
    else:
        chain = FileStorage(tmp_path / algorithm, algorithm)

    current = chain.rotate("first")
    private_key = serialization.load_pem_private_key(
        chain._material_for_verify(current.id), password=None
    )
    assert private_key.curve.name == curve

    jwt = JWT(alg=algorithm, keychain=chain)
    token = jwt.encode(payload={"value": algorithm})
    assert _signature_size(token) == size
    assert jwt.decode(token)["payload"]["value"] == algorithm


@pytest.mark.parametrize("storage", ["memory", "file"])
def test_key_lifecycle_and_historical_verification(tmp_path, storage):
    if storage == "memory":
        chain = Memory("ES256")
    else:
        chain = FileStorage(tmp_path / "keys", "ES256")

    first = chain.rotate("first")
    jwt = JWT(alg="ES256", keychain=chain)
    old_token = jwt.encode(payload={"generation": 1})
    second = chain.rotate("second")

    assert chain.get(first.id).status == KeyStatus.RETIRED
    assert chain.get(second.id).status == KeyStatus.CURRENT
    assert jwt.decode(old_token)["payload"]["generation"] == 1

    chain.add("standby")
    assert chain.retire("standby").status == KeyStatus.RETIRED
    assert chain.revoke(first.id).status == KeyStatus.REVOKED
    with pytest.raises(JamKeyChainError, match="revoked"):
        jwt.decode(old_token)


def test_file_storage_can_be_reopened(tmp_path):
    path = tmp_path / "keys"
    chain = FileStorage(path, "ES512")
    chain.rotate("persistent")
    token = JWT(alg="ES512", keychain=chain).encode(payload={"saved": True})

    reopened = FileStorage(path, "ES512")
    assert reopened.current().id == "persistent"
    assert JWT(alg="ES512", keychain=reopened).decode(token)["payload"]["saved"]
