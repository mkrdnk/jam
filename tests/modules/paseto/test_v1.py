# -*- coding: utf-8 -*-

from pytest import fixture

from jam.paseto.v1 import PASETOv1
from jam.utils import generate_rsa_key_pair, generate_symmetric_key


@fixture(scope="module")
def symmetric_key() -> str:
    return generate_symmetric_key(32)


@fixture(scope="module")
def rsa_keys() -> dict[str, str]:
    return generate_rsa_key_pair()


@fixture
def local_paseto(symmetric_key) -> PASETOv1:
    return PASETOv1.key(purpose="local", secret_key=symmetric_key)


@fixture
def public_paseto(rsa_keys) -> PASETOv1:
    return PASETOv1.key(purpose="public", secret_key=rsa_keys["private"])


def test_encode_local_paseto(local_paseto):
    payload = {"data": "test"}
    token = local_paseto.encode(payload)
    assert isinstance(token, str)
    decoded_payload, _ = local_paseto.decode(token)
    assert decoded_payload == payload


def test_encode_public_paseto(public_paseto, rsa_keys):
    payload = {"data": "test"}
    token = public_paseto.encode(payload)
    assert isinstance(token, str)

    verifier = PASETOv1.key(purpose="public", secret_key=rsa_keys["public"])
    decoded_payload, _ = verifier.decode(token)
    assert decoded_payload == payload
