# -*- coding: utf-8 -*-

from jam.exceptions import (
    JamJWTInBlackList,
    JamJWTNotInWhiteList,
    JamPASETOInvalidED25519Key,
)
from pytest import fixture, raises

from jam.paseto.v4 import PASETOv4
from jam.utils import generate_ed25519_keypair, generate_symmetric_key


@fixture(scope="module")
def symmetric_key() -> str:
    return generate_symmetric_key(32)


@fixture(scope="module")
def ed_key_pair() -> dict[str, str]:
    return generate_ed25519_keypair()


@fixture
def local_paseto(symmetric_key) -> PASETOv4:
    return PASETOv4.key(purpose="local", secret_key=symmetric_key)


@fixture
def public_paseto(ed_key_pair) -> PASETOv4:
    return PASETOv4.key("public", ed_key_pair["private"])


@fixture
def public_paseto_no_private(ed_key_pair) -> PASETOv4:
    return PASETOv4.key("public", ed_key_pair["public"])


def test_encode_local_paseto(local_paseto):
    payload = {"data": "test"}
    token = local_paseto.encode(payload)
    assert isinstance(token, str)

    decoded_payload, _ = local_paseto.decode(token)
    assert decoded_payload == payload


def test_encode_public_paseto(public_paseto):
    payload = {"data": "test"}
    token = public_paseto.encode(payload)
    assert isinstance(token, str)

    decoded_payload, _ = public_paseto.decode(token)
    assert decoded_payload == payload


def test_decode_token_by_public_key(public_paseto, public_paseto_no_private):
    payload = {"data": "test"}
    token = public_paseto.encode(payload)

    decoded_payload, _ = public_paseto_no_private.decode(token)
    assert decoded_payload == payload

    with raises(JamPASETOInvalidED25519Key):
        public_paseto_no_private.encode({"user": "error"})


def test_denylist_revokes_complete_token(symmetric_key):
    paseto = PASETOv4.key(
        purpose="local",
        secret_key=symmetric_key,
        list={"backend": "memory", "type": "black"},
    )
    token = paseto.encode({"data": "test"})

    paseto.list.add(token)

    with raises(JamJWTInBlackList):
        paseto.decode(token)


def test_allowlist_registers_issued_token(symmetric_key):
    paseto = PASETOv4.key(
        purpose="local",
        secret_key=symmetric_key,
        list={"backend": "memory", "type": "white"},
    )
    token = paseto.encode({"data": "test"})

    assert paseto.list.check(token)
    assert paseto.decode(token)[0] == {"data": "test"}


def test_allowlist_rejects_token_issued_elsewhere(symmetric_key):
    paseto = PASETOv4.key(
        purpose="local",
        secret_key=symmetric_key,
        list={"backend": "memory", "type": "white"},
    )
    token = PASETOv4.key(
        purpose="local",
        secret_key=symmetric_key,
    ).encode({"data": "test"})

    with raises(JamJWTNotInWhiteList):
        paseto.decode(token)
