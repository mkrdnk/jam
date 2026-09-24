# -*- coding: utf-8 -*-

from jam.exceptions import (
    JamPASETOImplicitAssertionUnsupported,
    JamPASETOInvalidED25519Key,
)
from pytest import fixture, mark, raises

from jam.paseto.v2 import PASETOv2
from jam.utils import generate_ed25519_keypair, generate_symmetric_key


@fixture(scope="module")
def symmetric_key() -> str:
    return generate_symmetric_key(32)


@fixture(scope="module")
def ed_key_pair() -> dict[str, str]:
    return generate_ed25519_keypair()


@fixture
def local_paseto(symmetric_key) -> PASETOv2:
    return PASETOv2.key(purpose="local", secret_key=symmetric_key)


@fixture
def public_paseto(ed_key_pair) -> PASETOv2:
    return PASETOv2.key("public", ed_key_pair["private"])


@fixture
def public_paseto_no_private(ed_key_pair) -> PASETOv2:
    return PASETOv2.key("public", ed_key_pair["public"])


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


@mark.parametrize("paseto_fixture", ("local_paseto", "public_paseto"))
@mark.parametrize("implicit_assertion", (b"tenant-a", "tenant-a"))
def test_rejects_nonempty_implicit_assertion_on_encode(
    request, paseto_fixture, implicit_assertion
):
    paseto = request.getfixturevalue(paseto_fixture)

    with raises(JamPASETOImplicitAssertionUnsupported) as error:
        paseto.encode({"data": "test"}, implicit_assertion=implicit_assertion)

    assert error.value.error_code == (
        "paseto.validation.implicit_assertion_unsupported"
    )
    assert error.value.details == {
        "version": "v2",
        "parameter": "implicit_assertion",
    }


@mark.parametrize("paseto_fixture", ("local_paseto", "public_paseto"))
@mark.parametrize("implicit_assertion", (b"tenant-a", "tenant-a"))
def test_rejects_nonempty_implicit_assertion_on_decode(
    request, paseto_fixture, implicit_assertion
):
    paseto = request.getfixturevalue(paseto_fixture)
    token = paseto.encode({"data": "test"})

    with raises(JamPASETOImplicitAssertionUnsupported) as error:
        paseto.decode(token, implicit_assertion=implicit_assertion)

    assert error.value.error_code == (
        "paseto.validation.implicit_assertion_unsupported"
    )
    assert error.value.details == {
        "version": "v2",
        "parameter": "implicit_assertion",
    }


@mark.parametrize("paseto_fixture", ("local_paseto", "public_paseto"))
@mark.parametrize("implicit_assertion", (b"", ""))
def test_accepts_empty_implicit_assertion(
    request, paseto_fixture, implicit_assertion
):
    paseto = request.getfixturevalue(paseto_fixture)
    payload = {"data": "test"}

    token = paseto.encode(payload, implicit_assertion=implicit_assertion)

    assert (
        paseto.decode(token, implicit_assertion=implicit_assertion)[0]
        == payload
    )
