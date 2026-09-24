# -*- coding: utf-8 -*-

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from pytest import fixture, mark, raises

from jam.exceptions import JamPASETOImplicitAssertionUnsupported
from jam.paseto.utils import __pae__, base64url_decode, base64url_encode
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
        "version": "v1",
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
        "version": "v1",
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


def test_v1_public_interoperates_with_sha384_digest_length_pss(rsa_keys):
    private_key = serialization.load_pem_private_key(
        rsa_keys["private"].encode(), password=None
    )
    public_paseto = PASETOv1.key(purpose="public", secret_key=private_key)
    verifier = PASETOv1.key(
        purpose="public", secret_key=private_key.public_key()
    )
    token = public_paseto.encode({"data": "test"})
    header, body = token.rsplit(".", 1)
    payload_and_signature = base64url_decode(body.encode())
    signature_size = private_key.key_size // 8
    payload = payload_and_signature[:-signature_size]
    signature = payload_and_signature[-signature_size:]
    pre_auth = __pae__([f"{header}.".encode(), payload, b""])
    pss = padding.PSS(
        mgf=padding.MGF1(hashes.SHA384()),
        salt_length=hashes.SHA384().digest_size,
    )

    private_key.public_key().verify(
        signature,
        pre_auth,
        pss,
        hashes.SHA384(),
    )

    raw_payload = b'{"data":"raw"}'
    raw_pre_auth = __pae__([b"v1.public.", raw_payload, b""])
    raw_signature = private_key.sign(raw_pre_auth, pss, hashes.SHA384())
    raw_token = (
        b"v1.public." + base64url_encode(raw_payload + raw_signature)
    ).decode()
    assert verifier.decode(raw_token)[0] == {"data": "raw"}

    legacy_pss = padding.PSS(
        mgf=padding.MGF1(hashes.SHA384()),
        salt_length=padding.PSS.MAX_LENGTH,
    )
    legacy_signature = private_key.sign(
        raw_pre_auth,
        legacy_pss,
        hashes.SHA384(),
    )
    legacy_token = (
        b"v1.public." + base64url_encode(raw_payload + legacy_signature)
    ).decode()
    assert verifier.decode(legacy_token)[0] == {"data": "raw"}
