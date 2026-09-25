# -*- coding: utf-8 -*-

from typing import Literal

import pytest

from jam.exceptions import (
    JamPASETOExpired,
    JamPASETOInvalidClaim,
    JamPASETONotYetValid,
)
from jam.paseto import BasePASETO, PASETOv1, PASETOv2, PASETOv3, PASETOv4
from jam.utils import (
    generate_ecdsa_p384_keypair,
    generate_ed25519_keypair,
    generate_rsa_key_pair,
    generate_symmetric_key,
)


NOW = 1_700_000_000.0

PASETO_CASES = [
    pytest.param((PASETOv1, "local"), id="v1-local"),
    pytest.param((PASETOv1, "public"), id="v1-public"),
    pytest.param((PASETOv2, "local"), id="v2-local"),
    pytest.param((PASETOv2, "public"), id="v2-public"),
    pytest.param((PASETOv3, "local"), id="v3-local"),
    pytest.param((PASETOv3, "public"), id="v3-public"),
    pytest.param((PASETOv4, "local"), id="v4-local"),
    pytest.param((PASETOv4, "public"), id="v4-public"),
]


@pytest.fixture(scope="module", params=PASETO_CASES)
def paseto(request) -> BasePASETO:
    paseto_type, purpose = request.param
    if purpose == "local":
        secret_key = generate_symmetric_key(32)
    elif paseto_type is PASETOv1:
        secret_key = generate_rsa_key_pair()["private"]
    elif paseto_type is PASETOv3:
        secret_key = generate_ecdsa_p384_keypair()["private"]
    else:
        secret_key = generate_ed25519_keypair()["private"]
    return paseto_type.key(purpose=purpose, secret_key=secret_key)


@pytest.fixture
def local_paseto() -> PASETOv4:
    return PASETOv4.key(
        purpose="local",
        secret_key=generate_symmetric_key(32),
    )


def test_rejects_expired_rfc3339_claim(paseto, monkeypatch):
    monkeypatch.setattr("jam.paseto.utils.time.time", lambda: NOW)
    token = paseto.encode({"exp": "2023-11-14T22:13:19Z"})

    with pytest.raises(JamPASETOExpired) as error:
        paseto.decode(token)

    assert error.value.error_code == "paseto.token_expired"
    assert error.value.details == {"exp": NOW - 1, "now": NOW}


def test_rejects_future_rfc3339_nbf_claim(paseto, monkeypatch):
    monkeypatch.setattr("jam.paseto.utils.time.time", lambda: NOW)
    token = paseto.encode({"nbf": "2023-11-14T22:13:21Z"})

    with pytest.raises(JamPASETONotYetValid) as error:
        paseto.decode(token)

    assert error.value.error_code == "paseto.token_not_yet_valid"
    assert error.value.details == {"nbf": NOW + 1, "now": NOW}


def test_accepts_legacy_numeric_date_claims(paseto, monkeypatch):
    monkeypatch.setattr("jam.paseto.utils.time.time", lambda: NOW)
    payload = {"exp": NOW + 1, "nbf": NOW - 1}
    token = paseto.encode(payload)

    assert paseto.decode(token)[0] == payload


@pytest.mark.parametrize("claim", ["exp", "nbf"])
@pytest.mark.parametrize(
    "value",
    [
        "1700000000",
        "2023-11-14 22:13:20Z",
        "2023-11-14T22:13:20z",
        "2023-11-14T22:13:20",
        True,
        None,
        float("nan"),
        float("inf"),
        -float("inf"),
    ],
)
def test_rejects_invalid_registered_claim(
    local_paseto,
    monkeypatch,
    claim: Literal["exp", "nbf"],
    value,
):
    monkeypatch.setattr("jam.paseto.utils.time.time", lambda: NOW)
    token = local_paseto.encode({claim: value})

    with pytest.raises(JamPASETOInvalidClaim) as error:
        local_paseto.decode(token)

    assert error.value.error_code == "paseto.invalid_claim"
    assert error.value.details["claim"] == claim


def test_accepts_offsets_and_fractional_seconds(local_paseto, monkeypatch):
    monkeypatch.setattr("jam.paseto.utils.time.time", lambda: NOW)
    payload = {
        "exp": "2023-11-14T23:13:20.000001+01:00",
        "nbf": "2023-11-14T17:13:19.999999-05:00",
    }
    token = local_paseto.encode(payload)

    assert local_paseto.decode(token)[0] == payload


def test_expiration_instant_is_still_valid(local_paseto, monkeypatch):
    monkeypatch.setattr("jam.paseto.utils.time.time", lambda: NOW)
    token = local_paseto.encode({"exp": "2023-11-14T22:13:20Z"})

    payload, _ = local_paseto.decode(token)
    assert payload["exp"] == "2023-11-14T22:13:20Z"


def test_claim_validation_can_be_disabled(local_paseto):
    token = local_paseto.encode({"exp": "not-a-datetime"})

    payload, _ = local_paseto.decode(token, validate_claims=False)

    assert payload["exp"] == "not-a-datetime"
