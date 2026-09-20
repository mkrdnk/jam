import pytest

from jam.macaroons import (
    Caveat,
    Limits,
    Macaroon,
    SerializationError,
    VerificationError,
    Verifier,
)


def test_reference_signature_vector() -> None:
    """Match the published PyMacaroons root signature vector."""
    macaroon = Macaroon.create(
        "this is our super secret key; only we should know it",
        "we used our secret key",
        "http://mybank/",
    )

    assert macaroon.signature.hex() == (
        "e3d9e02908526c4c0039ae15114115d97fdd68bf2ba379b342aaf0f617d0552f"
    )


def test_reference_v2_wire_and_first_party_signature() -> None:
    token = Macaroon.decode(
        "AgEAAgJpZAAABiBNj8zLAZtGxvKvKOLccsX51lb_YtCLWjcj5V7C451dSg"
    )
    assert token == Macaroon.create("root", "id")
    assert token.add_caveat("account = 7").signature.hex() == (
        "b73a455e9a8df447e376f280e77deb98aed7c1a7a070ce1d37daed8d5ddb0ec6"
    )


def test_round_trip_attenuation_and_tampering() -> None:
    original = Macaroon.create("secret", "token", "https://issuer")
    attenuated = original.add_caveat(Caveat("role", "reader"))

    assert original.caveats == ()
    decoded = Macaroon.decode(attenuated.encode())
    assert decoded == attenuated
    assert Verifier().verify(
        decoded, "secret", collect_structured=True
    ).caveats == (Caveat("role", "reader"),)

    tampered = decoded.__class__(
        decoded.identifier,
        decoded.location,
        decoded.caveats,
        bytes([decoded.signature[0] ^ 1]) + decoded.signature[1:],
    )
    with pytest.raises(VerificationError):
        Verifier().verify(tampered, "secret")


def test_raw_exact_and_general_satisfiers() -> None:
    macaroon = (
        Macaroon.create(b"root", b"id")
        .add_caveat(b"account = 7")
        .add_caveat(b"time < tomorrow")
    )
    verifier = Verifier().satisfy_exact("account = 7")
    verifier.satisfy_general(lambda value: value.startswith(b"time <"))

    assert verifier.verify(macaroon, b"root").caveats == ()
    with pytest.raises(VerificationError):
        Verifier().verify(macaroon, b"root")


def test_third_party_discharge_and_wrong_binding() -> None:
    primary = Macaroon.create(b"root", b"primary").add_third_party_caveat(
        b"caveat key", b"third-id", "https://third"
    )
    discharge = Macaroon.create_discharge(
        b"caveat key", b"third-id"
    ).add_caveat(Caveat("group", "staff"))
    bound = discharge.bind(primary)

    result = Verifier().verify(
        primary, b"root", [bound], collect_structured=True
    )
    assert result.caveats == (Caveat("group", "staff"),)
    with pytest.raises(VerificationError):
        Verifier().verify(primary, b"root")
    with pytest.raises(VerificationError):
        Verifier().verify(primary, b"root", [discharge])
    with pytest.raises(VerificationError):
        Verifier().verify(
            primary,
            b"root",
            [discharge.bind(Macaroon.create(b"other", b"other"))],
        )


def test_wrong_discharge_key_and_nested_discharge() -> None:
    primary = Macaroon.create(b"root", b"primary").add_third_party_caveat(
        b"outer key", b"outer"
    )
    outer = Macaroon.create_discharge(
        b"outer key", b"outer"
    ).add_third_party_caveat(b"inner key", b"inner")
    inner = Macaroon.create_discharge(b"inner key", b"inner").add_caveat(
        Caveat("tenant", 42)
    )

    result = Verifier().verify(
        primary,
        b"root",
        [outer.bind(primary), inner.bind(primary)],
        collect_structured=True,
    )
    assert result.caveats == (Caveat("tenant", 42),)
    wrong = Macaroon.create_discharge(b"wrong", b"outer").bind(primary)
    with pytest.raises(VerificationError):
        Verifier().verify(primary, b"root", [wrong])


def test_limits_are_enforced() -> None:
    macaroon = Macaroon.create(b"root", b"id").add_caveat(b"large")
    token = macaroon.encode()

    with pytest.raises(SerializationError):
        Macaroon.decode(token, Limits(serialized_size=4))
    with pytest.raises(SerializationError):
        Macaroon.decode(token, Limits(caveat_payload_size=2))
    with pytest.raises(SerializationError):
        Macaroon.decode(token, Limits(caveat_count=0))

    primary = Macaroon.create(b"root", b"p").add_third_party_caveat(b"k", b"d")
    discharge = Macaroon.create_discharge(b"k", b"d").bind(primary)
    with pytest.raises(VerificationError):
        Verifier(Limits(discharge_count=0)).verify(
            primary, b"root", [discharge]
        )
    with pytest.raises(VerificationError):
        Verifier(Limits(discharge_depth=0)).verify(
            primary, b"root", [discharge]
        )


def test_decode_rejects_noncanonical_transport() -> None:
    token = Macaroon.create(b"root", b"id").encode()
    with pytest.raises(SerializationError):
        Macaroon.decode(token + "=")


def test_unknown_structured_fails_closed() -> None:
    token = Macaroon.create("root", "id").add_caveat(Caveat("unknown", 1))
    with pytest.raises(VerificationError):
        Verifier().verify(token, "root")


def test_callbacks_run_only_after_all_signatures() -> None:
    from dataclasses import replace

    called = []
    token = Macaroon.create("root", "id").add_caveat(b"predicate")
    verifier = Verifier().satisfy_general(lambda value: called.append(value))
    with pytest.raises(VerificationError):
        verifier.verify(replace(token, signature=bytes(32)), "root")
    assert called == []


def test_discharge_generator_is_bounded() -> None:
    token = Macaroon.create("root", "id")
    consumed = []

    def discharges():
        while True:
            consumed.append(1)
            yield token

    with pytest.raises(VerificationError):
        Verifier(Limits(discharge_count=2)).verify(token, "root", discharges())
    assert len(consumed) == 3


def test_standard_cross_implementation() -> None:
    pymacaroons = pytest.importorskip("pymacaroons")
    primary = Macaroon.create("root", "primary", "issuer")
    primary = primary.add_caveat("account = 7").add_third_party_caveat(
        "third key", "third", "third party"
    )
    discharge = Macaroon.create_discharge("third key", "third").bind(primary)
    reference = pymacaroons.Macaroon.deserialize(primary.encode())
    verifier = pymacaroons.Verifier()
    verifier.satisfy_exact("account = 7")
    assert verifier.verify(
        reference,
        "root",
        [pymacaroons.Macaroon.deserialize(discharge.encode())],
    )
    reference = pymacaroons.Macaroon(
        location="issuer",
        identifier="primary",
        key="root",
        version=2,
    )
    reference.add_third_party_caveat("third party", "third key", "third")
    discharge_ref = pymacaroons.Macaroon(
        identifier="third",
        key="third key",
        version=2,
    )
    bound = reference.prepare_for_request(discharge_ref)
    assert (
        Verifier()
        .verify(
            Macaroon.decode(reference.serialize()),
            "root",
            [Macaroon.decode(bound.serialize())],
        )
        .caveats
        == ()
    )
