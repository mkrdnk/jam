"""Standalone module contract, without managed keys or Jam policy."""

from collections.abc import Callable, Iterable, Mapping
from typing import Any

import pytest

from jam.exceptions import JamConfigurationError
from jam.macaroons import (
    BaseMacaroon,
    Caveat,
    InvalidCaveatError,
    Limits,
    Macaroon,
    MacaroonModule,
    SerializationError,
    VerificationError,
    VerificationResult,
    Verifier,
)


@pytest.mark.parametrize("identifier", [b"opaque-id", "opaque-id"])
@pytest.mark.parametrize("key", [b"root-secret", "root-secret"])
def test_explicit_keys_round_trip(identifier, key):
    module: BaseMacaroon = MacaroonModule()
    token = module.encode(identifier, key, location="issuer")
    decoded = module.decode(token.encode())
    assert decoded.identifier == b"opaque-id"
    assert decoded.location == "issuer"
    assert module.verify(token, key) == VerificationResult(())
    assert module.verify(decoded, key) == VerificationResult(())
    with pytest.raises(VerificationError):
        module.verify(token, "wrong-key")


def test_unknown_predicates_fail_closed():
    module = MacaroonModule()
    root = module.decode(module.encode("id", "key"))
    opaque = root.add_caveat(b"opaque")
    with pytest.raises(VerificationError):
        module.verify(opaque, "key", collect_structured=True)
    module.satisfy_exact("opaque")
    assert module.verify(opaque, "key") == VerificationResult(())
    module.satisfy_general(lambda value: value == b"custom")
    assert module.verify(
        root.add_caveat(b"custom"), "key"
    ) == VerificationResult(())
    structured = root.add_caveat(Caveat("custom", "allowed"))
    with pytest.raises(InvalidCaveatError):
        module.verify(structured, "key")
    result = module.verify(
        structured,
        "key",
        structured_satisfiers={"custom": lambda value: value == "allowed"},
    )
    assert result.caveats == (Caveat("custom", "allowed"),)
    assert module.verify(structured, "key", collect_structured=True) == result
    with pytest.raises(VerificationError):
        module.verify(
            structured,
            "key",
            structured_satisfiers={"custom": lambda value: False},
            collect_structured=True,
        )
    with pytest.raises(InvalidCaveatError):
        module.verify(
            root.add_caveat(b"jam:v99:unknown"),
            "key",
            collect_structured=True,
        )


def test_discharge_graph_accepts_models_and_encoded_tokens():
    module = MacaroonModule()
    primary = module.decode(module.encode("id", "key"))
    primary = primary.add_third_party_caveat("third-party", "discharge")
    discharge = Macaroon.create_discharge("third-party", "discharge")
    with pytest.raises(VerificationError):
        module.verify(primary, "key")
    with pytest.raises(VerificationError):
        module.verify(primary, "key", [discharge])
    bound = discharge.bind(primary)
    for token in (bound, bound.encode(), bound.encode().encode()):
        assert module.verify(
            primary.encode(), "key", iter([token])
        ) == VerificationResult(())
    restricted = discharge.add_caveat(b"unknown").bind(primary)
    with pytest.raises(VerificationError):
        module.verify(primary, "key", [restricted])
    module.satisfy_exact(b"unknown")
    assert module.verify(primary, "key", [restricted]) == VerificationResult(())


def test_discharge_limit_applies_before_decoding():
    module = MacaroonModule(limits=Limits(discharge_count=1))
    with pytest.raises(VerificationError, match="Too many discharges"):
        module.verify(module.encode("id", "key"), "key", ["bad", "bad"])


def test_profile_operations_require_managed_keys():
    module = MacaroonModule()
    with pytest.raises(JamConfigurationError, match="require a KeyChain"):
        module.issue({"sub": "alice"})
    with pytest.raises(JamConfigurationError, match="require a KeyChain"):
        module.authenticate("invalid")
    with pytest.raises(SerializationError):
        module.decode("invalid")


class IndependentModule(BaseMacaroon):
    """Minimal protocol implementation using no Jam profile interfaces."""

    def __init__(self) -> None:
        self.verifier = Verifier()

    def encode(
        self,
        identifier: bytes | str,
        root_key: bytes | str,
        *,
        location: str = "",
    ) -> str:
        return Macaroon.create(root_key, identifier, location).encode()

    def decode(self, token: bytes | str) -> Macaroon:
        return Macaroon.decode(token)

    def verify(
        self,
        token: bytes | str | Macaroon,
        root_key: bytes | str,
        discharges: Iterable[bytes | str | Macaroon] = (),
        *,
        structured_satisfiers: Mapping[str, Callable[[Any], bool]]
        | None = None,
        collect_structured: bool = False,
    ) -> VerificationResult:
        return self.verifier.verify(
            token if isinstance(token, Macaroon) else self.decode(token),
            root_key,
            (
                item if isinstance(item, Macaroon) else self.decode(item)
                for item in discharges
            ),
            structured_satisfiers=structured_satisfiers,
            collect_structured=collect_structured,
        )

    def satisfy_exact(self, caveat: bytes | str) -> None:
        self.verifier.satisfy_exact(caveat)

    def satisfy_general(self, satisfier: Callable[[bytes], bool]) -> None:
        self.verifier.satisfy_general(satisfier)


def test_custom_protocol_implementation_has_no_profile_requirements():
    module: BaseMacaroon = IndependentModule()
    assert not hasattr(module, "issue")
    assert not hasattr(module, "authenticate")
    assert not hasattr(module, "keychain")
    assert module.verify(
        module.encode("id", "key"), "key"
    ) == VerificationResult(())
